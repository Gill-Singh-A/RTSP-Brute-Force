# RTSP Brute Force
A Python program that uses the OpenCV module to brute force the RTSP (Real Time Streaming Protocol) service used by IoT (Internet of Things) devices like CCTVs (Closed-circuit television), etc.

It is **vendor-aware**: before brute forcing, it fingerprints each camera's vendor (and model, when ONVIF is available) and tries **that vendor's default credential first** — using a bundled default-credentials list originally scraped from [ispyconnect.com](https://www.ispyconnect.com/cameras) — before falling back to the supplied wordlist. The tool is fully self-contained: the credential and camera-path databases ship under `data/`, so it has no dependency on any sibling project.

> ⚠️ **Authorized use only.** Use this tool exclusively on cameras you own or have explicit written permission to access.

## How it works
For each target host the tool runs a best-effort chain and stops at the first working credential:

1. **Reachability pre-check** — a fast TCP connect to the RTSP/HTTP port; offline hosts are marked *Unreachable* and skipped instantly (no slow RTSP probing). Timeout via `-r` (`0` disables the check).
2. **Fingerprint** — vendor/model via ONVIF `GetDeviceInformation` (if the optional `onvif-zeep` package is installed), else the HTTP `Server` header / 401 `WWW-Authenticate` realm / page `<title>`, else the RTSP `OPTIONS` `Server` header.
3. **Exact stream path (ONVIF)** — when the camera speaks ONVIF, `GetStreamUri` is queried for the device's *actual* RTSP path(s); these go to the **front** of the route list, so path discovery is a fact rather than a guess. The credential ONVIF accepts is also tried first at the RTSP layer. Behind the ONVIF paths come the vendor/model paths from `data/cameras.csv` and a set of generic fall-backs. Falls back silently to the DB/generic routes when ONVIF is absent.
4. **Credential order** — the fingerprinted vendor's default credential first, then the user-supplied `user × password` combinations, then (optionally, with `-a`) every scraped vendor default as a last-resort fallback.
5. **Brute force (credential-outer)** — every host is prepared once (steps 1–4), then the attack runs **credential-by-credential across the whole fleet**: round 1 tries each host's *first* credential, round 2 the *second*, and so on. Because a given camera is touched only **once per round** — instead of one worker draining its entire wordlist back-to-back — it gets time to cool down between attempts, which avoids the per-camera **rate-limiting / anti-brute-force** that otherwise drops cameras and makes the count vary run-to-run. Each attempt is a native RTSP `DESCRIBE` with a full Digest/Basic challenge+response handshake performed **on a single connection** (mandatory for Dahua/CP-Plus-style cameras whose nonce is bound to the TCP connection). A `200` is success; a `404` means the credential is valid but the path is wrong, so the remaining routes are swept with that known-good credential. A cheap unauthenticated **open-access** check runs first (round 0). After the native rounds, a **route-removed FFmpeg fallback** (the original tool's method — a full open on `rtsp://user:pass@host`, OpenCV-only) runs, also credential-outer, for any host the native engine couldn't crack; it handles the *401-both* case (a camera that answers `401` for both a wrong credential *and* a valid credential on a wrong path). FFmpeg hits are flagged *"(via ffmpeg, route removed)"* and confirm the **credential** rather than the exact path. The end-of-run summary breaks successes down **by method** (`native` / `ffmpeg` / `no-auth` / `no-route`) and reports `Reached, No Credential`.

The default-credentials list is loaded automatically from the bundled `data/default_credentials.csv`. Override the path with `-d`.

Concurrency uses a **thread pool** (`concurrent.futures.ThreadPoolExecutor`) — RTSP/socket work is I/O-bound, so threads avoid the pickling/startup cost of process pools while sharing the loaded credential DB. The parallelism is **across cameras within a round**, so many cameras are tried at once while any single camera still only sees one attempt per round.

> **Note on the scraped defaults:** the defaults are keyed on the vendor name and a vendor may have several known pairs (e.g. Hikvision → `admin/12345` then `admin/admin`), each tried in listed order before the wordlist. Enriching `data/default_credentials.csv` with more per-vendor defaults automatically improves this tool with no code change.

## Requirements
Language: Python 3<br />
Modules/Packages used: `colorama`, `tqdm` (progress bar), `cv2` (opencv-python — optional frame capture *and* the FFmpeg 401-both fallback), `scapy` (third-party); `pickle`, `hashlib`, `base64`, `socket`, `re`, `csv`, `threading`, `concurrent.futures`, `pathlib`, `datetime`, `urllib`, `optparse`, `time` (standard library). `onvif-zeep` is optional (enables ONVIF vendor+model fingerprinting and exact stream-path discovery via `GetStreamUri`). Every third-party import is guarded, so the tool still runs (with reduced features) if an optional one is missing.

Install the dependencies:
```bash
pip install -r requirements.txt
```

## Arguments
It takes in the following command line arguments:
* `-i`, `--ip` : File name of a list of IP addresses (separated by `,`, either a file name or the IP itself)
* `-C`, `--capture-file` : Packet capture files (separated by `,`)
* `-D`, `--capture-file-data` : Dump data extracted from the capture file in Pickle format (optional)
* `-u`, `--user` : Username for brute force (separated by `,`, either a file name or the username itself)
* `-p`, `--password` : Password for brute force (separated by `,`, either a file name or the password itself)
* `-d`, `--default-creds` : Path to the scraped default-credentials CSV (default: bundled `data/default_credentials.csv`)
* `-f`, `--fingerprint` : Fingerprint each camera's vendor/model and try its default credential first (True/False, Default=True)
* `-a`, `--all-defaults` : After the wordlist, also try every scraped vendor default as a fallback (True/False, Default=False)
* `-t`, `--threads` : Number of worker threads (Default: `min(64, cpu_count * 5)`)
* `-r`, `--reach-timeout` : TCP reachability pre-check timeout in seconds; `0` disables it (Default=2.0)
* `-R`, `--rtsp-timeout` : Per-request RTSP `DESCRIBE` timeout in seconds (Default=6.0)
* `-H`, `--http-port` : HTTP/ONVIF port for fingerprinting on cameras whose web interface isn't on `80` (Default=80). Tried first, ahead of the standard ONVIF ports. The **RTSP** port is set per target with `host:port` (see below).
* `-v`, `--verbose` : Display additional information (True/False, Default=True)
* `-c`, `--capture` : Capture a frame if login is successful (True/False, Default=False)
* `-w`, `--write` : Name of the CSV file for the successfully logged-in IPs to be dumped (default = current date and time). Columns: `User,Password,IP,Vendor,Model`
<!-- --><br />

### Target syntax (non-default ports)
Each target may be a bare host or `host:port`, where `port` is the **RTSP** port (default `554`). This applies both to `-i` values and to each line of an IP-list file. IPv6 must be bracketed.

```
172.29.114.250          # RTSP on the default 554
172.29.114.250:8554     # RTSP on a non-default port
[fe80::1]:10554         # bracketed IPv6 + port
```

The RTSP port set this way flows through reachability, the native `DESCRIBE` engine, and the FFmpeg fallback. Fingerprinting/ONVIF still targets HTTP port `80` (plus the standard ONVIF ports); use `-H`/`--http-port` when the camera's web/ONVIF interface is on a different port.

### Examples
```bash
# Vendor-aware brute force over a list of IPs (defaults tried first, then the wordlist)
python3 main.py -i targets.txt -u admin,root -p passwords.txt

# Also try every scraped vendor default as a fallback, capture a frame on success
python3 main.py -i 192.168.1.10,192.168.1.11 -u admin -p admin,12345 -a True -c True

# RTSP on a non-default port, with the web/ONVIF interface on 8899
python3 main.py -i 192.168.1.10:8554 -H 8899 -u admin -p admin@123

# Crack digest/basic auth captured in a packet capture
python3 main.py -C capture.pcap -p passwords.txt
```

### Progress
While running, a live [`tqdm`](https://github.com/tqdm/tqdm) bar tracks the current phase (one tick per host for the brute force, per device for the digest crack). Per-host result lines print **above** the bar so nothing is lost:

```text
[:] [2025-01-01 12:00:00] Total Number of IP Addresses = 3
[:] [2025-01-01 12:00:00] Starting 40 Threads
[-] [2025-01-01 12:00:01] 192.168.1.12 => Unreachable (skipped)
[*] [2025-01-01 12:00:02] 192.168.1.10 => Vendor=Hikvision Model=?
[+] [2025-01-01 12:00:02] admin:12345@192.168.1.10 => Access Granted (vendor=Hikvision)
Brute forcing:  67%|██████▋   | 2/3 [00:01<00:00,  1.98host/s]
```

If `tqdm` isn't installed the tool runs identically, just without the bar.

To see how we can brute-force the RTSP protocol and gain access to CCTVs using this program, see the blog [Compromising CCTVs 101](https://medium.com/@amansg22/compromising-cctvs-101-ecd41748c90c) on [Medium](https://medium.com/@amansg22).
