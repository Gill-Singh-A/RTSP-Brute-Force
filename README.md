# RTSP Brute Force
A Python program that uses the OpenCV module to brute force the RTSP (Real Time Streaming Protocol) service used by IoT (Internet of Things) devices like CCTVs (Closed-circuit television), etc.

It is **vendor-aware**: before brute forcing, it fingerprints each camera's vendor (and model, when ONVIF is available) and tries **that vendor's default credential first** — using a bundled default-credentials list originally scraped from [ispyconnect.com](https://www.ispyconnect.com/cameras) — before falling back to the supplied wordlist. The tool is fully self-contained: the credential and camera-path databases ship under `data/`, so it has no dependency on any sibling project.

> ⚠️ **Authorized use only.** Use this tool exclusively on cameras you own or have explicit written permission to access.

## How it works
For each target host the tool runs a best-effort chain and stops at the first working credential:

1. **Reachability pre-check** — a fast TCP connect to the RTSP/HTTP port; offline hosts are marked *Unreachable* and skipped instantly (no slow RTSP probing). Timeout via `-r` (`0` disables the check).
2. **Fingerprint** — vendor/model via ONVIF `GetDeviceInformation` (if the optional `onvif-zeep` package is installed), else the HTTP `Server` header / 401 `WWW-Authenticate` realm / page `<title>`, else the RTSP `OPTIONS` `Server` header.
3. **Credential order** — the fingerprinted vendor's default credential first, then the user-supplied `user × password` combinations, then (optionally, with `-a`) every scraped vendor default as a last-resort fallback.

The default-credentials list is loaded automatically from the bundled `data/default_credentials.csv`. Override the path with `-d`.

Concurrency uses a **thread pool** (`concurrent.futures.ThreadPoolExecutor`) — RTSP/socket work is I/O-bound, so threads avoid the pickling/startup cost of process pools while sharing the loaded credential DB. Each host is handled by one worker that stops at its first success.

> **Note on the scraped defaults:** the defaults are keyed on the vendor name and a vendor may have several known pairs (e.g. Hikvision → `admin/12345` then `admin/admin`), each tried in listed order before the wordlist. Enriching `data/default_credentials.csv` with more per-vendor defaults automatically improves this tool with no code change.

## Requirements
Language: Python 3<br />
Modules/Packages used: `colorama`, `tqdm` (progress bar), `cv2` (opencv-python), `scapy` (third-party); `pickle`, `hashlib`, `base64`, `socket`, `re`, `csv`, `threading`, `concurrent.futures`, `pathlib`, `datetime`, `urllib`, `optparse`, `time` (standard library). `onvif-zeep` is optional (enables ONVIF vendor+model fingerprinting). Every third-party import is guarded, so the tool still runs (with reduced features) if an optional one is missing.

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
* `-v`, `--verbose` : Display additional information (True/False, Default=True)
* `-c`, `--capture` : Capture a frame if login is successful (True/False, Default=False)
* `-w`, `--write` : Name of the CSV file for the successfully logged-in IPs to be dumped (default = current date and time). Columns: `User,Password,IP,Vendor,Model`
<!-- --><br />

### Examples
```bash
# Vendor-aware brute force over a list of IPs (defaults tried first, then the wordlist)
python3 main.py -i targets.txt -u admin,root -p passwords.txt

# Also try every scraped vendor default as a fallback, capture a frame on success
python3 main.py -i 192.168.1.10,192.168.1.11 -u admin -p admin,12345 -a True -c True

# Crack digest/basic auth captured in a packet capture
python3 main.py -C capture.pcap -p passwords.txt
```

To see how we can brute-force the RTSP protocol and gain access to CCTVs using this program, see the blog [Compromising CCTVs 101](https://medium.com/@amansg22/compromising-cctvs-101-ecd41748c90c) on [Medium](https://medium.com/@amansg22).
