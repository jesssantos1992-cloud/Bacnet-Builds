#!/usr/bin/env python3
"""
bacnet_live.py - Live BACnet capture with a Wireshark-style web interface.

Run it on the PC that is plugged into (or mirrored from) the BACnet network.
It opens bacnet_inspector.html in your browser with live capture switched on.
Keep bacnet_live.py and bacnet_inspector.html in the same folder.

    python bacnet_live.py                  # opens the browser, pick an interface, press Start
    python bacnet_live.py --lan            # also reachable from an iPhone/iPad on the same Wi-Fi
    python bacnet_live.py -i 5 -f "udp port 47808"          # start straight away (dumpcap interface 5)
    python bacnet_live.py --serial COM3 --baud 38400        # live MS/TP from a USB-RS485 adapter

Three ways to capture (the interface list shows whatever is available):
  1. Wireshark/Npcap  - install Wireshark (https://www.wireshark.org); this uses its
                        "dumpcap". Supports a capture filter (BPF). Best choice.
  2. Serial MS/TP     - a USB-RS485 adapter wired to the trunk. Needs:  pip install pyserial
  3. Built-in raw     - BACnet/IP only, no install, but needs Administrator (Windows) or root.

iPhone/iPad cannot capture packets themselves (iOS does not allow it). With --lan they can
watch the capture running on your PC. The link contains a secret token; the connection is
plain HTTP, so only use --lan on a network you trust.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = getattr(sys, "_MEIPASS", HERE)                 # inside a packaged .exe the page is unpacked here
UI_FILE = os.path.join(BASE, "bacnet_inspector.html")
NOWIN = 0x08000000 if os.name == "nt" else 0          # hide console windows on Windows
MAX_PACKETS = 200_000


# ------------------------------------------------------------------ updates --
def _read_bundled(name, default=""):
    for d in (BASE, HERE):
        try:
            with open(os.path.join(d, name), encoding="utf-8") as f:
                t = f.read().strip()
                if t:
                    return t
        except OSError:
            pass
    return default


APP_VERSION = _read_bundled("version.txt", "0.0.0")
# Where the update manifest (update.json) lives. Set in update_url.txt (bundled by build_windows.bat)
# or with the BACNET_INSPECTOR_UPDATE_URL environment variable. See RELEASING.txt.
UPDATE_URL = os.environ.get("BACNET_INSPECTOR_UPDATE_URL") or _read_bundled("update_url.txt")
_UPD_LOCK = threading.Lock()


def _vt(s):
    return tuple(int(x) for x in re.findall(r"\d+", str(s))[:4]) or (0,)


def _fetch(url, limit):
    req = urllib.request.Request(url, headers={"User-Agent": "BACnetInspector/" + APP_VERSION})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read(limit + 1)[:limit]


def update_manifest():
    """Download and sanity-check update.json. Returns (manifest, error)."""
    if not UPDATE_URL:
        return None, "Updates are not set up in this build."
    if not UPDATE_URL.lower().startswith("https://"):
        return None, "The update address must start with https://"
    try:
        m = json.loads(_fetch(UPDATE_URL, 200_000).decode("utf-8"))
    except Exception as ex:                                   # offline, 404, bad JSON ...
        return None, "Could not reach the update server (%s)." % (str(ex)[:80] or type(ex).__name__)
    if not isinstance(m, dict) or not m.get("version"):
        return None, "The update file is not valid."
    return m, ""


def update_check():
    m, err = update_manifest()
    out = {"current": APP_VERSION, "configured": bool(UPDATE_URL), "can_install": bool(getattr(sys, "frozen", False)) and sys.platform == "win32"}
    if err:
        out.update(ok=False, error=err)
        return out
    newer = _vt(m["version"]) > _vt(APP_VERSION)
    out.update(ok=True, latest=str(m["version"]), newer=newer, notes=str(m.get("notes") or "")[:4000],
               date=str(m.get("date") or "")[:40], page=(str(m.get("page") or "")[:300] if str(m.get("page") or "").lower().startswith("https://") else ""))
    return out


def update_install():
    """Download the installer named in the manifest, check its SHA-256, run it silently, then quit."""
    import hashlib
    import tempfile
    if not getattr(sys, "frozen", False) or sys.platform != "win32":
        return {"ok": False, "error": "Automatic install only works in the installed Windows app."}
    if not _UPD_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "An update is already in progress."}
    try:
        m, err = update_manifest()                            # re-read it here; never trust the page for the URL
        if err:
            return {"ok": False, "error": err}
        url, want = str(m.get("url") or ""), str(m.get("sha256") or "").lower()
        if _vt(m["version"]) <= _vt(APP_VERSION):
            return {"ok": False, "error": "You already have the latest version."}
        if not url.lower().startswith("https://") or not re.fullmatch(r"[0-9a-f]{64}", want):
            return {"ok": False, "error": "The update file is missing its download address or checksum."}
        try:
            data = _fetch(url, 400_000_000)
        except Exception as ex:
            return {"ok": False, "error": "Download failed (%s)." % (str(ex)[:80] or type(ex).__name__)}
        if hashlib.sha256(data).hexdigest() != want:
            return {"ok": False, "error": "The download did not match its checksum, so it was not installed."}
        d = tempfile.mkdtemp(prefix="bacnet-inspector-update-")
        path = os.path.join(d, "BACnet-Inspector-Setup-%s.exe" % re.sub(r"[^0-9A-Za-z.]", "", str(m["version"])))
        with open(path, "wb") as f:
            f.write(data)
        flags = 0x00000008 | 0x00000200                       # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        subprocess.Popen([path, "/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS", "/NOCANCEL"],
                         creationflags=flags, close_fds=True)
        threading.Timer(1.5, lambda: os._exit(0)).start()     # let the installer take over
        return {"ok": True}
    finally:
        _UPD_LOCK.release()


# ---------------------------------------------------------------- MS/TP CRC --
def _t8():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x81 if c & 1 else c >> 1
        t.append(c)
    return t


_T8 = _t8()


def header_crc_ok(h: bytes, crc: int) -> bool:
    c = 0xFF
    for b in h:
        c = _T8[c ^ b]
    return (~c) & 0xFF == crc


def is_bacnet_udp(f: bytes) -> bool:
    if len(f) < 42 or f[12:14] != b"\x08\x00" or f[23] != 17:
        return False
    u = 14 + (f[14] & 15) * 4
    if len(f) < u + 4:
        return False
    sp, dp = (f[u] << 8) | f[u + 1], (f[u + 2] << 8) | f[u + 3]
    return 47808 <= sp <= 47823 or 47808 <= dp <= 47823


# ------------------------------------------------------------ interfaces -----
def find_dumpcap():
    p = shutil.which("dumpcap")
    if p:
        return p
    exe = "dumpcap.exe" if os.name == "nt" else "dumpcap"
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                 r"C:\Program Files", "/Applications/Wireshark.app/Contents/MacOS", "/usr/bin"):
        for sub in ("Wireshark", ""):
            if base and os.path.isfile(os.path.join(base, sub, exe)):
                return os.path.join(base, sub, exe)
    return None


_VIRTUAL = re.compile(r"wi-?fi|wireless|wlan|bluetooth|loopback|vethernet|virtual|vmware|vbox|hyper-?v|wsl|vpn|\btap\b|\btun\b|docker|isatap|teredo|miniport|tailscale|zerotier|hamachi|pseudo", re.I)
_WIRED = re.compile(r"ethernet|\blan\b|\beth\d|\ben\d|\benp\d|\beno\d|local area", re.I)


def _wired_up_guids():
    """Windows: GUIDs of physical Ethernet (802.3) adapters that are connected right now."""
    if os.name != "nt":
        return set()
    cmd = ("Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.PhysicalMediaType -eq '802.3' } "
           "| ForEach-Object { $_.InterfaceGuid }")
    try:
        txt = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                             capture_output=True, text=True, timeout=8, creationflags=NOWIN).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    return {g.strip().strip("{}").lower() for g in txt.split() if g.strip()}


def _pick_auto(items, up_guids=frozenset()):
    """Mark the best capture adapter with auto=True: a connected wired Ethernet port."""
    best, score = None, 0
    for it in items:
        if it.get("backend") != "dumpcap":
            continue
        dev, label = it.get("dev", ""), it["name"].split("  [")[0]
        s = 1
        if any(g and g in dev.lower() for g in up_guids):
            s = 100
        elif _VIRTUAL.search(label) or _VIRTUAL.search(dev):
            s = 0
        elif _WIRED.search(label):
            s = 50
        if s > score:
            best, score = it, s
    if best:
        best["auto"] = True
        best["wired"] = score >= 50
    return best


def list_interfaces():
    out = []
    exe = find_dumpcap()
    if exe:
        try:
            txt = subprocess.run([exe, "-D"], capture_output=True, text=True, timeout=15,
                                 creationflags=NOWIN).stdout
            for line in txt.splitlines():
                m = re.match(r"\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line)
                if m:
                    out.append({"backend": "dumpcap", "id": m.group(1), "dev": m.group(2),
                                "name": f"{m.group(3) or m.group(2)}  [Wireshark/Npcap]"})
        except (OSError, subprocess.SubprocessError):
            pass
        _pick_auto([x for x in out if x.get('backend') == 'dumpcap'], _wired_up_guids())
    try:
        from serial.tools import list_ports
        ports = list(list_ports.comports())
        for p in ports:
            out.append({"backend": "serial", "id": p.device,
                        "name": f"{p.device} - {p.description}  [MS/TP serial]"})
        if not ports:
            out.append({"backend": "none", "id": "", "name": "(No serial / USB RS-485 adapter found - plug it in, then press \u21bb)",
                        "hint": "No serial adapter found. Plug in your USB RS-485 adapter, then press the refresh button (\u21bb)."})
    except ImportError:
        out.append({"backend": "none", "id": "", "name": "(MS/TP serial is unavailable - pyserial is not installed)",
                    "hint": "MS/TP serial capture needs pyserial. Run  pip install pyserial  (the Windows app includes it)."})
    if os.name == "nt":
        try:
            ips = socket.gethostbyname_ex(socket.gethostname())[2]
        except OSError:
            ips = []
        for ip in ips:
            out.append({"backend": "raw", "id": ip,
                        "name": f"{ip}  [built-in, BACnet/IP only, needs Administrator]"})
    elif hasattr(socket, "if_nameindex"):
        for _i, n in socket.if_nameindex():
            out.append({"backend": "raw", "id": n,
                        "name": f"{n}  [built-in, BACnet/IP only, needs root]"})
    return out


# --------------------------------------------------------------- capture -----
def serial_error(ex, port):
    t = str(ex)
    low = t.lower()
    if "access is denied" in low or "permission" in low or "busy" in low or "in use" in low:
        return (f"{port} is being used by another program (for example Wireshark, another BACnet tool or a "
                "serial terminal). Close it and press Start again.")
    if "cannot find" in low or "no such file" in low or "filenotfound" in low or "could not open port" in low and "2" in t[:80]:
        return f"{port} was not found. Is the adapter still plugged in? Press the refresh button (\u21bb) next to the adapter list."
    return f"Could not open {port}: {t}"


def count_frames(data: bytes) -> int:
    """How many MS/TP frames with a valid header CRC are in this byte stream (used to detect the baud rate)."""
    n = i = 0
    while True:
        i = data.find(b"\x55\xff", i)
        if i < 0 or i + 8 > len(data):
            return n
        ln = (data[i + 5] << 8) | data[i + 6]
        if data[i + 2] <= 7 and ln <= 1500 and header_crc_ok(data[i + 2:i + 7], data[i + 7]):
            n += 1
            i += 8 + (ln + 2 if ln else 0)
        else:
            i += 2


def autobaud(port, secs=2.5, rates=(38400, 9600, 19200, 76800, 115200, 57600)):
    """Listen on the port at each common baud rate; the right one produces valid MS/TP frames."""
    try:
        import serial
    except ImportError:
        return {"error": "Serial capture needs pyserial: run  pip install pyserial"}
    counts = {}
    for b in rates:
        try:
            sp = serial.Serial(port, b, timeout=0.05)
        except Exception as ex:
            return {"error": serial_error(ex, port)}
        buf = bytearray()
        end = time.time() + secs
        try:
            while time.time() < end:
                buf += sp.read(sp.in_waiting or 1)
        except Exception as ex:
            sp.close()
            return {"error": serial_error(ex, port)}
        sp.close()
        counts[b] = count_frames(bytes(buf))
        if counts[b] >= 10:
            break
    best = max(counts, key=counts.get)
    return {"baud": best if counts[best] >= 3 else None, "counts": counts}


class Capture:
    def __init__(self):
        self.lock = threading.Lock()
        self.pk = []                       # (ts, linktype, bytes)
        self.base = 0                      # absolute number of pk[0]
        self.running = False
        self.err = ""
        self.stop_ev = threading.Event()
        self.proc = None
        self.thread = None
        self.files = {}                   # id -> path of capture files to open as tabs
        self.queue = []                   # ids the web page has not picked up yet
        self.fid = 0

    def add(self, ts, lt, data):
        with self.lock:
            self.pk.append((ts, lt, data))
            if len(self.pk) > MAX_PACKETS:
                k = MAX_PACKETS // 10
                del self.pk[:k]
                self.base += k

    def clear(self):
        with self.lock:
            self.pk, self.base = [], 0

    def add_file(self, path):
        with self.lock:
            self.fid += 1
            self.files[self.fid] = path
            self.queue.append(self.fid)

    def pending(self):
        with self.lock:
            out = [{"id": i, "name": os.path.basename(self.files[i]), "path": self.files[i]} for i in self.queue]
            self.queue.clear()
            return out

    def fetch(self, since):
        with self.lock:
            end = self.base + len(self.pk)
            since = min(max(since, self.base), end)
            items = self.pk[since - self.base: since - self.base + 3000]
            return {"n": since + len(items), "running": self.running, "err": self.err,
                    "packets": [{"t": t, "lt": lt, "d": base64.b64encode(d).decode()}
                                for t, lt, d in items]}

    def pcapng(self):
        with self.lock:
            pk = list(self.pk)

        def blk(t, b):
            b += b"\0" * (-len(b) % 4)
            return struct.pack("<II", t, len(b) + 12) + b + struct.pack("<I", len(b) + 12)
        lts = sorted({lt for _, lt, _ in pk}) or [1]
        out = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        for lt in lts:
            out += blk(1, struct.pack("<HHI", lt, 0, 65535))
        for ts, lt, d in pk:
            t = int(ts * 1e6)
            out += blk(6, struct.pack("<IIIII", lts.index(lt), t >> 32, t & 0xFFFFFFFF,
                                      len(d), len(d)) + d)
        return out

    def stop(self):
        self.stop_ev.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=3)
        self.running = False

    def start(self, backend, iface, flt="", baud=38400):
        self.stop()
        self.clear()
        self.err = ""
        self.stop_ev = threading.Event()
        fn = {"dumpcap": self._dumpcap, "serial": self._serial, "raw": self._raw}.get(backend)
        if not fn:
            self.err = "Choose an interface first."
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, args=(fn, iface, flt, baud), daemon=True)
        self.thread.start()

    def _run(self, fn, iface, flt, baud):
        try:
            fn(iface, flt, baud)
        except Exception as ex:                      # keep the server alive
            self.err = self.err or f"Capture stopped: {ex}"
        self.running = False

    # -- backend 1: Wireshark dumpcap ----------------------------------------
    def _dumpcap(self, iface, flt, _baud):
        exe = find_dumpcap()
        if not exe:
            self.err = "Wireshark's dumpcap was not found. Install Wireshark (it includes Npcap)."
            return
        cmd = [exe, "-i", str(iface), "-P", "-q", "-w", "-"]
        if flt.strip():
            cmd += ["-f", flt.strip()]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     creationflags=NOWIN)
        errs = []
        threading.Thread(target=lambda: errs.append(self.proc.stderr.read()), daemon=True).start()
        out = self.proc.stdout
        hdr = out.read(24)
        if len(hdr) == 24:
            le = hdr[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
            nano = hdr[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
            e = "<" if le else ">"
            lt = struct.unpack(e + "I", hdr[20:24])[0] & 0x0FFFFFFF
            while not self.stop_ev.is_set():
                rec = out.read(16)
                if len(rec) < 16:
                    break
                s, f, incl, _o = struct.unpack(e + "IIII", rec)
                data = out.read(incl)
                if len(data) < incl:
                    break
                self.add(s + f / (1e9 if nano else 1e6), lt, data)
        if not self.stop_ev.is_set():
            time.sleep(0.3)
            msg = (errs[0].decode(errors="replace").strip() if errs else "")
            self.err = msg or "Capture ended unexpectedly."
            if "ermission" in msg or "denied" in msg:
                self.err += "  (Try running as Administrator, or reinstall Npcap without 'Restrict to Administrators'.)"

    # -- backend 2: serial MS/TP ---------------------------------------------
    def _serial(self, port, _flt, baud):
        try:
            import serial
        except ImportError:
            self.err = "Serial capture needs pyserial: run  pip install pyserial"
            return
        try:
            sp = serial.Serial(port, int(baud), timeout=0.02)
        except Exception as ex:
            self.err = serial_error(ex, port)
            return
        buf = bytearray()
        try:
            while not self.stop_ev.is_set():
                chunk = sp.read(sp.in_waiting or 1)          # short reads keep the timestamps accurate
                buf += chunk
                self.mstp_scan(buf, flush=not chunk)
        except Exception as ex:
            if not self.stop_ev.is_set():
                self.err = f"Lost the connection to {port} (was the adapter unplugged?) - {ex}"
        finally:
            try:
                sp.close()
            except Exception:
                pass

    def mstp_scan(self, buf: bytearray, flush=False):
        """Cut MS/TP frames out of a raw byte stream and store them (link type 165)."""
        while True:
            i = buf.find(b"\x55\xff")
            if i < 0:
                del buf[:max(0, len(buf) - 1)]
                return
            del buf[:i]
            if len(buf) < 8:
                if flush:
                    del buf[:2]
                    continue
                return
            if not header_crc_ok(bytes(buf[2:7]), buf[7]):          # damaged header
                self.add(time.time(), 165, bytes(buf[:8]))
                del buf[:2]
                continue
            ln = (buf[5] << 8) | buf[6]
            if ln > 1500:
                del buf[:2]
                continue
            need = 8 + (ln + 2 if ln else 0)
            if len(buf) < need:
                if flush:                                              # frame never finished
                    del buf[:2]
                    continue
                return
            self.add(time.time(), 165, bytes(buf[:need]))
            del buf[:need]

    # -- backend 3: built-in raw sockets (BACnet/IP only) ---------------------
    def _raw(self, iface, _flt, _baud):
        nt = os.name == "nt"
        try:
            if nt:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((iface, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                s.bind((iface, 0))
        except (OSError, AttributeError) as ex:
            self.err = f"Built-in capture needs Administrator/root: {ex}"
            return
        s.settimeout(0.5)
        while not self.stop_ev.is_set():
            try:
                data = s.recv(65535)
            except socket.timeout:
                continue
            frame = (b"\0" * 12 + b"\x08\x00" + data) if nt else data
            if is_bacnet_udp(frame):
                self.add(time.time(), 1, frame)
        if nt:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        s.close()


# ------------------------------------------------------------------ server ---
# ---- sending (BACnet/IP only) ----------------------------------------------------------------
# Each message is one UDP broadcast: BVLC "Original-Broadcast-NPDU" + NPDU (+ APDU).
PKTS = {
    # Who-Is, no device-ID limits, global broadcast (hop count 255) so routers pass it on
    "whois": bytes.fromhex("810b000c0120ffff00ff1008"),
    # Who-Is-Router-To-Network, no network given: every router answers with I-Am-Router-To-Network
    "whoisrouter": bytes.fromhex("810b0007018000"),
    # What-Is-Network-Number: routers answer with Network-Number-Is
    "netnum": bytes.fromhex("810b0007018012"),
}
_last_send = [0.0]


def local_ips():
    ips = set()
    try:
        ips.update(i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET))
    except OSError:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
    except OSError:
        pass
    finally:
        s.close()
    return sorted(i for i in ips if not i.startswith("127."))


def send_bacnet(kind, src, dst):
    """Returns "" on success or a plain-English error."""
    pkt = PKTS.get(kind)
    if not pkt:
        return "Unknown message type."
    try:
        ipaddress.IPv4Address(dst)
        if src:
            ipaddress.IPv4Address(src)
    except ValueError:
        return "Addresses must be IPv4, for example 255.255.255.255 or 10.0.0.255."
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((src or "0.0.0.0", 47808))              # devices expect BACnet traffic from 47808
        except OSError:
            s.bind((src or "0.0.0.0", 0))                  # another program owns 47808: use any port
        s.sendto(pkt, (dst, 47808))
    except OSError as ex:
        return f"Could not send: {ex}"
    finally:
        s.close()
    return ""


def send_request(body):
    if time.time() - _last_send[0] < 1.0:
        return {"ok": False, "error": "Please wait a second between sends."}
    err = send_bacnet(body.get("kind"), (body.get("from") or "").strip(),
                      (body.get("to") or "255.255.255.255").strip())
    if not err:
        _last_send[0] = time.time()
    return {"ok": not err, "error": err}


# ---------------------------------------------------------------------------------------------
# Network scan relay for the "Explorer" tab.
# The page builds BACnet requests; this relay only carries them. It is deliberately READ-ONLY:
# every packet is parsed here and refused unless it is Who-Is, Who-Has, ReadProperty,
# ReadPropertyMultiple, ReadRange, Segment-ACK, Who-Is-Router-To-Network or
# What-Is-Network-Number.
# The ONLY thing that can change a device is WriteProperty of present-value (with optional
# priority, or NULL to relinquish) to ONE device by unicast, and only while write access has
# been switched on by the user (it switches itself off after a few minutes). Every write is
# appended to writes.log. Restarts, communication control, object create/delete, COV and all
# other services can never leave this program this way.
# Destinations must be private, link-local or broadcast addresses.
# ---------------------------------------------------------------------------------------------
def _read_only_ok(d: bytes, armed: bool = False) -> str:
    """Return "" when the BACnet/IP packet is a permitted request, else the reason."""
    if len(d) < 4 or d[0] != 0x81:
        return "Not a BACnet/IP packet."
    if len(d) < 6 and d[1] not in (0x02, 0x06):
        return "Too short."
    if ((d[2] << 8) | d[3]) != len(d):
        return "Bad BVLC length."
    if d[1] == 0x05:                                     # Register-Foreign-Device (lets a BBMD forward broadcasts to us)
        return "" if len(d) == 6 else "Bad registration."
    if d[1] in (0x02, 0x06):                             # Read-BDT / Read-FDT (read-only table requests)
        return "" if len(d) == 4 else "Bad table request."
    if d[1] not in (0x0A, 0x0B, 0x09):                   # 0x09 = Distribute-Broadcast-To-Network (Who-Is via a BBMD)
        return "Only plain unicast/broadcast BACnet/IP packets are allowed."
    i = 4
    if d[i] != 1:
        return "Bad NPDU version."
    c = d[i + 1]
    i += 2
    if c & 0x20:
        if i + 3 > len(d):
            return "Truncated NPDU."
        i += 3 + d[i + 2]
    if c & 0x08:
        if i + 3 > len(d):
            return "Truncated NPDU."
        i += 3 + d[i + 2]
    if c & 0x20:
        i += 1                                           # hop count
    if i >= len(d):
        return "Empty message."
    if c & 0x80:                                         # network-layer message
        return "" if d[i] in (0x00, 0x12) else "Network message not allowed."
    t = d[i] >> 4
    if t == 1:                                           # unconfirmed request
        return "" if i + 1 < len(d) and d[i + 1] in (7, 8) else "Unconfirmed service not allowed."
    if t == 0:                                           # confirmed request
        if d[i] & 0x08 or i + 3 >= len(d):
            return "Segmented requests are not allowed."
        if d[i + 3] == 15:
            return _write_ok(d, i + 4, armed)
        return "" if d[i + 3] in (12, 14, 26) else "Only Read Property, Read Property Multiple and Read Range are allowed."
    if t == 4:                                           # segment ACK
        return ""
    return "Message type not allowed."


def _write_ok(d: bytes, k: int, armed: bool) -> str:
    """WriteProperty of present-value only: object id, property 85, one value, optional priority."""
    if d[1] != 0x0A:
        return "Writes can only be sent to one device, never broadcast."
    if not armed:
        return "Write access is switched off."
    if k + 9 > len(d) or d[k] != 0x0C or d[k + 5] != 0x19 or d[k + 6] != 85:
        return "Only the present-value property can be written."
    k += 7
    if d[k] != 0x3E:
        return "Array writes are not allowed."
    depth, j = 1, k + 1
    while j < len(d) and depth:
        t = d[j]
        if t >> 4 == 15:
            return "Unsupported value encoding."
        if t & 8 and t & 7 == 6:
            depth += 1
            j += 1
        elif t & 8 and t & 7 == 7:
            depth -= 1
            j += 1
        else:
            ln = t & 7
            j += 1
            if ln == 5:
                if j >= len(d):
                    return "Truncated."
                ln = d[j]
                j += 1
            if not t & 8 and t >> 4 == 1:                # boolean: value is in the tag itself
                ln = 0
            j += ln
    if depth or j > len(d):
        return "Bad value."
    rest = d[j:]
    if rest and not (len(rest) == 2 and rest[0] == 0x49 and 1 <= rest[1] <= 16):
        return "Only a priority (1-16) may follow the value."
    return ""


def _is_write(d: bytes) -> bool:
    try:
        i = 6
        c = d[5]
        if c & 0x20:
            i += 3 + d[i + 2]
        if c & 0x08:
            i += 3 + d[i + 2]
        if c & 0x20:
            i += 1
        return not c & 0x80 and d[i] >> 4 == 0 and d[i + 3] == 15
    except IndexError:
        return False


def _dest_ok(host: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local or ip == ipaddress.IPv4Address("255.255.255.255")


class Relay:
    def __init__(self):
        self.sock = None
        self.items = []
        self.seq = 0
        self.cv = threading.Condition()
        self.port = 0
        self.armed_until = 0.0

    def arm(self, minutes):
        self.armed_until = time.time() + max(0, min(60, float(minutes))) * 60 if minutes else 0.0
        return self.armed_left()

    def armed_left(self):
        return max(0, int(self.armed_until - time.time()))

    def open(self):
        if self.sock:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", 47808))                   # many devices answer to port 47808
        except OSError:
            s.bind(("0.0.0.0", 0))                       # another program owns it: unicast replies still work
        self.port = s.getsockname()[1]
        self.sock = s
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        own = set(local_ips())
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                return
            if addr[0] in own and addr[1] == self.port and data[:2] == b"\x81\x0b":
                continue                                 # our own broadcast echoed back
            with self.cv:
                self.seq += 1
                self.items.append((self.seq, addr[0], addr[1], data.hex(), time.time()))
                del self.items[:-5000]
                self.cv.notify_all()

    def send(self, dest, data):
        why = _read_only_ok(data, self.armed_left() > 0)
        if why:
            return "Blocked: " + why
        if dest == "broadcast" and len(data) > 6 and data[1] == 0x0A:
            return "Blocked: a unicast packet cannot be broadcast."
        self.open()
        targets = []
        if dest == "broadcast":
            targets = ["255.255.255.255"] + sorted({".".join(ip.split(".")[:3] + ["255"]) for ip in local_ips()})
        else:
            host = dest.rsplit(":", 1)[0]
            targets = [host]
        for host in targets:
            if not _dest_ok(host):
                return "Blocked: " + host + " is not a private or broadcast address."
        port = 47808
        if dest != "broadcast" and ":" in dest:
            try:
                port = int(dest.rsplit(":", 1)[1])
            except ValueError:
                return "Bad port."
        err = ""
        for host in targets:
            try:
                self.sock.sendto(data, (host, port))
            except OSError as ex:
                err = f"Could not send to {host}: {ex}"
        if not err and _is_write(data):
            try:
                with open(os.path.join(state_dir(), "writes.log"), "a", encoding="utf-8") as f:
                    f.write(json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "to": dest, "hex": data.hex()}) + "\n")
            except OSError:
                pass
        return err

    def recv(self, since, wait):
        end = time.time() + wait
        with self.cv:
            while True:
                out = [x for x in self.items if x[0] > since]
                if out or time.time() >= end:
                    return {"seq": self.seq, "port": self.port, "armed": self.armed_left(), "items": [
                        {"n": a, "ip": b, "port": c, "hex": d, "t": e} for a, b, c, d, e in out[:400]]}
                self.cv.wait(max(0.01, end - time.time()))


RELAY = Relay()


class Handler(BaseHTTPRequestHandler):
    cap: Capture
    token = ""
    on_open = None                  # called when another launch hands us a file

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        q = parse_qs(urlparse(self.path).query)
        t = self.headers.get("X-Token") or (q.get("t") or [""])[0]
        if secrets.compare_digest(t, self.token):
            return True
        self._send(403, "Wrong or missing token - open the link printed in the terminal.", "text/plain")
        return False

    def do_GET(self):
        if not self._auth():
            return
        u = urlparse(self.path)
        if u.path == "/":
            try:
                with open(UI_FILE, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(404, "bacnet_inspector.html must be in the same folder as bacnet_live.py",
                           "text/plain")
        elif u.path == "/api/udp/recv":
            q = parse_qs(u.query)
            RELAY.open()
            self._send(200, RELAY.recv(int((q.get("since") or ["0"])[0]), min(2.0, float((q.get("wait") or ["1"])[0]))))
        elif u.path == "/api/update/check":
            self._send(200, update_check())
        elif u.path == "/api/interfaces":
            self._send(200, list_interfaces())
        elif u.path == "/api/sendinfo":
            self._send(200, local_ips())
        elif u.path == "/api/packets":
            since = int((parse_qs(u.query).get("since") or ["0"])[0] or 0)
            self._send(200, self.cap.fetch(since))
        elif u.path == "/api/pending":                  # files to open as new tabs
            self._send(200, self.cap.pending())
        elif u.path == "/api/file":
            fid = int((parse_qs(u.query).get("id") or ["0"])[0] or 0)
            f = self.cap.files.get(fid)
            if f and os.path.isfile(f):
                with open(f, "rb") as fh:
                    self._send(200, fh.read(), "application/octet-stream")
            else:
                self._send(404, {"error": "no such file"})
        elif u.path == "/api/session":
            self._send(200, load_session())
        elif u.path == "/api/save":
            self._send(200, self.cap.pcapng(), "application/octet-stream",
                       {"Content-Disposition": 'attachment; filename="bacnet_capture.pcapng"'})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        n = int(self.headers.get("Content-Length") or 0)
        p = urlparse(self.path).path
        if p == "/api/write":                           # Save / Save As from the page
            path = unquote(self.headers.get("X-Path") or "")
            if not path or os.path.splitext(path)[1].lower() not in (
                    ".html", ".pcapng", ".pcap", ".csv", ".txt", ".json"):
                self._send(400, {"error": "unsupported file type"})
                return
            data = self.rfile.read(n)
            try:
                with open(path, "wb") as fh:
                    fh.write(data)
            except OSError as ex:
                self._send(500, {"error": str(ex)})
                return
            self._send(200, {"ok": True})
            return
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            body = {}
        if p == "/api/start":
            self.cap.start(body.get("backend"), body.get("id"), body.get("filter", ""),
                           body.get("baud", 38400))
        elif p == "/api/stop":
            self.cap.stop()
        elif p == "/api/clear":
            self.cap.clear()
        elif p == "/api/autobaud":                      # find the MS/TP baud rate by listening
            self.cap.stop()
            self._send(200, autobaud(str(body.get("id") or "")))
            return
        elif p == "/api/update/install":
            self._send(200, update_install())
            return
        elif p == "/api/udp/arm":                       # switch write access on (minutes) or off (0)
            self._send(200, {"armed": RELAY.arm(body.get("minutes") or 0)})
            return
        elif p == "/api/udp/send":
            try:
                raw = bytes.fromhex(str(body.get("hex") or ""))
            except ValueError:
                raw = b""
            err = RELAY.send(str(body.get("dest") or ""), raw)
            self._send(200, {"ok": not err, "error": err})
            return
        elif p == "/api/send":
            self._send(200, send_request(body))
            return
        elif p == "/api/session":                       # remember open tabs for the next launch
            tabs = [{"path": str(t.get("path")), "q": str(t.get("q") or "")[:500]}
                    for t in (body.get("tabs") or [])[:40] if isinstance(t, dict) and t.get("path")]
            save_session({"tabs": tabs, "active": body.get("active")})
        elif p == "/api/open":                          # another launch: add its file as a tab, show window
            f = body.get("path")
            if f and os.path.isfile(f) and f.lower().endswith((".pcap", ".pcapng", ".cap")):
                self.cap.add_file(f)
            if Handler.on_open:
                Handler.on_open()
        self._send(200, {"ok": True})


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


_WIN = {}                                         # holds the app window for the Save As dialog


class Api:
    """Functions the page can call when it runs inside the Windows app window."""

    def pick(self, name, label, ext):
        """Native 'Save As' dialog. Returns the chosen path, or None if cancelled."""
        import webview
        dlg = webview.FileDialog.SAVE if hasattr(webview, "FileDialog") else webview.SAVE_DIALOG
        r = _WIN["w"].create_file_dialog(dlg, save_filename=name,
                                         file_types=(f"{label} (*.{ext})", "All files (*.*)"))
        if isinstance(r, (list, tuple)):
            r = r[0] if r else None
        if not r:
            return None
        return r if r.lower().endswith("." + ext) else r + "." + ext

    def pick_open(self):
        """Native 'Open' dialog (several files). Returns a list of paths, so the tabs can be restored next time."""
        import webview
        dlg = webview.FileDialog.OPEN if hasattr(webview, "FileDialog") else webview.OPEN_DIALOG
        r = _WIN["w"].create_file_dialog(dlg, allow_multiple=True,
                                         file_types=("Capture files (*.pcap;*.pcapng;*.cap)", "All files (*.*)"))
        return [str(x) for x in r] if r else []

    def quit(self):
        _WIN["w"].destroy()


def say(*a):
    if sys.stdout:                                    # the packaged app has no console
        print(*a)


def state_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    d = os.path.join(base, "BACnetInspector")
    os.makedirs(d, exist_ok=True)
    return d


_SLOCK = threading.Lock()


def session_file():
    return os.path.join(state_dir(), "session.json")


def load_session():
    try:
        with open(session_file(), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_session(update):
    """Merge `update` into session.json (open tabs, filters, window size)."""
    with _SLOCK:
        d = load_session()
        d.update(update)
        try:
            with open(session_file(), "w", encoding="utf-8") as f:
                json.dump(d, f)
        except OSError:
            pass


def forward(path):
    """Hand a file (or just 'bring to front') to an already-running BACnet Inspector."""
    try:
        with open(os.path.join(state_dir(), "instance.json")) as f:
            st = json.load(f)
        req = urllib.request.Request(
            f"http://127.0.0.1:{st['port']}/api/open",
            data=json.dumps({"path": os.path.abspath(path) if path else None}).encode(),
            headers={"X-Token": st["token"], "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def claim_instance(path):
    """True if this is the first instance. False if the file was handed to one that is already running.
    The lock file makes several simultaneous launches (e.g. 'Open with' on 5 files) queue up properly."""
    lock = os.path.join(state_dir(), "instance.lock")
    for _ in range(50):
        if forward(path):
            return False
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            return True
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(lock) > 20:     # forward() just failed: stale lock
                    os.remove(lock)
                    continue
            except OSError:
                pass
            time.sleep(0.2)
    return True


def release_instance():
    for n in ("instance.json", "instance.lock"):
        try:
            os.remove(os.path.join(state_dir(), n))
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="Live BACnet capture with a web interface.")
    ap.add_argument("capture", nargs="?", help="a .pcap/.pcapng file to open (also used by Windows \"Open with\")")
    ap.add_argument("--port", type=int, default=8765, help="web server port (default 8765)")
    ap.add_argument("--lan", action="store_true", help="allow other devices on your network (e.g. iPhone)")
    ap.add_argument("--window", action="store_true", help="open in its own app window (needs pywebview)")
    ap.add_argument("--browser", action="store_true", help="open in your web browser instead of an app window")
    ap.add_argument("--no-browser", action="store_true", help="don't open anything automatically")
    ap.add_argument("--restore", action="store_true", help="reopen the tabs from last time (always on in the app window)")
    ap.add_argument("--new-instance", action="store_true", help="don't reuse an already-running window")
    ap.add_argument("-i", "--interface", help="start capturing right away on this Wireshark interface number")
    ap.add_argument("-f", "--filter", default="udp portrange 47808-47823", help="capture filter (BPF)")
    ap.add_argument("--serial", help="start capturing MS/TP from this serial port (e.g. COM3)")
    ap.add_argument("--baud", type=int, default=38400, help="MS/TP baud rate (default 38400)")
    a = ap.parse_args()

    packaged = getattr(sys, "frozen", False)
    use_window = (a.window or packaged) and not (a.browser or a.no_browser)
    single = use_window and not a.new_instance
    if single and not claim_instance(a.capture):
        return                                        # the running app now has the file as a new tab

    cap = Capture()
    new_file = os.path.abspath(a.capture) if a.capture and os.path.isfile(a.capture) else None
    if single or a.restore:                           # reopen the tabs from last time
        for t in load_session().get("tabs", []):
            p = t.get("path")
            if p and os.path.isfile(p) and os.path.abspath(p) != new_file:
                cap.add_file(p)
    if new_file:
        cap.add_file(new_file)
    Handler.cap, Handler.token = cap, secrets.token_urlsafe(16)
    host = "0.0.0.0" if a.lan else "127.0.0.1"
    try:
        srv = ThreadingHTTPServer((host, a.port), Handler)
    except OSError:                                   # port busy: let the OS pick one
        srv = ThreadingHTTPServer((host, 0), Handler)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/?t={Handler.token}"
    say("BACnet live capture is running.\n  On this PC:  " + url)
    if a.lan:
        say(f"  iPhone/iPad (same Wi-Fi):  http://{lan_ip()}:{port}/?t={Handler.token}")
    say("Press Ctrl+C to stop.")
    if a.interface:
        cap.start("dumpcap", a.interface, a.filter)
    elif a.serial:
        cap.start("serial", a.serial, "", a.baud)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    if single:
        with open(os.path.join(state_dir(), "instance.json"), "w") as f:
            json.dump({"port": port, "token": Handler.token, "pid": os.getpid()}, f)

    try:
        if use_window:
            try:
                import webview
                try:
                    webview.settings["ALLOW_DOWNLOADS"] = True     # lets the Save button work
                except Exception:
                    pass
                ss = load_session()
                ww = min(7680, max(700, int(ss.get("w") or 1300)))
                wh = min(4320, max(450, int(ss.get("h") or 820)))
                win = webview.create_window("BACnet Inspector", url, width=ww, height=wh, js_api=Api())
                _WIN["w"] = win
                _tm = {}

                def on_resize(w, h):                          # remember the window size (saved once resizing stops)
                    if _tm.get("t"):
                        _tm["t"].cancel()
                    _tm["t"] = threading.Timer(0.8, save_session, ({"w": int(w), "h": int(h)},))
                    _tm["t"].start()
                try:
                    win.events.resized += on_resize
                except Exception:
                    pass

                def to_front():
                    try:
                        win.restore()
                        win.on_top = True
                        win.on_top = False
                    except Exception:
                        pass
                Handler.on_open = staticmethod(to_front)
                try:                                              # keep names, notes and settings between launches
                    webview.start(private_mode=False, storage_path=os.path.join(state_dir(), "webview"))
                except TypeError:
                    webview.start()                               # older pywebview
                return
            except Exception as ex:
                say(f"App window unavailable ({ex}); opening your browser instead.")
        if not a.no_browser:
            webbrowser.open(url)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        cap.stop()
        srv.shutdown()
        if single:
            release_instance()


if __name__ == "__main__":
    main()
