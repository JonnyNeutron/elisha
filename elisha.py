#!/usr/bin/env python3
"""
Elisha
======
A free, local, no-internet-needed radio programming tool for Meshtastic and
MeshCore. It starts a small web UI on 127.0.0.1 and drives the official
command line tools (meshtastic, meshcore-cli, esptool) on your behalf, so you
get a GUI without needing to remember any CLI flags.

Nothing here talks to the internet. Everything is stored in ~/Elisha
(or $ELISHA_HOME): config backups, firmware you drop in, and an audit log.

Run:   python3 elisha.py
Needs: pip install meshtastic meshcore-cli "esptool>=5"
"""
import argparse
import base64
import datetime as dt
import glob
import json
import os
import re
import secrets
import shlex
import shutil
import string
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP = "Elisha"
VERSION = "0.1.0"
PY = sys.executable
HOME = Path(os.environ.get("ELISHA_HOME", str(Path.home() / "Elisha")))
DIRS = {"backups": HOME / "backups", "firmware": HOME / "firmware"}
AUDIT = HOME / "audit.log"
DRY = os.environ.get("ELISHA_DRYRUN") == "1"
LOCK = threading.Lock()
TOKEN = secrets.token_urlsafe(24)
MAX_UPLOAD = 64 * 1024 * 1024
UPLOAD_EXT = {"firmware": {".bin", ".uf2", ".zip", ".hex"}, "backups": {".yaml", ".yml", ".cfg", ".txt", ".mcs", ".json"}}


class Bad(Exception):
    """User input problem. Message is shown in the UI."""


# ----------------------------------------------------------------- helpers
def ensure_dirs():
    for d in DIRS.values():
        d.mkdir(parents=True, exist_ok=True)


def now_stamp():
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def redact(argv):
    """Hide keys in anything we display or log."""
    out, prev = [], ""
    for a in argv:
        if prev in ("psk", "private_key") or re.fullmatch(r"(0x)?[0-9a-fA-F]{32,}", a) or a.startswith("base64:") \
                or "meshtastic.org/e/" in a:
            out.append("<key hidden>")
        else:
            out.append(a)
        prev = a
    return out


def show_cmd(argv):
    a = list(argv)
    if a and a[0] == PY:
        a = a[1:]
        if a[:1] == ["-m"]:
            a = a[1:]
    return shlex.join(redact(a))


def audit(line):
    try:
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(f"{dt.datetime.now().isoformat(timespec='seconds')}  {line}\n")
    except OSError:
        pass


def run(argv, timeout=90):
    """Run a command without a shell. Returns (code, stdout, stderr)."""
    audit("RUN " + show_cmd(argv))
    if DRY:
        return 0, "DRY RUN, not executed.\n", ""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"}, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        def t(x):
            return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")
        return 124, t(e.stdout), t(e.stderr) + f"\nTimed out after {timeout}s."
    except FileNotFoundError as e:
        return 127, "", f"Could not start tool: {e}"


def result(argv, code, out, err, **extra):
    r = {"ok": code == 0, "code": code, "cmd": show_cmd(argv) if argv else "", "out": out, "err": err}
    r.update(extra)
    return r


# ----------------------------------------------------------------- validators
PORT_RE = re.compile(r"^(/dev/[A-Za-z0-9_./-]+|COM\d{1,3}|tcp:[A-Za-z0-9.\-]+(:\d{1,5})?)$")
NAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,80}$")


def port_of(a, allow_tcp=False):
    p = str(a.get("port", "")).strip()
    if not p:
        raise Bad("Pick a serial port first (top of the page).")
    if not PORT_RE.match(p):
        raise Bad("That port name does not look valid.")
    if p.startswith("tcp:") and not allow_tcp:
        raise Bad("TCP connections are only supported for Meshtastic.")
    return p


def s(a, key, maxlen=64, required=True, label=None):
    v = str(a.get(key, "")).strip()
    label = label or key
    if not v:
        if required:
            raise Bad(f"{label} is required.")
        return ""
    if len(v) > maxlen:
        raise Bad(f"{label} is too long (max {maxlen}).")
    if v.startswith("-"):
        raise Bad(f"{label} cannot start with a dash.")
    if any(ord(c) < 32 for c in v):
        raise Bad(f"{label} has control characters.")
    return v


def num(a, key, lo, hi, label=None, integer=False):
    label = label or key
    try:
        v = int(a.get(key)) if integer else float(a.get(key))
    except (TypeError, ValueError):
        raise Bad(f"{label} must be a number.")
    if not lo <= v <= hi:
        raise Bad(f"{label} must be between {lo} and {hi}.")
    return v


def enum(a, key, allowed, label=None):
    v = str(a.get(key, "")).strip()
    if v not in allowed:
        raise Bad(f"{label or key} is not one of the allowed values.")
    return v


def safe_name(n):
    n = str(n or "").strip()
    if not NAME_RE.match(n) or n.startswith(".") or ".." in n:
        raise Bad("Bad file name. Use letters, numbers, spaces, dots, dashes.")
    return n


def file_in(kind, name):
    p = DIRS[kind] / safe_name(name)
    if not p.is_file():
        raise Bad(f"File not found in {kind}: {name}")
    return p


def make_key(n):
    raw = secrets.token_bytes(n)
    return {"hex": raw.hex(), "base64": base64.b64encode(raw).decode()}


def psk_arg(mode, custom):
    if mode in ("random", "default", "none"):
        return mode
    if mode != "custom":
        raise Bad("Unknown key mode.")
    c = (custom or "").strip()
    if re.fullmatch(r"(0x)?([0-9a-fA-F]{32}|[0-9a-fA-F]{64})", c):
        return "0x" + (c[2:] if c.lower().startswith("0x") else c)
    if c.startswith("base64:"):
        c = c[7:]
    try:
        raw = base64.b64decode(c, validate=True)
    except Exception:
        raise Bad("Custom key must be 32 or 64 hex characters, or base64 for a 16 or 32 byte key.")
    if len(raw) not in (16, 32):
        raise Bad("Custom key must decode to 16 bytes (AES-128) or 32 bytes (AES-256).")
    return "base64:" + c


# ----------------------------------------------------------------- tool builders
def mt(a, *extra):
    p = port_of(a, allow_tcp=True)
    base = [PY, "-m", "meshtastic"]
    if p.startswith("tcp:"):
        base += ["--host", p[4:]]
    else:
        base += ["--port", p]
    return base + list(extra)


def mc(a, *cmds):
    p = port_of(a, allow_tcp=True)
    base = [PY, "-m", "meshcore_cli", "-q"]
    if p.startswith("tcp:"):
        host, _, prt = p[4:].partition(":")
        base += ["-t", host] + (["-p", prt] if prt else [])
    else:
        base += ["-s", p]
    return base + list(cmds)


MC_FAIL = re.compile(r"^Error|Traceback|Unknown destination|Could not|not found", re.M)


def go(argv, timeout=90, **extra):
    code, out, err = run(argv, timeout)
    # meshcore-cli exits 0 even when it failed, so look at what it printed too.
    if code == 0 and not DRY and "meshcore_cli" in argv and (MC_FAIL.search(out) or "Traceback" in err):
        code = 1
    return result(argv, code, out, err, **extra)


ACTIONS = {}


def action(name):
    def deco(fn):
        ACTIONS[name] = fn
        return fn
    return deco


# ----------------------------------------------------------------- Meshtastic
@action("mt_info")
def _(a):
    return go(mt(a, "--info"))


@action("mt_nodes")
def _(a):
    return go(mt(a, "--nodes"))


@action("mt_qr")
def _(a):
    return go(mt(a, "--qr-all"))


@action("mt_export")
def _(a):
    label = re.sub(r"[^A-Za-z0-9_-]+", "_", str(a.get("label", "")).strip())[:30] or "radio"
    path = DIRS["backups"] / f"meshtastic_{label}_{now_stamp()}.yaml"
    argv = mt(a, "--export-config", str(path))
    r = go(argv)
    if r["ok"] and path.exists() and not DRY:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        r["saved"] = path.name
        r["note"] = f"Saved {path.name} in your backups folder. It contains your channel keys, so protect it."
    elif r["ok"] and not DRY:
        r["ok"] = False
        r["err"] += "\nThe tool finished but no file was written."
    return r


@action("mt_import")
def _(a):
    p = file_in("backups", a.get("file"))
    if p.suffix.lower() not in (".yaml", ".yml", ".cfg"):
        raise Bad("Pick a .yaml or .cfg Meshtastic backup.")
    return go(mt(a, "--configure", str(p)), timeout=180)


@action("mt_owner")
def _(a):
    long_ = s(a, "long", 39, label="Long name")
    short = s(a, "short", 4, label="Short name")
    return go(mt(a, "--set-owner", long_, "--set-owner-short", short))


@action("mt_region")
def _(a):
    v = s(a, "region", 12)
    if not re.fullmatch(r"[A-Z0-9_]{2,12}", v):
        raise Bad("Region looks wrong. Example: US, EU_868, ANZ.")
    return go(mt(a, "--set", "lora.region", v))


@action("mt_preset")
def _(a):
    v = enum(a, "preset", {"LONG_FAST", "LONG_SLOW", "LONG_MODERATE", "LONG_TURBO", "MEDIUM_FAST", "MEDIUM_SLOW",
                           "SHORT_FAST", "SHORT_SLOW", "SHORT_TURBO", "VERY_LONG_SLOW"}, "Preset")
    return go(mt(a, "--set", "lora.modem_preset", v))


@action("mt_role")
def _(a):
    v = enum(a, "role", {"CLIENT", "CLIENT_MUTE", "CLIENT_HIDDEN", "CLIENT_BASE", "ROUTER", "ROUTER_LATE", "REPEATER",
                         "TRACKER", "SENSOR", "TAK", "TAK_TRACKER", "LOST_AND_FOUND"}, "Role")
    return go(mt(a, "--set", "device.role", v))


@action("mt_txpower")
def _(a):
    v = num(a, "tx", 0, 30, "TX power", integer=True)
    return go(mt(a, "--set", "lora.tx_power", str(v)))


@action("mt_set")
def _(a):
    field = s(a, "field", 60)
    if not re.fullmatch(r"[A-Za-z0-9_.]+", field):
        raise Bad("Field names use letters, numbers, underscores and dots, like lora.hop_limit.")
    value = str(a.get("value", "")).strip()
    if not re.fullmatch(r"-?\d+(\.\d+)?|[^\s-][\w.,:+/=@ ]{0,200}", value or "x"):
        raise Bad("Value has characters that are not allowed.")
    if not value:
        raise Bad("Value is required.")
    return go(mt(a, "--set", field, value))


@action("mt_get")
def _(a):
    field = s(a, "field", 60)
    if not re.fullmatch(r"[A-Za-z0-9_.]+", field):
        raise Bad("Bad field name.")
    return go(mt(a, "--get", field))


@action("mt_channel_set")
def _(a):
    idx = num(a, "index", 0, 7, "Channel slot", integer=True)
    name = s(a, "name", 11, required=False, label="Channel name")
    mode = str(a.get("psk_mode", "keep"))
    extra = []
    if name:
        extra += ["--ch-set", "name", name]
    if mode != "keep":
        extra += ["--ch-set", "psk", psk_arg(mode, a.get("psk"))]
    if not extra:
        raise Bad("Nothing to change. Enter a name or choose a key option.")
    return go(mt(a, *extra, "--ch-index", str(idx)))


@action("mt_channel_add")
def _(a):
    return go(mt(a, "--ch-add", s(a, "name", 11, label="Channel name")))


@action("mt_channel_del")
def _(a):
    idx = num(a, "index", 1, 7, "Channel slot", integer=True)
    return go(mt(a, "--ch-del", "--ch-index", str(idx)))


@action("mt_url_set")
def _(a):
    u = s(a, "url", 600, label="Channel URL")
    if "meshtastic.org/e/" not in u:
        raise Bad("That does not look like a Meshtastic channel URL (meshtastic.org/e/#...).")
    flag = "--ch-add-url" if a.get("mode") == "add" else "--seturl"
    return go(mt(a, flag, u))


@action("mt_position")
def _(a):
    lat = num(a, "lat", -90, 90, "Latitude")
    lon = num(a, "lon", -180, 180, "Longitude")
    alt = num(a, "alt", -500, 9000, "Altitude (m)", integer=True)
    return go(mt(a, "--setlat", str(lat), "--setlon", str(lon), "--setalt", str(alt)))


@action("mt_reboot")
def _(a):
    return go(mt(a, "--reboot"))


@action("mt_dfu")
def _(a):
    return go(mt(a, "--enter-dfu"))


@action("mt_nodedb")
def _(a):
    return go(mt(a, "--reset-nodedb"))


@action("mt_factory")
def _(a):
    if str(a.get("confirm", "")).strip() != "RESET":
        raise Bad("Type RESET to confirm a factory reset.")
    return go(mt(a, "--factory-reset"))


# ----------------------------------------------------------------- MeshCore
@action("mc_info")
def _(a):
    return go(mc(a, "infos"))


@action("mc_channels")
def _(a):
    return go(mc(a, "get_channels"))


@action("mc_name")
def _(a):
    return go(mc(a, "set", "name", s(a, "name", 31, label="Name")))


@action("mc_radio")
def _(a):
    f = num(a, "freq", 137, 1020, "Frequency (MHz)")
    bw = num(a, "bw", 7.8, 500, "Bandwidth (kHz)")
    sf = num(a, "sf", 5, 12, "Spreading factor", integer=True)
    cr = num(a, "cr", 5, 8, "Coding rate", integer=True)
    val = f"{f},{bw},{sf},{cr}"
    if a.get("repeat"):
        val += ",on"
    return go(mc(a, "set", "radio", val))


@action("mc_tx")
def _(a):
    return go(mc(a, "set", "tx", str(num(a, "tx", 1, 30, "TX power (dBm)", integer=True))))


@action("mc_coords")
def _(a):
    lat = num(a, "lat", -90, 90, "Latitude")
    lon = num(a, "lon", -180, 180, "Longitude")
    return go(mc(a, "set", "coords", f"{lat},{lon}"))


@action("mc_channel_set")
def _(a):
    idx = num(a, "index", 0, 39, "Channel slot", integer=True)
    name = s(a, "name", 31, label="Channel name")
    key = str(a.get("key", "")).strip()
    if name.startswith("#") or not key:
        return go(mc(a, "set_channel", str(idx), name))
    if not re.fullmatch(r"[0-9a-fA-F]{32}", key):
        raise Bad("MeshCore channel keys are 32 hex characters. Use Generate, or use a #hashtag name with no key.")
    return go(mc(a, "set_channel", str(idx), name, key))


@action("mc_channel_add")
def _(a):
    name = s(a, "name", 31, label="Channel name")
    key = str(a.get("key", "")).strip()
    if name.startswith("#") or not key:
        return go(mc(a, "add_channel", name))
    if not re.fullmatch(r"[0-9a-fA-F]{32}", key):
        raise Bad("MeshCore channel keys are 32 hex characters.")
    return go(mc(a, "add_channel", name, key))


@action("mc_channel_del")
def _(a):
    return go(mc(a, "remove_channel", str(num(a, "index", 1, 39, "Channel slot", integer=True))))


@action("mc_advert")
def _(a):
    return go(mc(a, "floodadv" if a.get("flood") else "advert"))


@action("mc_clock")
def _(a):
    return go(mc(a, "clock", "sync"))


@action("mc_reboot")
def _(a):
    return go(mc(a, "reboot"))


@action("mc_ver")
def _(a):
    return go(mc(a, "ver"))


@action("mc_key_export")
def _(a):
    if not a.get("confirm"):
        raise Bad("Tick the box to confirm you understand this exports your identity private key.")
    argv = mc(a, "get", "private_key")
    code, out, err = run(argv, 60)
    m = re.search(r"([0-9a-fA-F]{64,128})", out)
    if code == 0 and m and not DRY and not MC_FAIL.search(out):
        path = DIRS["backups"] / f"meshcore_identity_{now_stamp()}.key.txt"
        path.write_text("# MeshCore identity private key. Anyone with this can impersonate the node.\n"
                        f"private_key {m.group(1)}\n", encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return result(argv, 0, "Private key saved to your backups folder.\n", err, saved=path.name,
                      note=f"Saved {path.name}. Treat it like a password.")
    return result(argv, code if code else 1, "", err or "No key found in the output.\n" + out[:300])


@action("mc_key_import")
def _(a):
    if str(a.get("confirm", "")).strip() != "IMPORT":
        raise Bad("Type IMPORT to confirm. This replaces the node's identity.")
    p = file_in("backups", a.get("file"))
    m = re.search(r"private_key\s+([0-9a-fA-F]{64,128})", p.read_text(encoding="utf-8", errors="replace"))
    if not m:
        raise Bad("That file does not contain a private_key line.")
    return go(mc(a, "set", "private_key", m.group(1)))


def _parse_infos(text):
    i = text.find("{")
    if i < 0:
        raise ValueError("no JSON in output")
    obj, _ = json.JSONDecoder().raw_decode(text[i:])
    return obj


@action("mc_backup")
def _(a):
    label = re.sub(r"[^A-Za-z0-9_-]+", "_", str(a.get("label", "")).strip())[:30] or "radio"
    argv = mc(a, "infos", "get_channels")
    code, out, err = run(argv, 90)
    if DRY or code != 0 or MC_FAIL.search(out) or "Traceback" in err:
        return result(argv, code or (0 if DRY else 1), out, err)
    try:
        info = _parse_infos(out)
    except Exception as e:
        return result(argv, 1, out, err + f"\nCould not read device info: {e}")
    chans = re.findall(r"^(\d+): (.*) \[([0-9a-fA-F]{32})\]\s*$", out, re.M)
    stamp = now_stamp()
    lines = [f"# {APP} MeshCore backup {stamp}", "# Restore with the Restore button, or: meshcore-cli -s PORT script THIS_FILE"]
    if info.get("name"):
        lines.append("set name " + shlex.quote(str(info["name"])))
    if all(k in info for k in ("radio_freq", "radio_bw", "radio_sf", "radio_cr")):
        lines.append(f"set radio {info['radio_freq']},{info['radio_bw']},{info['radio_sf']},{info['radio_cr']}")
    if "tx_power" in info:
        lines.append(f"set tx {info['tx_power']}")
    if "adv_lat" in info and "adv_lon" in info:
        lines.append(f"set coords {info['adv_lat']},{info['adv_lon']}")
    for idx, name, key in chans:
        if name.startswith("#"):
            lines.append(f"set_channel {idx} {shlex.quote(name)}")
        else:
            lines.append(f"set_channel {idx} {shlex.quote(name)} {key.lower()}")
    path = DIRS["backups"] / f"meshcore_{label}_{stamp}.mcs"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return result(argv, 0, f"Backed up name, radio settings, position and {len(chans)} channel(s).\n", err,
                  saved=path.name, note=f"Saved {path.name}. It contains channel keys, so protect it.")


@action("mc_restore")
def _(a):
    p = file_in("backups", a.get("file"))
    if p.suffix.lower() != ".mcs":
        raise Bad("Pick a MeshCore backup (.mcs).")
    return go(mc(a, "script", str(p)), timeout=180)


# ----------------------------------------------------------------- repeater raw console
@action("rp_cmd")
def _(a):
    p = port_of(a)
    line = s(a, "line", 120, label="Command")
    a = dict(a)
    if str(a.get("wait", "")).strip() == "":
        a["wait"] = 2
    wait = num(a, "wait", 0.5, 10, "Wait (s)")
    audit(f"SERIAL {p} 115200 > {line.split()[0]} ...")
    if DRY:
        return result([], 0, "DRY RUN, not sent.\n", "", cmd=f"serial {p} > {line}")
    try:
        import serial
    except ImportError:
        raise Bad("pyserial is missing. It installs with the meshtastic package.")
    try:
        ser = serial.Serial()
        ser.port, ser.baudrate, ser.timeout = p, 115200, 0.25
        ser.dtr = False
        ser.rts = False
        ser.open()
    except Exception as e:
        return {"ok": False, "code": 1, "cmd": f"serial {p} > {line}", "out": "", "err": f"Could not open port: {e}"}
    buf = b""
    try:
        ser.reset_input_buffer()
        ser.write((line + "\r\n").encode())
        end = time.time() + wait
        while time.time() < end:
            buf += ser.read(512)
    finally:
        ser.close()
    return {"ok": True, "code": 0, "cmd": f"serial {p} > {line}", "out": buf.decode("utf-8", "replace") or "(no reply)", "err": ""}


# ----------------------------------------------------------------- firmware
def uf2_drives():
    roots = []
    if sys.platform.startswith("win"):
        roots = [f"{c}:\\" for c in string.ascii_uppercase if c not in "AB"]
    elif sys.platform == "darwin":
        roots = glob.glob("/Volumes/*")
    else:
        roots = glob.glob("/media/*/*") + glob.glob("/run/media/*/*") + glob.glob("/media/*") + glob.glob("/mnt/*")
    found = []
    for r in roots:
        info = os.path.join(r, "INFO_UF2.TXT")
        try:
            if os.path.isfile(info):
                head = Path(info).read_text(errors="replace").splitlines()[:3]
                found.append({"path": r, "info": " | ".join(x.strip() for x in head if x.strip())})
        except OSError:
            continue
    return found


@action("fw_drives")
def _(a):
    d = uf2_drives()
    msg = "\n".join(f"{x['path']}   {x['info']}" for x in d) or \
        "No UF2 drive found. Double tap the reset button (or use Enter DFU for Meshtastic) and try again."
    return {"ok": True, "code": 0, "cmd": "scan for UF2 drives", "out": msg + "\n", "err": "", "drives": d}


@action("fw_uf2_copy")
def _(a):
    f = file_in("firmware", a.get("file"))
    if f.suffix.lower() != ".uf2":
        raise Bad("Pick a .uf2 firmware file.")
    drive = str(a.get("drive", ""))
    if drive not in [d["path"] for d in uf2_drives()]:
        raise Bad("That drive is not a detected UF2 bootloader drive. Click Find UF2 drive first.")
    audit(f"UF2 copy {f.name} -> {drive}")
    if DRY:
        return {"ok": True, "code": 0, "cmd": f"copy {f.name} {drive}", "out": "DRY RUN, not copied.\n", "err": ""}
    try:
        shutil.copyfile(f, os.path.join(drive, f.name))
        note = "Copied. The board should reboot into the new firmware on its own."
    except OSError as e:
        note = f"Copy ended with: {e}. This is normal if the board rebooted mid copy. Check that the drive disappeared."
    return {"ok": True, "code": 0, "cmd": f"copy {f.name} to {drive}", "out": note + "\n", "err": ""}


def es(a, *cmd):
    p = port_of(a)
    base = [PY, "-m", "esptool", "--port", p]
    baud = str(a.get("baud", "460800"))
    if baud in ("115200", "230400", "460800", "921600"):
        base += ["--baud", baud]
    return base + list(cmd)


@action("fw_esp_flash")
def _(a):
    f = file_in("firmware", a.get("file"))
    if f.suffix.lower() != ".bin":
        raise Bad("ESP32 flashing needs a .bin file.")
    addr = str(a.get("addr", "0x0")).strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,7}", addr):
        raise Bad("Address should look like 0x0 or 0x10000.")
    return go(es(a, "write-flash", addr, str(f)), timeout=900)


@action("fw_esp_erase")
def _(a):
    if str(a.get("confirm", "")).strip() != "ERASE":
        raise Bad("Type ERASE to confirm. This wipes the whole flash including settings.")
    return go(es(a, "erase-flash"), timeout=300)


@action("fw_esp_id")
def _(a):
    return go(es(a, "chip-id"), timeout=60)


# ----------------------------------------------------------------- status and ports
def ver(pkg):
    try:
        from importlib.metadata import version
        return version(pkg)
    except Exception:
        return None


def list_ports():
    out = []
    try:
        from serial.tools import list_ports as lp
        for p in sorted(lp.comports(), key=lambda x: x.device):
            hint = {0x239A: "nRF52 style (RAK, T-Echo)", 0x303A: "ESP32 native USB", 0x10C4: "ESP32 (CP210x)",
                    0x1A86: "ESP32 (CH340)", 0x0403: "FTDI"}.get(p.vid, "")
            out.append({"device": p.device, "desc": p.description or "", "hint": hint})
    except Exception:
        for g in sorted(glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*") + glob.glob("/dev/cu.usb*")):
            out.append({"device": g, "desc": "", "hint": ""})
    return out


def status():
    return {"app": APP, "version": VERSION, "home": str(HOME), "dry": DRY, "python": sys.version.split()[0],
            "meshtastic": ver("meshtastic"), "meshcore_cli": ver("meshcore-cli"), "esptool": ver("esptool"),
            "pyserial": ver("pyserial")}


def list_files(kind):
    d = DIRS[kind]
    items = []
    for p in sorted(d.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file():
            st = p.stat()
            items.append({"name": p.name, "size": st.st_size,
                          "time": dt.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")})
    return items


# ----------------------------------------------------------------- http server
class Handler(BaseHTTPRequestHandler):
    server_version = "Elisha/" + VERSION

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def _guard(self, q):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in ("127.0.0.1", "localhost", "::1"):
            self._json({"ok": False, "error": "Bad host header"}, 403)
            return False
        tok = self.headers.get("X-Token") or (q.get("t") or [""])[0]
        if not secrets.compare_digest(tok, TOKEN):
            self._json({"ok": False, "error": "Bad or missing token. Open the URL printed in the terminal."}, 403)
            return False
        return True

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if u.path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")
        if not self._guard(q):
            return
        try:
            if u.path == "/api/status":
                return self._json(status())
            if u.path == "/api/ports":
                return self._json({"ports": list_ports()})
            if u.path == "/api/files":
                kind = (q.get("kind") or [""])[0]
                if kind not in DIRS:
                    raise Bad("Unknown folder.")
                return self._json({"files": list_files(kind)})
            if u.path == "/api/genkey":
                n = 32 if (q.get("n") or ["16"])[0] == "32" else 16
                return self._json(make_key(n))
            if u.path == "/api/download":
                kind = (q.get("kind") or [""])[0]
                if kind not in DIRS:
                    raise Bad("Unknown folder.")
                p = file_in(kind, (q.get("name") or [""])[0])
                return self._send(200, p.read_bytes(), "application/octet-stream",
                                  {"Content-Disposition": f'attachment; filename="{p.name}"'})
        except Bad as e:
            return self._json({"ok": False, "error": str(e)}, 400)
        self._json({"ok": False, "error": "Not found"}, 404)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if not self._guard(q):
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_UPLOAD:
                raise Bad("File is too large (64 MB max).")
            body = self.rfile.read(length) if length else b""
            if u.path == "/api/upload":
                kind = (q.get("kind") or [""])[0]
                if kind not in DIRS:
                    raise Bad("Unknown folder.")
                name = safe_name((q.get("name") or [""])[0])
                if Path(name).suffix.lower() not in UPLOAD_EXT[kind]:
                    raise Bad("File type not allowed here: " + ", ".join(sorted(UPLOAD_EXT[kind])))
                (DIRS[kind] / name).write_bytes(body)
                audit(f"UPLOAD {kind}/{name} ({len(body)} bytes)")
                return self._json({"ok": True, "name": name})
            if u.path == "/api/delete":
                d = json.loads(body or b"{}")
                if d.get("kind") not in DIRS:
                    raise Bad("Unknown folder.")
                p = file_in(d["kind"], d.get("name"))
                p.unlink()
                audit(f"DELETE {d['kind']}/{p.name}")
                return self._json({"ok": True})
            if u.path == "/api/run":
                d = json.loads(body or b"{}")
                fn = ACTIONS.get(d.get("action"))
                if not fn:
                    raise Bad("Unknown action.")
                if not LOCK.acquire(blocking=False):
                    return self._json({"ok": False, "error": "Another radio operation is still running."}, 409)
                try:
                    return self._json(fn(d.get("args") or {}))
                finally:
                    LOCK.release()
        except Bad as e:
            return self._json({"ok": False, "error": str(e)}, 400)
        except (json.JSONDecodeError, ValueError):
            return self._json({"ok": False, "error": "Bad request"}, 400)
        except Exception as e:  # keep the UI alive
            audit(f"ERROR {type(e).__name__}: {e}")
            return self._json({"ok": False, "error": f"Internal error: {e}"}, 500)
        self._json({"ok": False, "error": "Not found"}, 404)


def main():
    ap = argparse.ArgumentParser(description=APP)
    ap.add_argument("--port", type=int, default=8765, help="local web port (default 8765)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    args = ap.parse_args()
    ensure_dirs()
    srv = None
    for port in range(args.port, args.port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if not srv:
        sys.exit("Could not open a local port.")
    url = f"http://127.0.0.1:{srv.server_address[1]}/?t={TOKEN}"
    st = status()
    print(f"\n{APP} {VERSION}")
    print(f"Data folder: {HOME}")
    for k in ("meshtastic", "meshcore_cli", "esptool"):
        print(f"  {k:13} {st[k] or 'NOT INSTALLED'}")
    print(f"\nOpen: {url}\n(Ctrl+C to stop. Only this computer can reach it.)\n")
    audit("START")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nBye.")


# ----------------------------------------------------------------- the page
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Elisha</title>
<style>
:root{--bg:#0e1116;--pn:#161b22;--pn2:#1d242d;--bd:#2b3440;--tx:#e6edf3;--mu:#8b98a7;--ac:#e0b040;--ok:#3fb67a;--er:#e5534b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
header{position:sticky;top:0;z-index:5;background:var(--pn);border-bottom:1px solid var(--bd);padding:10px 14px}
h1{font-size:16px;margin:0 0 8px;letter-spacing:.04em}h1 small{color:var(--mu);font-weight:400}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
select,input,button,textarea{font:inherit;color:var(--tx);background:var(--pn2);border:1px solid var(--bd);border-radius:6px;padding:7px 9px}
input[type=checkbox]{width:auto}button{cursor:pointer}button:hover{border-color:var(--ac)}
button.p{background:var(--ac);color:#111;border-color:var(--ac);font-weight:600}button.d{border-color:var(--er);color:#ffb4ae}
.seg button{border-radius:0}.seg button:first-child{border-radius:6px 0 0 6px}.seg button:last-child{border-radius:0 6px 6px 0}
.seg button.on{background:var(--ac);color:#111;border-color:var(--ac);font-weight:600}
nav{display:flex;gap:6px;overflow-x:auto;padding:10px 14px 0}nav button{white-space:nowrap}
nav button.on{border-color:var(--ac);color:var(--ac)}
main{padding:12px 14px 40px;max-width:1100px;margin:auto}
.tab{display:none}.tab.on{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
form,.card{background:var(--pn);border:1px solid var(--bd);border-radius:10px;padding:12px}
form h3,.card h3{margin:0 0 4px;font-size:15px}.hint{color:var(--mu);font-size:13px;margin:0 0 8px}
label{display:block;font-size:13px;color:var(--mu);margin:6px 0 2px}form input,form select{width:100%}
form .row{margin-top:8px}form .row input,form .row select{width:auto;flex:1}
body[data-type=mt] .mc,body[data-type=mc] .mt,body[data-type=rp] .mt,body[data-type=rp] .mc{display:none}
body[data-type=mc] .rp,body[data-type=mt] .rp{display:none}
#out{background:#0a0d12;border:1px solid var(--bd);border-radius:10px;margin-top:16px}
#outbar{display:flex;gap:10px;align-items:center;padding:8px 12px;border-bottom:1px solid var(--bd);flex-wrap:wrap}
#log{max-height:46vh;overflow:auto;padding:10px 12px;font:13px/1.4 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
.e{margin-bottom:14px}.e .c{color:var(--ac)}.e .ok{color:var(--ok)}.e .bad{color:var(--er)}.e .n{color:#9ecbff}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:5px 6px;border-bottom:1px solid var(--bd);text-align:left}
.pill{font-size:12px;padding:2px 8px;border-radius:99px;border:1px solid var(--bd);color:var(--mu)}.pill.g{color:var(--ok);border-color:var(--ok)}.pill.r{color:var(--er);border-color:var(--er)}
a{color:#9ecbff}
</style></head>
<body data-type="mt">
<header>
 <h1>ELISHA <small>freely received, freely given. Local only, no cloud, no account</small></h1>
 <div class="row">
  <div class="seg" id="typeSeg"><button data-t="mt" class="on">Meshtastic</button><button data-t="mc">MeshCore</button><button data-t="rp">MC Repeater</button></div>
  <select id="port" style="min-width:230px;flex:1"></select>
  <input id="manual" placeholder="or tcp:192.168.1.50" style="width:170px">
  <button id="refresh">Refresh ports</button>
 </div>
 <div class="row" id="deps" style="margin-top:8px"></div>
</header>
<nav id="tabs">
 <button data-tab="radio" class="on">Radio</button><button data-tab="channels">Channels</button>
 <button data-tab="backup">Backup and restore</button><button data-tab="firmware">Firmware</button><button data-tab="adv">Advanced</button>
</nav>
<main>

<section class="tab on" id="t-radio"><div class="grid">
 <div class="card"><h3>Read device</h3><p class="hint">Start here to confirm the connection.</p>
  <div class="row">
   <button class="p mt" data-run="mt_info">Read config</button><button class="mt" data-run="mt_nodes">Node list</button>
   <button class="p mc" data-run="mc_info">Read device info</button><button class="mc" data-run="mc_ver">Firmware version</button>
   <button class="mc" data-run="mc_clock">Sync clock</button>
   <button class="p rp" data-rp="ver">ver</button><button class="rp" data-rp="get name">get name</button><button class="rp" data-rp="get radio">get radio</button><button class="rp" data-rp="clock">clock</button>
  </div></div>

 <form class="mt" data-a="mt_owner"><h3>Node name</h3><label>Long name</label><input name="long" maxlength="39"><label>Short name (4 max)</label><input name="short" maxlength="4"><div class="row"><button class="p">Apply</button></div></form>
 <form class="mt" data-a="mt_region"><h3>Region</h3><p class="hint">Must match your country's legal band.</p>
  <select name="region"><option>US</option><option>EU_868</option><option>EU_433</option><option>ANZ</option><option>CN</option><option>JP</option><option>KR</option><option>TW</option><option>RU</option><option>IN</option><option>NZ_865</option><option>TH</option><option>UA_868</option><option>LORA_24</option></select><div class="row"><button class="p">Apply</button></div></form>
 <form class="mt" data-a="mt_preset"><h3>Modem preset</h3>
  <select name="preset"><option>LONG_FAST</option><option>LONG_MODERATE</option><option>LONG_SLOW</option><option>LONG_TURBO</option><option>MEDIUM_FAST</option><option>MEDIUM_SLOW</option><option>SHORT_FAST</option><option>SHORT_SLOW</option><option>SHORT_TURBO</option></select><div class="row"><button class="p">Apply</button></div></form>
 <form class="mt" data-a="mt_role"><h3>Device role</h3>
  <select name="role"><option>CLIENT</option><option>CLIENT_MUTE</option><option>CLIENT_BASE</option><option>ROUTER</option><option>ROUTER_LATE</option><option>REPEATER</option><option>TRACKER</option><option>SENSOR</option><option>TAK</option><option>TAK_TRACKER</option><option>LOST_AND_FOUND</option><option>CLIENT_HIDDEN</option></select><div class="row"><button class="p">Apply</button></div></form>
 <form class="mt" data-a="mt_txpower"><h3>TX power (dBm)</h3><input name="tx" type="number" min="0" max="30" value="22"><div class="row"><button class="p">Apply</button></div></form>
 <form class="mt" data-a="mt_position"><h3>Fixed position</h3><div class="row"><input name="lat" placeholder="lat" inputmode="decimal"><input name="lon" placeholder="lon" inputmode="decimal"><input name="alt" placeholder="alt m" value="0"></div><div class="row"><button class="p">Apply</button></div></form>

 <form class="mc" data-a="mc_name"><h3>Node name</h3><input name="name" maxlength="31"><div class="row"><button class="p">Apply</button></div></form>
 <form class="mc" data-a="mc_radio"><h3>Radio parameters</h3><p class="hint">Every node on your mesh must use the same values.</p>
  <div class="row"><input name="freq" placeholder="MHz" value="910.525" inputmode="decimal"><input name="bw" placeholder="BW kHz" value="62.5" inputmode="decimal"></div>
  <div class="row"><input name="sf" placeholder="SF" value="7"><input name="cr" placeholder="CR" value="5"></div>
  <label><input type="checkbox" name="repeat" style="width:auto"> Client repeat mode on (only if your firmware supports it)</label><div class="row"><button class="p">Apply</button></div></form>
 <form class="mc" data-a="mc_tx"><h3>TX power (dBm)</h3><input name="tx" type="number" min="1" max="30" value="20"><div class="row"><button class="p">Apply</button></div></form>
 <form class="mc" data-a="mc_coords"><h3>Position</h3><div class="row"><input name="lat" placeholder="lat" inputmode="decimal"><input name="lon" placeholder="lon" inputmode="decimal"></div><div class="row"><button class="p">Apply</button></div></form>
 <form class="mc" data-a="mc_advert"><h3>Send advert</h3><label><input type="checkbox" name="flood" style="width:auto"> Flood advert (reaches further)</label><div class="row"><button class="p">Send</button></div></form>

 <form class="rp" data-a="rp_cmd"><h3>Repeater serial console</h3><p class="hint">Sends one line to a MeshCore repeater at 115200 baud and shows the reply. Anything the repeater CLI understands works.</p>
  <input name="line" placeholder="get name"><div class="row"><input name="wait" value="2" style="max-width:90px"><span class="hint" style="margin:0">seconds to listen</span><button class="p">Send</button></div></form>
</div></section>

<section class="tab" id="t-channels"><div class="grid">
 <div class="card"><h3>Key generator</h3><p class="hint">Made on this computer with the OS random source.</p>
  <div class="row"><button data-gen="16">16 byte (AES-128)</button><button data-gen="32" class="mt">32 byte (AES-256)</button></div>
  <label>Hex</label><input id="g-hex" readonly><label class="mt">Base64</label><input id="g-b64" class="mt" readonly>
  <div class="row"><button id="g-use-mt" class="mt">Use in Meshtastic form</button><button id="g-use-mc" class="mc">Use in MeshCore form</button></div></div>

 <form class="mt" data-a="mt_channel_set"><h3>Edit channel slot</h3><p class="hint">Slot 0 is primary. Leave name blank to keep it.</p>
  <label>Slot (0 to 7)</label><input name="index" type="number" min="0" max="7" value="0"><label>Name (11 max)</label><input name="name" maxlength="11">
  <label>Key</label><select name="psk_mode" id="mt-psk-mode"><option value="keep">Keep current</option><option value="random">New random key</option><option value="default">Default key</option><option value="none">No encryption</option><option value="custom">Custom (below)</option></select>
  <input name="psk" id="mt-psk" placeholder="hex or base64 key" autocomplete="off"><div class="row"><button class="p">Apply</button></div></form>
 <form class="mt" data-a="mt_channel_add"><h3>Add secondary channel</h3><input name="name" maxlength="11" placeholder="name"><div class="row"><button class="p">Add</button></div><p class="hint">Then set its key with Edit channel slot.</p></form>
 <form class="mt" data-a="mt_channel_del"><h3>Delete channel</h3><input name="index" type="number" min="1" max="7" value="1"><div class="row"><button class="d">Delete</button></div></form>
 <form class="mt" data-a="mt_url_set"><h3>Join from channel URL</h3><p class="hint">Paste a meshtastic.org/e/# link someone gave you. Works offline, it is just data.</p>
  <input name="url" autocomplete="off"><select name="mode"><option value="set">Replace all channels and LoRa config</option><option value="add">Add as extra channels</option></select><div class="row"><button class="p">Apply</button></div></form>
 <div class="card mt"><h3>Share my channels</h3><p class="hint">Prints the URL and a text QR code you can scan.</p><div class="row"><button data-run="mt_qr">Show URL and QR</button></div></div>

 <div class="card mc"><h3>Channels on device</h3><div class="row"><button class="p" data-run="mc_channels">Read channels</button></div></div>
 <form class="mc" data-a="mc_channel_set"><h3>Set channel slot</h3><p class="hint">Use a #hashtag name and no key, or a name with a 32 hex key.</p>
  <label>Slot</label><input name="index" type="number" min="0" max="39" value="1"><label>Name</label><input name="name"><label>Key (32 hex, optional)</label><input name="key" id="mc-key" autocomplete="off"><div class="row"><button class="p">Apply</button></div></form>
 <form class="mc" data-a="mc_channel_add"><h3>Add channel</h3><input name="name" placeholder="name or #hashtag"><label>Key (32 hex, optional)</label><input name="key" autocomplete="off"><div class="row"><button class="p">Add</button></div></form>
 <form class="mc" data-a="mc_channel_del"><h3>Remove channel</h3><input name="index" type="number" min="1" max="39" value="1"><div class="row"><button class="d">Remove</button></div></form>
</div></section>

<section class="tab" id="t-backup"><div class="grid">
 <form class="mt" data-a="mt_export"><h3>Back up this radio</h3><p class="hint">Saves the full config and channels to a YAML file in your backups folder.</p><label>Label</label><input name="label" placeholder="home-base"><div class="row"><button class="p">Back up now</button></div></form>
 <form class="mc" data-a="mc_backup"><h3>Back up this radio</h3><p class="hint">Saves name, radio settings, position and channels as a restore script.</p><label>Label</label><input name="label" placeholder="home-base"><div class="row"><button class="p">Back up now</button></div></form>
 <form data-a="restore" id="restoreForm"><h3>Restore to this radio</h3><p class="hint">Pick a backup from the list on the right. Applies it to the connected device.</p><label>Backup file</label><select name="file" class="fileSel" data-kind="backups"></select><div class="row"><button class="p">Restore</button></div></form>
 <form class="mc" data-a="mc_key_export"><h3>Export identity key</h3><p class="hint">Lets you clone or recover a node identity. Anyone holding it can impersonate that node.</p><label><input type="checkbox" name="confirm" style="width:auto"> I understand</label><div class="row"><button class="d">Export key</button></div></form>
 <form class="mc" data-a="mc_key_import"><h3>Import identity key</h3><label>Key file</label><select name="file" class="fileSel" data-kind="backups"></select><label>Type IMPORT</label><input name="confirm" autocomplete="off"><div class="row"><button class="d">Import key</button></div></form>
 <div class="card"><h3>Backups folder</h3><p class="hint" id="homeHint"></p><table id="bkTbl"></table>
  <div class="row"><input type="file" id="bkUp" accept=".yaml,.yml,.cfg,.txt,.mcs,.json"></div></div>
</div></section>

<section class="tab" id="t-firmware"><div class="grid">
 <div class="card"><h3>Firmware library</h3><p class="hint">Download firmware once while you have internet, drop it here, and flash any time with none. Get files from the Meshtastic and MeshCore release pages.</p><table id="fwTbl"></table>
  <div class="row"><input type="file" id="fwUp" accept=".bin,.uf2,.zip,.hex"></div></div>

 <form data-a="fw_esp_flash" class="esp"><h3>Flash ESP32 (T-Beam, Heltec, T-Deck, etc)</h3><p class="hint">Needs a .bin from your firmware library.</p>
  <label>Firmware file</label><select name="file" class="fileSel" data-kind="firmware"></select>
  <label>Flash address</label><select name="addr"><option value="0x0">0x0  factory or merged image (full flash)</option><option value="0x10000">0x10000  app only update (keeps settings)</option></select>
  <label>Speed</label><select name="baud"><option>460800</option><option>921600</option><option>230400</option><option>115200</option></select>
  <div class="row"><button class="p">Flash</button><button type="button" data-run="fw_esp_id">Check chip</button></div></form>
 <form data-a="fw_esp_erase" class="esp"><h3>Erase ESP32 flash</h3><p class="hint">Wipes everything. Use before a clean install.</p><label>Type ERASE</label><input name="confirm" autocomplete="off"><div class="row"><button class="d">Erase</button></div></form>

 <form data-a="fw_uf2_copy"><h3>Flash nRF52 (RAK4631, T-Echo, etc)</h3><p class="hint">Put the board in bootloader mode: double tap reset, or use Enter DFU below. A drive appears. Then pick the .uf2 and copy.</p>
  <div class="row"><button type="button" id="findUf2">Find UF2 drive</button><button type="button" class="mt" data-run="mt_dfu">Enter DFU (Meshtastic)</button></div>
  <label>Drive</label><select name="drive" id="uf2Drive"><option value="">none found yet</option></select>
  <label>Firmware file</label><select name="file" class="fileSel" data-kind="firmware"></select><div class="row"><button class="p">Copy to board</button></div></form>
</div></section>

<section class="tab" id="t-adv"><div class="grid">
 <form class="mt" data-a="mt_set"><h3>Set any setting</h3><p class="hint">Same names as the Meshtastic CLI, like lora.hop_limit or device.role.</p><label>Field</label><input name="field" placeholder="lora.hop_limit"><label>Value</label><input name="value" placeholder="5"><div class="row"><button class="p">Set</button></div></form>
 <form class="mt" data-a="mt_get"><h3>Read a setting</h3><input name="field" placeholder="lora"><div class="row"><button class="p">Read</button></div></form>
 <div class="card mt"><h3>Maintenance</h3><div class="row"><button data-run="mt_reboot">Reboot</button><button data-run="mt_nodedb">Clear node list</button></div></div>
 <form class="mt" data-a="mt_factory"><h3>Factory reset</h3><p class="hint">Resets configuration. Back up first.</p><label>Type RESET</label><input name="confirm" autocomplete="off"><div class="row"><button class="d">Factory reset</button></div></form>
 <div class="card mc"><h3>Maintenance</h3><div class="row"><button data-run="mc_reboot">Reboot</button></div></div>
 <div class="card"><h3>Audit log</h3><p class="hint">Every command this tool runs is written, with keys hidden, to audit.log in your data folder.</p></div>
</div></section>

<div id="out"><div id="outbar"><strong>Output</strong><label style="margin:0"><input type="checkbox" id="mask" checked style="width:auto"> hide keys</label><button id="copy">Copy</button><button id="clear">Clear</button></div><div id="log"></div></div>
</main>
<script>
const T=new URLSearchParams(location.search).get('t')||'';
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
let TYPE='mt',LOG=[];
const esc=t=>String(t).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function mask(t){if(!$('#mask').checked)return t;
 return t.replace(/((?:psk|private_?key|admin_?key|channel_?secret|secret|password)\W{0,4})(\S+)/gi,'$1••••')
  .replace(/(meshtastic\.org\/e\/#?)\S+/g,'$1••••').replace(/(base64:)[A-Za-z0-9+\/=]+/g,'$1••••')
  .replace(/\[[0-9a-f]{32}\]/gi,'[••••]').replace(/\b[0-9a-f]{40,}\b/gi,'••••');}
async function api(path,opt={}){opt.headers=Object.assign({'X-Token':T},opt.headers||{});
 const r=await fetch(path,opt);let j={};try{j=await r.json()}catch(e){}return j}
function render(){const el=$('#log');el.innerHTML=LOG.map(e=>{
 let h='<div class="e"><div class="c">$ '+esc(e.cmd||e.title||'')+'</div>';
 if(e.error)h+='<div class="bad">'+esc(e.error)+'</div>';
 else{h+='<div class="'+(e.ok?'ok':'bad')+'">'+(e.ok?'done':'failed (exit '+e.code+')')+'</div>';
  if(e.note)h+='<div class="n">'+esc(e.note)+'</div>';
  if(e.out)h+=esc(mask(e.out));if(e.err&&(!e.ok||e.err.trim()))h+='<div class="bad">'+esc(mask(e.err))+'</div>';}
 return h+'</div>'}).join('');el.scrollTop=el.scrollHeight}
function push(e){LOG.push(e);render()}
function port(){const m=$('#manual').value.trim();return m||$('#port').value}
async function run(action,args={}){args=Object.assign({port:port()},args);
 push({cmd:'running '+action+' ...',ok:true,code:0,out:''});
 const j=await api('/api/run',{method:'POST',body:JSON.stringify({action,args})});
 LOG.pop();push(j.error&&!j.cmd?{error:j.error,cmd:action}:j);
 if(j.saved||action.startsWith('fw_'))loadFiles();return j}
function setType(t){TYPE=t;document.body.dataset.type=t;$$('#typeSeg button').forEach(b=>b.classList.toggle('on',b.dataset.t===t));
 $$('.esp').forEach(x=>x.style.display='');}
$$('#typeSeg button').forEach(b=>b.onclick=()=>setType(b.dataset.t));
$$('#tabs button').forEach(b=>b.onclick=()=>{$$('#tabs button').forEach(x=>x.classList.toggle('on',x===b));
 $$('.tab').forEach(x=>x.classList.toggle('on',x.id==='t-'+b.dataset.tab));if(['backup','firmware'].includes(b.dataset.tab))loadFiles()});
document.addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;
 if(b.dataset.run){e.preventDefault();run(b.dataset.run)}
 if(b.dataset.rp){e.preventDefault();run('rp_cmd',{line:b.dataset.rp,wait:2})}});
$$('form[data-a]').forEach(f=>f.addEventListener('submit',async ev=>{ev.preventDefault();
 const args={};new FormData(f).forEach((v,k)=>args[k]=v);f.querySelectorAll('input[type=checkbox]').forEach(c=>args[c.name]=c.checked);
 let a=f.dataset.a;if(a==='restore')a=TYPE==='mt'?'mt_import':'mc_restore';
 const j=await run(a,args);if(j&&j.ok){f.querySelectorAll('input[name=confirm]:not([type=checkbox])').forEach(i=>i.value='')}}));
async function loadPorts(){const j=await api('/api/ports');const s=$('#port');s.innerHTML='';
 (j.ports||[]).forEach(p=>{const o=document.createElement('option');o.value=p.device;o.textContent=p.device+(p.desc&&p.desc!=='n/a'?'  '+p.desc:'')+(p.hint?'  ['+p.hint+']':'');s.appendChild(o)});
 if(!(j.ports||[]).length){const o=document.createElement('option');o.value='';o.textContent='no serial devices found (plug in, then Refresh)';s.appendChild(o)}}
$('#refresh').onclick=loadPorts;
async function loadStatus(){const j=await api('/api/status');if(!j.app){$('#deps').innerHTML='<span class="pill r">Bad token. Open the link from the terminal.</span>';return}
 const p=(n,v)=>'<span class="pill '+(v?'g':'r')+'">'+n+' '+(v||'missing')+'</span>';
 $('#deps').innerHTML=p('meshtastic',j.meshtastic)+p('meshcore-cli',j.meshcore_cli)+p('esptool',j.esptool)+(j.dry?'<span class="pill r">DRY RUN</span>':'');
 $('#homeHint').textContent='Folder on this computer: '+j.home}
async function loadFiles(){for(const kind of ['backups','firmware']){const j=await api('/api/files?kind='+kind);const fl=j.files||[];
  const tbl=$(kind==='backups'?'#bkTbl':'#fwTbl');
  tbl.innerHTML='<tr><th>File</th><th>Saved</th><th></th></tr>'+(fl.map(f=>'<tr><td>'+esc(f.name)+'</td><td>'+esc(f.time)+'</td><td><a href="/api/download?kind='+kind+'&name='+encodeURIComponent(f.name)+'&t='+encodeURIComponent(T)+'">get</a> <a href="#" data-del="'+kind+'|'+esc(f.name)+'">delete</a></td></tr>').join('')||'<tr><td colspan=3 class="hint">empty</td></tr>');
  $$('.fileSel[data-kind='+kind+']').forEach(sel=>{const cur=sel.value;sel.innerHTML=fl.map(f=>'<option>'+esc(f.name)+'</option>').join('')||'<option value="">no files yet</option>';if(cur)sel.value=cur})}}
document.addEventListener('click',async e=>{const a=e.target.closest('a[data-del]');if(!a)return;e.preventDefault();
 const [kind,name]=a.dataset.del.split('|');if(!confirm('Delete '+name+'?'))return;
 await api('/api/delete',{method:'POST',body:JSON.stringify({kind,name})});loadFiles()});
function uploader(inp,kind){inp.onchange=async()=>{const f=inp.files[0];if(!f)return;
 const j=await api('/api/upload?kind='+kind+'&name='+encodeURIComponent(f.name),{method:'POST',body:await f.arrayBuffer()});
 push(j.ok?{title:'uploaded '+f.name,ok:true,code:0,out:''}:{error:j.error,cmd:'upload '+f.name});inp.value='';loadFiles()}}
uploader($('#bkUp'),'backups');uploader($('#fwUp'),'firmware');
$('#findUf2').onclick=async()=>{const j=await run('fw_drives');const s=$('#uf2Drive');s.innerHTML='';
 (j.drives||[]).forEach(d=>{const o=document.createElement('option');o.value=d.path;o.textContent=d.path+'  '+d.info;s.appendChild(o)});
 if(!(j.drives||[]).length)s.innerHTML='<option value="">none found yet</option>'};
$$('[data-gen]').forEach(b=>b.onclick=async()=>{const j=await api('/api/genkey?n='+b.dataset.gen);$('#g-hex').value=j.hex;$('#g-b64').value=j.base64});
$('#g-use-mt').onclick=()=>{$('#mt-psk-mode').value='custom';$('#mt-psk').value=$('#g-hex').value};
$('#g-use-mc').onclick=()=>{$('#mc-key').value=$('#g-hex').value.slice(0,32)};
$('#mask').onchange=render;$('#clear').onclick=()=>{LOG=[];render()};
$('#copy').onclick=()=>navigator.clipboard&&navigator.clipboard.writeText($('#log').innerText);
loadStatus();loadPorts();loadFiles();
</script></body></html>
"""

if __name__ == "__main__":
    main()
