"""Kavacham engine: Kavacham's own detection layer, running next to Microsoft Defender.

- File scanner with SHA-256 fingerprints, matched against a local signature database (MalwareBazaar)
- Heuristic rules for suspicious files (disguised programs, hostile scripts, auto-running macros, ...)
- Quarantine that neutralises files (XOR-encoded, so they can't run) and can restore them
- URL reputation from free threat feeds (URLhaus, OpenPhish) plus link heuristics
- Real-time monitoring of chosen folders, run as a background process
- Feed updates and a security event log

All threat intelligence comes from free, keyless feeds.
"""
import hashlib
import io
import csv
import ipaddress
import json
import math
import os
import re
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from collections import Counter
from urllib.parse import urlsplit

from core import DATA_DIR, LOCAL, NO_WINDOW, PROGDATA, SCRIPT, SETTINGS_FILE, WINDIR, decrypt_secret, \
    encrypt_secret, fixed_drives, is_admin, load_settings, notify, ps_quote, pythonw, run_ps, write_json

ENGINE_DIR = os.path.join(DATA_DIR, "engine")
DB_FILE = os.path.join(ENGINE_DIR, "engine.db")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
QUARANTINE_INDEX = os.path.join(QUARANTINE_DIR, "index.json")
EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")
MONITOR_BEAT = os.path.join(ENGINE_DIR, "monitor.beat")
MONITOR_TASK = "PC Guard - Real-time Monitor"

HOME = os.path.expanduser("~")
APPDATA = os.environ.get("APPDATA", os.path.join(HOME, "AppData", "Roaming"))
TEMP = os.environ.get("TEMP", os.path.join(LOCAL, "Temp"))
DOWNLOADS = os.path.join(HOME, "Downloads")
DESKTOP = os.path.join(HOME, "Desktop")
STARTUP = os.path.join(APPDATA, r"Microsoft\Windows\Start Menu\Programs\Startup")
COMMON_STARTUP = os.path.join(PROGDATA, r"Microsoft\Windows\Start Menu\Programs\StartUp")
PUBLIC = os.environ.get("PUBLIC", r"C:\Users\Public")

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# abuse.ch retired its open downloads (HTTP 410) in Oct 2026: exports now need a free Auth-Key in the path
ABUSECH_SIGNUP = "https://auth.abuse.ch/"
FEEDS = [  # (name, kind, url) - {key} is the abuse.ch Auth-Key
    ("MalwareBazaar", "hash", "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"),
    ("URLhaus", "urlhaus", "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"),
    ("OpenPhish", "url", "https://openphish.com/feed.txt"),
    ("Stalkerware apps", "stalker_pkgs",
     "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"),
    ("Stalkerware samples", "stalker_hashes",
     "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/samples.csv"),
]
UPDATE_EVERY = 6 * 3600

PROGRAM_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".ocx", ".drv"}
SCRIPT_EXT = {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd"}
MACRO_EXT = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam"}
OFFICE_EXT = {".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".rtf"} | MACRO_EXT
ARCHIVE_EXT = {".zip", ".jar", ".apk"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png",
             ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".mkv", ".csv"}
# programs are recognised by their MZ header whatever the extension, so these only add non-program types
HASH_EXT = PROGRAM_EXT | SCRIPT_EXT | OFFICE_EXT | ARCHIVE_EXT | {".lnk", ".iso", ".img", ".vhd", ".7z", ".rar",
                                                                   ".pdf", ".chm"}
MAX_HASH = 300 * 1024 ** 2
SKIP_DIRS = {"winsxs", "system volume information", "$windows.~bt", "$windows.~ws", "node_modules", ".git",
             "__pycache__", "windowsapps"}

# score >= SUSPICIOUS is reported as "Suspicious", >= LOW as "Worth a look"; a signature match is "Malware"
SUSPICIOUS, LOW = 70, 40

SCRIPT_RULES = [  # (regex on lowercased text, score, reason)
    (r"-(e|en|enc|encodedcommand)\s+[a-z0-9+/=]{40,}", 45, "Runs a hidden, encoded PowerShell command"),
    (r"frombase64string", 15, "Decodes hidden (Base64) content"),
    (r"\biex\b|invoke-expression", 20, "Executes code it builds at run time"),
    (r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|start-bitstransfer|"
     r"bitsadmin\s+/transfer|certutil[^\n]*-urlcache|msxml2\.xmlhttp|winhttp\.winhttprequest", 25,
     "Downloads files from the internet"),
    (r"set-mppreference[^\n]*-disable|add-mppreference[^\n]*-exclusion|disableantispyware", 60,
     "Tries to switch off or bypass antivirus protection"),
    (r"vssadmin[^\n]*delete[^\n]*shadows|wbadmin[^\n]*delete|bcdedit[^\n]*recoveryenabled\s+no|"
     r"wmic[^\n]*shadowcopy[^\n]*delete", 70, "Deletes backups or recovery points (ransomware behaviour)"),
    (r"-windowstyle\s+hidden|-w\s+hidden|-noni?\b|-nop\b", 15, "Runs hidden from the user"),
    (r"schtasks[^\n]*/create|currentversion\\\\?run|register-scheduledtask", 20, "Makes itself start automatically"),
    (r"wscript\.shell|shell\.application|createobject\(", 10, "Starts other programs"),
    (r"\[char\]\s*\d+\s*\+\s*\[char\]|-join\s*\(\s*\[char", 20, "Hides text one character at a time (obfuscation)"),
]
MACRO_AUTO = re.compile(rb"autoopen|auto_open|document_open|workbook_open|autoexec|document_close", re.I)
MACRO_RISKY = re.compile(rb"shell|createobject|wscript|powershell|urldownloadtofile|xmlhttp", re.I)
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp[34]|avi|zip)[\s_.]*\."
                        r"(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|hta|lnk|ps1|msi)$", re.I)
LNK_TOOL = re.compile(r"powershell|pwsh|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin", re.I)
# a shortcut to PowerShell or Command Prompt is normal; one that hands it hidden or downloading arguments is not
LNK_ARGS = re.compile(r"-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}|hidden|https?://|iex|invoke-expression|"
                      r"downloadstring|frombase64|-urlcache|/transfer|javascript:|vbscript:", re.I)


# ---------------------------------------------------------------- security event log

def log_event(category, level, title, details=""):
    """category: scan, detection, quarantine, update, monitor, url, engine; level: ok, info, warn, bad."""
    os.makedirs(DATA_DIR, exist_ok=True)
    entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "category": category, "level": level, "title": title,
             "details": details}
    try:
        if os.path.exists(EVENTS_FILE) and os.path.getsize(EVENTS_FILE) > 2 * 1024 ** 2:
            with open(EVENTS_FILE, encoding="utf-8") as f:
                keep = f.readlines()[-3000:]
            with open(EVENTS_FILE, "w", encoding="utf-8") as f:
                f.writelines(keep)
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def read_events(limit=1000):
    try:
        with open(EVENTS_FILE, encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


# ---------------------------------------------------------------- signature database

_db_ready = False


def db():
    """A connection to the engine database. The schema is created once per process, so later connections only
    read unless asked to write - which lets lookups run while a scan holds its write transaction."""
    global _db_ready
    os.makedirs(ENGINE_DIR, exist_ok=True)
    con = sqlite3.connect(DB_FILE, timeout=30)
    if _db_ready:
        return con
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS hashes (sha256 BLOB PRIMARY KEY, source TEXT) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS urls (url TEXT PRIMARY KEY, source TEXT) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS hosts (host TEXT PRIMARY KEY, source TEXT) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS packages (package TEXT PRIMARY KEY, source TEXT) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS filecache (path TEXT PRIMARY KEY, size INTEGER, mtime REAL, sha256 TEXT);
        CREATE TABLE IF NOT EXISTS ignored (sha256 TEXT PRIMARY KEY, path TEXT);
        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
    """)
    con.execute("INSERT OR IGNORE INTO hashes VALUES (?, ?)", (bytes.fromhex(EICAR_SHA256), "EICAR test file"))
    con.commit()
    _db_ready = True
    return con


def meta_get(con, key, default=None):
    row = con.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
    return json.loads(row[0]) if row else default


def meta_set(con, key, value):
    con.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, json.dumps(value)))


def engine_status():
    with db() as con:
        return {
            "hashes": con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0],
            "urls": con.execute("SELECT COUNT(*) FROM urls").fetchone()[0],
            "hosts": con.execute("SELECT COUNT(*) FROM hosts").fetchone()[0],
            "updated": meta_get(con, "last_update", 0),
            "sources": meta_get(con, "sources", {}),
            "rules": len(SCRIPT_RULES) + 9,
        }


def lookup_hash(con, sha256):
    row = con.execute("SELECT source FROM hashes WHERE sha256=?", (bytes.fromhex(sha256),)).fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------- updates

def _fetch(url, timeout=60, tries=3):
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PC-Guard/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # the feeds are free and occasionally slow: retry with a short back-off
            last = e
            time.sleep(2 + attempt * 3)
    raise last


def _lines(data):
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def abusech_key():
    return decrypt_secret(load_settings()["engine"]["abusech_key"])


def save_abusech_key(key):
    settings = load_settings()
    settings["engine"]["abusech_key"] = encrypt_secret(key.strip())
    write_json(SETTINGS_FILE, settings)
    log_event("engine", "info", "abuse.ch key " + ("saved" if key else "removed"))


def _csv_rows(data):
    if data[:2] == b"PK":  # exports may come zipped
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            data = z.read(z.namelist()[0])
    return csv.reader(_lines(data), skipinitialspace=True)


def needs_update(max_age=UPDATE_EVERY):
    with db() as con:
        return time.time() - meta_get(con, "last_update", 0) > max_age


def update(progress=lambda text: None):
    """Download the threat feeds. Hashes accumulate; URL and host lists are replaced by the current ones.
    The abuse.ch feeds are skipped (not failed) until the user adds their free key."""
    summary, errors = [], []
    with db() as con:
        sources = meta_get(con, "sources", {})
    key = abusech_key()
    plan = [f for f in FEEDS if key or "{key}" not in f[2]]
    skipped = [f[0] for f in FEEDS if f not in plan]
    for name, kind, url in plan:
        progress(f"Downloading {name}…")
        try:
            try:
                data = _fetch(url.format(key=key), tries=1 if "{key}" in url else 3)
            except urllib.error.HTTPError as e:  # never log the URL: it contains the key
                raise RuntimeError("abuse.ch rejected the key" if e.code in (401, 403) else f"HTTP {e.code}") from None
            progress(f"Importing {name}…")
            with db() as con:
                if kind == "hash":  # MalwareBazaar CSV: "first_seen_utc","sha256_hash",... - take the first SHA-256
                    rows = [(bytes.fromhex(h), "MalwareBazaar") for r in _csv_rows(data)
                            for h in [next((f for f in r if re.fullmatch(r"[0-9a-fA-F]{64}", f)), None)] if h]
                    if not rows:
                        raise RuntimeError("no signatures in the download")
                    before = con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
                    con.executemany("INSERT OR IGNORE INTO hashes VALUES (?, ?)", rows)
                    added = con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] - before
                    summary.append(f"{name}: +{added:,} signatures")
                elif kind == "urlhaus":  # URLhaus CSV: "id","dateadded","url","url_status",... - keep online ones
                    urls = [f for r in _csv_rows(data) if "online" in r for f in r if "://" in f]
                    if not urls:
                        raise RuntimeError("no live links in the download")
                    hosts = set()
                    for u in urls:
                        host = (urlsplit(u).hostname or "").lower()
                        try:
                            ipaddress.ip_address(host)
                        except ValueError:
                            if host:
                                hosts.add((host, "URLhaus hosts"))
                    con.execute("DELETE FROM urls WHERE source=?", (name,))
                    con.executemany("INSERT OR IGNORE INTO urls VALUES (?, ?)", {(normalize_url(u), name) for u in urls})
                    con.execute("DELETE FROM hosts WHERE source='URLhaus hosts'")
                    con.executemany("INSERT OR IGNORE INTO hosts VALUES (?, ?)", hosts)
                    summary.append(f"{name}: {len(urls):,} links, {len(hosts):,} domains")
                elif kind == "url":
                    rows = {(normalize_url(l), name) for l in _lines(data) if "://" in l}
                    con.execute("DELETE FROM urls WHERE source=?", (name,))
                    con.executemany("INSERT OR IGNORE INTO urls VALUES (?, ?)", rows)
                    summary.append(f"{name}: {len(rows):,} links")
                elif kind == "stalker_pkgs":  # ioc.yaml: "- name: Family" ... "packages:" "  - com.x.y"
                    rows, family, in_pkgs = set(), "", False
                    for line in data.decode("utf-8", "replace").splitlines():
                        if line.startswith("- name:"):
                            family, in_pkgs = line.split(":", 1)[1].strip(), False
                        elif re.match(r"\s{0,2}packages:\s*$", line):
                            in_pkgs = True
                        elif in_pkgs and re.match(r"\s*- [\w.]+\s*$", line):
                            rows.add((line.strip()[2:].strip(), f"stalkerware: {family}"))
                        elif re.match(r"\s{0,2}\w+:", line):
                            in_pkgs = False
                    con.execute("DELETE FROM packages WHERE source LIKE 'stalkerware:%'")
                    con.executemany("INSERT OR IGNORE INTO packages VALUES (?, ?)", rows)
                    summary.append(f"{name}: {len(rows):,} spy-app names")
                elif kind == "stalker_hashes":  # samples.csv: SHA256,Package Name,Certificate,Version,App
                    rows = [l.split(",") for l in _lines(data)][1:]
                    hashes = [(bytes.fromhex(r[0]), f"Stalkerware: {r[4].strip()}") for r in rows
                              if len(r) >= 5 and re.fullmatch(r"[0-9a-fA-F]{64}", r[0])]
                    con.executemany("INSERT OR IGNORE INTO hashes VALUES (?, ?)", hashes)
                    con.executemany("INSERT OR IGNORE INTO packages VALUES (?, ?)",
                                    {(r[1].strip(), f"stalkerware: {r[4].strip()}") for r in rows if len(r) >= 5})
                    summary.append(f"{name}: {len(hashes):,} spy-app fingerprints")
                sources[name] = time.time()
                meta_set(con, "sources", sources)
        except Exception as e:
            errors.append(f"{name}: {str(e)[:80]}")
    with db() as con:
        if len(errors) < len(plan):
            meta_set(con, "last_update", time.time())
    if errors and len(errors) == len(plan):
        log_event("update", "warn", "Threat feed update failed", "; ".join(errors))
    else:
        notes = [f"failed: {e}" for e in errors]
    if skipped:
        notes.append(f"skipped {' and '.join(skipped)}: add your free abuse.ch key in Engine > Threat intelligence")
    log_event("update", "warn" if errors or skipped else "ok", "Threat feeds updated", "; ".join(summary + notes))
    return summary, errors


# ---------------------------------------------------------------- hashing and heuristics

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def cached_sha256(con, path, st):
    row = con.execute("SELECT size, mtime, sha256 FROM filecache WHERE path=?", (path,)).fetchone()
    if row and row[0] == st.st_size and row[1] == st.st_mtime:
        return row[2]
    digest = sha256_file(path)
    con.execute("INSERT OR REPLACE INTO filecache VALUES (?, ?, ?, ?)", (path, st.st_size, st.st_mtime, digest))
    return digest


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _under(path, *roots):
    p = os.path.normcase(path)
    return any(r and p.startswith(os.path.normcase(r) + os.sep) for r in roots)


def heuristics(path, head, name=None):
    """Returns [(score, reason)] for one file. head: the first bytes (up to 2 MB)."""
    name = name or os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    found = []
    is_pe = head[:2] == b"MZ"
    if "\u202e" in name:
        found.append((80, "Name uses a hidden right-to-left character to fake its extension"))
    if DOUBLE_EXT.search(name):
        found.append((75, "Double extension: a program pretending to be a document or picture"))
    if is_pe and ext in DECOY_EXT:
        found.append((75, f"A program disguised as a {ext} file"))
    risky_place = _under(path, TEMP, DOWNLOADS, STARTUP, COMMON_STARTUP, PUBLIC) or \
        os.path.normcase(os.path.dirname(path)) == os.path.normcase(APPDATA) or "$recycle.bin" in path.lower()
    if is_pe or ext in PROGRAM_EXT:
        if _under(path, STARTUP, COMMON_STARTUP):
            found.append((35, "Program in the Startup folder (runs at every sign-in)"))
        elif risky_place:
            found.append((15, "Program in a folder malware often uses"))
        if is_pe and len(head) > 4096 and entropy(head[:256 * 1024]) > 7.4:
            found.append((20, "Compressed or encrypted program (packed)"))
    if ext in SCRIPT_EXT:
        text = head.decode("latin-1").lower()
        if ext in (".ps1", ".psm1", ".bat", ".cmd"):
            text = text.replace("^", "").replace("`", "")  # strip cmd/PowerShell escape-character obfuscation
        for rx, score, reason in SCRIPT_RULES:
            if re.search(rx, text):
                found.append((score, reason))
        if found and _under(path, STARTUP, COMMON_STARTUP):
            found.append((25, "Script in the Startup folder (runs at every sign-in)"))
    if ext in OFFICE_EXT:
        has_macro = ext in MACRO_EXT or b"vbaProject.bin" in head or b"_VBA_PROJECT" in head
        if has_macro:
            found.append((20, "Document contains macros"))
            if MACRO_AUTO.search(head):
                found.append((25, "Macros run automatically when the document opens"))
            if MACRO_RISKY.search(head):
                found.append((20, "Macros can start programs or download files"))
    if ext in (".apk", ".xapk", ".apks") and os.path.isfile(path) and os.path.getsize(path) <= 150 * 1024 ** 2:
        try:
            with open(path, "rb") as f:
                found += apk_heuristics(f.read())
        except OSError:
            pass
    if ext == ".lnk":
        text = head.decode("utf-16-le", "ignore") + head.decode("latin-1")
        if LNK_TOOL.search(text) and LNK_ARGS.search(text):
            found.append((60, "Shortcut secretly runs a hidden or downloading command"))
    return found


def apk_heuristics(data):
    """Risky permission combinations in an Android app, read from its (binary) manifest."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            manifest = z.read("AndroidManifest.xml")
    except (zipfile.BadZipFile, KeyError, OSError, RuntimeError):
        return []

    def has(perm):
        return perm.encode("utf-16-le") in manifest or perm.encode() in manifest
    found = []
    sms = has("android.permission.READ_SMS") or has("android.permission.RECEIVE_SMS")
    access = has("android.permission.BIND_ACCESSIBILITY_SERVICE")
    admin = has("android.permission.BIND_DEVICE_ADMIN")
    if sms and (access or admin):
        found.append((70, "Android app that can read your text messages and control the screen "
                          "(banking-trojan pattern)"))
    elif access and admin:
        found.append((50, "Android app that wants both screen control (accessibility) and device-admin rights"))
    if has("android.permission.REQUEST_INSTALL_PACKAGES") and (access or sms):
        found.append((20, "Can install other apps"))
    if has("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE") and sms:
        found.append((15, "Can read all your notifications"))
    return found


def score_of(found):
    return min(100, sum(s for s, _r in found))


def verdict_of(score, signature):
    if signature:
        return "Malware"
    return "Suspicious" if score >= SUSPICIOUS else "Worth a look" if score >= LOW else None


def signatures(paths):
    """Authenticode status for PE files -> {path: (valid, signer)}. One PowerShell call for the whole batch."""
    if not paths:
        return {}
    script = ("$p = $env:PCG_PATHS | ConvertFrom-Json; $r = @($p | % { $s = Get-AuthenticodeSignature -LiteralPath $_;"
              " [pscustomobject]@{P=$_; V=([string]$s.Status -eq 'Valid'); S=[string]$s.SignerCertificate.Subject} });"
              " ConvertTo-Json -InputObject $r -Compress")
    try:
        out = run_ps(script, env={**os.environ, "PCG_PATHS": json.dumps(list(paths))}, timeout=300)
        rows = json.loads(out.stdout or "[]")
    except Exception:
        return {}
    return {r["P"]: (r["V"], re.sub(r"^CN=\"?([^,\"]+).*", r"\1", r["S"] or "")) for r in rows}


# ---------------------------------------------------------------- scanning

def quick_paths():
    return [p for p in (DOWNLOADS, DESKTOP, os.path.join(HOME, "Documents"), TEMP, STARTUP, COMMON_STARTUP, APPDATA,
                        os.path.join(PUBLIC, "Desktop"), os.path.join(PUBLIC, "Downloads")) if os.path.isdir(p)]


def full_paths():
    return list(fixed_drives())


def walk(roots, max_depth=None):
    skip = {os.path.normcase(QUARANTINE_DIR), os.path.normcase(ENGINE_DIR), os.path.normcase(os.path.join(WINDIR,
                                                                                                          "WinSxS"))}
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        base = root.rstrip("\\").count(os.sep)
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS
                       and os.path.normcase(os.path.join(dirpath, d)) not in skip
                       and not os.path.islink(os.path.join(dirpath, d))]
            if max_depth is not None and dirpath.rstrip("\\").count(os.sep) - base >= max_depth:
                dirs[:] = []
            for f in files:
                yield os.path.join(dirpath, f)


def scan_file(con, path, deep_archives=True):
    """Examine one file. Returns a list of detections (dicts); empty when clean."""
    try:
        st = os.stat(path)
        if st.st_size == 0:
            return []
        ext = os.path.splitext(path)[1].lower()
        with open(path, "rb") as f:
            head = f.read(2)
            if head == b"MZ" or ext in HASH_EXT:  # anything else only gets the (free) file-name checks
                head += f.read(2 * 1024 * 1024 if ext in SCRIPT_EXT | OFFICE_EXT | {".lnk"} else 1024 * 1024)
    except OSError:
        return []  # locked, or already removed (often by Defender)
    is_pe = head[:2] == b"MZ"
    digest = source = None
    if (is_pe or ext in HASH_EXT) and st.st_size <= MAX_HASH:
        try:
            digest = cached_sha256(con, path, st)
            source = lookup_hash(con, digest)
        except OSError:
            pass
    if digest and con.execute("SELECT 1 FROM ignored WHERE sha256=?", (digest,)).fetchone():
        return []
    found = heuristics(path, head)
    results = []
    score = score_of(found)
    if source or score >= LOW:
        results.append({"path": path, "name": os.path.basename(path), "sha256": digest or "", "size": st.st_size,
                        "pe": is_pe, "score": 100 if source else score, "verdict": verdict_of(score, source),
                        "reasons": [f"Matches known malware ({source})"] if source else [r for _s, r in found],
                        "found": found, "signature": source})
    if deep_archives and ext == ".zip" and st.st_size <= 200 * 1024 ** 2 and not source:
        results += scan_archive(con, path)
    return results


def scan_archive(con, path):
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist()[:2000]:
                if info.is_dir() or info.file_size == 0 or info.file_size > 50 * 1024 ** 2 or info.flag_bits & 1:
                    continue
                data = z.read(info)
                digest = hashlib.sha256(data).hexdigest()
                source = lookup_hash(con, digest)
                found = heuristics(os.path.join(path, info.filename), data[:2 * 1024 * 1024],
                                   os.path.basename(info.filename))
                found = [(s, r) for s, r in found if "folder" not in r]  # location rules don't apply inside archives
                score = score_of(found)
                if source or score >= LOW:
                    out.append({"path": path, "name": f"{os.path.basename(path)} › {info.filename}", "sha256": digest,
                                "size": info.file_size, "pe": data[:2] == b"MZ", "score": 100 if source else score,
                                "verdict": verdict_of(score, source), "signature": source, "found": found,
                                "reasons": [f"Matches known malware ({source})"] if source else [r for _s, r in found]})
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, ValueError):
        pass
    return out


def apply_signatures(results):
    """Trusted, validly signed programs don't get location/packing points; unsigned risky ones get extra points."""
    pe = [r["path"] for r in results if r["pe"] and not r["signature"] and "›" not in r["name"]]
    info = signatures(pe)
    kept = []
    for r in results:
        if r["path"] in info and "›" not in r["name"]:
            valid, signer = info[r["path"]]
            if valid:  # a trusted publisher explains odd locations and packing, but never a disguised name
                found = [(s, x) for s, x in r["found"] if not any(k in x for k in ("folder", "packed", "Startup"))]
                r["score"], r["reasons"] = score_of(found), [x for _s, x in found]
                if found:
                    r["reasons"].append(f"Signed by {signer}")
            else:
                r["reasons"].append("Not digitally signed")
                r["score"] = min(100, r["score"] + 25)
            r["verdict"] = verdict_of(r["score"], None)
        if r["verdict"]:
            kept.append(r)
    return kept


def scan(roots, progress=lambda n, path, hits: None, cancelled=lambda: False, max_depth=None):
    """Scan files under roots. Returns (detections, files_scanned, seconds)."""
    t0, n, hits, pending = time.time(), 0, [], []
    with db() as con:
        for path in walk(roots, max_depth):
            if cancelled():
                break
            n += 1
            found = scan_file(con, path)
            for r in found:
                (hits if r["signature"] or not r["pe"] else pending).append(r)
            if n % 50 == 0:
                con.commit()
                progress(n, path, len(hits) + len(pending))
        con.commit()
    hits += apply_signatures(pending)
    hits.sort(key=lambda r: -r["score"])
    return hits, n, time.time() - t0


def scan_and_act(roots, label, auto_quarantine=True, progress=lambda *a: None, cancelled=lambda: False):
    """Scan, quarantine known malware automatically, and log everything. Used by the UI, schedule and monitor."""
    log_event("scan", "info", f"{label} started", ", ".join(roots)[:300])
    hits, n, secs = scan(roots, progress, cancelled)
    for r in hits:
        log_event("detection", "bad" if r["verdict"] != "Worth a look" else "warn",
                  f"{r['verdict']}: {r['name']}", f"{r['path']} · " + "; ".join(r["reasons"]))
        if auto_quarantine and r["signature"]:
            qid = quarantine(r["path"], "; ".join(r["reasons"]), r["sha256"])
            r["action"] = "Quarantined" if qid else "Could not quarantine"
    malware = sum(1 for r in hits if r["signature"])
    state = "Cancelled" if cancelled() else "Finished"
    log_event("scan", "bad" if malware else "warn" if hits else "ok", f"{label} {state.lower()}",
              f"{n:,} files in {int(secs)} s · {malware} malware, {len(hits) - malware} suspicious")
    return hits, n, secs


# ---------------------------------------------------------------- quarantine

def _xor(data, key=0xA5):
    return bytes(b ^ key for b in data) if len(data) < 4096 else \
        (int.from_bytes(data, "little") ^ int.from_bytes(bytes([key]) * len(data), "little")).to_bytes(len(data),
                                                                                                    "little")


def quarantine_list():
    try:
        with open(QUARANTINE_INDEX, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def _save_index(items):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    tmp = QUARANTINE_INDEX + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)
    os.replace(tmp, QUARANTINE_INDEX)


def quarantine(path, reason, sha256=""):
    """Move a file into quarantine, XOR-encoded so it can't run or be opened. Returns the id or None."""
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        qid = uuid.uuid4().hex
        size = os.path.getsize(path)
        with open(path, "rb") as src, open(os.path.join(QUARANTINE_DIR, qid + ".qtn"), "wb") as dst:
            for chunk in iter(lambda: src.read(4 * 1024 * 1024), b""):
                dst.write(_xor(chunk))
        os.remove(path)
    except OSError as e:
        try:
            os.remove(os.path.join(QUARANTINE_DIR, qid + ".qtn"))
        except (OSError, UnboundLocalError):
            pass
        log_event("quarantine", "warn", f"Could not quarantine {os.path.basename(path)}", f"{path} · {e}")
        return None
    items = quarantine_list()
    items.insert(0, {"id": qid, "path": path, "name": os.path.basename(path), "reason": reason, "sha256": sha256,
                     "size": size, "time": time.strftime("%d %b %Y %H:%M")})
    _save_index(items)
    log_event("quarantine", "ok", f"Quarantined {os.path.basename(path)}", f"{path} · {reason}")
    return qid


def restore(qid):
    """Put a quarantined file back. Its hash is added to the ignore list so it isn't flagged again."""
    items = quarantine_list()
    item = next(i for i in items if i["id"] == qid)
    target = item["path"]
    if os.path.exists(target):
        stem, ext = os.path.splitext(target)
        target = f"{stem} (restored){ext}"
    os.makedirs(os.path.dirname(target), exist_ok=True)
    blob = os.path.join(QUARANTINE_DIR, qid + ".qtn")
    with open(blob, "rb") as src, open(target, "wb") as dst:
        for chunk in iter(lambda: src.read(4 * 1024 * 1024), b""):
            dst.write(_xor(chunk))
    os.remove(blob)
    _save_index([i for i in items if i["id"] != qid])
    if item.get("sha256"):
        with db() as con:
            con.execute("INSERT OR REPLACE INTO ignored VALUES (?, ?)", (item["sha256"], target))
    log_event("quarantine", "warn", f"Restored {item['name']}", f"{target} · now on the ignore list")
    return target


def delete_quarantined(qid):
    items = quarantine_list()
    item = next(i for i in items if i["id"] == qid)
    try:
        os.remove(os.path.join(QUARANTINE_DIR, qid + ".qtn"))
    except FileNotFoundError:
        pass
    _save_index([i for i in items if i["id"] != qid])
    log_event("quarantine", "ok", f"Deleted {item['name']} permanently", item["path"])


def ignore(sha256, path):
    with db() as con:
        con.execute("INSERT OR REPLACE INTO ignored VALUES (?, ?)", (sha256, path))
    log_event("detection", "info", f"Marked as safe: {os.path.basename(path)}", path)


# ---------------------------------------------------------------- URL reputation

def normalize_url(url):
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        port = f":{parts.port}" if parts.port and parts.port not in (80, 443) else ""
    except ValueError:
        return url.lower()
    path = parts.path or "/"
    return f"{host}{port}{path}" + (f"?{parts.query}" if parts.query else "")


BRANDS = ["paypal", "microsoft", "office365", "outlook", "apple", "icloud", "google", "gmail", "amazon", "netflix",
          "facebook", "instagram", "whatsapp", "meta", "metamask", "coinbase", "binance", "trust wallet", "ledger",
          "linkedin", "dropbox", "docusign", "adobe", "dhl", "fedex", "usps", "shopee", "flipkart", "chase",
          "wells fargo", "anz", "hdfc", "icici", "sbi", "axis bank", "paytm", "phonepe", "steam", "roblox", "telegram",
          "yahoo", "irs", "hmrc", "india post", "santander", "zoom"]
# free hosting where anyone can publish a page in seconds: real brands don't put their sign-in pages here
FREE_HOSTS = {"pages.dev", "workers.dev", "vercel.app", "netlify.app", "r2.dev", "blogspot.com", "github.io",
              "firebaseapp.com", "web.app", "weebly.com", "wixsite.com", "glitch.me", "000webhostapp.com",
              "repl.co", "replit.app", "ngrok.io", "ngrok-free.app", "godaddysites.com", "square.site",
              "webflow.io", "framer.app", "carrd.co", "sites.google.com", "azurewebsites.net", "herokuapp.com",
              "onrender.com", "surge.sh", "translate.goog", "wix-site-host.com"}


def _has_brand(brand, text):
    return re.search(r"(?<![a-z])" + re.escape(brand) + r"(?![a-z])", text) is not None
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "ml", "cf", "tk", "ga", "work", "rest", "support"}


def check_url(text, log=True):
    """Returns {"verdict": malicious|suspicious|no-known-threats, "reasons": [...], "url": normalized}."""
    norm = normalize_url(text)
    host = norm.split("/")[0].split(":")[0]
    reasons, verdict = [], "no-known-threats"
    with db() as con:
        candidates = {norm, norm.rstrip("/"), norm.rstrip("/") + "/"}
        for c in candidates:
            row = con.execute("SELECT source FROM urls WHERE url=?", (c,)).fetchone()
            if row:
                verdict = "malicious"
                reasons.append(f"Listed as malicious by {row[0]}")
                break
        labels = host.split(".")
        for i in range(len(labels) - 1):
            row = con.execute("SELECT source FROM hosts WHERE host=?", (".".join(labels[i:]),)).fetchone()
            if row:
                verdict = "malicious"
                reasons.append(f"Domain {'.'.join(labels[i:])} hosts malware ({row[0]})")
                break
    score = 0
    try:
        ipaddress.ip_address(host)
        score += 30
        reasons.append("Uses a bare IP address instead of a domain name")
    except ValueError:
        pass
    if "xn--" in host:
        score += 30
        reasons.append("Uses look-alike international characters (punycode)")
    if "@" in text.split("?")[0].split("://")[-1].split("/")[0]:
        score += 40
        reasons.append("Contains '@' to hide the real destination")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        score += 20
        reasons.append(f".{tld} domains are often used for scams")
    registrable = registrable_domain(host)
    for b in BRANDS:
        if " " not in b and b in host and b not in registrable and len(b) >= 4:
            score += 45
            reasons.append(f"Mentions '{b}' but the real site is {registrable}")
            break
    if host.count(".") >= 4 or host.count("-") >= 4:
        score += 15
        reasons.append("Unusually long or complex address")
    if verdict != "malicious" and score >= 40:
        verdict = "suspicious"
    if log:
        log_event("url", {"malicious": "bad", "suspicious": "warn"}.get(verdict, "ok"), f"Link checked: {verdict}",
                  f"{text.strip()[:200]} · " + ("; ".join(reasons) or "not in any threat list"))
    return {"verdict": verdict, "reasons": reasons, "url": norm}


# ---------------------------------------------------------------- real-time monitoring

def monitor_running():
    try:
        return time.time() - os.path.getmtime(MONITOR_BEAT) < 20
    except OSError:
        return False


def monitor_wanted(settings=None):
    """The background monitor runs while real-time protection or camera & microphone alerts are on."""
    settings = settings or load_settings()
    return bool(settings["engine"]["realtime"] or settings["privacy"]["watch"])


def monitor_task_exists():
    return bool(run_ps(f"Get-ScheduledTask -TaskName {ps_quote(MONITOR_TASK)} -ErrorAction SilentlyContinue | "
                       "% { 'yes' }", timeout=60).stdout.strip())


def run_monitor():
    """Background process: watch folders, scan new or changed files once they stop growing, watch the camera and
    microphone, update the feeds."""
    if monitor_running():
        return
    log_event("monitor", "ok", "Background monitor started")
    seen, settling, last_cfg, last_update_try, last_alerts = {}, {}, 0, 0, 0
    import privacy
    import usb
    usb_watch = usb.Watcher()
    cam_watch = None
    folders, cfg, priv = [], {}, {}
    while True:
        if time.time() - last_cfg > 10:
            settings = load_settings()
            cfg, priv = settings["engine"], settings["privacy"]
            if not monitor_wanted(settings):
                break
            want = [f for f in cfg["folders"] if os.path.isdir(f)] if cfg["realtime"] else []
            if want != folders:
                folders = want
                seen = {p: _sig(p) for p in walk(folders, max_depth=3)}  # baseline: only react to new changes
            last_cfg = time.time()
        if priv.get("watch"):
            try:
                cam_watch = cam_watch or privacy.Watcher()
                cam_watch.step(priv.get("trusted", []))
            except Exception as ex:
                log_event("privacy", "warn", "Camera & microphone watch error", str(ex)[:200])
        else:
            cam_watch = None  # switched back on later: don't alert for what was already on
        try:
            usb_watch.step(on_new=lambda root: threading.Thread(target=usb.auto_scan, args=(root,), daemon=True).start()
                           if load_settings()["usb"]["auto_scan"] else None)
        except Exception as ex:
            log_event("usb", "warn", "USB watch error", str(ex)[:200])
        if time.time() - last_alerts > 600:
            last_alerts = time.time()
            threading.Thread(target=_alerts_quietly, daemon=True).start()
        if cfg.get("auto_update") and time.time() - last_update_try > 1800 and needs_update():
            last_update_try = time.time()
            try:
                update()
            except Exception:
                pass
        current = {p: _sig(p) for p in walk(folders, max_depth=3)}
        for p, s in list(settling.items()):
            if current.get(p) != s:
                settling.pop(p)  # still growing (or gone): wait for it to settle
            else:
                settling.pop(p)  # unchanged for a whole poll: the download or copy is finished
                try:
                    _check_new(p, cfg)
                except Exception as ex:  # one unreadable file must never stop the monitor
                    log_event("monitor", "warn", f"Could not check {os.path.basename(p)}", f"{p} · {ex}")
        for p, s in current.items():
            if s and seen.get(p) != s:
                settling[p] = s
        seen = current
        with open(MONITOR_BEAT, "w") as f:
            f.write(str(os.getpid()))
        time.sleep(3)
    log_event("monitor", "info", "Background monitor stopped")
    try:
        os.remove(MONITOR_BEAT)
    except OSError:
        pass


def _alerts_quietly():
    try:
        import alerts
        alerts.run_checks()
    except Exception as e:
        log_event("monitor", "warn", "Alert check failed", str(e)[:200])


def _sig(path):
    try:
        st = os.stat(path)
        return st.st_size, st.st_mtime
    except OSError:
        return None


def _check_new(path, cfg):
    if os.path.splitext(path)[1].lower() in PARTIAL_EXT:
        return  # still downloading: the browser renames it when finished, and the new name gets checked
    is_download = _under(path, DOWNLOADS) or download_source(path) is not None
    with db() as con:
        if is_download and cfg.get("download_protection", True):
            found = check_download(con, path)
        else:
            found = scan_file(con, path)
            found = [r for r in found if r["signature"] or not r["pe"]] + apply_signatures(
                [r for r in found if r["pe"] and not r["signature"]])
    kind = "Download" if is_download else "Real-time"
    for r in found:
        source = f" · from {r['source']}" if r.get("source") else ""
        log_event("detection", "bad" if r["verdict"] != "Worth a look" else "warn",
                  f"{kind}: {r['verdict']} - {r['name']}", f"{r['path']}{source} · " + "; ".join(r["reasons"]))
        if r["verdict"] == "Malware" and cfg.get("auto_quarantine", True):
            if quarantine(r["path"], "; ".join(r["reasons"]), r["sha256"]):
                notify("Kavacham blocked a threat", f"{r['name']}: {r['reasons'][0]}. It was quarantined.")
        elif r["verdict"] == "Suspicious" and is_download and cfg.get("hold_downloads", True):
            if quarantine(r["path"], "Held for review: " + "; ".join(r["reasons"]), r["sha256"]):
                notify("Kavacham held a download", f"{r['name']} looks suspicious ({r['reasons'][0]}). "
                                                    "Review it in Kavacham > Quarantine before opening it.")
        elif r["verdict"] != "Worth a look":
            notify("Kavacham: suspicious file", f"{r['name']}: {r['reasons'][0]}. Open Kavacham to review it.")


def set_monitor(enabled):
    """Register (or remove) the sign-in task that runs the monitor, and start it now. Returns an error or None."""
    name = ps_quote(MONITOR_TASK)
    if not enabled:
        run_ps(f"Unregister-ScheduledTask -TaskName {name} -Confirm:$false -ErrorAction SilentlyContinue")
        log_event("engine", "info", "Background monitor turned off")
        return None
    user = '"$env:USERDOMAIN\\$env:USERNAME"'
    script = f"""
$ErrorActionPreference = 'Stop'
$a = New-ScheduledTaskAction -Execute {ps_quote(pythonw())} -Argument {ps_quote(f'"{SCRIPT}" --task monitor')} -WorkingDirectory {ps_quote(os.path.dirname(SCRIPT))}
$t = New-ScheduledTaskTrigger -AtLogOn -User {user}
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$p = New-ScheduledTaskPrincipal -UserId {user} -LogonType Interactive -RunLevel {"Highest" if is_admin() else "Limited"}
Register-ScheduledTask -TaskName {name} -Action $a -Trigger $t -Settings $s -Principal $p -Description 'Created by Kavacham' -Force | Out-Null
"""
    out = run_ps(script)
    err = None
    if out.returncode != 0:  # the task only adds start-at-sign-in; monitoring still starts now
        lines = out.stderr.strip().splitlines()
        err = next((l for l in lines if l.strip() and not l.startswith(("At line", "+", "#<"))), "Unknown error")
    start_monitor()
    log_event("engine", "ok", "Background monitor turned on")
    return err


def start_monitor():
    if not monitor_running():
        subprocess.Popen([pythonw(), SCRIPT, "--task", "monitor"], creationflags=NO_WINDOW,
                         cwd=os.path.dirname(SCRIPT))


# ---------------------------------------------------------------- web protection: page inspection

PAGE_LIMIT = 1024 * 1024
LOGIN_WORDS = re.compile(r"sign[\s-]?in|log[\s-]?in|verify your|account (suspended|locked|limited)|password|"
                         r"confirm your identity|unusual activity", re.I)
SECOND_LEVEL = ("com", "co", "net", "org", "gov", "edu", "ac")


def registrable_domain(host):
    labels = host.split(".")
    return ".".join(labels[-3:] if len(labels) >= 3 and labels[-2] in SECOND_LEVEL else labels[-2:])


def domain_age_days(host):
    """Days since the domain was registered, from free RDAP data; None when unknown."""
    try:
        data = json.loads(_fetch(f"https://rdap.org/domain/{registrable_domain(host)}", timeout=10, tries=1))
    except Exception:
        return None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            try:
                t = time.mktime(time.strptime(ev["eventDate"][:10], "%Y-%m-%d"))
                return int((time.time() - t) // 86400)
            except (ValueError, KeyError):
                return None
    return None


def inspect_page(url):
    """Fetch a page as text only (no scripts run, no cookies, nothing saved) and look for phishing signs.
    Returns {"final_url", "redirects", "score", "reasons", ...}."""
    if "://" not in url:
        url = "http://" + url
    reasons, score = [], 0
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                                             "PC-Guard-LinkCheck/1.0", "Accept": "text/html,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            final = r.geturl()
            ctype = r.headers.get("Content-Type", "")
            body = r.read(PAGE_LIMIT)
    except Exception as e:
        return {"final_url": url, "redirects": False, "score": 0, "reasons": [], "error": str(e)[:120]}
    start_host = (urlsplit(url).hostname or "").lower()
    host = (urlsplit(final).hostname or "").lower()
    redirected = host != start_host
    if redirected:
        if check_url(final, log=False)["verdict"] == "malicious":
            score += 100
            reasons.append(f"Redirects to a known malicious site ({host})")
        else:
            reasons.append(f"Redirects to another site: {host}")
    if body[:2] == b"MZ" or "application/x-msdownload" in ctype or "octet-stream" in ctype:
        score += 40
        reasons.append("The link downloads a file straight away instead of opening a page")
    html = body.decode("utf-8", "replace")
    low = html.lower()
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
    registrable = registrable_domain(host)
    has_password = re.search(r"<input[^>]+type\s*=\s*['\"]?password", low) is not None
    sample = (title + " " + low[:20000]).lower()
    # a fake page wears the brand where people look (title, site name, logo text) and repeats it; a real site
    # that merely mentions another company once ("sign in with Amazon") is not impersonating it
    identity = (title + " " + " ".join(re.findall(r"(?:og:site_name|application-name)[^>]*content\s*=\s*['\"]"
                                                  r"([^'\"]+)", low)) + " " +
                " ".join(re.findall(r"<img[^>]+alt\s*=\s*['\"]([^'\"]+)", low)[:10])).lower()
    brand = next((b for b in BRANDS if _has_brand(b, identity) and b.replace(" ", "") not in registrable
                  and len(re.findall(r"(?<![a-z])" + re.escape(b) + r"(?![a-z])", sample)) >= 2), None)
    free_host = registrable in FREE_HOSTS or any(host.endswith("." + f) for f in FREE_HOSTS)
    name = brand.title() if brand else ""
    if has_password:
        score += 15
        reasons.append("The page asks for a password")
        if brand:
            score += 50
            reasons.append(f"Fake login page: it looks like {name} but is hosted on {registrable}")
        elif free_host:
            score += 25
            reasons.append(f"A sign-in form on a free hosting site ({registrable})")
    elif brand and LOGIN_WORDS.search(sample):
        score += 25
        reasons.append(f"Uses {name}'s name with sign-in wording on {registrable}")
    if brand and free_host:
        score += 40
        reasons.append(f"Pretends to be {name} on a free hosting site ({registrable}) where anyone can publish")
    for action in re.findall(r"<form[^>]+action\s*=\s*['\"]([^'\"]+)", html, re.I):
        target = (urlsplit(action).hostname or "").lower()
        if "api.telegram.org" in action or "discord.com/api/webhooks" in action:
            score += 60
            reasons.append("Sends what you type to a Telegram/Discord bot")
            break
        if target and registrable not in target:
            score += 25
            reasons.append(f"The form sends your details to a different site ({target})")
            break
    if re.search(r"api\.telegram\.org/bot|discord(app)?\.com/api/webhooks", low) and \
            not any("bot" in r for r in reasons):
        score += 50
        reasons.append("Page script sends data to a Telegram/Discord bot")
    if re.search(r"eval\s*\(\s*(atob|unescape|decodeuricomponent)\s*\(|document\.write\s*\(\s*unescape", low):
        score += 20
        reasons.append("Hides its code (obfuscated JavaScript)")
    if re.search(r"<meta[^>]+http-equiv\s*=\s*['\"]?refresh", low):
        score += 10
        reasons.append("Automatically forwards you to another page")
    age = domain_age_days(host) if host and not re.fullmatch(r"[\d.]+", host) else None
    if age is not None and age < 30:
        score += 30
        reasons.append(f"The domain was registered only {age} day{'s' if age != 1 else ''} ago")
    elif age is not None and age < 180:
        score += 10
        reasons.append(f"The domain is new ({age} days old)")
    return {"final_url": final, "redirects": redirected, "score": score, "reasons": reasons, "title": title,
            "age_days": age}


def check_link(text, inspect=True):
    """Web protection: threat lists and address checks, plus (optionally) a text-only look at the page itself."""
    result = check_url(text, log=False)
    result["page"] = None
    if inspect and result["verdict"] != "malicious":
        page = inspect_page(text)
        result["page"] = page
        result["reasons"] += page["reasons"]
        if page["score"] >= 100:
            result["verdict"] = "malicious"
        elif page["score"] >= 40 and result["verdict"] == "no-known-threats":
            result["verdict"] = "suspicious"
        elif page.get("error"):
            result["reasons"].append(f"Couldn't open the page to inspect it ({page['error']})")
    log_event("url", {"malicious": "bad", "suspicious": "warn"}.get(result["verdict"], "ok"),
              f"Link checked: {result['verdict']}",
              f"{text.strip()[:200]} · " + ("; ".join(result["reasons"]) or "no warning signs"))
    return result


# ---------------------------------------------------------------- download protection

PARTIAL_EXT = {".crdownload", ".part", ".partial", ".download", ".opdownload", ".tmp", ".!ut"}


def download_source(path):
    """Where a downloaded file came from, from the Mark-of-the-Web browsers attach (Zone.Identifier)."""
    try:
        with open(path + ":Zone.Identifier", encoding="utf-8", errors="replace") as f:
            text = f.read(4096)
    except OSError:
        return None
    info = dict(re.findall(r"^(\w+)=(.*)$", text, re.M))
    return {"zone": info.get("ZoneId"), "url": info.get("HostUrl", "").strip(),
            "referrer": info.get("ReferrerUrl", "").strip()}


def defender_check(path):
    """Second opinion from Microsoft Defender on one file. True = threat, False = clean, None = unavailable."""
    from core import find_mpcmdrun
    mp = find_mpcmdrun()
    if not mp:
        return None
    try:
        out = subprocess.run([mp, "-Scan", "-ScanType", "3", "-File", os.path.normpath(path), "-DisableRemediation"],
                             capture_output=True, text=True, errors="replace", creationflags=NO_WINDOW,
                             stdin=subprocess.DEVNULL, timeout=120)
    except Exception:
        return None
    text = out.stdout.lower()
    if "found no threats" in text:
        return False
    # exit code 2 also covers errors such as a bad path, so only trust it when Defender names a threat
    return True if out.returncode == 2 and "threat" in text else None


def check_download(con, path):
    """Full check of a new download: engine scan, the website it came from and (for risky types) Defender."""
    found = scan_file(con, path)
    con.commit()  # release the hash-cache write before the URL lookups below open their own connection
    found = [r for r in found if r["signature"] or not r["pe"]] + apply_signatures(
        [r for r in found if r["pe"] and not r["signature"]])
    src = download_source(path) or {}
    ext = os.path.splitext(path)[1].lower()
    extra, extra_score = [], 0
    for u in (src.get("url"), src.get("referrer")):
        if u and not u.startswith(("about:", "blob:", "data:")) and check_url(u, log=False)["verdict"] == "malicious":
            extra.append(f"Downloaded from a known malicious site ({urlsplit(u).hostname})")
            extra_score = 100
            break
    risky = ext in PROGRAM_EXT | SCRIPT_EXT | MACRO_EXT | ARCHIVE_EXT | {".iso", ".img", ".lnk", ".7z", ".rar"}
    if (risky or found) and defender_check(path):
        extra.append("Microsoft Defender also flags this file")
        extra_score = 100
    if extra:
        if found:
            found[0]["reasons"] = extra + found[0]["reasons"]
            found[0]["score"] = max(found[0]["score"], extra_score)
            if extra_score >= 100:
                found[0]["verdict"] = "Malware"
        else:
            found = [{"path": path, "name": os.path.basename(path), "sha256": "", "size": os.path.getsize(path),
                      "pe": False, "score": extra_score, "verdict": "Malware", "reasons": extra, "found": [],
                      "signature": None}]
    for r in found:
        r["source"] = src.get("url") or src.get("referrer") or ""
    return found
