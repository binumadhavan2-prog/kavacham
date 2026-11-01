"""Kavacham phone care: the connection guide, keeping the phone awake during long jobs, wireless debugging, folders
Kavacham never deletes, and the Kavacham bin.

Phones have no recycle bin, so "Delete" moves files into a hidden .KavachamBin folder on the same storage (a rename,
so it's instant and needs no free space). They can be restored from there for KEEP_DAYS days, after which Kavacham
empties them the next time the phone is connected. Layout: <storage>/.KavachamBin/<YYYYmmdd-HHMMSS>/<original path>,
so the original place is known without any separate list, on whichever PC the phone is plugged into next.

A phone is ("adb", serial) when USB debugging works, or ("mtp", device name) over the plain File transfer connection.
"""
import io
import json
import os
import re
import shutil
import tempfile
import threading
import time
import zipfile
from contextlib import contextmanager

import engine
import usb
from core import DATA_DIR, read_json, write_json
from security import _run_elevated

BIN = ".KavachamBin"
KEEP_DAYS = 7
AWAKE_FILE = os.path.join(DATA_DIR, "phone_awake.json")
USB_DRIVER = "https://dl.google.com/android/repository/usb_driver_r13-windows.zip"
DRIVER_DIR = os.path.join(usb.TOOLS_DIR, "usb_driver")

# Never deleted or moved off the phone by Kavacham, whatever is selected: chat databases and backups that apps need
# to restore your history.
PROTECTED = re.compile(r"(^|/)(WhatsApp( Business)?/(Databases|Backups)|MIUI/backup|\.KavachamBin)(/|$)", re.I)


def is_protected(path):
    return bool(PROTECTED.search(path))


# ---------------------------------------------------------------- what each phone needs next

_PS_STATUS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$sh = New-Object -ComObject Shell.Application
$phones = @($sh.Namespace(17).Items() | ? { $_.IsFolder -and -not $_.IsFileSystem } | % {
  $n = -1
  if ($env:PCG_FILES -eq '1') { $n = @($_.GetFolder.Items() | ? { $_.IsFolder }).Count }
  @{ name = [string]$_.Name; stores = $n }
})
# a debugging connection Windows has no driver for: the ADB interface class, or Google's IDs that Xiaomi and others use
$driver = @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' | ? {
  (@($_.CompatibleID) -match 'Class_ff&SubClass_42&Prot_01') -or ($_.DeviceID -match 'VID_18D1&PID_4EE[2467]')
} | % { [string]$_.Name })
ConvertTo-Json -Compress -Depth 4 -InputObject @{ phones = $phones; driver = $driver }
"""


def connection_status(check_files=True):
    """{"adb": [adb devices], "files": [names whose files are visible], "hidden": [names connected but showing no
    storage: locked or "Charging only"], "driver": [debugging connections without a driver], "tools": adb installed}.
    check_files=False skips asking the phones for their storages (while a long job is reading one)."""
    try:
        data = json.loads(usb._ps(_PS_STATUS, env={**os.environ, "PCG_FILES": "1" if check_files else "0"},
                                  timeout=45) or "{}") or {}
    except Exception:
        if check_files:  # a phone busy with another job can be too slow to answer: just list what's plugged in
            return connection_status(check_files=False)
        data = {}
    phones = data.get("phones") or []
    phones = [phones] if isinstance(phones, dict) else phones
    driver = data.get("driver") or []
    return {"adb": usb.adb_devices(), "tools": bool(usb.adb_path()),
            "files": [p["name"] for p in phones if p.get("stores", -1) != 0],
            "hidden": [p["name"] for p in phones if p.get("stores", -1) == 0],
            "driver": [driver] if isinstance(driver, str) else driver}


def is_wifi(serial):
    return ":" in serial or "_adb-tls" in serial


def install_driver(progress=lambda t: None):
    """Google's free USB driver for the debugging connection (Windows asks for admin permission). Returns True if it
    went in."""
    inf = os.path.join(DRIVER_DIR, "android_winusb.inf")
    if not os.path.exists(inf):
        progress("Downloading Google's USB driver…")
        data = engine._fetch(USB_DRIVER, timeout=180)
        shutil.rmtree(DRIVER_DIR, ignore_errors=True)  # our own earlier download
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                if name.startswith("usb_driver/") and not name.endswith("/"):
                    target = os.path.join(usb.TOOLS_DIR, *name.split("/"))
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "wb") as f:
                        f.write(z.read(name))
    progress("Installing the driver (Windows asks for permission)…")
    quoted = inf.replace("'", "''")
    # 259: added, but no device needed it right now; 3010: added, restart needed
    ok = _run_elevated(f"pnputil /add-driver '{quoted}' /install; "
                       "if ($LASTEXITCODE -in 0, 259, 3010) { exit 0 } else { exit $LASTEXITCODE }")
    engine.log_event("usb", "ok" if ok else "warn", "Android USB driver " + ("installed" if ok else "not installed"),
                     inf)
    return ok


# ---------------------------------------------------------------- Wi-Fi (wireless debugging, Android 11 and newer)

def wifi_pair(address, code):
    """Pair with the address and 6-digit code from the phone's "Pair device with pairing code" screen, then wait for
    the phone to connect. Returns (ok, message)."""
    address, code = address.strip(), re.sub(r"\D", "", code)
    if not re.fullmatch(r"[\w.\-]+:\d{2,5}", address) or len(code) != 6:
        return False, "Type the IP address & port and the 6-digit code exactly as the phone shows them."
    before = {d["serial"] for d in usb.adb_devices()}
    out = usb.adb("pair", address, code, timeout=40)
    if "Successfully paired" not in out:
        return False, ("Pairing didn't work. Keep the pairing screen open on the phone, check both are on the same "
                       "Wi-Fi, and try again.")
    engine.log_event("usb", "ok", "Phone paired for wireless debugging", address)
    host = address.rsplit(":", 1)[0]
    for _ in range(10):  # adb connects paired phones on its own once it sees them on the network
        new = [d for d in usb.adb_devices() if d["serial"] not in before or host in d["serial"]]
        if any(d["state"] == "device" for d in new):
            return True, "Connected over Wi-Fi."
        m = re.search(rf"_adb-tls-connect\._tcp\.?\s+({re.escape(host)}:\d+)", usb.adb("mdns", "services", timeout=10))
        if m and "connected to" in usb.adb("connect", m.group(1), timeout=20):
            return True, "Connected over Wi-Fi."
        time.sleep(1.5)
    return False, ("Paired, but not connected yet. Use \"Connect\" with the IP address & port shown at the top of "
                   "the phone's Wireless debugging screen.")


def wifi_connect(address):
    address = address.strip()
    if not re.fullmatch(r"[\w.\-]+:\d{2,5}", address):
        return False, "Type the IP address & port exactly as the phone shows them, e.g. 192.168.1.5:41235."
    out = usb.adb("connect", address, timeout=20)
    ok = "connected to" in out and "cannot" not in out and "failed" not in out
    return ok, "Connected over Wi-Fi." if ok else ("Couldn't connect. Pair the phone first, and check both are on "
                                                    "the same Wi-Fi.")


# ---------------------------------------------------------------- keep the phone awake during long jobs
# A locked phone stops answering half way through a scan. While a job runs, "stay awake while charging" is switched
# on; the phone's own setting is saved to a file first and put back after, or on the next connect after a crash.

_awake_lock = threading.Lock()
_awake_jobs = {}


@contextmanager
def awake(phone):
    kind, serial = phone
    if kind != "adb":
        yield  # File transfer can't change phone settings
        return
    with _awake_lock:
        _awake_jobs[serial] = _awake_jobs.get(serial, 0) + 1
        if _awake_jobs[serial] == 1:
            _stay_on(serial)
    try:
        yield
    finally:
        with _awake_lock:
            _awake_jobs[serial] -= 1
            if not _awake_jobs[serial]:
                del _awake_jobs[serial]
                _restore(serial)


def _stay_on(serial):
    try:
        saved = read_json(AWAKE_FILE, {})
        if serial not in saved:  # else a crash left it switched on: the value saved back then is the phone's own
            old = usb.adb("shell", "settings", "get", "global", "stay_on_while_plugged_in", serial=serial,
                          timeout=15).strip()
            saved[serial] = old if old.isdigit() else "0"
            write_json(AWAKE_FILE, saved)
        usb.adb("shell", "svc", "power", "stayon", "usb", serial=serial, timeout=15)
    except Exception:
        pass


def _restore(serial):
    saved = read_json(AWAKE_FILE, {})
    if serial not in saved:
        return
    try:
        usb.adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", saved[serial], serial=serial,
                timeout=15)
        now = usb.adb("shell", "settings", "get", "global", "stay_on_while_plugged_in", serial=serial,
                      timeout=15).strip()
    except Exception:
        return
    if now == saved[serial]:
        saved.pop(serial)
        write_json(AWAKE_FILE, saved)


def restore_awake(serial):
    """Put the phone's screen setting back if an earlier job couldn't (Kavacham closed mid-job)."""
    with _awake_lock:
        if serial in _awake_jobs:
            return
    _restore(serial)


# ---------------------------------------------------------------- the Kavacham bin

_ADB_ROOT = re.compile(r"^(/sdcard|/storage/emulated/\d+|/storage/(?!emulated/)[^/]+)/(.+)$")
_IN_BIN = re.compile(rf"^(.*?)/{re.escape(BIN)}/(\d{{8}}-\d{{6}})/(.+)$")


def _split(kind, path):
    """(storage root, path inside it) or None."""
    if kind == "adb":
        m = _ADB_ROOT.match(path)
        return (m.group(1), m.group(2)) if m else None
    root, _, rel = path.partition("/")
    return (root, rel) if rel else None


def _when(stamp):
    try:
        return time.mktime(time.strptime(stamp, "%Y%m%d-%H%M%S"))
    except ValueError:
        return 0


def _alt_name(path):
    stem, ext = os.path.splitext(path)
    return f"{stem} (restored){ext}"


def to_bin(phone, paths):
    """Move phone files into the bin. Returns the set of paths moved (protected ones never are)."""
    kind, ident = phone
    stamp = time.strftime("%Y%m%d-%H%M%S")
    jobs = []
    for p in paths:
        parts = _split(kind, p)
        if parts and not is_protected(p):
            jobs.append((p, f"{parts[0]}/{BIN}/{stamp}/{parts[1]}"))
    moved = _adb_moves(ident, jobs, mark="MOVED") if kind == "adb" else _mtp_moves(ident, jobs)
    total = len(moved)
    engine.log_event("usb", "ok" if total == len(paths) else "warn", f"{total} file(s) moved to the Kavacham bin",
                     f"{ident} · " + ", ".join(os.path.basename(p) for p in list(moved)[:20]))
    return moved


def bin_items(phone):
    """Everything in the bin: [{"path", "original", "size", "when", "stamp"}], newest first."""
    kind, ident = phone
    rows = _adb_bin_files(ident) if kind == "adb" else _mtp_bin_files(ident)
    items = []
    for size, path in rows:
        m = _IN_BIN.match(path)
        if m:
            items.append({"path": path, "original": f"{m.group(1)}/{m.group(3)}", "size": size,
                          "when": _when(m.group(2)), "stamp": m.group(2)})
    items.sort(key=lambda i: (-i["when"], i["original"]))
    return items


def restore(phone, items):
    """Put bin items back where they were (as "name (restored)" if that name is taken). Returns bin paths restored."""
    kind, ident = phone
    jobs = [(i["path"], i["original"]) for i in items]
    done = _adb_moves(ident, jobs, mark="BACK", keep_existing=True) if kind == "adb" else \
        _mtp_moves(ident, jobs, keep_existing=True)
    engine.log_event("usb", "ok", f"{len(done)} file(s) restored from the Kavacham bin", ident)
    _tidy(phone, items)
    return done


def empty(phone, items):
    """Delete bin items for good. Whole deletions (a stamp folder with everything selected) go in one step.
    Returns the bin paths that are gone."""
    kind, ident = phone
    if not items:
        return set()
    every = {}
    for i in bin_items(phone):
        every.setdefault(_stamp_dir(i["path"]), set()).add(i["path"])
    chosen = {}
    for i in items:
        chosen.setdefault(_stamp_dir(i["path"]), set()).add(i["path"])
    targets, covered = [], {}
    for folder, paths in chosen.items():
        if paths >= every.get(folder, set()):
            targets.append(folder)
            covered[folder] = paths
        else:
            targets += sorted(paths)
    if kind == "adb":
        gone_targets = {t for t in targets if _adb_rm(ident, t)}
    else:
        # Deleting a whole folder fails or hangs the link on some phones (a Redmi), so go file by file
        targets, covered = sorted(i["path"] for i in items), {}
        gone_targets = usb.delete_many_from_phone(ident, targets)
    gone = set()
    for t in gone_targets:
        gone |= covered.get(t, {t})
    freed = sum(i["size"] for i in items if i["path"] in gone)
    engine.log_event("usb", "ok", f"Kavacham bin emptied: {len(gone)} file(s)", f"{ident} · {freed:,} bytes freed")
    return gone


def purge(phone):
    """Empty what's been in the bin longer than KEEP_DAYS. Returns (files, bytes)."""
    old = [i for i in bin_items(phone) if i["when"] and time.time() - i["when"] > KEEP_DAYS * 86400]
    gone = empty(phone, old) if old else set()
    return len(gone), sum(i["size"] for i in old if i["path"] in gone)


def _stamp_dir(path):
    m = _IN_BIN.match(path)
    return f"{m.group(1)}/{BIN}/{m.group(2)}" if m else path


def _tidy(phone, items):
    """After a restore or delete: remove stamp folders that are now empty (over USB debugging only)."""
    kind, ident = phone
    if kind == "adb":
        roots = {_IN_BIN.match(i["path"]).group(1) for i in items if _IN_BIN.match(i["path"])}
        for r in roots:
            usb.adb("shell", f"find {usb._sh_quote(r + '/' + BIN)} -mindepth 1 -type d -empty -delete 2>/dev/null",
                    serial=ident, timeout=60)
        return
    # Over File transfer, empty folders stay: they take no space, are hidden, and deleting a folder can hang the
    # phone's link (seen on a Redmi).


# over USB debugging

def _adb_moves(serial, jobs, mark, keep_existing=False):
    """mv each (source, target) on the phone, creating folders. keep_existing: if target exists, use
    "name (restored)". Returns the sources moved."""
    moved = set()
    roots = {_IN_BIN.match(t).group(1) if _IN_BIN.match(t) else None for _s, t in jobs}
    for r in roots - {None}:
        usb.adb("shell", f"mkdir -p {usb._sh_quote(r + '/' + BIN)} && touch {usb._sh_quote(r + '/' + BIN + '/.nomedia')}",
                serial=serial, timeout=30)  # .nomedia: the gallery doesn't show binned photos
    for start in range(0, len(jobs), 40):
        cmds = []
        for src, dst in jobs[start:start + 40]:
            q, qd = usb._sh_quote(src), usb._sh_quote(dst)
            pick = f'd={qd}; [ -e "$d" ] && d={usb._sh_quote(_alt_name(dst))}; ' if keep_existing else f"d={qd}; "
            cmds.append(f'{pick}[ ! -e "$d" ] && mkdir -p "$(dirname "$d")" && mv {q} "$d" && [ ! -e {q} ] && '
                        f"echo {usb._sh_quote(mark + ' ' + src)}")
        out = usb.adb("shell", "; ".join(cmds), serial=serial, timeout=600)
        moved |= {line[len(mark) + 1:] for line in out.splitlines() if line.startswith(mark + " ")}
    return moved


def _adb_bin_files(serial):
    cmds = []
    for r in usb.storage_roots(serial):
        b = usb._sh_quote(r.rstrip("/") + "/" + BIN)
        cmds.append(f"[ -d {b} ] && find {b} -type f ! -name .nomedia -exec stat -c '%s|%n' {{}} + 2>/dev/null")
    out = usb.adb("shell", "; ".join(cmds) + "; true", serial=serial, timeout=300)
    rows = []
    for line in out.splitlines():
        size, _, path = line.partition("|")
        if size.isdigit():
            rows.append((int(size), path))
    return rows


def _adb_rm(serial, path):
    if f"/{BIN}/" not in path:
        return False  # only ever inside the bin
    q = usb._sh_quote(path)
    return "gone" in usb.adb("shell", f"rm -rf {q}; [ -e {q} ] || echo gone", serial=serial, timeout=600)


# over File transfer

_PS_ENSURE = r"""
function Ensure-Folder($path) {
  $cur = $dev
  foreach ($seg in ($path -split '/')) {
    $next = @($cur.GetFolder.Items() | ? { $_.IsFolder -and ($_.Name -eq $seg -or (Real-Name $_) -eq $seg) })[0]
    if (-not $next) {
      if ($fileop) { try { [PcgFileOp]::NewFolder($cur, $seg) } catch {} } else { $cur.GetFolder.NewFolder($seg) }
      $next = @($cur.GetFolder.Items() | ? { $_.IsFolder -and $_.Name -eq $seg })[0]
    }
    if (-not $next) { return $null }
    $cur = $next
  }
  return $cur
}
"""


def _mtp_moves(device, jobs, keep_existing=False):
    if not jobs:
        return set()
    usb.phone_storages(device)  # a locked phone hides its files: say so rather than move nothing
    listing = os.path.join(tempfile.gettempdir(), f"kavacham-bin-{os.getpid()}.json")
    with open(listing, "w", encoding="utf-8") as f:
        json.dump([{"src": s, "dst": d, "alt": _alt_name(d)} for s, d in jobs], f)
    script = usb._PS_FIND + usb._PS_FILEOP + _PS_ENSURE + r"""
$keep = $env:PCG_KEEP -eq '1'
$done = New-Object System.Collections.ArrayList
foreach ($j in (Get-Content -Raw -Encoding UTF8 $env:PCG_LIST | ConvertFrom-Json)) {
  $it = Find-Item $j.src
  if (-not $it) { continue }
  $target = $j.dst
  if (Find-Item $target) { if ($keep) { $target = $j.alt } else { continue } }
  if (Find-Item $target) { continue }
  $parts = $target -split '/'
  $dest = Ensure-Folder (($parts[0..($parts.Count - 2)]) -join '/')
  if (-not $dest) { continue }
  $name = $parts[-1]
  $src = $j.src
  if ($name -ne (Real-Name $it)) {
    # rename where it is first, so the move never meets a file of the same name. Setting Name follows Explorer's
    # "hide extensions" too: when it's hidden, Windows adds the extension back itself.
    $srcParts = $src -split '/'
    $renamed = ($srcParts[0..($srcParts.Count - 2)] + $name) -join '/'
    if (Find-Item $renamed) { continue }
    $it.Name = if ($it.Name -ne (Real-Name $it)) { [IO.Path]::GetFileNameWithoutExtension($name) } else { $name }
    for ($i = 0; $i -lt 20 -and -not (Find-Item $renamed); $i++) { Start-Sleep -Milliseconds 250 }
    $it = Find-Item $renamed
    if (-not $it) { continue }
    $src = $renamed
  }
  # IFileOperation quietly aborts phone-to-phone moves (seen on a Redmi), so use the Explorer-style move and wait
  # until it has finished: the copy shows up first, the original goes after.
  $dest.GetFolder.MoveHere($it, 0x614)
  for ($i = 0; $i -lt 240; $i++) {
    if ((Find-Item $target) -and -not (Find-Item $src)) { break }
    Start-Sleep -Milliseconds 250
  }
  if (-not (Find-Item $src) -and (Find-Item $target)) { [void]$done.Add($j.src) }
}
ConvertTo-Json -Compress -InputObject @($done)
"""
    try:
        out = usb._ps(script, env={**os.environ, "PCG_DEVICE": device, "PCG_LIST": listing,
                                   "PCG_KEEP": "1" if keep_existing else "0"}, timeout=120 + 60 * len(jobs)).strip()
    finally:
        os.remove(listing)
    done = json.loads(out or "[]") or []
    return {done} if isinstance(done, str) else set(done)


def _mtp_bin_files(device):
    usb.phone_storages(device)  # else a locked phone would look like an empty bin
    script = usb._PS_FIND + r"""
function Walk($folder, $p) {
  foreach ($it in $folder.GetFolder.Items()) {
    $q = "$p/$(Real-Name $it)"
    if ($it.IsFolder) { Walk $it $q }
    elseif ((Real-Name $it) -ne '.nomedia') {
      $size = [int64]$it.ExtendedProperty('System.Size'); if (-not $size) { $size = [int64]$it.Size }
      "$size`t$q"
    }
  }
}
foreach ($s in @($dev.GetFolder.Items() | ? { $_.IsFolder })) {
  $b = Find-Item ".KavachamBin" $s
  if ($b) { Walk $b "$($s.Name)/.KavachamBin" }
}
"""
    rows = []
    for line in usb._ps(script, env={**os.environ, "PCG_DEVICE": device}, timeout=600).splitlines():
        size, _, path = line.partition("\t")
        if size.isdigit():
            rows.append((int(size), path))
    return rows


# ---------------------------------------------------------------- look at a file before deciding

PREVIEW_DIR = os.path.join(tempfile.gettempdir(), "kavacham-preview")


def preview(phone, path):
    """Copy one phone file to a temporary folder on this PC and return its local path (None if it couldn't)."""
    kind, ident = phone
    shutil.rmtree(PREVIEW_DIR, ignore_errors=True)  # the previous preview, our own folder
    os.makedirs(PREVIEW_DIR, exist_ok=True)
    if kind == "adb":
        local = os.path.join(PREVIEW_DIR, os.path.basename(path))
        usb.adb("pull", path, local, serial=ident, timeout=600)
        return local if os.path.exists(local) else None
    mapping = usb.copy_from_phone(ident, [path], PREVIEW_DIR)
    return next(iter(mapping), None)


PICTURES = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}
THUMB_LIMIT = 40 * 1024 * 1024  # bigger "pictures" aren't worth copying just for a preview


def thumbnail(phone, path, size, box):
    """A PIL image of a phone picture fitting box (width, height), or None for other files. The copy it's made from
    is deleted at once."""
    if os.path.splitext(path)[1].lower() not in PICTURES or not 0 < size <= THUMB_LIMIT:
        return None
    from PIL import Image, ImageOps
    kind, ident = phone
    folder = tempfile.mkdtemp(prefix="kavacham-thumb-")
    try:
        if kind == "adb":
            local = os.path.join(folder, os.path.basename(path))
            usb.adb("pull", path, local, serial=ident, timeout=120)
        else:
            local = next(iter(usb.copy_from_phone(ident, [path], folder)), None)
        if not local or not os.path.exists(local):
            return None
        with Image.open(local) as im:
            im = ImageOps.exif_transpose(im)  # phone photos are often stored sideways with a "rotate" note
            im.thumbnail(box)
            return im.convert("RGB")
    except Exception:
        return None
    finally:
        shutil.rmtree(folder, ignore_errors=True)  # our own temporary copy
