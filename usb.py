"""Kavacham USB protection: pendrives, USB disks and Android phones plugged into this PC.

Drives get the engine scan, a Defender scan and USB-specific checks (autorun tricks, the "shortcut virus" that hides
your folders behind fake shortcuts). Phones are checked two ways:
- files over the normal USB file connection (MTP): risky files are copied to a temporary folder and scanned there
- installed apps over ADB, when USB debugging is on: hashes, known stalkerware, and risky access such as
  accessibility control or device admin by apps that didn't come from an app store
"""
import ctypes
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import date

import engine
from core import DATA_DIR, NO_WINDOW, load_settings, notify, run_ps

TOOLS_DIR = os.path.join(DATA_DIR, "tools")
ADB_LOCAL = os.path.join(TOOLS_DIR, "platform-tools", "adb.exe")
PLATFORM_TOOLS = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"

HIDDEN, SYSTEM = 0x2, 0x4
SYSTEM_DIRS = {"system volume information", "$recycle.bin", "recycler", "$windows.~bt", "found.000"}
PHONE_EXT = {".apk", ".xapk", ".apks", ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".jar", ".hta", ".lnk",
             ".zip", ".rar", ".7z", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".pdf", ".iso"}
# where downloaded and shared files land on Android (paths inside a storage, lower case)
PHONE_FOCUS = ["download", "documents", "bluetooth", "whatsapp", "telegram", "android/media/com.whatsapp",
               "android/media/org.telegram.messenger", "android/media/com.whatsapp.w4b", "shareit", "xender"]
STORES = {"com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket", "com.xiaomi.market",
          "com.xiaomi.mipicks", "com.oppo.market", "com.heytap.market", "com.vivo.appstore", "com.amazon.venezia",
          "com.google.android.packageinstaller.store"}
DANGEROUS_PERMS = {
    "android.permission.READ_SMS": "read your text messages (including bank codes)",
    "android.permission.RECEIVE_SMS": "intercept incoming text messages",
    "android.permission.SEND_SMS": "send text messages",
    "android.permission.READ_CALL_LOG": "read your call history",
    "android.permission.RECORD_AUDIO": "record audio",
    "android.permission.ACCESS_FINE_LOCATION": "track your exact location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "track your location in the background",
    "android.permission.READ_CONTACTS": "read your contacts",
    "android.permission.CAMERA": "use the camera",
}


# ---------------------------------------------------------------- drives

def _drive_mask():
    return ctypes.windll.kernel32.GetLogicalDrives()


def _volume_label(root):
    buf = ctypes.create_unicode_buffer(261)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(root, buf, 261, None, None, None, None, 0)
    return buf.value if ok else ""


_usb_fixed_cache = {}


def usb_drives():
    """Pendrives and USB disks: [{"root", "label", "size", "free"}]. USB hard disks report as fixed, so their bus
    type is looked up once per set of drive letters."""
    mask = _drive_mask()
    if mask not in _usb_fixed_cache:
        try:
            out = run_ps("@(Get-Partition | ? { $_.DriveLetter -and (Get-Disk -Number $_.DiskNumber).BusType -eq "
                         "'USB' } | % { [string]$_.DriveLetter }) -join ','", timeout=30).stdout.strip()
        except Exception:
            out = ""
        _usb_fixed_cache.clear()
        _usb_fixed_cache[mask] = {f"{c}:\\" for c in out.split(",") if c}
    usb_fixed = _usb_fixed_cache[mask]
    drives = []
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = f"{chr(65 + i)}:\\"
        kind = ctypes.windll.kernel32.GetDriveTypeW(root)
        if kind == 2 or (kind == 3 and root in usb_fixed):
            try:
                du = shutil.disk_usage(root)
            except OSError:
                continue  # card reader with no card
            drives.append({"root": root, "label": _volume_label(root) or "USB drive", "size": du.total,
                           "free": du.free})
    return drives


def _attrs(path):
    a = ctypes.windll.kernel32.GetFileAttributesW(path)
    return 0 if a == 0xFFFFFFFF else a


def _result(path, name, verdict, score, reasons, fix=None, **extra):
    r = {"path": path, "name": name, "sha256": "", "size": 0, "pe": False, "score": score, "verdict": verdict,
         "reasons": reasons, "found": [], "signature": None, "fix": fix}
    r.update(extra)
    return r


def drive_checks(root):
    """USB-specific tricks in the drive's top folder."""
    out = []
    try:
        entries = os.listdir(root)
    except OSError:
        return out
    hidden_dirs = []
    for name in entries:
        p = os.path.join(root, name)
        a = _attrs(p)
        low = name.lower()
        if low in SYSTEM_DIRS:
            continue
        if low == "autorun.inf" and os.path.isfile(p):
            try:
                text = open(p, encoding="latin-1").read(20000)
            except OSError:
                text = ""
            cmds = re.findall(r"^\s*(?:open|shellexecute|shell\\[^\\]+\\command)\s*=\s*(.+)$", text, re.I | re.M)
            if cmds:
                out.append(_result(p, name, "Suspicious", 80, [f"Autorun file tries to start '{cmds[0].strip()[:60]}' "
                                                              "when the drive is opened (classic USB worm)"],
                                   fix="quarantine"))
            continue
        if os.path.isdir(p) and a & HIDDEN:
            hidden_dirs.append(low)
            if name.strip(" \u00a0_") == "" or a & SYSTEM:
                shown = name if name.strip(" \u00a0_") else "(folder with a blank name)"
                out.append(_result(p, shown, "Worth a look", 45,
                                   ["Folder hidden as a system item (the shortcut virus hides your files like this)"],
                                   fix="unhide"))
        ext = os.path.splitext(low)[1]
        if os.path.isfile(p) and a & HIDDEN and (ext in engine.PROGRAM_EXT or ext in engine.SCRIPT_EXT):
            out.append(_result(p, name, "Suspicious", 75, ["Hidden program or script in the top of the drive"],
                               fix="quarantine"))
    for name in entries:
        p = os.path.join(root, name)
        stem, ext = os.path.splitext(name)
        if ext.lower() != ".lnk" or not os.path.isfile(p):
            continue
        try:
            data = open(p, "rb").read(16384)
        except OSError:
            continue
        text = data.decode("utf-16-le", "ignore") + data.decode("latin-1")
        runs_tool = engine.LNK_TOOL.search(text)
        if runs_tool or stem.lower() in hidden_dirs or stem.lower().rstrip() in hidden_dirs:
            why = ["Shortcut virus: a fake shortcut " + ("that starts " + runs_tool.group(0) if runs_tool else
                                                         "in place of a folder it hid")]
            out.append(_result(p, name, "Suspicious", 85, why, fix="quarantine"))
    return out


def repair_drive(root):
    """Undo shortcut-virus damage: quarantine its shortcuts/autorun/scripts and unhide the real files."""
    fixed, unhidden = [], 0
    for r in drive_checks(root):
        if r["fix"] == "quarantine" and engine.quarantine(r["path"], "USB repair: " + r["reasons"][0]):
            fixed.append(r["name"])
    for name in os.listdir(root):
        p = os.path.join(root, name)
        a = _attrs(p)
        if name.lower() in SYSTEM_DIRS or not a & (HIDDEN | SYSTEM):
            continue
        if ctypes.windll.kernel32.SetFileAttributesW(p, a & ~(HIDDEN | SYSTEM)):
            unhidden += 1
    engine.log_event("usb", "ok", f"Repaired USB drive {root[:2]}",
                     f"{len(fixed)} item(s) quarantined, {unhidden} item(s) unhidden")
    return fixed, unhidden


def defender_scan(path):
    """Defender scan of a drive or folder. Returns [(threat name, file)] (empty when clean), or None."""
    from core import find_mpcmdrun
    mp = find_mpcmdrun()
    if not mp:
        return None
    try:
        out = subprocess.run([mp, "-Scan", "-ScanType", "3", "-File", os.path.normpath(path), "-DisableRemediation"],
                             capture_output=True, text=True, errors="replace", creationflags=NO_WINDOW,
                             stdin=subprocess.DEVNULL, timeout=3600).stdout
    except Exception:
        return None
    threats, current = [], None
    for line in out.splitlines():
        m = re.match(r"\s*Threat\s*:\s*(.+)", line)
        if m:
            current = m.group(1).strip()
        m = re.match(r"\s*file\s*:\s*(.+)", line, re.I)
        if m and current:
            threats.append((current, m.group(1).strip()))
    return threats


def scan_drive(root, progress=lambda *a: None, cancelled=lambda: False, auto_quarantine=True):
    """Everything for one drive: engine (all files), USB tricks, Defender. Known malware is quarantined."""
    label = f"USB drive {root[:2]}"
    engine.log_event("usb", "info", f"{label} scan started", _volume_label(root))
    hits, n, secs = engine.scan([root], progress, cancelled)
    hits += drive_checks(root)
    if not cancelled():
        progress(n, "Microsoft Defender is checking the drive…", len(hits))
        for threat, path in defender_scan(root) or []:
            match = next((h for h in hits if os.path.normcase(h["path"]) == os.path.normcase(path)), None)
            if match:
                match["reasons"].insert(0, f"Microsoft Defender: {threat}")
                match["verdict"], match["score"] = "Malware", 100
            else:
                hits.append(_result(path, os.path.basename(path), "Malware", 100, [f"Microsoft Defender: {threat}"],
                                    fix="quarantine"))
    for h in hits:
        h["device"] = label
        engine.log_event("detection", "bad" if h["verdict"] != "Worth a look" else "warn",
                         f"USB: {h['verdict']} - {h['name']}", f"{h['path']} · " + "; ".join(h["reasons"]))
        if auto_quarantine and h["verdict"] == "Malware" and os.path.isfile(h["path"]):
            if engine.quarantine(h["path"], "; ".join(h["reasons"]), h["sha256"]):
                h["action"] = "Quarantined"
    malware = sum(1 for h in hits if h["verdict"] == "Malware")
    engine.log_event("usb", "bad" if malware else "warn" if hits else "ok", f"{label} scan finished",
                     f"{n:,} files in {int(secs)} s · {malware} malware, {len(hits) - malware} other findings")
    return hits, n, secs


# ---------------------------------------------------------------- Android phones over the file connection (MTP)

_PS_FIND = r"""
$ErrorActionPreference = 'SilentlyContinue'
$sh = New-Object -ComObject Shell.Application
$dev = @($sh.Namespace(17).Items() | ? { $_.IsFolder -and -not $_.IsFileSystem -and $_.Name -eq $env:PCG_DEVICE })[0]
function Find-Item($path) {
  $cur = $dev
  foreach ($seg in ($path -split '/')) {
    $cur = @($cur.GetFolder.Items() | ? { $_.Name -eq $seg })[0]
    if (-not $cur) { return $null }
  }
  return $cur
}
"""


def phones():
    """Phones and other portable devices showing up in This PC (no setup needed): [names]."""
    script = ("$sh = New-Object -ComObject Shell.Application; $r = @($sh.Namespace(17).Items() | "
              "? { $_.IsFolder -and -not $_.IsFileSystem } | % { [string]$_.Name }); ConvertTo-Json -InputObject $r "
              "-Compress")
    try:
        return json.loads(run_ps(script, timeout=30).stdout or "[]") or []
    except Exception:
        return []


def phone_files(device):
    """Risky files in the places downloads and shared files land: [{"Path", "Size"}]."""
    script = _PS_FIND + r"""
$exts = $env:PCG_EXTS -split ','
$focus = $env:PCG_FOCUS -split '\|'
$found = New-Object System.Collections.ArrayList
function Walk($item, $rel, $prefix) {
  foreach ($it in $item.GetFolder.Items()) {
    $p = if ($rel) { "$rel/$($it.Name)" } else { $it.Name }
    $low = $p.ToLower()
    if ($it.IsFolder) {
      if (@($focus | ? { $low.StartsWith($_) -or $_.StartsWith($low + '/') }).Count) { Walk $it $p $prefix }
    } elseif ($exts -contains [IO.Path]::GetExtension($it.Name).ToLower()) {
      [void]$found.Add([pscustomobject]@{Path="$prefix/$p"; Size=[int64]$it.Size})
    }
  }
}
if ($dev) { foreach ($store in $dev.GetFolder.Items()) { if ($store.IsFolder) { Walk $store '' $store.Name } } }
ConvertTo-Json -InputObject @($found) -Compress
"""
    env = {**os.environ, "PCG_DEVICE": device, "PCG_EXTS": ",".join(sorted(PHONE_EXT)), "PCG_FOCUS": "|".join(PHONE_FOCUS)}
    out = run_ps(script, env=env, timeout=900)
    return json.loads(out.stdout or "[]") or []


def copy_from_phone(device, paths, dest):
    """Copy phone files into dest (one subfolder each, so equal names don't collide). Returns {local: phone path}."""
    listing = os.path.join(dest, "_list.json")
    with open(listing, "w", encoding="utf-8") as f:
        json.dump(paths, f)
    script = _PS_FIND + r"""
$paths = Get-Content -Raw -Encoding UTF8 $env:PCG_LIST | ConvertFrom-Json
$map = @{}
$i = 0
foreach ($p in $paths) {
  $i++
  $it = Find-Item $p
  if (-not $it) { continue }
  $dir = Join-Path $env:PCG_DEST $i
  New-Item -ItemType Directory -Force $dir | Out-Null
  $sh.Namespace($dir).CopyHere($it, 0x614)
  $target = Join-Path $dir $it.Name
  $t0 = Get-Date; $last = -1
  while (((Get-Date) - $t0).TotalSeconds -lt 180) {
    Start-Sleep -Milliseconds 400
    if (Test-Path -LiteralPath $target) {
      $len = (Get-Item -LiteralPath $target).Length
      if ($len -gt 0 -and $len -eq $last) { break }
      $last = $len
    }
  }
  if (Test-Path -LiteralPath $target) { $map[$target] = $p }
}
$map | ConvertTo-Json -Compress
"""
    env = {**os.environ, "PCG_DEVICE": device, "PCG_LIST": listing, "PCG_DEST": dest}
    out = run_ps(script, env=env, timeout=3600)
    return json.loads(out.stdout or "{}") or {}


def delete_from_phone(device, path):
    """Delete one file on the phone. Windows may ask for confirmation. Returns True when it's gone."""
    script = _PS_FIND + r"""
$it = Find-Item $env:PCG_PATH
if (-not $it) { 'not-found'; exit }
$it.InvokeVerb('delete'); Start-Sleep 2
if (Find-Item $env:PCG_PATH) { 'still-there' } else { 'deleted' }
"""
    out = run_ps(script, env={**os.environ, "PCG_DEVICE": device, "PCG_PATH": path}, timeout=120)
    ok = "deleted" in out.stdout
    engine.log_event("usb", "ok" if ok else "warn", f"{'Deleted' if ok else 'Could not delete'} on phone: "
                                                     f"{os.path.basename(path)}", f"{device} · {path}")
    return ok


def scan_phone_files(device, progress=lambda *a: None, cancelled=lambda: False):
    """Find risky files on the phone, copy them to a temporary folder, scan them there."""
    engine.log_event("usb", "info", f"Phone files scan started: {device}")
    progress(0, "Looking for downloaded and shared files on the phone…", 0)
    items = [i for i in phone_files(device) if (i.get("Size") or 0) <= engine.MAX_HASH]
    if cancelled() or not items:
        engine.log_event("usb", "ok", f"Phone files scan finished: {device}", f"{len(items)} risky-type files")
        return [], len(items)
    hits = []
    staging = tempfile.mkdtemp(prefix="pcguard-phone-")
    try:
        for start in range(0, len(items), 25):
            if cancelled():
                break
            batch = items[start:start + 25]
            progress(start, f"Copying files from the phone ({start + len(batch)}/{len(items)})…", len(hits))
            mapping = copy_from_phone(device, [i["Path"] for i in batch], staging)
            with engine.db() as con:
                for local, phone_path in mapping.items():
                    found = engine.scan_file(con, local)  # includes the APK permission checks
                    for r in found:
                        r.update(device=device, phone_path=phone_path, path=phone_path, fix="phone_delete",
                                 name=os.path.basename(phone_path) if "›" not in r["name"] else r["name"])
                        hits.append(r)
        for threat, local in defender_scan(staging) or []:
            hits.append(_result(local, os.path.basename(local), "Malware", 100, [f"Microsoft Defender: {threat}"],
                                fix="phone_delete", device=device))
    finally:
        shutil.rmtree(staging, ignore_errors=True)  # our own temporary copies
    for h in hits:
        engine.log_event("detection", "bad" if h["verdict"] != "Worth a look" else "warn",
                         f"Phone: {h['verdict']} - {h['name']}", f"{device} · {h['path']} · " + "; ".join(h["reasons"]))
    engine.log_event("usb", "bad" if hits else "ok", f"Phone files scan finished: {device}",
                     f"{len(items)} risky-type files checked · {len(hits)} findings")
    return hits, len(items)


# ---------------------------------------------------------------- Android phones over ADB (USB debugging)

def adb_path():
    if os.path.exists(ADB_LOCAL):
        return ADB_LOCAL
    return shutil.which("adb")


def setup_adb(progress=lambda t: None):
    """Download Google's Android platform tools (free, ~7 MB) and keep only adb."""
    progress("Downloading Android tools from Google…")
    data = engine._fetch(PLATFORM_TOOLS, timeout=180)
    os.makedirs(TOOLS_DIR, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            if os.path.basename(name).lower() in ("adb.exe", "adbwinapi.dll", "adbwinusbapi.dll"):
                z.extract(name, TOOLS_DIR)
    engine.log_event("usb", "ok", "Android tools installed", ADB_LOCAL)
    return adb_path()


def adb(*args, serial=None, timeout=60):
    exe = adb_path()
    if not exe:
        raise RuntimeError("Android tools aren't installed")
    cmd = [exe] + (["-s", serial] if serial else []) + list(args)
    out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", creationflags=NO_WINDOW,
                         stdin=subprocess.DEVNULL, timeout=timeout)
    return out.stdout


def adb_devices():
    """[{"serial", "state", "model"}]; state is device, unauthorized (accept the prompt on the phone) or offline."""
    if not adb_path():
        return []
    try:
        out = adb("devices", "-l", timeout=20)
    except Exception:
        return []
    devs = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            model = next((p.split(":", 1)[1] for p in parts if p.startswith("model:")), "")
            devs.append({"serial": parts[0], "state": parts[1], "model": model.replace("_", " ")})
    return devs


def phone_info(serial):
    props = {}
    for key in ("ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
                "ro.build.version.security_patch"):
        props[key] = adb("shell", "getprop", key, serial=serial).strip()
    return {"maker": props["ro.product.manufacturer"].title(), "model": props["ro.product.model"],
            "android": props["ro.build.version.release"], "patch": props["ro.build.version.security_patch"]}


def _setting(serial, key):
    v = adb("shell", "settings", "get", "secure", key, serial=serial).strip()
    return "" if v == "null" else v


def installed_apps(serial):
    """User-installed apps: [{"package", "apk", "installer"}]."""
    out = adb("shell", "pm", "list", "packages", "-3", "-f", "-i", serial=serial, timeout=120)
    apps = []
    for line in out.splitlines():
        m = re.match(r"package:(.+?\.apk)=(\S+)(?:\s+installer=(\S+))?", line.strip())
        if m:
            apps.append({"apk": m.group(1), "package": m.group(2),
                         "installer": None if m.group(3) in (None, "null") else m.group(3)})
    return apps


def phone_security(info):
    """Advice rows about the phone itself."""
    out = []
    try:
        patch = date.fromisoformat(info["patch"])
        days = (date.today() - patch).days
        if days > 180:
            out.append(_result("", "Security updates", "Worth a look", 50,
                               [f"Last security patch is from {info['patch']} ({days // 30} months ago). Check "
                                "Settings → System → Software update."], kind="advice"))
    except (ValueError, KeyError):
        pass
    try:
        if int(info["android"].split(".")[0]) < 10:
            out.append(_result("", "Android version", "Worth a look", 45,
                               [f"Android {info['android']} no longer gets security fixes."], kind="advice"))
    except (ValueError, KeyError):
        pass
    out.append(_result("", "USB debugging", "Info", 0, ["Turn USB debugging off again when you're done: Settings → "
                                                         "Developer options → USB debugging."], kind="advice"))
    return out


def check_apps(serial, progress=lambda *a: None, cancelled=lambda: False):
    """Installed-app check. Hashes are computed on the phone (nothing is copied off it)."""
    info = phone_info(serial)
    name = f"{info['maker']} {info['model']}".strip()
    engine.log_event("usb", "info", f"App check started: {name}", f"Android {info['android']}, patch {info['patch']}")
    apps = installed_apps(serial)
    access = _setting(serial, "enabled_accessibility_services")
    listeners = _setting(serial, "enabled_notification_listeners")
    admins = adb("shell", "dumpsys", "device_policy", serial=serial, timeout=60)
    launchable = adb("shell", "cmd", "package", "query-activities", "--brief", "-a", "android.intent.action.MAIN",
                     "-c", "android.intent.category.LAUNCHER", serial=serial, timeout=60)
    with engine.db() as con:
        stalker = dict(con.execute("SELECT package, source FROM packages").fetchall())
    hits = []
    for i, app in enumerate(apps):
        if cancelled():
            break
        pkg = app["package"]
        progress(i, f"Checking {pkg}…", len(hits))
        digest = adb("shell", "sha256sum", app["apk"], serial=serial).split(" ")[0].strip()
        reasons, score, source = [], 0, None
        if re.fullmatch(r"[0-9a-f]{64}", digest):
            with engine.db() as con:
                source = engine.lookup_hash(con, digest)
                if con.execute("SELECT 1 FROM ignored WHERE sha256=?", (digest,)).fetchone():
                    continue
        if source:
            reasons.append(f"Matches known malware ({source})")
        if pkg in stalker:
            source = source or stalker[pkg]
            reasons.append(f"Known stalkerware / spy app ({stalker[pkg]})")
        store = app["installer"] in STORES
        weight = 0.5 if store else 1.0  # store apps are reviewed; the same access from a sideloaded app is riskier
        if pkg in access:
            score += 45 * weight
            reasons.append("Has accessibility access: can read your screen and tap for you")
        if re.search(r"admin=ComponentInfo\{" + re.escape(pkg) + "/", admins) or f"{pkg}/" in admins:
            score += 35 * weight
            reasons.append("Is an active device administrator (hard to uninstall)")
        if pkg in listeners:
            score += 20 * weight
            reasons.append("Can read all your notifications")
        if launchable and f"{pkg}/" not in launchable:
            score += 30 * weight
            reasons.append("Has no app icon (stays hidden from you)")
        if score and not store:
            score += 15
            reasons.append(f"Installed from outside an app store ({app['installer'] or 'sideloaded'})")
        if score >= 40:  # only then is it worth asking which sensitive permissions it holds
            dump = adb("shell", "dumpsys", "package", pkg, serial=serial, timeout=60)
            granted = [what for perm, what in DANGEROUS_PERMS.items() if re.search(re.escape(perm) + r": granted=true",
                                                                                   dump)]
            if granted:
                score += 5 * len(granted)
                reasons.append("Allowed to " + ", ".join(granted[:5]))
        score = 100 if source else min(100, int(score))
        verdict = engine.verdict_of(score, source)
        if verdict:
            hits.append(_result(app["apk"], pkg, verdict, score, reasons, fix="uninstall", sha256=digest,
                                device=name, serial=serial, package=pkg, installer=app["installer"],
                                signature=source))
    hits += phone_security(info)
    for h in hits:
        if h.get("kind") != "advice":
            engine.log_event("detection", "bad" if h["verdict"] != "Worth a look" else "warn",
                             f"Phone app: {h['verdict']} - {h['name']}", f"{name} · " + "; ".join(h["reasons"]))
    flagged = sum(1 for h in hits if h.get("kind") != "advice")
    engine.log_event("usb", "bad" if flagged else "ok", f"App check finished: {name}",
                     f"{len(apps)} apps checked · {flagged} flagged")
    return hits, len(apps), info


def _sh_quote(path):
    """Quote a path for the phone's shell."""
    return "'" + path.replace("'", "'\\''") + "'"


def storage_roots(serial):
    """Internal shared storage plus any SD cards / USB sticks attached to the phone."""
    roots = ["/sdcard/"]
    for vol in adb("shell", "ls", "/storage", serial=serial).split():
        if vol not in ("emulated", "self") and re.fullmatch(r"[\w-]+", vol):
            roots.append(f"/storage/{vol}/")
    return roots


def deep_scan_storage(serial, progress=lambda *a: None, cancelled=lambda: False, pull_limit=300):
    """With the user's permission: every risky-type file in the phone's shared storage, including app folders
    (Android/data, Android/obb) and hidden dot-folders. Fingerprints are computed on the phone; only files worth
    a closer look are copied to a temporary folder on the PC. Apps' fully private storage (/data/data) stays out of
    reach: Android only opens it to rooted phones."""
    info = phone_info(serial)
    name = f"{info['maker']} {info['model']}".strip()
    engine.log_event("usb", "info", f"Deep storage scan started: {name}", "with the user's permission")
    exts = sorted(e.lstrip(".") for e in PHONE_EXT)
    pattern = " -o ".join(f"-iname '*.{e}'" for e in exts)
    progress(0, "Listing every file on the phone (including app and hidden folders)…", 0)
    roots = " ".join(_sh_quote(r) for r in storage_roots(serial))
    listing = adb("shell", f"find {roots} -type f \\( {pattern} \\) -size -300M -print0 2>/dev/null | "
                           "xargs -0 sha256sum 2>/dev/null", serial=serial, timeout=1800)
    files = []
    for line in listing.splitlines():
        m = re.match(r"([0-9a-f]{64})\s+(.+)$", line.strip())
        if m:
            files.append((m.group(1), m.group(2)))
    blocked = "Android/data" not in listing and adb("shell", "ls /sdcard/Android/data 2>&1 | head -1",
                                                     serial=serial).strip().lower().endswith("denied")
    hits, pulled = [], 0
    staging = tempfile.mkdtemp(prefix="pcguard-deep-")
    try:
        with engine.db() as con:
            ignored = {r[0] for r in con.execute("SELECT sha256 FROM ignored")}
            for i, (digest, path) in enumerate(files):
                if cancelled():
                    break
                if i % 20 == 0:
                    progress(i, path, len(hits))
                if digest in ignored:
                    continue
                low = path.lower()
                in_app_folder = "/android/data/" in low or "/android/obb/" in low
                hidden = any(part.startswith(".") for part in path.split("/")[:-1])
                source = engine.lookup_hash(con, digest)
                if source:
                    hits.append(_result(path, os.path.basename(path), "Malware", 100,
                                        [f"Matches known malware ({source})"], fix="adb_delete", sha256=digest,
                                        device=name, serial=serial, signature=source))
                    continue
                found = []
                ext = os.path.splitext(low)[1]
                if pulled < pull_limit and ext in engine.SCRIPT_EXT | engine.OFFICE_EXT | {".apk", ".xapk", ".apks",
                                                                                         ".lnk", ".exe", ".scr"}:
                    local = os.path.join(staging, f"{i}{ext}")
                    adb("pull", path, local, serial=serial, timeout=300)
                    pulled += 1
                    if os.path.exists(local):
                        found = [(s, r) for s, r in engine.heuristics(local, open(local, "rb").read(2 * 1024 ** 2),
                                                                       os.path.basename(path)) if "folder" not in r]
                        os.remove(local)
                if ext in (".apk", ".xapk", ".apks", ".exe", ".scr") and (in_app_folder or hidden):
                    found.append((45, "App package tucked away in a hidden or app-only folder"))
                score = engine.score_of(found)
                if score >= engine.LOW:
                    hits.append(_result(path, os.path.basename(path), engine.verdict_of(score, None), score,
                                        [r for _s, r in found], fix="adb_delete", sha256=digest, device=name,
                                        serial=serial))
    finally:
        shutil.rmtree(staging, ignore_errors=True)  # our own temporary copies
    if blocked:
        hits.append(_result("", "App folders", "Info", 0, ["This phone doesn't let USB debugging read Android/data, "
                                                            "so app folders were skipped."], kind="advice"))
    for h in hits:
        if h.get("kind") != "advice":
            engine.log_event("detection", "bad" if h["verdict"] != "Worth a look" else "warn",
                             f"Phone storage: {h['verdict']} - {h['name']}", f"{name} · {h['path']} · "
                             + "; ".join(h["reasons"]))
    flagged = sum(1 for h in hits if h.get("kind") != "advice")
    engine.log_event("usb", "bad" if flagged else "ok", f"Deep storage scan finished: {name}",
                     f"{len(files):,} risky-type files fingerprinted, {pulled} inspected · {flagged} flagged")
    return hits, len(files), name


def adb_delete(serial, path):
    out = adb("shell", f"rm -f {_sh_quote(path)} && echo deleted", serial=serial)
    ok = "deleted" in out
    engine.log_event("usb", "ok" if ok else "warn", f"{'Deleted' if ok else 'Could not delete'} on phone: "
                                                     f"{os.path.basename(path)}", path)
    return ok


def uninstall_app(serial, pkg):
    out = adb("uninstall", pkg, serial=serial, timeout=120)
    ok = "Success" in out
    engine.log_event("usb", "ok" if ok else "warn", f"{'Uninstalled' if ok else 'Could not uninstall'} {pkg}",
                     out.strip()[:200])
    return ok, out.strip()


# ---------------------------------------------------------------- plug-in watching

class Watcher:
    """Call step() every few seconds: scans newly plugged-in USB drives (if enabled) and toasts the result."""

    def __init__(self):
        self.mask, self.known = None, set()

    def step(self, on_new=None):
        mask = _drive_mask()
        if mask == self.mask:
            return
        first = self.mask is None
        self.mask = mask
        roots = {d["root"] for d in usb_drives()}
        new, self.known = roots - self.known, roots
        if first:
            return  # drives already plugged in when watching starts aren't "new"
        for root in sorted(new):
            if on_new:
                on_new(root)
            elif load_settings()["usb"]["auto_scan"]:
                auto_scan(root)


def auto_scan(root):
    notify("Kavacham: USB drive connected", f"Scanning {root[:2]} {_volume_label(root)} for threats…")
    hits, n, _secs = scan_drive(root)
    malware = sum(1 for h in hits if h["verdict"] == "Malware")
    shortcut = any("Shortcut virus" in r for h in hits for r in h["reasons"])
    if hits:
        notify("Kavacham: USB drive needs attention",
               f"{root[:2]}: {malware} malware (quarantined), {len(hits) - malware} other finding(s)"
               + (". Shortcut virus found - use Repair in Kavacham." if shortcut else ". Open Kavacham → USB & phone."))
    else:
        notify("Kavacham: USB drive is clean", f"{root[:2]}: {n:,} files checked, nothing found.")
    return hits


# ---------------------------------------------------------------- phone storage: large files and duplicates

PHONE_SCOPES = {  # name -> folders inside internal storage (SD cards are added for "Whole phone")
    "Whole phone": [""],
    "Camera & pictures": ["DCIM", "Pictures"],
    "WhatsApp & Telegram": ["WhatsApp", "Android/media/com.whatsapp", "Android/media/com.whatsapp.w4b", "Telegram",
                            "Android/media/org.telegram.messenger"],
    "Downloads": ["Download"],
    "Videos & music": ["Movies", "Music", "DCIM", "Recordings"],
}
LARGE_SIZES = {"10 MB": 10, "50 MB": 50, "100 MB": 100, "500 MB": 500, "1 GB": 1024}
DUP_SIZES = {"Any size": 1, "100 KB": 100, "1 MB": 1024, "10 MB": 10 * 1024}  # in KB


def _scope_roots(serial, scope):
    folders = PHONE_SCOPES[scope]
    roots = [f"/sdcard/{f}/".replace("//", "/") for f in folders]
    if scope == "Whole phone":
        roots = storage_roots(serial)
    return roots


def list_phone_files(serial, scope, min_kb, hidden=False, app_folders=False):
    """Files on the phone bigger than min_kb: [(size, mtime, path)]. Only names and sizes come to the PC."""
    prune = []
    if not hidden:
        prune.append("-path '*/.*'")
    if not app_folders:
        prune += ["-path '/sdcard/Android/data'", "-path '/sdcard/Android/obb'", "-path '/storage/*/Android/data'",
                  "-path '/storage/*/Android/obb'"]
    prune_expr = f"\\( {' -o '.join(prune)} \\) -prune -o " if prune else ""
    roots = " ".join(_sh_quote(r) for r in _scope_roots(serial, scope))
    out = adb("shell", f"find {roots} {prune_expr}-type f -size +{max(0, int(min_kb) - 1)}k -print0 2>/dev/null | "
                       "xargs -0 stat -c '%s|%Y|%n' 2>/dev/null", serial=serial, timeout=1800)
    files, seen = [], set()
    for line in out.splitlines():
        parts = line.split("|", 2)
        if len(parts) == 3 and parts[0].isdigit():
            path = parts[2]
            key = path.replace("/storage/emulated/0/", "/sdcard/")
            if key not in seen:  # some phones list the same file under two names
                seen.add(key)
                files.append((int(parts[0]), int(parts[1]) if parts[1].isdigit() else 0, path))
    return files


def phone_large_files(serial, scope, min_mb, hidden=False, app_folders=False, limit=1000):
    files = list_phone_files(serial, scope, min_mb * 1024, hidden, app_folders)
    files.sort(key=lambda f: -f[0])
    engine.log_event("usb", "info", "Phone large files listed", f"{scope} · over {min_mb} MB · {len(files)} files")
    return files[:limit]


def phone_duplicates(serial, scope, min_kb, hidden=False, app_folders=False, progress=lambda *a: None,
                     cancelled=lambda: False):
    """Identical files by content. Candidates are files with equal sizes; their SHA-256 is computed on the phone in
    batches, so photos and videos never leave it. Returns [(size, [(mtime, path), ...])], most wasted space first."""
    progress("listing", 0, 0)
    files = list_phone_files(serial, scope, min_kb, hidden, app_folders)
    by_size = {}
    for size, mtime, path in files:
        by_size.setdefault(size, []).append((mtime, path))
    candidates = [(size, mtime, path) for size, group in by_size.items() if len(group) > 1 for mtime, path in group]
    by_hash = {}
    for start in range(0, len(candidates), 150):
        if cancelled():
            break
        batch = candidates[start:start + 150]
        progress("hashing", start, len(candidates))
        meta = {path: (size, mtime) for size, mtime, path in batch}
        out = adb("shell", "sha256sum " + " ".join(_sh_quote(p) for _s, _m, p in batch) + " 2>/dev/null",
                  serial=serial, timeout=1800)
        for line in out.splitlines():
            m = re.match(r"([0-9a-f]{64})\s+(.+)$", line.strip())
            if m and m.group(2) in meta:
                size, mtime = meta[m.group(2)]
                by_hash.setdefault((m.group(1), size), []).append((mtime, m.group(2)))
    groups = [(size, sorted(paths)) for (_h, size), paths in by_hash.items() if len(paths) > 1]
    groups.sort(key=lambda g: -g[0] * (len(g[1]) - 1))
    wasted = sum(size * (len(p) - 1) for size, p in groups)
    engine.log_event("usb", "info", "Phone duplicates found", f"{scope} · {len(groups)} sets · {wasted:,} bytes extra")
    return groups


def move_to_pc(serial, path, dest_root):
    """Copy a phone file to the PC, check the copy is complete, then delete it from the phone."""
    rel = re.sub(r"^/(sdcard|storage/emulated/0|storage/[\w-]+)/", "", path)
    local = os.path.join(dest_root, *rel.split("/"))
    os.makedirs(os.path.dirname(local), exist_ok=True)
    if os.path.exists(local):
        stem, ext = os.path.splitext(local)
        local = f"{stem} (from phone){ext}"
    size = adb("shell", f"stat -c %s {_sh_quote(path)}", serial=serial).strip()
    adb("pull", "-a", path, local, serial=serial, timeout=3600)
    if not (os.path.exists(local) and size.isdigit() and os.path.getsize(local) == int(size)):
        if os.path.exists(local) and size.isdigit() and os.path.getsize(local) != int(size):
            os.remove(local)  # our own incomplete copy
        return None
    if not adb_delete(serial, path):
        return None
    return local
