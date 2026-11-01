"""Kavacham USB protection: pendrives, USB disks and Android phones plugged into this PC.

Drives get the engine scan, a Defender scan and USB-specific checks (autorun tricks, the "shortcut virus" that hides
your folders behind fake shortcuts). Phones are checked two ways:
- files over the normal USB file connection (MTP): risky files are copied to a temporary folder and scanned there
- installed apps over ADB, when USB debugging is on: hashes, known stalkerware, and risky access such as
  accessibility control or device admin by apps that didn't come from an app store
"""
import base64
import ctypes
import hashlib
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
# media-only folders inside those: photos, videos and voice notes can't be risky types, and walking them over MTP
# is what makes a phone scan crawl
PHONE_SKIP = ["whatsapp images", "whatsapp video", "whatsapp audio", "whatsapp voice notes", "whatsapp stickers",
              "whatsapp animated gifs", "whatsapp video notes", "whatsapp profile photos", "whatsapp business images",
              "whatsapp business video", "whatsapp business audio", "whatsapp business voice notes", ".statuses",
              ".thumbs", ".shared", ".trash", "telegram images", "telegram video", "telegram audio", "databases",
              "backups"]
# media-only folders the junk search can pass by (WhatsApp Documents stays in: installers shared in chats land there)
JUNK_SKIP = PHONE_SKIP + ["camera", "screenshots"]
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
# Shell item names follow Explorer's "hide extensions" setting, so 'game.apk' can show up as just 'game'.
# The real file name (with its extension) comes from the System.FileName property.
function Real-Name($it) {
  $n = [string]$it.ExtendedProperty('System.FileName')
  if ($n) { $n } else { [string]$it.Name }
}
function Find-Item($path, $cur = $dev) {
  foreach ($seg in ($path -split '/')) {
    if (-not $cur) { return $null }
    $cur = @($cur.GetFolder.Items() | ? { (Real-Name $_) -eq $seg -or $_.Name -eq $seg })[0]
  }
  return $cur
}
"""

# Windows' own file operation engine (IFileOperation): unlike Folder.CopyHere it waits until the copy is done, and it
# deletes without a confirmation box per file. Phones have no recycle bin, so a delete is permanent either way.
_PS_FILEOP = r"""
try {
Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PcgFileOp {
  [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IShellItem { }
  [ComImport, Guid("947aab5f-0a5c-4c13-b4d6-4bf7836fc9f8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IFileOperation {
    uint Advise(IntPtr sink); void Unadvise(uint cookie); void SetOperationFlags(uint flags);
    void SetProgressMessage([MarshalAs(UnmanagedType.LPWStr)] string msg); void SetProgressDialog(IntPtr dlg);
    void SetProperties(IntPtr props); void SetOwnerWindow(IntPtr hwnd); void ApplyPropertiesToItem(IShellItem item);
    void ApplyPropertiesToItems([MarshalAs(UnmanagedType.IUnknown)] object items);
    void RenameItem(IShellItem item, [MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr sink);
    void RenameItems([MarshalAs(UnmanagedType.IUnknown)] object items, [MarshalAs(UnmanagedType.LPWStr)] string name);
    void MoveItem(IShellItem item, IShellItem dest, [MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr sink);
    void MoveItems([MarshalAs(UnmanagedType.IUnknown)] object items, IShellItem dest);
    void CopyItem(IShellItem item, IShellItem dest, [MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr sink);
    void CopyItems([MarshalAs(UnmanagedType.IUnknown)] object items, IShellItem dest);
    void DeleteItem(IShellItem item, IntPtr sink);
    void DeleteItems([MarshalAs(UnmanagedType.IUnknown)] object items);
    void NewItem(IShellItem dest, uint attrs, [MarshalAs(UnmanagedType.LPWStr)] string name,
                 [MarshalAs(UnmanagedType.LPWStr)] string template, IntPtr sink);
    void PerformOperations();
    [return: MarshalAs(UnmanagedType.Bool)] bool GetAnyOperationsAborted();
  }
  [DllImport("shell32.dll", PreserveSig = false)]
  static extern void SHGetIDListFromObject([MarshalAs(UnmanagedType.IUnknown)] object obj, out IntPtr pidl);
  [DllImport("shell32.dll", PreserveSig = false)]
  static extern void SHCreateItemFromIDList(IntPtr pidl, [In] ref Guid riid, out IShellItem item);
  [DllImport("ole32.dll")] static extern void CoTaskMemFree(IntPtr p);
  static IShellItem Item(object folderItem) {
    IntPtr pidl; SHGetIDListFromObject(folderItem, out pidl);
    try { Guid g = typeof(IShellItem).GUID; IShellItem it; SHCreateItemFromIDList(pidl, ref g, out it); return it; }
    finally { CoTaskMemFree(pidl); }
  }
  static IFileOperation Op() {
    var op = (IFileOperation)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("3ad05575-8857-4850-9277-11b85bdb8e09")));
    op.SetOperationFlags(0x0614);  // no confirmation, no progress window, no error dialogs
    return op;
  }
  public static void Copy(object folderItem, object destFolderItem) {
    var op = Op(); op.CopyItem(Item(folderItem), Item(destFolderItem), null, IntPtr.Zero); op.PerformOperations();
  }
  public static void Delete(object folderItem) {
    var op = Op(); op.DeleteItem(Item(folderItem), IntPtr.Zero); op.PerformOperations();
  }
  public static void NewFolder(object parentFolderItem, string name) {
    var op = Op(); op.NewItem(Item(parentFolderItem), 0x10, name, null, IntPtr.Zero); op.PerformOperations();
  }
}
'@
$fileop = $true
} catch { $fileop = $false }
"""

PHONE_NOT_READY = ("The phone is connected but its files aren't visible. Unlock the phone and choose \"File "
                   "transfer\" in its USB notification.")
PHONE_GONE = "The phone isn't connected any more. Check the cable, unlock the phone and choose \"File transfer\"."
PHONE_SLOW = ("The phone stopped answering. Unlock it, keep the screen on, check \"File transfer\" is still chosen, "
              "then try again.")


def _ps(script, env=None, timeout=120):
    """run_ps, but with UTF-8 output so phone file names in any language come through intact."""
    script = "$ProgressPreference = 'SilentlyContinue'\n[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false\n" \
             + script
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                             capture_output=True, encoding="utf-8", errors="replace", creationflags=NO_WINDOW,
                             timeout=timeout, env=env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise RuntimeError(PHONE_SLOW) from None
    return out.stdout or ""


def _ps_lines(script, env, cancelled=lambda: False):
    """Run a PowerShell script and yield its output lines as they come; stops it when cancelled."""
    script = "$ProgressPreference = 'SilentlyContinue'\n[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false\n" \
             + script
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    p = subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                         encoding="utf-8", errors="replace", creationflags=NO_WINDOW, env=env)
    try:
        for line in p.stdout:
            if cancelled():
                break
            yield line.rstrip("\r\n")
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()


def phones():
    """Phones and other portable devices showing up in This PC (no setup needed): [names]."""
    script = ("$sh = New-Object -ComObject Shell.Application; $r = @($sh.Namespace(17).Items() | "
              "? { $_.IsFolder -and -not $_.IsFileSystem } | % { [string]$_.Name }); ConvertTo-Json -InputObject $r "
              "-Compress")
    try:
        return json.loads(_ps(script, timeout=30) or "[]") or []
    except Exception:
        return []


def phone_storages(device):
    """The phone's storages ("Internal shared storage", SD card). Raises a plain-language error when the phone has
    gone, or shows up without any storage (locked, or set to "Charging only")."""
    script = _PS_FIND + r"""
if (-not $dev) { 'GONE'; exit }
ConvertTo-Json -Compress -InputObject @($dev.GetFolder.Items() | ? { $_.IsFolder } | % { [string]$_.Name })
"""
    out = _ps(script, env={**os.environ, "PCG_DEVICE": device}, timeout=60).strip()
    if out.startswith("GONE"):
        raise RuntimeError(PHONE_GONE)
    stores = json.loads(out or "[]") or []
    if not stores:
        raise RuntimeError(PHONE_NOT_READY)
    return stores


def phone_files(device):
    """Risky files in the places downloads and shared files land: [{"Path", "Size"}]."""
    phone_storages(device)
    script = _PS_FIND + r"""
$exts = $env:PCG_EXTS -split ','
$focus = $env:PCG_FOCUS -split '\|'
$skip = $env:PCG_SKIP -split '\|'
$found = New-Object System.Collections.ArrayList
function Walk($item, $rel, $prefix) {
  foreach ($it in $item.GetFolder.Items()) {
    $name = Real-Name $it
    $p = if ($rel) { "$rel/$name" } else { $name }
    $low = $p.ToLower()
    if ($it.IsFolder) {
      if ($skip -contains $name.ToLower()) { continue }
      if (@($focus | ? { $low.StartsWith($_) -or $_.StartsWith($low + '/') }).Count) { Walk $it $p $prefix }
    } elseif ($exts -contains [IO.Path]::GetExtension($name).ToLower()) {
      [void]$found.Add([pscustomobject]@{Path="$prefix/$p"; Size=[int64]$it.Size})
    }
  }
}
if ($dev) { foreach ($store in $dev.GetFolder.Items()) { if ($store.IsFolder) { Walk $store '' $store.Name } } }
ConvertTo-Json -InputObject @($found) -Compress
"""
    env = {**os.environ, "PCG_DEVICE": device, "PCG_EXTS": ",".join(sorted(PHONE_EXT)), "PCG_FOCUS": "|".join(PHONE_FOCUS),
           "PCG_SKIP": "|".join(PHONE_SKIP)}
    return json.loads(_ps(script, env=env, timeout=900) or "[]") or []


def copy_from_phone(device, paths, dest):
    """Copy phone files into dest (one subfolder each, so equal names don't collide). Returns {local: phone path}."""
    listing = os.path.join(dest, "_list.json")
    with open(listing, "w", encoding="utf-8") as f:
        json.dump(paths, f)
    script = _PS_FIND + _PS_FILEOP + r"""
$paths = Get-Content -Raw -Encoding UTF8 $env:PCG_LIST | ConvertFrom-Json
$map = @{}
$i = 0
foreach ($p in $paths) {
  $i++
  $it = Find-Item $p
  if (-not $it) { continue }
  $dir = Join-Path $env:PCG_DEST $i
  New-Item -ItemType Directory -Force $dir | Out-Null
  $done = $false
  if ($fileop) { try { [PcgFileOp]::Copy($it, $sh.Namespace($dir).Self); $done = $true } catch {} }
  if (-not $done) {  # older way: CopyHere returns at once, so wait for the file to stop growing
    $sh.Namespace($dir).CopyHere($it, 0x614)
    $t0 = Get-Date; $last = -1
    while (((Get-Date) - $t0).TotalSeconds -lt 180) {
      Start-Sleep -Milliseconds 400
      $f = @(Get-ChildItem -LiteralPath $dir -File)[0]
      if ($f) { if ($f.Length -gt 0 -and $f.Length -eq $last) { break }; $last = $f.Length }
    }
  }
  $f = @(Get-ChildItem -LiteralPath $dir -File)[0]  # each file gets its own folder, so the only file is ours
  if ($f) { $map[$f.FullName] = $p }
}
$map | ConvertTo-Json -Compress
"""
    env = {**os.environ, "PCG_DEVICE": device, "PCG_LIST": listing, "PCG_DEST": dest}
    out = _ps(script, env=env, timeout=3600).strip()
    os.remove(listing)
    return json.loads(out or "{}") or {}


def delete_many_from_phone(device, paths):
    """Delete files on the phone over the file connection. Returns the set of paths that are gone."""
    if not paths:
        return set()
    phone_storages(device)  # a locked phone hides its files: say so rather than delete nothing
    listing = os.path.join(tempfile.gettempdir(), f"pcguard-del-{os.getpid()}.json")
    with open(listing, "w", encoding="utf-8") as f:
        json.dump(list(paths), f)
    script = _PS_FIND + _PS_FILEOP + r"""
$gone = New-Object System.Collections.ArrayList
foreach ($p in (Get-Content -Raw -Encoding UTF8 $env:PCG_LIST | ConvertFrom-Json)) {
  $it = Find-Item $p
  if (-not $it) { continue }
  if ($fileop) { try { [PcgFileOp]::Delete($it) } catch { $it.InvokeVerb('delete') } } else { $it.InvokeVerb('delete') }
  if (-not (Find-Item $p)) { [void]$gone.Add($p) }
}
ConvertTo-Json -Compress -InputObject @($gone)
"""
    try:
        out = _ps(script, env={**os.environ, "PCG_DEVICE": device, "PCG_LIST": listing},
                  timeout=60 + 30 * len(paths)).strip()
    finally:
        os.remove(listing)
    gone = set(json.loads(out or "[]") or [])
    for p in paths:
        ok = p in gone
        engine.log_event("usb", "ok" if ok else "warn", f"{'Deleted' if ok else 'Could not delete'} on phone: "
                                                         f"{os.path.basename(p)}", f"{device} · {p}")
    return gone


def delete_from_phone(device, path):
    """Delete one file on the phone. Returns True when it's gone."""
    return path in delete_many_from_phone(device, [path])


def scan_phone_files(device, progress=lambda *a: None, cancelled=lambda: False):
    """Find risky files on the phone, copy them to a temporary folder, scan them there."""
    engine.log_event("usb", "info", f"Phone files scan started: {device}")
    progress(0, "Looking for downloaded and shared files on the phone…", 0)
    items = [i for i in phone_files(device) if (i.get("Size") or 0) <= engine.MAX_HASH]
    if cancelled() or not items:
        engine.log_event("usb", "ok", f"Phone files scan finished: {device}", f"{len(items)} risky-type files")
        return [], len(items)
    hits, copied = [], {}
    staging = tempfile.mkdtemp(prefix="pcguard-phone-")
    try:
        for start in range(0, len(items), 25):
            if cancelled():
                break
            batch = items[start:start + 25]
            progress(start, f"Copying files from the phone ({start + len(batch)}/{len(items)})…", len(hits))
            mapping = copy_from_phone(device, [i["Path"] for i in batch], staging)
            copied.update({os.path.normcase(k): v for k, v in mapping.items()})
            with engine.db() as con:
                for local, phone_path in mapping.items():
                    found = engine.scan_file(con, local)  # includes the APK permission checks
                    for r in found:
                        r.update(device=device, phone_path=phone_path, path=phone_path, fix="phone_delete",
                                 name=os.path.basename(phone_path) if "›" not in r["name"] else r["name"])
                        hits.append(r)
        for threat, local in defender_scan(staging) or []:
            phone_path = copied.get(os.path.normcase(local.split("->")[0]))  # "x.zip->inner.exe": the zip
            if not phone_path:
                continue  # not one of the copied files
            same = next((h for h in hits if h["phone_path"] == phone_path), None)
            if same:
                same["reasons"].insert(0, f"Microsoft Defender: {threat}")
                same.update(verdict="Malware", score=100)
                continue
            hits.append(_result(phone_path, os.path.basename(phone_path), "Malware", 100,
                                [f"Microsoft Defender: {threat}"], fix="phone_delete", device=device,
                                phone_path=phone_path))
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
    prune = ["-name .KavachamBin"]  # files already deleted with Kavacham, see phone.py
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


# ---------------------------------------------------------------- the same, over the plain file connection (MTP)
# No USB debugging needed: Windows' own phone connection is walked folder by folder. Paths look like
# "Internal shared storage/DCIM/Camera/IMG_1.jpg".

def mtp_list_files(device, scope, min_kb, hidden=False, app_folders=False, progress=lambda *a: None,
                   cancelled=lambda: False, junk=False):
    """Files on the phone of at least min_kb: [(size, mtime, path)]. junk: skip folders junk can't be in (photo and
    chat media, app data other than caches), which over File transfer turns tens of minutes into a few."""
    phone_storages(device)
    script = _PS_FIND + r"""
$min = [int64]$env:PCG_MIN
$hidden = $env:PCG_HIDDEN -eq '1'
$appf = $env:PCG_APPF -eq '1'
$junk = $env:PCG_JUNK -eq '1'
$skipdirs = $env:PCG_SKIPDIRS -split '\|'
function Walk($folder, $p) {
  "D`t$p"
  $items = $null
  try { $items = $folder.GetFolder.Items() } catch {}
  if ($null -eq $items) { "S`t$p"; return }
  foreach ($it in $items) {
    # Every property read can be a round trip to the phone, so ask only what each item needs: the shown name and
    # the cheap Size first; the real file name, exact size and date only for files that pass the size filter.
    $name = [string]$it.Name
    if (-not $hidden -and $name.StartsWith('.')) { continue }
    if ($it.IsFolder) {
      if ($name -eq '.KavachamBin') { continue }  # files already deleted with Kavacham, see phone.py
      $q = "$p/$name"
      if (-not $appf -and $q -match '^[^/]+/Android/(data|obb)$') { continue }
      if ($junk) {  # only where junk can be: an app's private folder matters just for its cache
        if ($skipdirs -contains $name.ToLower() -or $q -match '/Android/obb$') { continue }
        if ($q -match '/Android/data/[^/]+/[^/]+$' -and $name -ne 'cache') { continue }
      }
      Walk $it $q
    } else {
      $size = [int64]$it.Size
      if ($size -lt $min -and $size -gt 0) { continue }  # Size tops out near 4 GB, so big files are re-checked below
      $exact = [int64]$it.ExtendedProperty('System.Size')
      if ($exact) { $size = $exact }
      if ($size -ge $min) {
        $q = "$p/$(Real-Name $it)"
        $t = 0  # phones leave ModifyDate empty (1899); the real date is in System.DateModified
        try { $t = ([DateTimeOffset]$it.ExtendedProperty('System.DateModified').ToUniversalTime()).ToUnixTimeSeconds() } catch {}
        "F`t$size`t$t`t$q"
      }
    }
  }
}
if (-not $dev) { "E`tgone"; exit }
foreach ($s in @($dev.GetFolder.Items() | ? { $_.IsFolder })) {
  foreach ($r in ($env:PCG_ROOTS -split '\|')) {
    if ($r) { $f = Find-Item $r $s; if ($f) { Walk $f "$($s.Name)/$r" } } else { Walk $s $s.Name }
  }
}
"END"
"""
    env = {**os.environ, "PCG_DEVICE": device, "PCG_MIN": str(max(1, int(min_kb)) * 1024),
           "PCG_HIDDEN": "1" if hidden else "0", "PCG_APPF": "1" if app_folders else "0",
           "PCG_ROOTS": "|".join(PHONE_SCOPES[scope]), "PCG_JUNK": "1" if junk else "0",
           "PCG_SKIPDIRS": "|".join(JUNK_SKIP)}
    files, skipped, finished = [], [], False
    for line in _ps_lines(script, env, cancelled):
        kind, _, rest = line.partition("\t")
        if kind == "F":
            parts = rest.split("\t", 2)
            if len(parts) == 3 and parts[0].isdigit():
                files.append((int(parts[0]), max(0, int(parts[1])) if parts[1].lstrip("-").isdigit() else 0,
                              parts[2]))
        elif kind == "D":
            progress("listing", len(files), rest)
        elif kind == "S":
            skipped.append(rest)
        elif kind == "END":
            finished = True
        elif kind == "E":
            raise RuntimeError(PHONE_GONE)
    if skipped:
        engine.log_event("usb", "warn", "Phone folders couldn't be read", f"{device} · " + ", ".join(skipped[:20]))
    if finished and not cancelled():
        try:
            phone_storages(device)
        except RuntimeError:
            finished = False  # it locked part way: folders read after that came back empty, not missing
    if not finished and not cancelled():
        # The listing died part way (phone locked, cable, or Windows' phone link gave up): don't pass off a partial
        # list as the whole phone.
        raise RuntimeError("The phone stopped answering part way through, so the list would be incomplete. "
                           "Unlock it, keep the screen on and try again.")
    return files


def mtp_large_files(device, scope, min_mb, hidden=False, app_folders=False, progress=lambda *a: None,
                    cancelled=lambda: False, limit=1000):
    files = mtp_list_files(device, scope, min_mb * 1024, hidden, app_folders, progress, cancelled)
    files.sort(key=lambda f: -f[0])
    engine.log_event("usb", "info", "Phone large files listed", f"{device} · {scope} · over {min_mb} MB · "
                                                                f"{len(files)} files")
    return files[:limit]


def mtp_duplicates(device, scope, min_kb, hidden=False, app_folders=False, progress=lambda *a: None,
                   cancelled=lambda: False):
    """Identical files by content. Only files with an equal size can match; those are copied to a temporary folder
    on this PC a few at a time, fingerprinted and deleted straight away. Same result shape as phone_duplicates."""
    files = mtp_list_files(device, scope, min_kb, hidden, app_folders, progress, cancelled)
    by_size = {}
    for size, mtime, path in files:
        by_size.setdefault(size, []).append((mtime, path))
    candidates = [(size, mtime, path) for size, group in by_size.items() if len(group) > 1 for mtime, path in group]
    by_hash = {}
    for start in range(0, len(candidates), 20):
        if cancelled():
            break
        batch = candidates[start:start + 20]
        progress("copying", start, len(candidates))
        meta = {path: (size, mtime) for size, mtime, path in batch}
        staging = tempfile.mkdtemp(prefix="pcguard-dups-")
        try:
            for local, path in copy_from_phone(device, [p for _s, _m, p in batch], staging).items():
                size, mtime = meta[path]
                if os.path.getsize(local) != size:
                    continue  # incomplete copy: never call it a duplicate
                h = hashlib.sha256()
                with open(local, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                by_hash.setdefault((h.hexdigest(), size), []).append((mtime, path))
        finally:
            shutil.rmtree(staging, ignore_errors=True)  # our own temporary copies
    groups = [(size, sorted(paths)) for (_h, size), paths in by_hash.items() if len(paths) > 1]
    groups.sort(key=lambda g: -g[0] * (len(g[1]) - 1))
    wasted = sum(size * (len(p) - 1) for size, p in groups)
    engine.log_event("usb", "info", "Phone duplicates found", f"{device} · {scope} · {len(groups)} sets · "
                                                              f"{wasted:,} bytes extra")
    return groups


def mtp_move_to_pc(device, items, dest_root):
    """Copy phone files [(path, size)] to dest_root keeping their folders, check each copy is complete, then delete
    those from the phone. Returns {phone path: local path} for the files moved."""
    staging = tempfile.mkdtemp(prefix=".kavacham-moving-", dir=_mkdirs(dest_root))  # same drive: moving in is instant
    sizes = dict(items)
    copied = {}
    try:
        for local, path in copy_from_phone(device, [p for p, _s in items], staging).items():
            if os.path.getsize(local) != sizes[path]:
                continue  # incomplete: leave the phone's file alone
            rel = path.split("/", 1)[1] if "/" in path else os.path.basename(path)  # drop the storage name
            target = os.path.join(dest_root, *rel.split("/"))
            _mkdirs(os.path.dirname(target))
            if os.path.exists(target):
                stem, ext = os.path.splitext(target)
                target = f"{stem} (from phone){ext}"
            os.replace(local, target)
            copied[path] = target
    finally:
        shutil.rmtree(staging, ignore_errors=True)  # our own temporary folder
    gone = delete_many_from_phone(device, list(copied))
    return {p: local for p, local in copied.items() if p in gone}


def _mkdirs(path):
    os.makedirs(path, exist_ok=True)
    return path


# ---------------------------------------------------------------- phone junk: caches, thumbnails, leftovers
# Looks inside the phone's hidden and app folders (Android/data, Android/obb). Apps' fully private storage
# (/data/data) can't be opened without rooting the phone, but with USB debugging Android itself can be asked to empty
# every app's private cache (SYSTEM_CACHE).

SYSTEM_CACHE = "All apps' private cache (emptied by Android itself)"
JUNK_KINDS = [  # (name, selected by default)
    ("Leftovers from uninstalled apps", True),
    ("App cache", True),
    ("Private app cache", True),
    ("Thumbnails", True),
    ("Log and temp files", True),
    ("App installer files (.apk)", False),
]
_JUNK_PATTERNS = [  # (kind, regex): the first group is the item that gets deleted
    ("App cache", re.compile(r"^(.*?/Android/data/[^/]+/cache)/", re.I)),
    ("Thumbnails", re.compile(r"^(.*?/\.thumbnails)/", re.I)),
    ("App installer files (.apk)", re.compile(r"^((?!.*/Android/(?:data|obb)/).*\.(?:apk|apks|xapk))$", re.I)),
    ("Log and temp files", re.compile(r"^((?!.*/Android/(?:data|obb)/).*\.(?:log|tmp|temp))$", re.I)),
]
_APP_FOLDER = re.compile(r"^(.*?/Android/(?:data|obb)/([^/]+))/", re.I)


def is_junk_path(path):
    """Only these may be bulk-deleted from the junk list: never a whole storage or a normal folder."""
    if path == SYSTEM_CACHE:
        return True
    p = path.rstrip("/")
    return bool(re.search(r"/Android/(?:data|obb)/[^/]+(/cache)?$|/\.thumbnails$|\.(apk|apks|xapk|log|tmp|temp)$",
                          p, re.I))


def _classify_junk(files, installed=None):
    """files [(size, mtime, path)] -> {kind: {item path: size}}. installed: package names, when known, to spot
    folders left behind by apps that are gone."""
    found = {}
    for size, _mtime, path in files:
        m = _APP_FOLDER.match(path)
        if installed is not None and m and m.group(2) not in installed and not m.group(2).startswith("."):
            kind, item = "Leftovers from uninstalled apps", m.group(1)
        else:
            for kind, rx in _JUNK_PATTERNS:
                m = rx.match(path)
                if m:
                    item = m.group(1)
                    break
            else:
                continue
        found.setdefault(kind, {})
        found[kind][item] = found[kind].get(item, 0) + size
    return found


def _junk_result(found):
    """[(kind, selected by default, [(size, path)])], biggest items first, in JUNK_KINDS order."""
    out = []
    for kind, default in JUNK_KINDS:
        items = sorted(((s, p) for p, s in found.get(kind, {}).items()), key=lambda i: -i[0])
        if items:
            out.append((kind, default, items))
    total = sum(s for _k, _d, items in out for s, _p in items)
    engine.log_event("usb", "info", "Phone junk found", f"{sum(len(i) for _k, _d, i in out)} items · {total:,} bytes")
    return out


def phone_junk(serial, progress=lambda *a: None, cancelled=lambda: False):
    """Junk over USB debugging, including leftovers of removed apps and every app's private cache."""
    progress("listing", 0, 0)
    files = list_phone_files(serial, "Whole phone", 1, hidden=True, app_folders=True)
    installed = set(re.findall(r"package:(\S+)", adb("shell", "pm", "list", "packages", serial=serial, timeout=120)))
    found = _classify_junk(files, installed if installed else None)
    m = re.search(r"App Cache Size:\s*(\d+)", adb("shell", "dumpsys", "diskstats", serial=serial, timeout=60))
    found.setdefault("Private app cache", {})[SYSTEM_CACHE] = int(m.group(1)) if m else 0
    return _junk_result(found)


def mtp_junk(device, progress=lambda *a: None, cancelled=lambda: False):
    """Junk over the plain file connection. Leftovers of removed apps need USB debugging (the app list)."""
    files = mtp_list_files(device, "Whole phone", 1, True, True, progress, cancelled, junk=True)
    return _junk_result(_classify_junk(files))


def clean_junk_adb(serial, path):
    """Delete one junk item (a folder or a file) over USB debugging."""
    if not is_junk_path(path):
        return False
    if path == SYSTEM_CACHE:
        adb("shell", "pm", "trim-caches", "999G", serial=serial, timeout=300)
        engine.log_event("usb", "ok", "Phone: all apps' private cache emptied", serial)
        return True
    out = adb("shell", f"rm -rf {_sh_quote(path)}; [ -e {_sh_quote(path)} ] || echo deleted", serial=serial,
              timeout=300)
    ok = "deleted" in out
    engine.log_event("usb", "ok" if ok else "warn", f"{'Cleaned' if ok else 'Could not clean'} on phone: "
                                                     f"{os.path.basename(path)}", path)
    return ok


def clean_junk_mtp(device, paths):
    return delete_many_from_phone(device, [p for p in paths if is_junk_path(p) and p != SYSTEM_CACHE])
