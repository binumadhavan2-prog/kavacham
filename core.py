"""PC Guard core: Defender scanning, junk cleaning, Task Scheduler integration and the headless task runner."""
import base64
import ctypes
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from ctypes import wintypes

NO_WINDOW = 0x08000000
LOCAL = os.environ.get("LOCALAPPDATA", "")
PROGDATA = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
WINDIR = os.environ.get("WINDIR", r"C:\Windows")
DATA_DIR = os.path.join(LOCAL, "PCGuard")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pc_guard.py")
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]



# ---------------------------------------------------------------- helpers

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def pythonw():
    exe = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return exe if os.path.exists(exe) else sys.executable


def relaunch_as_admin():
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", pythonw(), f'"{SCRIPT}"', None, 1)
    return rc > 32


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def run_ps(script, env=None, timeout=120):
    script = "$ProgressPreference = 'SilentlyContinue'\n" + script
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True, text=True, creationflags=NO_WINDOW, timeout=timeout, env=env,
        stdin=subprocess.DEVNULL,  # never let PowerShell wait on an inherited console
    )


def ps_quote(s):
    return "'" + str(s).replace("'", "''") + "'"


def powershell_json(script):
    out = run_ps(script)
    if out.returncode != 0 and not out.stdout.strip():
        raise RuntimeError(out.stderr.strip() or "PowerShell command failed")
    text = out.stdout.strip()
    return json.loads(text) if text else None


def find_mpcmdrun():
    platform = sorted(glob.glob(os.path.join(PROGDATA, r"Microsoft\Windows Defender\Platform\*\MpCmdRun.exe")))
    if platform:
        return platform[-1]
    fallback = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), r"Windows Defender\MpCmdRun.exe")
    return fallback if os.path.exists(fallback) else None


class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_int64), ("i64NumItems", ctypes.c_int64)]


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT), ("pFrom", wintypes.LPCWSTR),
                ("pTo", wintypes.LPCWSTR), ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", wintypes.BOOL),
                ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", wintypes.LPCWSTR)]


def recycle_bin_info():
    info = SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(info)
    if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) == 0:
        return info.i64Size, info.i64NumItems
    return 0, 0


def empty_recycle_bin():
    ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x1 | 0x2 | 0x4)


def send_to_recycle_bin(path):
    op = SHFILEOPSTRUCTW()
    op.wFunc = 3  # FO_DELETE
    op.pFrom = path + "\0"
    op.fFlags = 0x40 | 0x10 | 0x4 | 0x400  # ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
    return ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op)) == 0


def fixed_drives():
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if mask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:
                yield root


# ---------------------------------------------------------------- cleaner targets

def browser_dirs(base, subdirs):
    return [os.path.join(base, "*", s) for s in subdirs]


CHROMIUM_CACHE = ["Cache", "Code Cache", "GPUCache", "Service Worker\\CacheStorage"]
CLEAN_TARGETS = [
    ("User temporary files", [os.environ.get("TEMP", os.path.join(LOCAL, "Temp"))], False),
    ("Windows temporary files", [os.path.join(WINDIR, "Temp")], True),
    ("Google Chrome cache", browser_dirs(os.path.join(LOCAL, r"Google\Chrome\User Data"), CHROMIUM_CACHE), False),
    ("Microsoft Edge cache", browser_dirs(os.path.join(LOCAL, r"Microsoft\Edge\User Data"), CHROMIUM_CACHE), False),
    ("Firefox cache", [os.path.join(LOCAL, r"Mozilla\Firefox\Profiles\*\cache2")], False),
    ("Thumbnail cache", [os.path.join(LOCAL, r"Microsoft\Windows\Explorer\thumbcache_*.db")], False),
    ("Crash dumps & error reports", [os.path.join(LOCAL, "CrashDumps"),
                                     os.path.join(LOCAL, r"Microsoft\Windows\WER"),
                                     os.path.join(PROGDATA, r"Microsoft\Windows\WER\ReportArchive"),
                                     os.path.join(PROGDATA, r"Microsoft\Windows\WER\ReportQueue")], False),
    ("Windows Update download cache", [os.path.join(WINDIR, r"SoftwareDistribution\Download")], True),
]


def expand(patterns):
    for pattern in patterns:
        yield from glob.glob(pattern)


def iter_files(path):
    if os.path.isfile(path):
        yield path
        return
    for root, _dirs, files in os.walk(path):
        for f in files:
            yield os.path.join(root, f)


def measure(patterns):
    total = count = 0
    for p in expand(patterns):
        for f in iter_files(p):
            try:
                total += os.path.getsize(f)
                count += 1
            except OSError:
                pass
    return total, count


def clean(patterns):
    """Delete the contents of each target; locked/in-use files are skipped."""
    freed = removed = skipped = 0
    for p in expand(patterns):
        for f in iter_files(p):
            try:
                size = os.path.getsize(f)
                os.remove(f)
                freed += size
                removed += 1
            except OSError:
                skipped += 1
        if os.path.isdir(p):
            for root, dirs, _files in os.walk(p, topdown=False):
                for d in dirs:
                    try:
                        os.rmdir(os.path.join(root, d))
                    except OSError:
                        pass
    return freed, removed, skipped


def clean_categories(names, admin):
    """Clean the named categories. Admin-only ones are skipped (and reported) when not elevated."""
    freed = removed = skipped = 0
    needs_admin = []
    for name, pats, admin_only in CLEAN_TARGETS:
        if name not in names:
            continue
        if admin_only and not admin:
            needs_admin.append(name)
            continue
        f, r, s = clean(pats)
        freed, removed, skipped = freed + f, removed + r, skipped + s
    if "Recycle Bin" in names:
        size, count = recycle_bin_info()
        if count:
            empty_recycle_bin()
            freed, removed = freed + size, removed + count
    return freed, removed, skipped, needs_admin


# ---------------------------------------------------------------- duplicate files

# Folders whose "duplicates" belong to Windows or to programs and must not be touched.
SKIP_DIRS = {"appdata", "$recycle.bin", "windows", "program files", "program files (x86)", "programdata",
             "system volume information", "node_modules", ".git", "venv", ".venv", "__pycache__", "site-packages"}
HIDDEN_OR_SYSTEM = 0x2 | 0x4
PARTIAL = 64 * 1024


def file_hash(path, limit=None):
    h = hashlib.blake2b(digest_size=20)
    with open(path, "rb") as f:
        if limit:
            h.update(f.read(limit))
        else:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return h.digest()


def _buckets(paths, key):
    out = {}
    for p in paths:
        try:
            out.setdefault(key(p), []).append(p)
        except OSError:
            pass
    return [b for b in out.values() if len(b) > 1]


def find_duplicates(root, min_size=1, skip_system=True, progress=None, cancelled=lambda: False):
    """Group identical files: same size, then same first 64 KB, then same full hash.

    Returns (groups, files_checked) where groups is [(size, [paths])], biggest waste first.
    """
    by_size, scanned, stack = {}, 0, [root]
    while stack and not cancelled():
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir():
                            if skip_system and (e.name.lower() in SKIP_DIRS
                                                or e.stat().st_file_attributes & HIDDEN_OR_SYSTEM):
                                continue
                            stack.append(e.path)
                        elif e.is_file():
                            scanned += 1
                            size = e.stat().st_size
                            if size >= min_size:
                                by_size.setdefault(size, []).append(e.path)
                            if progress and scanned % 2000 == 0:
                                progress("listing", scanned, 0)
                    except OSError:
                        pass
        except OSError:
            pass

    candidates = [(s, p) for s, p in by_size.items() if len(p) > 1]
    total, done, groups = sum(len(p) for _s, p in candidates), 0, []
    for size, paths in candidates:
        if cancelled():
            break
        for same_start in _buckets(paths, lambda p: file_hash(p, PARTIAL)):
            if size <= PARTIAL:
                groups.append((size, same_start))  # the partial hash already covered the whole file
            else:
                groups.extend((size, same) for same in _buckets(same_start, file_hash))
        done += len(paths)
        if progress:
            progress("hashing", done, total)
    groups.sort(key=lambda g: g[0] * (len(g[1]) - 1), reverse=True)
    return groups, scanned


# ---------------------------------------------------------------- settings, history, notifications

DEFAULT_SETTINGS = {
    "scan": {"enabled": False, "frequency": "Weekly", "days": ["Sunday"], "time": "12:00", "type": "Quick",
             "update_first": True, "run_missed": True, "skip_on_battery": True, "idle": False, "notify": True,
             "engine": True},
    "clean": {"enabled": False, "frequency": "Weekly", "days": ["Sunday"], "time": "13:00",
              "categories": ["User temporary files", "Crash dumps & error reports", "Thumbnail cache"],
              "min_free_gb": 0, "run_missed": True, "skip_on_battery": True, "idle": True, "notify": True},
    "engine": {"realtime": False, "auto_update": True, "auto_quarantine": True, "download_protection": True,
               "hold_downloads": True,
               "folders": [os.path.join(os.path.expanduser("~"), "Downloads"),
                           os.path.join(os.path.expanduser("~"), "Desktop")]},
    "ai": {"enabled": False, "key": ""},  # key is DPAPI-encrypted: only this Windows account can read it
    "alerts": {"enabled": True},
    "usb": {"auto_scan": True, "deep_consent": [],
            "storage": {"scope": "Whole phone", "large": "100 MB", "dup": "1 MB", "hidden": False,
                        "app_folders": False}},
}


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load_settings():
    saved = read_json(SETTINGS_FILE, {})
    return {k: {**v, **saved.get(k, {})} for k, v in DEFAULT_SETTINGS.items()}


def add_history(task, result, details, level="ok"):
    history = read_json(HISTORY_FILE, [])
    history.insert(0, {"time": time.strftime("%d %b %Y %H:%M"), "task": task, "result": result,
                       "details": details, "level": level})
    write_json(HISTORY_FILE, history[:300])


def notify(title, message):
    """Windows toast notification (shown under 'Windows PowerShell' in the notification centre)."""
    script = (
        "$m=[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime];"
        "$x=$m::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
        "$t=$x.GetElementsByTagName('text');"
        "$t.Item(0).AppendChild($x.CreateTextNode($env:PCG_TITLE)) | Out-Null;"
        "$t.Item(1).AppendChild($x.CreateTextNode($env:PCG_MSG)) | Out-Null;"
        "$m::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe')"
        ".Show([Windows.UI.Notifications.ToastNotification]::new($x))"
    )
    try:
        run_ps(script, env={**os.environ, "PCG_TITLE": title, "PCG_MSG": message}, timeout=30)
    except Exception:
        pass


# ---------------------------------------------------------------- Windows Task Scheduler

TASK_NAMES = {"scan": "PC Guard - Scheduled Scan", "clean": "PC Guard - Scheduled Cleaning"}


def register_task(kind, cfg):
    """Create/replace (or remove, when disabled) the Task Scheduler entry. Returns an error string or None."""
    name = ps_quote(TASK_NAMES[kind])
    if not cfg["enabled"]:
        run_ps(f"Unregister-ScheduledTask -TaskName {name} -Confirm:$false -ErrorAction SilentlyContinue")
        return None
    user = '"$env:USERDOMAIN\\$env:USERNAME"'
    at = ps_quote(cfg["time"])
    if cfg["frequency"] == "Daily":
        trigger = f"New-ScheduledTaskTrigger -Daily -At {at}"
    elif cfg["frequency"] == "Weekly":
        trigger = f"New-ScheduledTaskTrigger -Weekly -DaysOfWeek {','.join(cfg['days'])} -At {at}"
    else:
        # wait 5 minutes after sign-in so the scan doesn't slow down startup
        trigger = f"New-ScheduledTaskTrigger -AtLogOn -User {user}\n$t.Delay = 'PT5M'"
    battery = "$false" if cfg["skip_on_battery"] else "$true"
    idle = ("-RunOnlyIfIdle -IdleDuration (New-TimeSpan -Minutes 10) -IdleWaitTimeout (New-TimeSpan -Hours 4) "
            "-DontStopOnIdleEnd") if cfg["idle"] else ""
    level = "Highest" if is_admin() else "Limited"
    script = f"""
$ErrorActionPreference = 'Stop'
$a = New-ScheduledTaskAction -Execute {ps_quote(pythonw())} -Argument {ps_quote(f'"{SCRIPT}" --task {kind}')} -WorkingDirectory {ps_quote(os.path.dirname(SCRIPT))}
$t = {trigger}
$s = New-ScheduledTaskSettingsSet -StartWhenAvailable:${str(cfg['run_missed']).lower()} -AllowStartIfOnBatteries:{battery} -DontStopIfGoingOnBatteries:{battery} -ExecutionTimeLimit (New-TimeSpan -Hours 6) -MultipleInstances IgnoreNew {idle}
$p = New-ScheduledTaskPrincipal -UserId {user} -LogonType Interactive -RunLevel {level}
Register-ScheduledTask -TaskName {name} -Action $a -Trigger $t -Settings $s -Principal $p -Description 'Created by PC Guard' -Force | Out-Null
"""
    out = run_ps(script)
    if out.returncode != 0:
        err = out.stderr.strip().splitlines()
        return next((l for l in err if l.strip() and not l.startswith(("At line", "+", "#<"))), "Unknown error")
    return None


def task_info(kind):
    script = f"""
$t = Get-ScheduledTask -TaskName {ps_quote(TASK_NAMES[kind])} -ErrorAction SilentlyContinue
if ($t) {{
  $i = $t | Get-ScheduledTaskInfo
  $f = {{ param($d) if ($d -and $d.Year -gt 2000) {{ $d.ToString('dd MMM yyyy, HH:mm') }} else {{ '' }} }}
  [pscustomobject]@{{State=[string]$t.State; Next=(& $f $i.NextRunTime); Last=(& $f $i.LastRunTime); Result=[int64]$i.LastTaskResult}} | ConvertTo-Json -Compress
}}
exit 0"""
    return powershell_json(script)


def start_task(kind):
    if task_info(kind):
        run_ps(f"Start-ScheduledTask -TaskName {ps_quote(TASK_NAMES[kind])}")
    else:
        subprocess.Popen([pythonw(), SCRIPT, "--task", kind], creationflags=NO_WINDOW)


# ---------------------------------------------------------------- headless task runner

def fmt_duration(seconds):
    m, s = divmod(int(seconds), 60)
    return f"{m} min {s} s" if m else f"{s} s"


def scheduled_scan(cfg):
    mp = find_mpcmdrun()
    if not mp:
        raise RuntimeError("Microsoft Defender (MpCmdRun.exe) not found")
    start = time.time()
    if cfg.get("update_first"):
        try:
            subprocess.run([mp, "-SignatureUpdate"], capture_output=True, creationflags=NO_WINDOW, timeout=900)
        except Exception:
            pass  # Defender also updates itself; a failed update must not block the scan
    rc = subprocess.run([mp, "-Scan", "-ScanType", "2" if cfg["type"] == "Full" else "1"],
                        capture_output=True, creationflags=NO_WINDOW).returncode
    details = f"{cfg['type']} scan · {fmt_duration(time.time() - start)}"
    if rc == 0:
        add_history("Scheduled scan", "No threats found", details, "ok")
        if cfg["notify"]:
            notify("PC Guard: scan complete", f"No threats found. {details}")
    elif rc == 2:
        add_history("Scheduled scan", "Threats found and quarantined", details, "bad")
        notify("PC Guard: threats found", "Threats were found and quarantined. Open PC Guard → Threat History.")
    else:
        add_history("Scheduled scan", "Scan error", f"{details} · Defender exit code {rc}", "warn")
        if cfg["notify"]:
            notify("PC Guard: scan problem", f"The scheduled scan ended with error code {rc}.")
    if cfg.get("engine", True):
        scheduled_engine_scan(cfg)


def scheduled_engine_scan(cfg):
    """Second opinion from PC Guard's own engine, after Defender. Known malware is quarantined automatically."""
    import engine
    if load_settings()["engine"]["auto_update"] and engine.needs_update():
        try:
            engine.update()
        except Exception:
            pass  # scan with the signatures we have
    roots = engine.full_paths() if cfg["type"] == "Full" else engine.quick_paths()
    hits, n, secs = engine.scan_and_act(roots, f"Scheduled {cfg['type'].lower()} engine scan",
                                        load_settings()["engine"]["auto_quarantine"])
    malware = sum(1 for h in hits if h["signature"])
    details = f"PC Guard engine · {n:,} files · {fmt_duration(secs)}"
    if hits:
        add_history("Scheduled engine scan", f"{malware} malware, {len(hits) - malware} suspicious", details, "bad")
        notify("PC Guard: engine scan found something", f"{len(hits)} file(s) need a look. Open PC Guard → Engine scan.")
    else:
        add_history("Scheduled engine scan", "No threats found", details, "ok")


def scheduled_clean(cfg):
    drive = os.environ.get("SystemDrive", "C:") + "\\"
    free = shutil.disk_usage(drive).free
    if cfg["min_free_gb"] and free >= cfg["min_free_gb"] * 1024 ** 3:
        add_history("Scheduled cleaning", "Skipped",
                    f"{human(free)} free on {drive[:2]} (cleans below {cfg['min_free_gb']} GB)", "ok")
        return
    freed, removed, skipped, needs_admin = clean_categories(cfg["categories"], is_admin())
    details = f"{removed} files removed"
    if skipped:
        details += f", {skipped} in use skipped"
    if needs_admin:
        details += f" · needs admin: {', '.join(needs_admin)}"
    add_history("Scheduled cleaning", f"Freed {human(freed)}", details, "warn" if needs_admin else "ok")
    if cfg["notify"]:
        notify("PC Guard: cleaning complete", f"Freed {human(freed)} of junk files.")


def run_task(kind):
    os.makedirs(DATA_DIR, exist_ok=True)
    if kind == "monitor":  # long-running; keeps its own heartbeat instead of a lock
        import engine
        engine.run_monitor()
        return
    lock = os.path.join(DATA_DIR, f"{kind}.lock")
    try:
        if os.path.exists(lock) and time.time() - os.path.getmtime(lock) > 8 * 3600:
            os.remove(lock)  # stale lock from a crashed run
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
    except OSError:
        return  # the same task is already running
    label = "Scheduled scan" if kind == "scan" else "Scheduled cleaning"
    try:
        cfg = load_settings()[kind]
        scheduled_scan(cfg) if kind == "scan" else scheduled_clean(cfg)
    except Exception as e:
        add_history(label, "Failed", str(e)[:200], "bad")
        notify("PC Guard", f"{label} failed: {e}")
    finally:
        try:
            os.remove(lock)
        except OSError:
            pass
    try:  # smart alerts also run after every scheduled task, so they work without real-time monitoring
        import alerts
        alerts.run_checks()
    except Exception:
        pass
