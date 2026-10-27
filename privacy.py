"""Kavacham privacy: camera & microphone alerts and a privacy checkup of Windows' own settings.

Camera and microphone use is read from the record Windows itself keeps for its privacy indicator (the
CapabilityAccessManager registry keys): which app last used each device, when it started and stopped. An app whose
"stop" time is still zero is using the device right now. Nothing is recorded or sent anywhere.
"""
import ctypes
import os
import re
import threading
import time
import winreg

import engine
from core import notify, powershell_json, run_ps
from security import _check, _run_elevated

CONSENT = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
DEVICES = {"webcam": "camera", "microphone": "microphone"}
# Store apps whose package name doesn't say what they are
KNOWN_APPS = {"windowscamera": "Camera", "screensketch": "Snipping Tool", "xboxgamingoverlay": "Xbox Game Bar",
              "immersivecontrolpanel": "Windows Settings", "windowssoundrecorder": "Sound Recorder",
              "skypeapp": "Skype", "msteams": "Microsoft Teams", "whatsappdesktop": "WhatsApp",
              "svchost": "Windows service"}
_names = {}


# ---------------------------------------------------------------- camera & microphone

def _filetime(v):
    return v / 1e7 - 11644473600 if v else 0


def _file_description(path):
    """The program's own name from its version info ("Google Chrome" for chrome.exe), or None."""
    try:
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return None
        ptr, n = ctypes.c_void_p(), ctypes.c_uint()
        if not ver.VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(ptr), ctypes.byref(n)) or n.value < 4:
            return None
        lang, cp = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ushort * 2)).contents
        if ver.VerQueryValueW(buf, rf"\StringFileInfo\{lang:04x}{cp:04x}\FileDescription", ctypes.byref(ptr),
                              ctypes.byref(n)) and n.value > 1:
            return ctypes.wstring_at(ptr, n.value - 1).strip() or None
    except Exception:
        pass
    return None


def app_name(app_id):
    """A readable name for a registry entry: a Store package or a program path written with '#' for '\\'."""
    if app_id in _names:
        return _names[app_id]
    if "#" in app_id:
        path = app_id.replace("#", "\\")
        stem = os.path.splitext(os.path.basename(path))[0]
        name = KNOWN_APPS.get(stem.lower()) or _file_description(path) or stem
    else:
        part = app_id.split("_")[0].split(".")[-1]
        name = KNOWN_APPS.get(part.lower()) or re.sub(r"(?<=[a-z])(?=[A-Z])", " ", part)
    _names[app_id] = name
    return name


def _subkeys(hive, path):
    try:
        with winreg.OpenKey(hive, path) as k:
            return [winreg.EnumKey(k, i) for i in range(winreg.QueryInfoKey(k)[0])]
    except OSError:
        return []


def _entries(hive, device):
    """(app id, start, stop) for every app Windows recorded using this device: Store apps directly under the
    device key, desktop programs under NonPackaged."""
    base = rf"{CONSENT}\{device}"
    for path in (base, rf"{base}\NonPackaged"):
        for name in _subkeys(hive, path):
            if name == "NonPackaged":
                continue
            try:
                with winreg.OpenKey(hive, rf"{path}\{name}") as k:
                    start = winreg.QueryValueEx(k, "LastUsedTimeStart")[0]
                    stop = winreg.QueryValueEx(k, "LastUsedTimeStop")[0]
            except OSError:
                continue
            yield name, start, stop


def usage():
    """Every app that has used the camera or microphone: [{"id", "name", "path", "camera", "microphone"}], where
    each device is {"start", "stop", "in_use"} or None. Apps using something right now come first."""
    apps = {}
    for device, key in DEVICES.items():
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for app_id, start, stop in _entries(hive, device):
                a = apps.setdefault(app_id, {"id": app_id, "name": app_name(app_id),
                                             "path": app_id.replace("#", "\\") if "#" in app_id else "",
                                             "camera": None, "microphone": None})
                old = a[key]
                if old is None or _filetime(start) > old["start"]:
                    a[key] = {"start": _filetime(start), "stop": _filetime(stop), "in_use": bool(start) and not stop}
    rows = list(apps.values())

    def order(a):
        uses = [a[k] for k in ("camera", "microphone") if a[k]]
        return (not any(u["in_use"] for u in uses), -max((u["start"] for u in uses), default=0))
    rows.sort(key=order)
    return rows


def in_use(rows=None):
    """[(app row, "camera" / "microphone")] for whatever is using a device right now."""
    return [(a, k) for a in (usage() if rows is None else rows) for k in ("camera", "microphone")
            if a[k] and a[k]["in_use"]]


class Watcher:
    """Call step() every few seconds: alerts once each time an app starts using the camera or microphone."""

    def __init__(self):
        self.seen = {(a["id"], k, a[k]["start"]) for a, k in in_use()}  # already on when we started: no alert

    def step(self, trusted=()):
        now = in_use()
        current = {(a["id"], k, a[k]["start"]) for a, k in now}
        fresh = [(a, k) for a, k in now if (a["id"], k, a[k]["start"]) not in self.seen]
        self.seen = current
        by_app = {}
        for a, k in fresh:
            by_app.setdefault(a["id"], (a, []))[1].append(k)
        for app_id, (a, kinds) in by_app.items():
            what = " and ".join(kinds)
            trusted_app = app_id in trusted
            engine.log_event("privacy", "info" if trusted_app else "warn", f"{a['name']} started using your {what}",
                             a["path"] or app_id)
            if not trusted_app:
                threading.Thread(target=notify, daemon=True, args=(
                    f"Kavacham: {what} turned on",
                    f"{a['name']} is using your {what}. Not you? Open Kavacham → Privacy to close it.")).start()
        return [a for a, _k in fresh]


def close_app(path):
    """End every running copy of a desktop program. Returns how many were closed."""
    out = run_ps("$n = 0; Get-Process | ? { $_.Path -eq $env:PCG_PATH } | % { Stop-Process -Id $_.Id -Force; $n++ }; "
                 "$n", env={**os.environ, "PCG_PATH": path}, timeout=60)
    try:
        n = int(out.stdout.strip() or 0)
    except ValueError:
        n = 0
    engine.log_event("privacy", "ok" if n else "warn", f"{'Closed' if n else 'Could not close'} "
                                                       f"{os.path.basename(path)}", path)
    return n


# ---------------------------------------------------------------- privacy checkup

HKCU, HKLM = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE


def _reg(hive, path, name, default=None):
    try:
        with winreg.OpenKey(hive, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default


def _set(path, name, value):
    """PowerShell that sets one per-user DWORD (creating the key if needed)."""
    return f"New-Item -Path 'HKCU:\\{path}' -Force -ErrorAction SilentlyContinue | Out-Null; " \
           f"Set-ItemProperty -Path 'HKCU:\\{path}' -Name '{name}' -Value {value} -Type DWord"


ADV = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
# fix id -> (PowerShell to run, needs admin). "open:" fixes open a Windows Settings page instead.
FIXES = {
    "samples": ("Set-MpPreference -SubmitSamplesConsent 0", True),
    "adid": (_set(r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0), False),
    "tailored": (_set(r"Software\Microsoft\Windows\CurrentVersion\Privacy",
                      "TailoredExperiencesWithDiagnosticDataEnabled", 0), False),
    "inking": ("; ".join([_set(r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1),
                          _set(r"Software\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", 1),
                          _set(r"Software\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", 0),
                          _set(r"Software\Microsoft\Personalization\Settings", "AcceptedPrivacyPolicy", 0)]), False),
    "language": (_set(r"Control Panel\International\User Profile", "HttpAcceptLanguageOptOut", 1), False),
    "trackprogs": (_set(ADV, "Start_TrackProgs", 0), False),
    "speech": (_set(r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy", "HasAccepted", 0), False),
    "cloudclip": (_set(r"Software\Microsoft\Clipboard", "EnableCloudClipboard", 0), False),
    "lockscreen": (_set(r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
                        "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK", 0), False),
    "suggestions": ("; ".join(_set(r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", v, 0) for v in
                              ("SubscribedContent-338393Enabled", "SubscribedContent-353694Enabled",
                               "SubscribedContent-353696Enabled", "SubscribedContent-338388Enabled",
                               "SystemPaneSuggestionsEnabled")), False),
    "remoteassist": ("Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' "
                     "fAllowToGetHelp 0 -Type DWord", True),
    "telemetry": ("open:ms-settings:privacy-feedback", False),
    "location": ("open:ms-settings:privacy-location", False),
    "camera": ("open:ms-settings:privacy-webcam", False),
    "microphone": ("open:ms-settings:privacy-microphone", False),
    "watch": ("kavacham:watch", False),  # switched on inside Kavacham
}


def run_checks(watch_on=True):
    """Returns {"score": 0-100, "checks": [...], "time": epoch}; same rows as the security checkup."""
    out = []
    add = out.append
    add(_check("watch", "Camera & microphone alerts", watch_on,
               "Kavacham tells you whenever an app turns on your camera or microphone.",
               "Off: an app could watch or listen without you noticing.", 10, "watch"))
    samples = _reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SubmitSamplesConsent")
    if samples is None:  # the registry answers instantly; Get-MpPreference can take 10+ seconds
        samples = _reg(HKLM, r"SOFTWARE\Microsoft\Windows Defender\Spynet", "SubmitSamplesConsent")
    if samples is None:
        try:
            samples = powershell_json("(Get-MpPreference).SubmitSamplesConsent")
        except Exception:
            samples = None
    add(_check("samples", "Defender sends files to Microsoft", samples in (0, 2),
               "Microsoft Defender asks before sending any of your files to Microsoft." if samples == 0 else
               "Microsoft Defender never sends your files to Microsoft.",
               "Defender uploads suspicious files to Microsoft by itself" +
               (", including documents." if samples == 3 else " (it asks first only for documents)."), 8, "samples",
               status=None if samples is not None else "na"))
    tele = _reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry")
    if tele is None:
        tele = _reg(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 3)
    add(_check("telemetry", "Diagnostic data", tele is not None and tele <= 1,
               "Only the required minimum is sent to Microsoft.",
               "Optional diagnostic data is on: details about the sites you browse and how you use apps are sent to "
               "Microsoft. Turn off \"Send optional diagnostic data\".", 7, "telemetry"))
    add(_check("tailored", "Tailored experiences", _reg(HKCU, r"Software\Microsoft\Windows\CurrentVersion\Privacy",
                                                        "TailoredExperiencesWithDiagnosticDataEnabled", 1) == 0,
               "Microsoft doesn't use your diagnostic data for personal tips and ads.",
               "On: Microsoft uses your diagnostic data for personalised tips, ads and offers.", 5, "tailored"))
    add(_check("adid", "Advertising ID", _reg(HKCU, r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                                              "Enabled", 1) == 0,
               "Apps can't follow you with an advertising ID.",
               "On: apps share an ID that lets advertisers track you across apps.", 6, "adid"))
    inking = (_reg(HKCU, r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 0) == 1 and
              _reg(HKCU, r"Software\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", 0) == 1)
    add(_check("inking", "Typing & handwriting data", inking,
               "What you type and write isn't collected to build a personal dictionary.",
               "On: Windows collects words you type and write to build a personal dictionary.", 5, "inking"))
    add(_check("speech", "Online speech recognition",
               _reg(HKCU, r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy", "HasAccepted", 0) != 1,
               "Your voice isn't sent to Microsoft's online speech service.",
               "On: what you say to voice typing is sent to Microsoft's cloud.", 5, "speech"))
    add(_check("cloudclip", "Clipboard sync", _reg(HKCU, r"Software\Microsoft\Clipboard", "EnableCloudClipboard", 0) != 1,
               "What you copy stays on this PC.",
               "On: everything you copy (including passwords) is synced to Microsoft's cloud.", 6, "cloudclip"))
    add(_check("lockscreen", "Notifications on the lock screen",
               _reg(HKCU, r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
                    "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK", 1) == 0,
               "Messages don't show while the PC is locked.",
               "On: anyone near the locked laptop can read new messages and alerts.", 5, "lockscreen"))
    add(_check("language", "Websites see your language list",
               _reg(HKCU, r"Control Panel\International\User Profile", "HttpAcceptLanguageOptOut", 0) == 1,
               "Websites can't read your list of languages.",
               "On: websites can read your language list, which helps them fingerprint you.", 3, "language"))
    add(_check("trackprogs", "App launch tracking", _reg(HKCU, ADV, "Start_TrackProgs", 1) == 0,
               "Windows doesn't record which apps you open.",
               "On: Windows records which apps you open to personalise Start and search.", 2, "trackprogs"))
    cdm = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    add(_check("suggestions", "Suggestions & ads in Windows",
               all(_reg(HKCU, cdm, v, 1) == 0 for v in ("SubscribedContent-338393Enabled",
                                                        "SubscribedContent-353694Enabled", "SystemPaneSuggestionsEnabled")),
               "No suggested content or app ads in Settings and Start.",
               "On: Windows shows suggested content and app ads based on how you use the PC.", 3, "suggestions"))
    add(_check("remoteassist", "Remote Assistance",
               _reg(HKLM, r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", 1) == 0,
               "Nobody can be invited to see or control this PC.",
               "On: a helper can be invited to see and control this PC. Scammers ask for this.", 6, "remoteassist"))
    loc = _reg(HKCU, rf"{CONSENT}\location", "Value", "Allow") == "Deny" or \
        _reg(HKLM, rf"{CONSENT}\location", "Value", "Allow") == "Deny"
    add(_check("location", "Location", loc, "Apps can't see where you are.",
               "On: apps you allowed can see your location. Check which ones in Settings.", 3, "location"))
    counted = [c for c in out if c["status"] != "na"]
    total = sum(c["weight"] for c in counted) or 1
    score = round(100 * sum(c["weight"] for c in counted if c["status"] == "ok") / total)
    return {"score": score, "checks": out, "time": time.time()}


def apply_fix(fix_id):
    """Applies one fix. Returns "done", "opened" (a Settings page was opened) or "failed"."""
    script, admin = FIXES[fix_id]
    if script.startswith("open:"):
        os.startfile(script[5:])
        return "opened"
    ok = _run_elevated(script) if admin else run_ps(script, timeout=120).returncode == 0
    engine.log_event("privacy", "ok" if ok else "warn", f"Privacy checkup: {'fixed' if ok else 'could not fix'} {fix_id}")
    return "done" if ok else "failed"
