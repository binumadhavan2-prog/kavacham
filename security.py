"""Kavacham security checkup: a score from Windows' own security settings, one-click fixes and the ransomware shield.

Everything here reads or changes built-in Windows features (Defender, the registry, Settings pages); nothing leaves
the PC. Settings that need administrator rights are changed through a single elevated PowerShell (UAC prompt).
"""
import base64
import subprocess
import time
from datetime import datetime

import engine
from core import NO_WINDOW, is_admin, powershell_json, run_ps

_READ = r"""
$ErrorActionPreference = 'SilentlyContinue'
$p = Get-MpPreference; $s = Get-MpComputerStatus
function reg($path, $name) { (Get-ItemProperty -Path $path -Name $name).$name }
# registry reads instead of Get-NetFirewallProfile / Get-SmbServerConfiguration: same answer, seconds faster
$fwk = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
$fw = @(@{Domain='DomainProfile'; Private='StandardProfile'; Public='PublicProfile'}.GetEnumerator() |
        ? { (reg "$fwk\$($_.Value)" 'EnableFirewall') -eq 0 } | % { $_.Key })
$smbsvc = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
$smb1 = ((reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1') -eq 1) -or
        ((Test-Path $smbsvc) -and (reg $smbsvc 'Start') -ne 4)
$patch = (Get-HotFix | ? InstalledOn | sort InstalledOn -Desc | select -First 1).InstalledOn
[pscustomobject]@{
  Defender = [bool]$s.AntivirusEnabled; RTP = [bool]$s.RealTimeProtectionEnabled; Tamper = [bool]$s.IsTamperProtected
  SigAge = [int]$s.AntivirusSignatureAge; CFA = [int]$p.EnableControlledFolderAccess; PUA = [int]$p.PUAProtection
  FirewallOff = $fw
  SmartScreen = [string](reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')
  SmartScreenPolicy = (reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen')
  LUA = (reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')
  Consent = (reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin')
  RDPDeny = (reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections')
  Autoplay = (reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' 'DisableAutoplay')
  HideExt = (reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt')
  SecureBoot = (reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled')
  HVCI = (reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled')
  BitLocker = (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
  Guest = (Get-LocalUser -Name Guest).Enabled
  SMB1 = $smb1
  PatchDays = if ($patch) { [int]((Get-Date) - $patch).TotalDays } else { $null }
  Reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
} | ConvertTo-Json -Compress
"""

# fix id -> (PowerShell to run, needs admin). "open:" fixes open a Windows Settings page instead.
FIXES = {
    "rtp": ("Set-MpPreference -DisableRealtimeMonitoring $false", True),
    "firewall": ("Set-NetFirewallProfile -All -Enabled True", True),
    "cfa": ("Set-MpPreference -EnableControlledFolderAccess Enabled", True),
    "cfa_off": ("Set-MpPreference -EnableControlledFolderAccess Disabled", True),
    "pua": ("Set-MpPreference -PUAProtection Enabled", True),
    "sigs": ("Update-MpSignature", False),
    "uac": ("$k='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; "
            "Set-ItemProperty $k EnableLUA 1 -Type DWord; Set-ItemProperty $k ConsentPromptBehaviorAdmin 5 -Type DWord",
            True),
    "rdp": ("Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' fDenyTSConnections 1 "
            "-Type DWord", True),
    "guest": ("Disable-LocalUser -Name Guest", True),
    "smb1": ("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; "
             "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart", True),
    "autoplay": ("$k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers'; "
                 "New-Item $k -Force | Out-Null; Set-ItemProperty $k DisableAutoplay 1 -Type DWord", False),
    "extensions": ("Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' "
                   "HideFileExt 0 -Type DWord", False),
    "smartscreen": ("open:windowsdefender://appbrowser", False),
    "tamper": ("open:windowsdefender://threatsettings", False),
    "update": ("open:ms-settings:windowsupdate", False),
    "encryption": ("open:ms-settings:deviceencryption", False),
    "hvci": ("open:windowsdefender://coreisolation", False),
}


def _check(cid, title, ok, good, bad, weight, fix=None, status=None):
    """One checklist row. status overrides ok: 'na' rows are shown but don't count toward the score."""
    st = status or ("ok" if ok else ("bad" if weight >= 8 else "warn"))
    return {"id": cid, "title": title, "status": st, "detail": good if st == "ok" else bad, "weight": weight,
            "fix": None if st in ("ok", "na") else fix}


def run_checks():
    """Returns {"score": 0-100, "checks": [...], "cfa": 0 off / 1 on / 2 audit, "time": epoch}."""
    s = powershell_json(_READ) or {}
    out = []
    add = out.append
    add(_check("rtp", "Real-time virus protection", s.get("Defender") and s.get("RTP"),
               "Microsoft Defender checks files as they're opened.",
               "Real-time protection is off, so new malware isn't stopped as it arrives.", 15, "rtp"))
    off = s.get("FirewallOff") or []
    add(_check("firewall", "Windows Firewall", not off, "On for every network type.",
               f"Off for {', '.join(off)} networks: other devices could reach this PC.", 12, "firewall"))
    cfa = s.get("CFA") or 0
    add(_check("cfa", "Ransomware shield", cfa == 1,
               "Unknown programs can't change your Documents, Pictures and Desktop.",
               "Off: ransomware that slips past antivirus could lock your personal files." if cfa != 2 else
               "Only watching (audit mode): attempts are logged but not blocked.", 10, "cfa"))
    add(_check("sigs", "Virus definitions", (s.get("SigAge") or 0) <= 3,
               "Up to date.", f"{s.get('SigAge')} days old: recent threats may be missed.", 8, "sigs"))
    add(_check("tamper", "Tamper protection", s.get("Tamper"),
               "Malware can't switch Defender off behind your back.",
               "Off: malicious programs could change Defender's settings.", 8, "tamper"))
    days = s.get("PatchDays")
    patched = days is not None and days <= 45 and not s.get("Reboot")
    add(_check("update", "Windows updates", patched,
               f"Last security update installed {days} days ago." if days is not None else "Up to date.",
               "A restart is needed to finish installing updates." if s.get("Reboot") else
               f"No update installed for {days} days: known holes stay open." if days is not None else
               "Couldn't tell when Windows was last updated.", 10, "update"))
    bl = s.get("BitLocker")
    add(_check("encryption", "Disk encryption", bl in (1, 3),
               "Your disk is encrypted: a stolen laptop doesn't expose your files.",
               "Not encrypted: anyone who takes the laptop can read the disk.", 8, "encryption",
               status=None if bl in (1, 2, 3) else "na"))
    pol = s.get("SmartScreenPolicy")
    ss_on = (s.get("SmartScreen") or "").lower() != "off" and pol != 0
    add(_check("smartscreen", "SmartScreen", ss_on,
               "Warns before unknown downloaded apps and dangerous sites run (checks them with Microsoft).",
               "Off: unknown downloaded apps run without a warning.", 6, "smartscreen"))
    add(_check("uac", "User Account Control", s.get("LUA") == 1 and s.get("Consent") not in (0,),
               "Apps must ask before making system changes.",
               "Off or never notifies: programs can change the system silently.", 8, "uac"))
    add(_check("pua", "Block unwanted apps", s.get("PUA") == 1,
               "Adware, bundled toolbars and crypto-miners are blocked.",
               "Off: adware and bundled junk can install freely.", 4, "pua"))
    add(_check("extensions", "Show file extensions", s.get("HideExt") == 0,
               "Full names are shown, so 'invoice.pdf.exe' can't pass as a PDF.",
               "Hidden: a program named 'invoice.pdf.exe' looks like a harmless 'invoice.pdf'.", 5, "extensions"))
    add(_check("autoplay", "AutoPlay off", s.get("Autoplay") == 1,
               "USB drives and discs don't start anything by themselves.",
               "On: plugging in a USB drive can pop up and run things straight away.", 3, "autoplay"))
    add(_check("rdp", "Remote Desktop closed", s.get("RDPDeny") != 0,
               "Nobody can sign in to this PC remotely.",
               "Open: attackers on the network can try passwords on this PC.", 6, "rdp"))
    add(_check("guest", "Guest account off", not s.get("Guest"), "Disabled.",
               "Enabled: anyone can use this PC without a password.", 4, "guest"))
    add(_check("smb1", "Old file sharing (SMBv1) off", not s.get("SMB1"), "Disabled.",
               "On: the outdated protocol that WannaCry ransomware spread through.", 6, "smb1"))
    add(_check("secureboot", "Secure Boot", s.get("SecureBoot") == 1,
               "Only trusted software can start before Windows.",
               "Off: hidden boot-level malware (rootkits) could load. It's switched on in the PC's BIOS setup.",
               4, None, status=None if s.get("SecureBoot") is not None else "na"))
    add(_check("hvci", "Memory integrity", s.get("HVCI") == 1,
               "Core isolation blocks malicious drivers.",
               "Off: malware drivers could hide in the core of Windows.", 4, "hvci"))
    counted = [c for c in out if c["status"] != "na"]
    total = sum(c["weight"] for c in counted) or 1
    score = round(100 * sum(c["weight"] for c in counted if c["status"] == "ok") / total)
    return {"score": score, "checks": out, "cfa": cfa, "time": time.time()}


def _run_elevated(script):
    """Runs PowerShell as administrator (UAC prompt) and waits. Returns True if it ran."""
    if is_admin():
        return run_ps(script, timeout=180).returncode == 0
    enc = base64.b64encode(("$ErrorActionPreference='Stop'; " + script).encode("utf-16-le")).decode()
    outer = ("try { $p = Start-Process powershell -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList "
             f"'-NoProfile','-NonInteractive','-EncodedCommand','{enc}'; exit $p.ExitCode }} catch {{ exit 1223 }}")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", outer], capture_output=True,
                           creationflags=NO_WINDOW, stdin=subprocess.DEVNULL, timeout=300)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def apply_fix(fix_id):
    """Applies one fix. Returns "done", "opened" (a Settings page was opened) or "failed"."""
    script, admin = FIXES[fix_id]
    if script.startswith("open:"):
        import os
        os.startfile(script[5:])
        return "opened"
    ok = _run_elevated(script) if admin else run_ps(script, timeout=180).returncode == 0
    if ok and fix_id == "extensions":
        _refresh_explorer()
    engine.log_event("protection", "ok" if ok else "warn",
                     f"Security checkup: {'fixed' if ok else 'could not fix'} {fix_id}")
    return "done" if ok else "failed"


def _refresh_explorer():
    """Tell open Explorer windows that settings changed, so extensions appear without signing out."""
    try:
        import ctypes
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)  # SHCNE_ASSOCCHANGED
    except Exception:
        pass


# ---------------------------------------------------------------- ransomware shield

def blocked_apps(days=30, limit=200):
    """Programs Controlled folder access stopped: [{"time", "app", "file"}], newest first."""
    script = (f"$since=(Get-Date).AddDays(-{int(days)}); @(Get-WinEvent -FilterHashtable @{{LogName="
              "'Microsoft-Windows-Windows Defender/Operational'; Id=1123,1124; StartTime=$since} "
              f"-MaxEvents {int(limit)} -ErrorAction SilentlyContinue | % {{ $x=[xml]$_.ToXml(); "
              "$d=@{}; $x.Event.EventData.Data | % { $d[$_.Name]=$_.'#text' }; [pscustomobject]@{"
              "Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); App=$d['Process Name']; File=$d['Path']} }) | "
              "ConvertTo-Json -Compress")
    rows = powershell_json(script) or []
    if isinstance(rows, dict):
        rows = [rows]
    return [{"time": r.get("Time", ""), "app": r.get("App") or "", "file": r.get("File") or ""} for r in rows]


def allowed_apps():
    rows = powershell_json("@((Get-MpPreference).ControlledFolderAccessAllowedApplications) | ConvertTo-Json "
                           "-Compress") or []
    rows = [rows] if isinstance(rows, str) else rows
    return [r for r in rows if r and not r.startswith("N/A")]  # non-admins get an "N/A: must be admin" line


def allow_app(path):
    ok = _run_elevated(f"Add-MpPreference -ControlledFolderAccessAllowedApplications '{path.replace(chr(39), chr(39) * 2)}'")
    engine.log_event("protection", "ok" if ok else "warn",
                     f"Ransomware shield: {'allowed' if ok else 'could not allow'} {path}")
    return ok


def set_shield(on):
    return apply_fix("cfa" if on else "cfa_off") == "done"


def checked_ago(result):
    if not result:
        return ""
    return datetime.fromtimestamp(result["time"]).strftime("checked %H:%M")
