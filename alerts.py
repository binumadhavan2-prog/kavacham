"""Kavacham smart alerts and security activity.

- Protection status: Defender real-time protection and signatures, Windows Firewall, the engine and its monitor
- Smart alerts for disabled protection, outdated signatures, failed scans and unresolved threats, with toast
  notifications that repeat at most once a day while a problem lasts
- Protection changes (something switched off or back on) recorded in the security log
- Windows Defender's own event log, merged into the activity feed
"""
import os
import time

import engine
from core import DATA_DIR, HISTORY_FILE, load_settings, notify, powershell_json, read_json, write_json

STATE_FILE = os.path.join(DATA_DIR, "alerts_state.json")
RENOTIFY = 24 * 3600

# Windows Defender Operational log: event id -> (level, title). Health heartbeats and config noise are left out.
DEFENDER_EVENTS = {
    1116: ("bad", "Defender detected a threat"), 1117: ("ok", "Defender acted on a threat"),
    1006: ("bad", "Defender found malware"), 1007: ("ok", "Defender acted on malware"),
    1008: ("warn", "Defender could not act on malware"), 1118: ("warn", "Defender could not act on a threat"),
    1119: ("warn", "Defender hit an error acting on a threat"),
    1000: ("info", "Defender scan started"), 1001: ("ok", "Defender scan finished"),
    1002: ("warn", "Defender scan stopped before completion"), 1005: ("warn", "Defender scan failed"),
    2000: ("ok", "Defender virus definitions updated"), 2001: ("warn", "Defender definition update failed"),
    2003: ("warn", "Defender engine update failed"),
    5000: ("ok", "Real-time protection turned on"), 5001: ("bad", "Real-time protection turned off"),
    5010: ("bad", "Spyware scanning turned off"), 5012: ("bad", "Virus scanning turned off"),
    5008: ("bad", "Defender engine stopped unexpectedly"),
}


def protection_status():
    """One PowerShell round trip for everything the alerts need from Windows."""
    script = (
        "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue;"
        "$fw = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ? { -not $_.Enabled } | % { [string]$_.Name });"
        "$act = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | ? { $_.ThreatStatusID -in 1,102,103,105,107 }).Count;"
        "[pscustomobject]@{Defender=[bool]$s; Rtp=[bool]$s.RealTimeProtectionEnabled; Av=[bool]$s.AntivirusEnabled;"
        " SigAge=[int]$s.AntivirusSignatureAge; FirewallOff=$fw; ActiveThreats=[int]$act} | ConvertTo-Json -Compress"
    )
    try:
        st = powershell_json(script) or {}
    except Exception:
        st = {}
    cfg = load_settings()["engine"]
    try:
        eng = engine.engine_status()
    except Exception:
        eng = {"updated": 0, "hashes": 0}
    st.update(engine_updated=eng["updated"], engine_hashes=eng["hashes"], realtime=cfg["realtime"],
              monitor=engine.monitor_running(), firewall_off=st.pop("FirewallOff", None) or [])
    return st


def check_alerts(st):
    """Active problems, most serious first. Each alert: id, level, title, detail, fix (a hint for the UI)."""
    out = []
    if st.get("Defender") is False or ("Defender" in st and not st.get("Av", True)):
        out.append(("defender_off", "bad", "Microsoft Defender antivirus is off",
                    "Your main antivirus isn't running. Turn it on in Windows Security.", "windows_security"))
    elif "Rtp" in st and not st["Rtp"]:
        out.append(("rtp_off", "bad", "Defender real-time protection is off",
                    "Files aren't checked as they open. Turn it back on in Windows Security.", "windows_security"))
    if st["firewall_off"]:
        out.append(("firewall_off", "bad", f"Windows Firewall is off ({', '.join(st['firewall_off'])})",
                    "Your PC is open to incoming network connections.", "firewall"))
    if st.get("ActiveThreats"):
        out.append(("active_threats", "bad", f"{st['ActiveThreats']} threat(s) need attention",
                    "Defender found threats that haven't been removed yet.", "threats"))
    if st["realtime"] and not st["monitor"]:
        out.append(("monitor_down", "bad", "Kavacham real-time monitoring has stopped",
                    "It's switched on but not running. Kavacham will restart it.", "engine"))
    if st.get("SigAge", 0) > 3:
        out.append(("defender_sigs", "warn", f"Defender virus definitions are {st['SigAge']} days old",
                    "Update them so new threats are recognised.", "update_defender"))
    age = time.time() - st["engine_updated"] if st["engine_updated"] else None
    if age is None:
        out.append(("engine_sigs", "warn", "Kavacham engine has no signatures yet",
                    "Download the threat feeds (about 45 MB, once).", "engine"))
    elif age > 2 * 86400:
        out.append(("engine_sigs", "warn", f"Kavacham engine signatures are {int(age // 86400)} days old",
                    "Update the threat feeds.", "engine"))
    week = time.time() - 7 * 86400
    for h in read_json(HISTORY_FILE, [])[:50]:
        try:
            when = time.mktime(time.strptime(h["time"], "%d %b %Y %H:%M"))
        except (ValueError, KeyError):
            continue
        if when < week:
            break
        if h["task"].startswith("Scheduled") and (h["result"] in ("Failed", "Cancelled") or
                                                   h["result"].startswith("Scan error")):
            out.append(("failed_scan", "warn", f"{h['task']} failed on {h['time']}",
                        h.get("details", "")[:160] or "Check the Automation page.", "schedule"))
            break
    return [{"id": i, "level": lv, "title": t, "detail": d, "fix": f} for i, lv, t, d, f in out]


def record_changes(st, state):
    """Log protection switched off/on since the last check."""
    prev = state.get("snapshot")
    snap = {"rtp": st.get("Rtp"), "firewall_off": sorted(st["firewall_off"]),
            "monitor": st["monitor"] if st["realtime"] else None}
    if prev:
        if prev.get("rtp") is not None and snap["rtp"] is not None and prev["rtp"] != snap["rtp"]:
            engine.log_event("protection", "ok" if snap["rtp"] else "bad",
                             f"Defender real-time protection turned {'on' if snap['rtp'] else 'off'}")
        if prev.get("firewall_off") != snap["firewall_off"]:
            off = snap["firewall_off"]
            engine.log_event("protection", "bad" if off else "ok",
                             f"Windows Firewall off for {', '.join(off)}" if off else "Windows Firewall back on")
        if prev.get("monitor") is not None and snap["monitor"] is not None and prev["monitor"] != snap["monitor"]:
            engine.log_event("protection", "ok" if snap["monitor"] else "bad",
                             "Kavacham monitoring " + ("running again" if snap["monitor"] else "stopped unexpectedly"))
    state["snapshot"] = snap


def run_checks(send=True):
    """Check everything, log changes, toast new alerts (once a day per alert). Returns (status, alerts)."""
    st = protection_status()
    alerts = check_alerts(st)
    state = read_json(STATE_FILE, {})
    record_changes(st, state)
    notified = state.get("notified", {})
    now = time.time()
    active = {a["id"] for a in alerts}
    for gone in [k for k in notified if k not in active]:
        notified.pop(gone)
        engine.log_event("protection", "ok", "Resolved: " + gone.replace("_", " "))
    if send and load_settings()["alerts"]["enabled"]:
        for a in alerts:
            if now - notified.get(a["id"], 0) > RENOTIFY:
                notify(f"Kavacham: {a['title']}", a["detail"])
                engine.log_event("alert", a["level"], a["title"], a["detail"])
                notified[a["id"]] = now
    state["notified"] = notified
    write_json(STATE_FILE, state)
    if st["realtime"] and not st["monitor"]:
        engine.start_monitor()  # self-heal: the alert above says Kavacham restarts it
    return st, alerts


def defender_events(days=14, limit=300):
    """Windows Defender's own log as security-log style events."""
    ids = ",".join(str(i) for i in DEFENDER_EVENTS)
    script = (
        "$e = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';"
        f" Id={ids}; StartTime=(Get-Date).AddDays(-{int(days)})}} -MaxEvents {int(limit)} -ErrorAction SilentlyContinue"
        " | % { [pscustomobject]@{Id=$_.Id; T=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss');"
        " M=(($_.Message -split \"`n\") | ? { $_ -match 'Name:|Path:|Scan Type:|Security intelligence Version:' } |"
        " % { $_.Trim() }) -join ' · '} });"
        "ConvertTo-Json -InputObject $e -Compress"
    )
    try:
        rows = powershell_json(script) or []
    except Exception:
        return []
    out = []
    for r in rows:
        level, title = DEFENDER_EVENTS.get(r["Id"], ("info", f"Defender event {r['Id']}"))
        out.append({"time": r["T"], "category": "system", "level": level, "title": title,
                    "details": (r.get("M") or "")[:400]})
    return out


def summary(events, days=7):
    """Counts for the activity page header, from the security log."""
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days * 86400))
    recent = [e for e in events if e["time"] >= since]
    return {
        "scans": sum(1 for e in recent if e["category"] == "scan" and "started" not in e["title"]),
        "detections": sum(1 for e in recent if e["category"] == "detection" and e["level"] in ("bad", "warn")),
        "quarantined": sum(1 for e in recent if e["category"] == "quarantine" and e["title"].startswith("Quarantined")),
        "links": sum(1 for e in recent if e["category"] == "url"),
    }
