# Kavacham

**Created by Binu Madhavan.**

A security and cleanup app for Windows. It runs Microsoft Defender scans alongside its own scanning engine, adds privacy alerts and a security checkup, and cleans up junk files, all in one desktop app.

*Kavacham* (കവചം) means "armour" in Malayalam.

## What it does

- **Virus scanning:** quick and full Microsoft Defender scans, plus Kavacham's own engine:
  - SHA-256 fingerprints matched against a local signature database (MalwareBazaar)
  - heuristic rules for suspicious files: disguised programs, hostile scripts, auto-running macros, shortcuts that secretly run commands
  - quarantine that neutralises files so they can't run, and can restore them
- **Real-time protection:** watches folders you choose and checks new downloads as they arrive.
- **Link checking:** URL reputation from threat feeds (URLhaus, OpenPhish) plus heuristics for fake login pages.
- **USB drives:** scans drives when you plug them in.
- **Phone care:** scans an Android phone over USB or Wi-Fi with ADB, or over a plain file transfer connection.
- **Security checkup:** finds weak settings and fixes them in one click.
- **Privacy alerts:** tells you when an app starts using your camera or microphone.
- **Cleanup:** junk and temporary files, large files and duplicate files, with a Kavacham bin so nothing is lost by accident.
- **Schedules:** runs scans and cleanups through Windows Task Scheduler.
- **Event log:** a history of everything it found and did.

## Run it

Requires Windows 10 or 11 and Python 3.11 or newer. The interface is Tkinter, from Python's standard library. Pillow and NumPy are optional: they add the richer cleaning animation and photo previews when scanning a phone.

```bash
pip install pillow numpy   # optional
python pc_guard.py
```

Some actions (Defender scans, the security checkup fixes, scheduled tasks) ask for administrator rights.

Optional:

- **Threat feeds:** abuse.ch (MalwareBazaar, URLhaus) needs a free Auth-Key since October 2026. Get one at <https://auth.abuse.ch/> and paste it into the engine settings. OpenPhish needs no key.
- **Phone scanning over ADB:** install Android's [platform tools](https://developer.android.com/tools/releases/platform-tools) and turn on USB debugging on the phone.

## Where it keeps its data

Settings, history, the signature database and quarantined files are stored in `%LOCALAPPDATA%\PCGuard` on your own PC. Your abuse.ch key is stored encrypted for your Windows account.

## Project layout

| File | What it holds |
| --- | --- |
| `pc_guard.py` | Entry point (the app, or a scheduled task with `--task`) |
| `ui.py` | The desktop interface |
| `core.py` | Defender scanning, junk cleaning, Task Scheduler and settings |
| `engine.py` | Kavacham's own engine: signatures, heuristics, quarantine, URL reputation, feeds |
| `security.py` | Security checkup |
| `privacy.py` | Camera and microphone alerts |
| `usb.py`, `phone.py` | USB drive and phone scanning |
| `alerts.py`, `explain.py` | Notifications and plain-language explanations of findings |
