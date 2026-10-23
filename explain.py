"""Kavacham plain-language explanations: turns the engine's detection reasons into simple words and next steps.

Works fully offline. Every reason string the engine, link checker and USB/phone scanner can produce is matched
by one rule below; anything new falls back to a generic line, so an unknown reason never breaks the dialog.
"""
import re

# (regex on the reason, what it means in plain words, what to do). Checked in order; first match wins.
RULES = [
    # -- known threats
    (r"^Matches known malware", "This exact file is on a list of confirmed malware. It is not a guess: the "
     "same file has already harmed other computers.", "Quarantine it. Don't open or run it."),
    (r"^Microsoft Defender", "Microsoft Defender, the antivirus built into Windows, also recognises this as a threat. "
     "Two separate checks agree.", "Quarantine it."),
    (r"^Known stalkerware", "This is a known spy app. It's made to secretly track messages, location or calls, "
     "usually installed by someone who had the phone in their hands.",
     "Uninstall it. If you didn't install it, think about who had access to the phone and change your passwords "
     "from a different device."),
    (r"^Downloaded from a known malicious site", "The website this file came from is on a list of sites that "
     "spread malware.", "Delete or quarantine the download, and don't go back to that site."),
    # -- disguised files
    (r"right-to-left character", "The name contains an invisible character that flips the text, so "
     "'photo_exe.jpg' can really be a program. Normal files never do this.", "Quarantine it."),
    (r"^Double extension", "The name ends in something like '.pdf.exe'. Windows hides the last part, so it looks "
     "like a document but is really a program.", "Don't open it. Quarantine it."),
    (r"^A program disguised as", "The file pretends to be a document or picture, but it is actually a program "
     "that would run when opened.", "Don't open it. Quarantine it."),
    # -- programs and where they live
    (r"^Program in the Startup folder", "This program starts automatically every time you sign in. Some real "
     "apps do this, but malware does it to stay running.",
     "If you don't recognise the program, quarantine it."),
    (r"^Script in the Startup folder", "A script runs automatically every time you sign in. Ordinary users rarely "
     "have these.", "If you didn't set it up, quarantine it."),
    (r"^Program in a folder malware often uses", "The program is in a temporary or hidden app folder, a common "
     "hiding place for malware. Installers also sometimes leave files there.",
     "If you didn't just install something, quarantine it."),
    (r"\(packed\)", "The program is compressed or scrambled so its contents can't be read. Some honest software "
     "does this, but malware uses it to hide from antivirus.", "Only keep it if it comes from a source you trust."),
    (r"^Not digitally signed", "There's no publisher's digital signature, so there's no way to confirm who made it. "
     "Many small free tools are unsigned, so on its own this isn't a problem.",
     "Only a concern together with other warnings."),
    (r"^Signed by", "The program carries a publisher's digital signature, so it hasn't been changed since they "
     "published it.", "Check the publisher name is one you expect."),
    # -- scripts
    (r"encoded PowerShell", "It runs a PowerShell command written in scrambled form so nobody can read what it "
     "does. Legitimate scripts have no reason to hide like this.", "Quarantine it."),
    (r"Base64", "It unpacks hidden content that is stored in encoded form.", "Be careful, especially together with "
     "other warnings."),
    (r"^Executes code it builds at run time", "It builds commands while running and then runs them, a way to "
     "avoid showing what it really does.", "Be careful, especially together with other warnings."),
    (r"^Downloads files from the internet", "It fetches more files from the internet. That's how many attacks "
     "bring in the real malware after the first step.", "If you don't know what this script is, quarantine it."),
    (r"switch off or bypass antivirus", "It tries to turn off your antivirus or hide from it. Normal software "
     "never does this.", "Quarantine it straight away."),
    (r"ransomware", "It deletes Windows backups and recovery points. Ransomware does this before locking your "
     "files so you can't restore them.", "Quarantine it straight away and don't run it."),
    (r"^Runs hidden from the user", "It runs without showing a window, so you wouldn't see it working.",
     "A concern together with other warnings."),
    (r"^Makes itself start automatically", "It sets itself up to run again automatically, for example at every "
     "sign-in.", "If you didn't set it up, quarantine it."),
    (r"^Starts other programs", "It can launch other programs. Many scripts do this; on its own it's a minor sign.",
     "Only a concern together with other warnings."),
    (r"one character at a time", "It assembles text one letter at a time, a trick to hide words from antivirus.",
     "Quarantine it."),
    # -- documents and shortcuts
    (r"^Document contains macros", "The document has macros, small programs inside Office files. They're used "
     "at work, but also a common way to spread malware.", "Only enable editing or content if you trust the sender."),
    (r"^Macros run automatically", "The macros start on their own as soon as the document opens.",
     "Don't click 'Enable content'. Quarantine it if you didn't expect it."),
    (r"^Macros can start programs", "The macros can launch programs or download files, which is how "
     "document-based attacks deliver malware.", "Quarantine it unless you know exactly what it is."),
    (r"^Shortcut secretly runs", "This shortcut doesn't just open a file: it secretly runs a hidden or downloading "
     "command.", "Quarantine it."),
    # -- Android apps and phones
    (r"banking-trojan", "The app can read your text messages and control the screen. Banking trojans use this "
     "to steal one-time codes and take over bank apps.", "Uninstall it."),
    (r"screen control \(accessibility\) and device-admin", "The app wants to control your screen and become a "
     "device administrator, which also makes it hard to remove.", "Uninstall it unless it's a security app you chose."),
    (r"^Can install other apps", "The app can install further apps, so it could bring in more malware.",
     "Only keep it if you trust it."),
    (r"read all your notifications", "The app can read every notification, including messages and login codes.",
     "Only keep it if it really needs this, like a smartwatch app."),
    (r"accessibility access", "The app can see everything on the screen and tap for you. Apps for people with "
     "disabilities need this; spyware abuses it.", "Remove the permission or uninstall it if you don't know why it "
     "has it."),
    (r"device administrator", "The app is a device administrator, which blocks normal uninstalling.",
     "If you don't recognise it, remove its admin rights in Settings → Security, then uninstall it."),
    (r"^Has no app icon", "The app has no icon, so it stays hidden from you. Spy apps often do this.",
     "Uninstall it if you don't know what it is."),
    (r"^Installed from outside an app store", "The app didn't come from Google Play or another store, so it "
     "skipped their safety checks.", "Keep it only if you installed it yourself from a trusted source."),
    (r"^Allowed to", "These are sensitive permissions the app has been granted.",
     "Check they make sense for what the app does."),
    (r"^App package tucked away", "An app installer file is stored in a hidden or app-only folder, where people "
     "don't normally keep them.", "Delete it if you didn't save it there."),
    (r"security patch", "The phone hasn't had a security update for a long time, so known holes stay open.",
     "Install any available update. If none comes, the phone is no longer supported."),
    (r"no longer gets security fixes", "This Android version no longer receives security updates.",
     "Avoid banking on this phone, or think about replacing it."),
    # -- USB drives
    (r"^Autorun file", "The drive has an autorun file that tries to start a program when the drive is opened, a "
     "classic way USB worms spread.", "Use Repair, or quarantine it."),
    (r"^Folder hidden as a system item", "Your folder was hidden by the shortcut virus. Your files are usually "
     "still inside.", "Use Repair to unhide it."),
    (r"^Hidden program or script", "A hidden program sits at the top of the drive, where USB worms put themselves.",
     "Quarantine it."),
    (r"^Shortcut virus", "This is a fake shortcut made by the shortcut virus. Clicking it runs the virus and then "
     "opens your folder so you don't notice.", "Use Repair: it removes the fake shortcuts and unhides your files."),
    # -- links and web pages
    (r"^Listed as malicious", "This exact link is on a list of known dangerous web addresses.", "Don't open it."),
    (r"hosts malware", "The website is known to host malware.", "Don't open it."),
    (r"bare IP address", "The link is just a number instead of a name like example.com. Real companies almost "
     "never send links like this.", "Don't open it unless you know exactly what it is."),
    (r"punycode", "The address uses letters from other alphabets that look like normal ones, to imitate a real "
     "website.", "Don't open it. Type the site's address yourself instead."),
    (r"'@' to hide", "Everything before '@' in a web address is ignored, so the real site is hidden after it.",
     "Don't open it."),
    (r"often used for scams", "This domain ending is cheap and popular with scammers. Real sites use it too, so "
     "it's only a hint.", "Be careful, especially with other warnings."),
    (r"^Mentions '.*' but the real site is", "The link uses a well-known brand name, but it actually goes to a "
     "different website.", "Don't sign in. Go to the brand's real site yourself."),
    (r"long or complex address", "The address is unusually long or complicated, which can hide where it really "
     "goes.", "A small sign on its own."),
    (r"^Redirects to a known malicious", "The link forwards you to a known dangerous site.", "Don't open it."),
    (r"^Redirects to another site", "The link sends you on to a different website than the one shown.",
     "Check the final site before you trust it."),
    (r"downloads a file straight away", "Opening the link downloads a file immediately instead of showing a page.",
     "Don't open the downloaded file unless you expected it."),
    (r"asks for a password", "The page has a password box.", "Only sign in if you're sure it's the real site."),
    (r"^Fake login page", "The page copies a well-known sign-in page but runs on a different website. This is "
     "phishing: it steals passwords.", "Don't type anything. If you already did, change that password now."),
    (r"sign-in form on a free hosting", "A sign-in form on a free website builder, which real companies don't use "
     "for logins.", "Don't type your password."),
    (r"name with sign-in wording", "The page uses a brand's name and asks you to sign in, but isn't that brand's "
     "site.", "Don't type your password."),
    (r"^Pretends to be", "The page imitates a well-known brand on a site anyone can publish to.",
     "Don't trust it or type anything."),
    (r"Telegram/Discord bot", "What you type is sent to a chat bot, a common way scammers collect stolen details.",
     "Don't type anything into it."),
    (r"sends your details to a different site", "The form sends what you type to another website, not the one "
     "you're on.", "Don't fill it in."),
    (r"obfuscated JavaScript", "The page hides its code so it can't be easily read.",
     "Be careful, especially with other warnings."),
    (r"forwards you to another page", "The page sends you elsewhere automatically.",
     "Check where you end up before trusting it."),
    (r"registered only|domain is new", "The website was created very recently. Scam sites are usually only days or "
     "weeks old.", "Be very careful, especially if it asks for money or passwords."),
    (r"^Couldn't open the page", "The page couldn't be loaded for inspection, so only the address was checked.",
     "Being unchecked doesn't make it safe."),
]
_COMPILED = [(re.compile(rx, re.I), what, todo) for rx, what, todo in RULES]

# verdict -> (tone, headline, summary)
VERDICTS = {
    "Malware": ("bad", "Dangerous", "This is confirmed malware. Remove it."),
    "Suspicious": ("warn", "Suspicious", "Several warning signs together. Treat it as dangerous unless you know "
                   "exactly what it is."),
    "Worth a look": ("info", "Worth a look", "A mild warning sign. Often harmless, but check you recognise it."),
    "malicious": ("bad", "Dangerous link", "This link is known to be dangerous. Don't open it."),
    "suspicious": ("warn", "Suspicious link", "This link shows signs of a scam or fake site."),
    "no-known-threats": ("ok", "No known threats", "Nothing bad was found, but that doesn't prove the link is "
                         "safe. If a message is unexpected or urgent, go to the site yourself instead of clicking."),
}


def explain(verdict, reasons):
    """Returns {"tone", "title", "summary", "items": [(reason, meaning)], "what_to_do": [...]}."""
    tone, title, summary = VERDICTS.get(verdict, ("info", verdict or "Result", ""))
    items, todo = [], []
    for reason in reasons:
        for rx, what, step in _COMPILED:
            if rx.search(reason):
                items.append((reason, what))
                if step not in todo:
                    todo.append(step)
                break
        else:
            items.append((reason, "A warning sign found by Kavacham's checks."))
    return {"tone": tone, "title": title, "summary": summary, "items": items, "what_to_do": todo[:4]}
