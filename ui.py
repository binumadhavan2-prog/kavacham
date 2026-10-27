"""Kavacham user interface: a dark, Windows 11 style front end for core.py."""
import ctypes
import heapq
import math
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk

# numpy's maths library reserves a large buffer per CPU thread (235 MB on an 8-thread laptop); the animations
# never do matrix maths, so one thread is plenty. Must be set before numpy is imported.
for _var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_var, "1")

try:  # optional: richer cleaning animation
    import numpy as np
    from PIL import Image, ImageDraw, ImageFilter, ImageTk
except ImportError:
    Image = None

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

import alerts
import engine
import explain
import phone as phonecare
import privacy
import security
import usb
from core import (CLEAN_TARGETS, DAYS, DEFAULT_SETTINGS, HISTORY_FILE, SETTINGS_FILE, TASK_NAMES, add_history, empty_recycle_bin,
                  find_duplicates, find_mpcmdrun, fixed_drives, human, is_admin, load_settings, notify, measure, clean, powershell_json,
                  ps_quote, read_json, recycle_bin_info, register_task, relaunch_as_admin, run_ps,
                  send_to_recycle_bin, start_task, task_info, write_json, NO_WINDOW)

# ---------------------------------------------------------------- design tokens

BG = "#070706"
SIDEBAR = "#0a0908"
SURFACE = "#11100d"
SURFACE_2 = "#1b1915"
HOVER = "#24211b"
BORDER = "#211e18"
TRACK = "#24211b"
TEXT = "#f6f2ea"
MUTED = "#9a9284"
SUBTLE = "#5f594e"
GOLD = "#d8b46e"  # the logo's gold: Kavacham's accent
ACCENT = GOLD
ACCENT_HOVER = "#ecd096"
ACCENT_DIM = "#231c10"
ACCENT_LINE = "#4e3f22"  # gold hairlines: hero frame, active menu item
ON_ACCENT = "#1c1406"  # text and knobs on gold
OK, OK_DIM = "#3fc28c", "#0d2219"  # green stays the colour of "protected"
WARN, WARN_DIM = "#ec8f4c", "#2e1c0f"  # orange, so warnings don't blur into the gold
BAD, BAD_DIM = "#ec625b", "#301513"
TONES = {"ok": (OK, OK_DIM), "warn": (WARN, WARN_DIM), "bad": (BAD, BAD_DIM), "info": (ACCENT, ACCENT_DIM)}

ICONS = {"home": "", "scan": "", "shield": "", "warning": "", "clean": "",
         "folder": "", "calendar": "", "refresh": "", "play": "", "stop": "",
         "download": "", "check": "", "clock": "", "admin": "", "drive": "",
         "bolt": "", "file": "", "open": "", "history": "", "search": "",
         "copy": "", "arrow": "", "lock": "\ue72e", "wifi": "\ue701", "undo": "\ue7a7", "camera": "", "mic": ""}

# Cleaner groups: gold, terracotta and green, picked to stay apart from each other (also for colour-blind eyes)
# and to sit with the gold theme.
CLEAN_GROUPS = [
    ("System", "#d8b46e", ["User temporary files", "Windows temporary files", "Thumbnail cache",
                           "Crash dumps & error reports", "Windows Update download cache"]),
    ("Browsers", "#d0653f", ["Google Chrome cache", "Microsoft Edge cache", "Firefox cache"]),
    ("Recycle Bin", "#3fa98a", ["Recycle Bin"]),
]

DUP_MIN_SIZES = {"Any size": 1, "100 KB": 100 * 1024, "1 MB": 1024 ** 2, "10 MB": 10 * 1024 ** 2,
                 "100 MB": 100 * 1024 ** 2}

F = {}       # fonts, filled once Tk exists
SCALE = 1.0  # DPI scale, filled once Tk exists


def px(n):
    return int(round(n * SCALE))


def init_fonts(root):
    global SCALE
    SCALE = max(1.0, root.winfo_fpixels("1i") / 96)
    families = set(tkfont.families(root))

    def pick(*names):
        return next((n for n in names if n in families), "Segoe UI")
    ui = pick("Segoe UI Variable Text", "Segoe UI")
    light = pick("Segoe UI Variable Display Semil", "Segoe UI Semilight", "Segoe UI")
    semi = pick("Segoe UI Variable Display Semib", "Segoe UI Semibold", "Segoe UI")
    text_semi = pick("Segoe UI Variable Text Semibold", "Segoe UI Semibold", "Segoe UI")
    serif = pick("Sitka Display", "Cambria", "Georgia", light)
    icon, mono = pick("Segoe Fluent Icons", "Segoe MDL2 Assets"), pick("Cascadia Mono", "Consolas")
    F.update({
        "body": (ui, 10), "body_b": (text_semi, 10), "small": (ui, 9), "small_b": (text_semi, 9),
        "caption": (text_semi, 8), "h1": (serif, 25), "h2": (semi, 13),
        "h3": (light, 15), "hero": (serif, 27), "big": (serif, 34),
        "brand": (serif, 16, "bold"), "nav": (ui, 10), "button": (text_semi, 10),
        "icon": (icon, 13), "icon_sm": (icon, 11), "icon_lg": (icon, 20), "icon_xl": (icon, 36), "mono": (mono, 9),
    })


def dark_titlebar(win):
    """Windows 11: dark caption bar matching the app background."""
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        on = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(on), 4)
        r, g, b = int(BG[1:3], 16), int(BG[3:5], 16), int(BG[5:7], 16)
        color = ctypes.c_int(b << 16 | g << 8 | r)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(color), 4)
    except Exception:
        pass


def round_rect(c, x1, y1, x2, y2, r, **kw):
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2, x1, y2,
           x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


def _mix(a, b, t):
    """Colour a blended toward b by t (0..1)."""
    a, b = [int(a[i:i + 2], 16) for i in (1, 3, 5)], [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def gold_rule(parent, width=None, height=2, center=False):
    """A gold hairline that fades into the background: to the right, or toward both ends when centred.
    Without a width it stretches to fill its parent."""
    c = tk.Canvas(parent, height=height, bg=parent["bg"], highlightthickness=0, bd=0,
                  **({"width": width} if width else {}))

    def draw(w):
        c.delete("all")
        for x in range(0, w, 2):
            t = abs(x - w / 2) / (w / 2) if center else x / w
            c.create_rectangle(x, 0, x + 2, height, width=0, fill=_mix(GOLD, parent["bg"], min(1, t) ** 1.4))
    if width:
        draw(width)
    else:
        c.bind("<Configure>", lambda e: draw(e.width))
    return c


def label(parent, text="", font="body", fg=TEXT, **kw):
    return tk.Label(parent, text=text, font=F[font], fg=fg, bg=parent["bg"], **kw)


def frame(parent, bg=None, **kw):
    return tk.Frame(parent, bg=bg or parent["bg"], **kw)


def divider(parent, **pack):
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", **pack)


# ---------------------------------------------------------------- components

class Card(tk.Frame):
    """Borderless panel with rounded corners. Tk frames can't be rounded, so each corner gets a small canvas
    painted in the parent's colour with a quarter circle of the card's; it sits in the padding, under no content."""

    def __init__(self, parent, padding=20, bg=SURFACE, radius=16, border=None, **kw):
        super().__init__(parent, bg=bg, highlightthickness=0, padx=px(padding), pady=px(padding), **kw)
        r, pad = px(min(radius, padding)), px(padding)
        if r < 2:
            return
        for corner in ("nw", "ne", "sw", "se"):
            c = tk.Canvas(self, width=r, height=r, bg=parent["bg"], highlightthickness=0, bd=0)
            x0, y0 = (0 if corner[1] == "w" else -r), (0 if corner[0] == "n" else -r)
            c.create_oval(x0, y0, x0 + 2 * r - 1, y0 + 2 * r - 1, fill=bg, outline=border or bg)
            # place() measures from inside the padding, so step back out to the card's real edge
            c.place(relx=0 if corner[1] == "w" else 1, rely=0 if corner[0] == "n" else 1, anchor=corner,
                    x=-pad if corner[1] == "w" else pad, y=-pad if corner[0] == "n" else pad)
        if border:  # straight edges between the corners
            for side in ("n", "s", "w", "e"):
                line = tk.Frame(self, bg=border, highlightthickness=0)
                if side in "ns":
                    line.place(relx=0, rely=0 if side == "n" else 1, anchor="nw" if side == "n" else "sw",
                               x=r - pad, y=-pad if side == "n" else pad, relwidth=1, width=2 * (pad - r), height=1)
                else:
                    line.place(relx=0 if side == "w" else 1, rely=0, anchor="nw" if side == "w" else "ne",
                               x=-pad if side == "w" else pad, y=r - pad, relheight=1, height=2 * (pad - r), width=1)


class CanvasWidget(tk.Canvas):
    """Base for custom-drawn controls; supports configure(state=..., text=...) like ttk widgets."""

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=parent["bg"], highlightthickness=0, bd=0, cursor="hand2", **kw)
        self._state = "normal"
        self._hover = False
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))

    def _set_hover(self, on):
        self._hover = on
        self._draw()

    @property
    def disabled(self):
        return self._state == "disabled"

    def configure(self, cnf=None, **kw):
        kw = {**(cnf or {}), **kw}
        changed = False
        if "state" in kw:
            self._state = "disabled" if kw.pop("state") == "disabled" else "normal"
            super().configure(cursor="arrow" if self.disabled else "hand2")
            changed = True
        if "text" in kw:
            self.text = kw.pop("text")
            changed = True
        if kw:
            super().configure(**kw)
        if changed:
            self._draw()

    config = configure

    def _draw(self):
        raise NotImplementedError


class Button(CanvasWidget):
    STYLES = {  # fill, hover fill, text, border
        "primary": (GOLD, ACCENT_HOVER, ON_ACCENT, None),
        "secondary": (SURFACE_2, HOVER, TEXT, None),
        "ghost": (None, SURFACE_2, ACCENT, None),
        "danger": (BAD_DIM, "#3f1b18", BAD, "#5c2622"),
    }

    def __init__(self, parent, text, command=None, kind="secondary", icon=None, width=None, height=36):
        self.text, self.icon, self.command, self.kind = text, icon, command, kind
        self._tf, icf = tkfont.Font(font=F["button"]), tkfont.Font(font=F["icon_sm"])
        self._tw = self._tf.measure(text)
        self._iw = icf.measure(ICONS[icon]) + px(8) if icon else 0
        super().__init__(parent, width=width or self._tw + self._iw + px(40), height=px(height))
        self.bind("<ButtonRelease-1>", self._click)
        self.bind("<Configure>", lambda _e: self._draw())
        self._draw()

    def _click(self, e):
        if not self.disabled and self.command and 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height():
            self.command()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width() if self.winfo_width() > 1 else int(self.cget("width"))
        h = int(self.cget("height"))
        fill, hover, fg, border = self.STYLES[self.kind]
        self._tw = self._tf.measure(self.text)  # the text may have changed since it was created
        if self.disabled:
            fill, fg, border = (SURFACE_2 if fill else None), SUBTLE, (BORDER if border else None)
        elif self._hover:
            fill = hover
        if fill:
            round_rect(self, 1, 1, w - 1, h - 1, (h - 2) / 2, fill=fill, outline=border or fill)
        x = (w - self._tw - self._iw) / 2
        if self.icon:
            self.create_text(x, h / 2 + 1, text=ICONS[self.icon], font=F["icon_sm"], fill=fg, anchor="w")
            x += self._iw
        self.create_text(x, h / 2, text=self.text, font=F["button"], fill=fg, anchor="w")


class Toggle(CanvasWidget):
    def __init__(self, parent, variable, command=None):
        self.var, self.command = variable, command
        super().__init__(parent, width=px(42), height=px(24))
        self.bind("<Button-1>", self._click)
        variable.trace_add("write", lambda *_a: self._draw())
        self._draw()

    def _click(self, _e):
        if not self.disabled:
            self.var.set(not self.var.get())
            if self.command:
                self.command()

    def _draw(self):
        self.delete("all")
        w, h, on = px(42), px(24), self.var.get()
        track = ACCENT if on else TRACK
        if self._hover and not self.disabled:
            track = ACCENT_HOVER if on else HOVER
        if self.disabled:
            track = ACCENT_DIM if on else SURFACE_2
        round_rect(self, 1, 1, w - 1, h - 1, h / 2, fill=track, outline=track if on else BORDER)
        d, m = h - px(8), px(4)
        x = w - m - d - 1 if on else m + 1
        knob = ON_ACCENT if on else (MUTED if not self.disabled else SUBTLE)
        self.create_oval(x, m, x + d, m + d, fill=knob, outline=knob)


class Chip(CanvasWidget):
    """A pill that toggles a BooleanVar (day pickers, multi-select lists)."""

    def __init__(self, parent, text, variable, width=None, height=32):
        self.text, self.var = text, variable
        tw = tkfont.Font(font=F["small_b"]).measure(text)
        super().__init__(parent, width=width or tw + px(30), height=px(height))
        self.bind("<Button-1>", lambda _e: None if self.disabled else self.var.set(not self.var.get()))
        variable.trace_add("write", lambda *_a: self._draw())
        self.bind("<Configure>", lambda _e: self._draw())
        self._draw()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width() if self.winfo_width() > 1 else int(self.cget("width"))
        h, on = int(self.cget("height")), self.var.get()
        fill, outline, fg = (ACCENT_DIM, ACCENT, TEXT) if on else (SURFACE_2, BORDER, MUTED)
        if self._hover and not self.disabled and not on:
            fill = HOVER
        if self.disabled:
            fill, outline, fg = SURFACE, (ACCENT_DIM if on else BORDER), SUBTLE
        round_rect(self, 1, 1, w - 1, h - 1, h / 2, fill=fill, outline=outline)
        self.create_text(w / 2, h / 2, text=self.text, font=F["small_b"], fill=fg)


class Bar(tk.Canvas):
    """Thin rounded progress bar with determinate (set) and indeterminate (start/stop) modes."""

    def __init__(self, parent, height=6, color=ACCENT):
        super().__init__(parent, height=px(height), bg=parent["bg"], highlightthickness=0, bd=0)
        self.h, self.color, self.frac, self.pos, self._anim = px(height), color, 0.0, 0.0, None
        self.bind("<Configure>", lambda _e: self._draw())

    def set(self, frac, color=None):
        self.frac, self.color = max(0.0, min(1.0, frac)), color or self.color
        self._draw()

    def start(self):
        if not self._anim:
            self._tick()

    def stop(self):
        if self._anim:
            self.after_cancel(self._anim)
            self._anim = None
        self._draw()

    def _tick(self):
        self.pos = (self.pos + 0.011) % 1.35
        self._draw()
        self._anim = self.after(16, self._tick)

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.h
        if w < 4:
            return
        round_rect(self, 0, 0, w, h, h / 2, fill=TRACK, outline=TRACK)
        if self._anim:
            x1, x2 = max(0, (self.pos - 0.35) * w), min(w, self.pos * w)
            if x2 - x1 > h:
                round_rect(self, x1, 0, x2, h, h / 2, fill=self.color, outline=self.color)
        elif self.frac > 0:
            round_rect(self, 0, 0, max(h, self.frac * w), h, h / 2, fill=self.color, outline=self.color)


class StackedBar(tk.Canvas):
    """Part-to-whole bar: segments separated by a 2px surface gap, with a hover tooltip."""

    def __init__(self, parent, height=14):
        super().__init__(parent, height=px(height), bg=parent["bg"], highlightthickness=0, bd=0)
        self.h, self.parts, self.spans = px(height), [], []
        self.tip = tk.Label(parent.winfo_toplevel(), font=F["small_b"], bg=SURFACE_2, fg=TEXT, padx=px(8),
                            pady=px(4), highlightthickness=1, highlightbackground=BORDER)
        self.bind("<Configure>", lambda _e: self._draw())
        self.bind("<Motion>", self._hover)
        self.bind("<Leave>", lambda _e: self.tip.place_forget())

    def set(self, parts):
        """parts: [(label, value, color)] — zero values are left out."""
        self.parts = [p for p in parts if p[1] > 0]
        self._draw()

    def _draw(self):
        self.delete("all")
        self.spans = []
        w, h = self.winfo_width(), self.h
        if w < 4:
            return
        total = sum(v for _n, v, _c in self.parts)
        if not total:
            round_rect(self, 0, 0, w, h, px(4), fill=TRACK, outline=TRACK)
            return
        gap = px(2)
        usable, x = w - gap * (len(self.parts) - 1), 0
        for i, (name, value, color) in enumerate(self.parts):
            x2 = w if i == len(self.parts) - 1 else min(w, x + max(px(6), usable * value / total))
            round_rect(self, x, 0, x2, h, px(4), fill=color, outline=color)
            self.spans.append((x, x2, name, value, total))
            x = x2 + gap

    def _hover(self, e):
        for x1, x2, name, value, total in self.spans:
            if x1 <= e.x <= x2:
                top = self.winfo_toplevel()
                self.tip.configure(text=f"{name}  ·  {human(value)}  ({value / total:.0%})")
                self.tip.place(x=self.winfo_rootx() - top.winfo_rootx() + e.x,
                               y=self.winfo_rooty() - top.winfo_rooty() - px(6), anchor="s")
                self.tip.lift()
                return
        self.tip.place_forget()


class StatusRing(tk.Canvas):
    """The dashboard's protection indicator: a slowly turning orb of glowing dotted contour lines, tinted by the
    protection tone, that spins faster while a scan runs. Frames are rendered once per tone with Pillow on a worker
    thread; each tick only swaps an image, and it idles while the dashboard is hidden. Without Pillow it falls back
    to a flat ring."""

    FRAMES, SS, TICK = 32, 2, 90  # frames per turn, supersampling, ms per frame

    def __init__(self, parent, size=196):
        self.size = px(size)
        super().__init__(parent, width=self.size, height=self.size, bg=parent["bg"], highlightthickness=0)
        self.tone, self.angle, self._anim, self.idx = "info", 0, None, 0
        self.frames, self._pending, self._rendering = {}, None, None
        self.item = self.create_image(self.size / 2, self.size / 2, anchor="center")
        self.glyph = self.create_text(self.size / 2, self.size / 2 + 1, text="", font=F["icon_xl"], fill=TEXT)
        self.emblem_img = self._emblem()
        if self.emblem_img:
            self.create_image(self.size / 2, self.size / 2, image=self.emblem_img, anchor="center")
            # on a problem a small warning sign sits on the emblem's lower right
            self.glyph = self.create_text(self.size / 2 + px(30), self.size / 2 + px(30), text="", font=F["icon"])
        self._spinning = False
        if Image is None:
            self._draw()
        else:
            self._render(self.tone)
            self._loop()

    def set(self, tone):
        self.tone = tone
        if Image is None:
            self._draw()
        else:
            self._render(tone)
            self._glyph()

    def spin(self, on):
        self._spinning = bool(on)
        if Image is None:
            if on and not self._anim:
                self._tick()
            elif not on and self._anim:
                self.after_cancel(self._anim)
                self._anim = None
                self._draw()
        else:
            self._glyph()

    # ---- orb
    def _shown_tone(self):
        return "info" if self._spinning else self.tone

    @staticmethod
    def _color(tone):
        """Orb colour: gold while all is well (or scanning), the warning colour otherwise."""
        return GOLD if tone in ("ok", "info") else TONES[tone][0]

    def _emblem(self):
        """The Kavacham emblem, cut to a circle with a soft edge so it melts into the orb's glow."""
        path = os.path.join(ASSETS, "logo.png")
        if Image is None or not os.path.exists(path):
            return None
        d, ss = px(84), 4
        img = Image.open(path).convert("RGBA").resize((d, d), Image.LANCZOS)
        mask = Image.new("L", (d * ss, d * ss), 0)
        ImageDraw.Draw(mask).ellipse((0, 0, d * ss - 1, d * ss - 1), fill=255)
        mask = mask.resize((d, d), Image.LANCZOS).filter(ImageFilter.GaussianBlur(px(1)))
        img.putalpha(mask)
        return ImageTk.PhotoImage(img)

    def _glyph(self):
        tone = self._shown_tone()
        ok = tone in ("ok", "info")
        if self.emblem_img:
            self.itemconfigure(self.glyph, text="" if ok else ICONS["warning"], fill=TONES[tone][0])
            return
        glyph = ICONS["shield"] if ok else ICONS["warning"]
        self.itemconfigure(self.glyph, text=glyph, fill=TEXT if ok else TONES[tone][0])

    def _render(self, tone):
        color, bgcol = self._color(tone), self["bg"]
        if color in self.frames or self._rendering == color:
            return
        self._rendering = color

        def work():
            self._pending = (color, [self._orb_frame(k, color, bgcol) for k in range(self.FRAMES)])
        threading.Thread(target=work, daemon=True).start()

    def _orb_frame(self, k, color, bgcol):
        n = self.size * self.SS
        lat = np.linspace(0.18, np.pi - 0.18, 36)[:, None]
        lon = np.linspace(0, 2 * np.pi, 150, endpoint=False)[None, :]
        r = 1 + 0.13 * np.sin(3 * lon + 2 * lat) + 0.08 * np.sin(5 * lat - 2 * lon + 1) + 0.05 * np.cos(4 * lon)
        x, y, z = r * np.sin(lat) * np.cos(lon), r * np.cos(lat), r * np.sin(lat) * np.sin(lon)
        a = 2 * np.pi * k / self.FRAMES
        x, z = x * np.cos(a) + z * np.sin(a), -x * np.sin(a) + z * np.cos(a)
        t = 0.35
        y, z = y * np.cos(t) - z * np.sin(t), y * np.sin(t) + z * np.cos(t)
        R = n * 0.36
        px_, py_ = (n / 2 + R * x).astype(int).ravel(), (n / 2 + R * y).astype(int).ravel()
        rim = np.clip(np.hypot(x, y) / r, 0, 1).ravel() ** 3   # dots near the silhouette glow brightest
        front = np.where(z.ravel() > 0, 1.0, 0.4)
        acc = np.zeros((n, n), np.float32)
        ok = (px_ >= 0) & (px_ < n) & (py_ >= 0) & (py_ < n)
        np.add.at(acc, (py_[ok], px_[ok]), ((0.25 + 0.9 * rim) * front)[ok])
        dots = np.asarray(Image.fromarray(np.clip(acc * 255, 0, 255).astype(np.uint8)).filter(
            ImageFilter.GaussianBlur(0.6 * self.SS)), np.float32) / 255
        small = Image.fromarray(np.clip(acc * 120, 0, 255).astype(np.uint8)).resize((n // 4, n // 4), Image.BOX)
        glow = np.asarray(small.filter(ImageFilter.GaussianBlur(9 * self.SS / 4)).resize((n, n), Image.BILINEAR),
                          np.float32) / 255
        if getattr(self, "_core", None) is None or self._core.shape[0] != n:
            yy, xx = np.mgrid[0:n, 0:n]
            self._core = np.exp(-((xx - n / 2) ** 2 + (yy - n / 2) ** 2) / (2 * (n * 0.16) ** 2)) * 0.5
        inten = np.clip(dots * 1.8 + glow * 6 + self._core, 0, 1.6)
        # shrink first, then colour: a quarter of the pixels to tint
        small = Image.fromarray((inten * 159).astype(np.uint8)).resize((self.size, self.size), Image.LANCZOS)
        inten = (np.asarray(small, np.float32) / 159)[..., None]
        c = np.array(Image.new("RGB", (1, 1), color).getpixel((0, 0)), np.float32)
        b = self._backdrop(bgcol)
        rgb = b + inten * (c - b) + np.clip(inten - 1, 0, 1) * (255 - c) * 0.8  # hot spots go toward white
        return Image.fromarray(np.clip(rgb, 0, 255).astype(np.uint8))

    def _backdrop(self, bgcol):
        """Behind the orb: faint gold armour scales and a warm glow, fading to the card colour at the edge."""
        if getattr(self, "_back", None) is not None and self._back[0] == bgcol:
            return self._back[1]
        s, ss = self.size, 3
        n = s * ss
        scales = Image.new("L", (n, n), 0)
        d = ImageDraw.Draw(scales)
        r = n / 9
        for row in range(-1, int(n / (r * 0.62)) + 2):  # top to bottom, each row overlapping the one above
            y = row * r * 0.62
            for col in range(-1, int(n / r) + 2):
                x = col * r * 1.1 + (r * 0.55 if row % 2 else 0)
                d.ellipse((x - r * 0.55, y - r * 0.55, x + r * 0.55, y + r * 0.55), fill=0, outline=255,
                          width=ss)
        scales = np.asarray(scales.resize((s, s), Image.LANCZOS), np.float32) / 255
        yy, xx = np.mgrid[0:s, 0:s]
        dist = np.hypot(xx - s / 2, yy - s / 2) / (s / 2)
        fade = np.clip(1 - dist, 0, 1) ** 1.6
        amount = (scales * 0.16 + 0.22 * np.exp(-dist ** 2 / 0.18)) * fade
        b = np.array(Image.new("RGB", (1, 1), bgcol).getpixel((0, 0)), np.float32)
        g = np.array(Image.new("RGB", (1, 1), GOLD).getpixel((0, 0)), np.float32)
        back = b + amount[..., None] * (g - b)
        self._back = (bgcol, back)
        return back

    def _loop(self):
        if self._pending:
            color, imgs = self._pending
            self._pending, self._rendering = None, None
            current = self._color(self._shown_tone())
            for old in [k for k in self.frames if k not in (color, current)]:
                del self.frames[old]  # keep at most two colours in memory
            self.frames[color] = [ImageTk.PhotoImage(im) for im in imgs]
            self._glyph()
        color = self._color(self._shown_tone())
        frames = self.frames.get(color) or next(iter(self.frames.values()), None)
        # animate only while the Overview is on screen and Kavacham is the active window (or a scan runs), so the
        # orb costs nothing while you're working in other apps
        top = self.winfo_toplevel()
        visible = self.winfo_ismapped() and top.state() != "iconic" and (
            self._spinning or top.focus_displayof() is not None)
        if frames and (visible or self.itemcget(self.item, "image") == ""):
            self.idx = (self.idx + (2 if self._spinning else 1)) % len(frames)
            self.itemconfigure(self.item, image=frames[self.idx])
        if color not in self.frames:
            self._render(self._shown_tone())
        self.after(self.TICK if visible else 500, self._loop)

    # ---- flat fallback (no Pillow)
    def _tick(self):
        self.angle = (self.angle - 6) % 360
        self._draw()
        self._anim = self.after(16, self._tick)

    def _draw(self):
        self.delete("all")
        s, w = self.size, px(9)
        color, dim = TONES["info" if self._anim else self.tone]
        o = w + px(6)
        self.create_oval(px(4), px(4), s - px(4), s - px(4), outline=dim, width=px(3))
        self.create_oval(o, o, s - o, s - o, outline=dim, width=w)
        if self._anim:
            self.create_arc(o, o, s - o, s - o, start=self.angle, extent=100, style="arc", outline=color, width=w)
        else:
            self.create_oval(o, o, s - o, s - o, outline=color, width=w)
        inner = o + w + px(10)
        self.create_oval(inner, inner, s - inner, s - inner, fill=dim, outline=dim)
        glyph = ICONS["shield"] if self.tone in ("ok", "info") or self._anim else ICONS["warning"]
        self.create_text(s / 2, s / 2 + 1, text=glyph, font=F["icon_xl"], fill=color)


class SpiralFunnel(tk.Canvas):
    """Cleaning animation after React Bits' Spiral Funnel: threads of light spiral round a turning vortex while
    sparks, one color per cleaner group, are pulled down into it. A live freed-space count sits in the mouth, and
    when cleaning ends the vortex speeds up, collapses into the tip with a flash and turns green.

    The vortex and the spark layers are rendered once with Pillow on a worker thread as seamless loops (the loop
    turns exactly one thread spacing); each tick only blends them by how active each group is."""

    THREADS, SEGMENTS, FRAMES, FINALE, FADE, SS = 21, 56, 60, 34, 14, 2
    MIN_SHOW = 2.6  # seconds: even a quick clean gets a visible moment
    BLUE = [(0.0, "#2a1d08"), (0.45, "#b88a3c"), (0.75, "#f0d396"), (1.0, "#fffaf0")]  # accent gold, kept the name
    GREEN = [(0.0, "#12291f"), (0.45, "#3a9e72"), (0.75, "#86d4ae"), (1.0, "#f2fbf6")]

    def __init__(self, parent, groups, width=680, height=170):
        super().__init__(parent, height=px(height), bg=parent["bg"], highlightthickness=0, bd=0)
        self.w, self.h, self.bgcol = px(width), px(height), parent["bg"]
        self.bg_rgb = np.array(Image.new("RGB", (1, 1), self.bgcol).getpixel((0, 0)), np.float32)
        self.colors = [np.array(Image.new("RGB", (1, 1), c).getpixel((0, 0)), np.float32) for _n, c in groups]
        self.base = self.layers = self.finale = None
        self.photo, self._anim, self.state, self.idx = None, None, "idle", 0.0
        geo = self._geometry()
        self.text_y = geo[4] / self.SS - px(24)
        self.item = self.create_image(0, self.h / 2, anchor="center")
        self.count = self.create_text(0, 0, font=F["hero"], fill=TEXT)
        self.status = self.create_text(0, 0, font=F["small"], fill=MUTED)
        self.bind("<Configure>", lambda e: self._place(e.width))
        threading.Thread(target=self._render_loop, daemon=True).start()

    # ---------------------------------------------------------- public API (Tk thread)
    def begin(self, groups, total):
        """groups: indexes of the groups being cleaned; total: bytes expected to be freed."""
        self.groups, self.total = set(groups), max(1, total)
        self.weights = [0.0] * len(self.colors)
        self.current, self.freed, self.shown, self.tick = None, 0, 0.0, 0
        self.t0, self.on_done, self.state, self.finale = time.time(), None, "run", None
        self.itemconfigure(self.count, text=human(0), fill=TEXT)
        self.itemconfigure(self.status, text="Preparing…")
        threading.Thread(target=self._render_finale, daemon=True).start()
        if not self._anim:
            self._step()

    def progress(self, freed, text, group=None):
        self.freed, self.current = freed, group
        if text:
            self.itemconfigure(self.status, text=text)

    def finish(self, on_done):
        """Plays the finale once the minimum show time has passed, then calls on_done."""
        self.on_done, self.state = on_done, "ending"

    def stop(self):
        if self._anim:
            self.after_cancel(self._anim)
            self._anim = None
        self.state = "idle"

    # ---------------------------------------------------------- playback
    def _place(self, width):
        cx = width / 2
        self.coords(self.item, cx, self.h / 2)
        self.coords(self.count, cx, self.text_y)
        self.coords(self.status, cx, self.text_y + px(26))

    def _show(self, arr):
        img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))
        if self.photo is None:
            self.photo = ImageTk.PhotoImage(img)
            self.itemconfigure(self.item, image=self.photo)
        else:
            self.photo.paste(img)

    def _step(self):
        self.tick += 1
        self.shown += (self.freed - self.shown) * 0.12
        if abs(self.freed - self.shown) < 1024:
            self.shown = self.freed
        self.itemconfigure(self.count, text=human(int(self.shown)))
        ready = self.base is not None
        elapsed = time.time() - self.t0
        if self.state == "ending" and elapsed >= self.MIN_SHOW and self.shown == self.freed:
            if ready and self.finale is not None:
                self.state, self.fstep = "finale", 0
                self.itemconfigure(self.status, text="All clean")
            elif not ready or elapsed > self.MIN_SHOW + 2:  # finale not ready yet: don't hold the UI
                return self._done()
        if self.state == "finale":
            k = self.fstep
            self.fstep += 1
            if k < self.FINALE:
                self._show(self.finale[k])
                if k == int(self.FINALE * 0.55):
                    self.itemconfigure(self.count, fill=OK)
            elif k < self.FINALE + self.FADE:
                a = 1 - (k - self.FINALE + 1) / self.FADE
                self._show(self.bg_rgb + (self.finale[-1].astype(np.float32) - self.bg_rgb) * a)
            else:
                return self._done()
        elif ready:
            p = min(1.0, self.freed / self.total)
            self.idx = (self.idx + 1 + 0.9 * p) % self.FRAMES         # spins up as the clean progresses
            for g in range(len(self.weights)):
                target = 1.0 if g == self.current else 0.35 if g in self.groups else 0.0
                self.weights[g] += (target - self.weights[g]) * 0.08
            self._show(self._compose(int(self.idx), min(1.0, self.tick / 12)))
        self._anim = self.after(33, self._step)

    def _compose(self, i, alpha):
        out = self.base[i].astype(np.float32)
        for g, w in enumerate(self.weights):
            if w > 0.02:
                lum = self.layers[g][i].astype(np.float32) * (w / 255)
                out += lum[..., None] * self.colors[g] * 1.5 + (lum ** 4)[..., None] * 170  # white-hot core
        return out if alpha >= 1 else self.bg_rgb + (out - self.bg_rgb) * alpha

    def _done(self):
        self.stop()
        if self.on_done:
            self.on_done()

    # ---------------------------------------------------------- rendering (worker threads)
    def _geometry(self, collapse=0.0):
        s = self.SS
        W, H = self.w * s, self.h * s
        rmax = min(W * 0.4, H * 1.35)
        bottom, top = H - px(16) * s, px(10) * s + rmax * 0.24  # mouth ellipse stays in frame
        return W, H, W / 2, bottom, top + (bottom - top) * 0.82 * collapse, rmax * (1 - 0.94 * collapse)

    def _point(self, geo, i, t, phase):
        _W, _H, cx, bottom, top, rmax = geo
        r = px(3) * self.SS + (rmax - px(3) * self.SS) * t ** 1.8
        a = phase + i * 6.2832 / self.THREADS + t * 1.25 * 6.2832
        depth = math.sin(a)
        return cx + r * math.cos(a), bottom - (bottom - top) * t + r * depth * 0.24, depth

    @staticmethod
    def _lut(stops):
        rgb = [(k, Image.new("RGB", (1, 1), c).getpixel((0, 0))) for k, c in stops]
        lut = []
        for v in range(256):
            k = v / 255
            (k1, c1), (k2, c2) = next(((a, b) for a, b in zip(rgb, rgb[1:]) if k <= b[0]), (rgb[-2], rgb[-1]))
            f = (k - k1) / (k2 - k1)
            lut.append(tuple(int(x + (y - x) * f) for x, y in zip(c1, c2)))
        return lut

    def _threads(self, dr, geo, phase, lut, gain=1.0):
        _W, _H, _cx, bottom, top, _r = geo
        lines = []
        for i in range(self.THREADS):
            pts = [self._point(geo, i, k / self.SEGMENTS, phase) for k in range(self.SEGMENTS + 1)]
            for (x1, y1, d1), (x2, y2, d2) in zip(pts, pts[1:]):
                depth = (d1 + d2) / 4 + 0.5                        # 0 back .. 1 front
                t = min(1.0, max(0.0, (y1 - bottom) / ((top - bottom) or 1)))
                heat = (0.12 + 0.6 * depth) * (0.6 + 0.4 * (1 - t) ** 0.6) * gain
                lines.append((depth, (x1, y1, x2, y2), min(1.0, heat), 1 + (depth > 0.75)))
        for _d, xy, heat, wdt in sorted(lines):                     # painter's order: back to front
            dr.line(xy, fill=lut[int(heat * 255)], width=wdt)

    def _bloom(self, img, sharp_k=0.9, small_k=0.45, wide_k=0.55):
        w, h = self.w, self.h
        sharp = np.asarray(img.resize((w, h), Image.LANCZOS), np.float32)
        small = np.asarray(img.resize((w, h), Image.BILINEAR).filter(ImageFilter.GaussianBlur(px(2.5))), np.float32)
        wide = np.asarray(img.resize((w // 2, h // 2), Image.BILINEAR).filter(ImageFilter.GaussianBlur(px(7)))
                          .resize((w, h), Image.BILINEAR), np.float32)
        return sharp * sharp_k + small * small_k + wide * wide_k

    def _backdrop(self):
        """Card color plus a soft blue halo in the funnel; also the darker pocket that sits behind the count."""
        base = np.empty((self.h, self.w, 3), np.float32)
        base[:] = self.bg_rgb
        yy, xx = np.mgrid[0:self.h, 0:self.w].astype(np.float32)
        cx, tip = self.w / 2, self.h - px(16)
        d = np.sqrt(((xx - cx) / (self.w * 0.32)) ** 2 + ((yy - tip) / (self.h * 0.9)) ** 2)
        halo = np.exp(-d * d * 3)[..., None]
        pocket = np.exp(-(((xx - cx) / px(120)) ** 2 + ((yy - self.text_y - px(12)) / px(34)) ** 2))[..., None]
        return base + halo * np.array([18, 34, 80], np.float32), pocket

    def _render_loop(self):
        geo = self._geometry()
        backdrop, pocket = self._backdrop()
        lut, n = self._lut(self.BLUE), self.THREADS
        base, layers = [], [[] for _c in self.colors]
        for f in range(self.FRAMES):
            u = f / self.FRAMES
            phase = u * 6.2832 / n
            img = Image.new("RGB", (geo[0], geo[1]))
            self._threads(ImageDraw.Draw(img), geo, phase, lut)
            out = backdrop + self._bloom(img)
            out = out - (out - self.bg_rgb) * pocket * 0.6           # keep the count readable
            base.append(np.clip(out, 0, 255).astype(np.uint8))
            for g in range(len(self.colors)):
                layers[g].append(self._sparks(geo, u, phase, g / len(self.colors), pocket))
        self.layers, self.base = layers, base

    def _sparks(self, geo, u, phase, offset, pocket):
        """One group's sparks as a luminance layer: a comet per thread heading down into the tip. Each moves
        1 - 8/n per loop and thread i starts at 8i/n, so after the loop's one-spacing turn they line up again."""
        n, s = self.THREADS, self.SS
        img = Image.new("L", (geo[0], geo[1]))
        dr = ImageDraw.Draw(img)
        for i in range(n):
            head = (8 * i / n + offset - u * (1 - 8 / n)) % 1
            swallow = min(1.0, head * 5)                             # fades as it is pulled into the tip
            prev = self._point(geo, i, head, phase)
            for k in range(1, 16):                                  # tapering streak behind (above) the head
                t = head + k * 0.007
                if t >= 1:
                    break
                cur = self._point(geo, i, t, phase)
                fade = (1 - k / 16) ** 1.5 * (0.35 + 0.65 * (prev[2] + 1) / 2) * swallow
                dr.line((prev[0], prev[1], cur[0], cur[1]), fill=int(60 + 150 * fade),
                        width=max(1, round((1 + 2 * fade) * s)))
                prev = cur
            x, y, depth = self._point(geo, i, head, phase)
            r = (1 + 1.2 * (depth + 1) / 2) * s * (0.5 + 0.5 * swallow)
            dr.ellipse((x - r, y - r, x + r, y + r), fill=int(255 * (0.4 + 0.6 * swallow)))
        lum = self._bloom(img, 1.0, 0.8, 0.9) * (1 - pocket[..., 0] * 0.6)
        return np.clip(lum, 0, 255).astype(np.uint8)

    def _render_finale(self):
        """Speed-up, collapse into the tip, blue -> green, then a flash and a shockwave ring."""
        while self.base is None:
            time.sleep(0.1)
        blue, green = self._lut(self.BLUE), self._lut(self.GREEN)
        backdrop, _pocket = self._backdrop()
        yy, xx = np.mgrid[0:self.h, 0:self.w].astype(np.float32)
        frames, phase = [], 0.0
        for k in range(self.FINALE):
            e = k / (self.FINALE - 1)
            collapse = e ** 2.2
            phase += 0.05 + 0.5 * e ** 2                             # whirls faster as it closes
            geo = self._geometry(collapse)
            g = min(1.0, e * 1.8)
            lut = [tuple(int(b + (c - b) * g) for b, c in zip(bb, cc)) for bb, cc in zip(blue, green)]
            img = Image.new("RGB", (geo[0], geo[1]))
            dr = ImageDraw.Draw(img)
            self._threads(dr, geo, phase, lut, gain=1 + 0.6 * e)
            cx, tip = geo[2], geo[3]
            if e > 0.55:                                             # shockwave ring leaving the tip
                q = (e - 0.55) / 0.45
                rx = q * geo[0] * 0.42
                ry = rx * 0.09  # flat, so it stays inside the frame
                dr.ellipse((cx - rx, tip - ry, cx + rx, tip + ry), outline=green[int(255 * (1 - q) ** 1.5)],
                           width=self.SS * 2)
            out = backdrop + self._bloom(img)
            flash = math.exp(-((e - 0.72) / 0.12) ** 2)              # peaks just after the collapse
            d2 = ((xx - cx / self.SS) / px(90)) ** 2 + ((yy - tip / self.SS) / px(40)) ** 2
            out += (np.exp(-d2) * flash)[..., None] * np.array([150, 255, 200], np.float32)
            frames.append(np.clip(out, 0, 255).astype(np.uint8))
        self.finale = frames


class NavItem(tk.Frame):
    def __init__(self, parent, icon, text, command):
        super().__init__(parent, bg=SIDEBAR, cursor="hand2")
        self.bar = tk.Frame(self, bg=SIDEBAR, width=px(3))
        self.bar.pack(side="left", fill="y")
        self.inner = tk.Frame(self, bg=SIDEBAR, padx=px(13), pady=px(4), highlightthickness=1,
                              highlightbackground=SIDEBAR)
        self.inner.pack(side="left", fill="x", expand=True, padx=(px(8), px(12)))
        self.icon = tk.Label(self.inner, text=ICONS[icon], font=F["icon"], bg=SIDEBAR, fg=MUTED, width=2)
        self.icon.pack(side="left")
        self.text = tk.Label(self.inner, text=text, font=F["nav"], bg=SIDEBAR, fg=MUTED, anchor="w")
        self.text.pack(side="left", padx=(px(8), 0))
        self.active = False
        for w in (self, self.inner, self.icon, self.text):
            w.bind("<Button-1>", lambda _e: command())
            w.bind("<Enter>", lambda _e: self._paint(hover=True))
            w.bind("<Leave>", lambda _e: self._paint())

    def set_active(self, on):
        self.active = on
        self._paint()

    def _paint(self, hover=False):
        bg = ACCENT_DIM if self.active else SURFACE if hover else SIDEBAR
        self.bar.configure(bg=GOLD if self.active else SIDEBAR)
        self.inner.configure(highlightbackground=ACCENT_LINE if self.active else bg)
        for w in (self.inner, self.icon, self.text):
            w.configure(bg=bg)
        self.icon.configure(fg=GOLD if self.active else (TEXT if hover else MUTED))
        self.text.configure(fg=ACCENT_HOVER if self.active else TEXT if hover else MUTED)


class Segmented(tk.Frame):
    """Tab strip that switches between content frames."""

    def __init__(self, parent, items, on_change):
        super().__init__(parent, bg=SURFACE, padx=px(4), pady=px(4))
        self.buttons, self.on_change = {}, on_change
        for key, text in items:
            b = tk.Label(self, text=text, font=F["small_b"], bg=SURFACE, fg=MUTED, padx=px(16), pady=px(7),
                         cursor="hand2")
            b.pack(side="left", padx=px(2))
            b.bind("<Button-1>", lambda _e, k=key: self.select(k))
            self.buttons[key] = b

    def select(self, key):
        for k, b in self.buttons.items():
            b.configure(bg=SURFACE_2 if k == key else SURFACE, fg=ACCENT_HOVER if k == key else MUTED)
        self.on_change(key)


class ScrollFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=parent["bg"])
        self.canvas = tk.Canvas(self, bg=parent["bg"], highlightthickness=0, bd=0)
        sb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=parent["bg"])
        win = self.canvas.create_window(0, 0, window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(win, width=e.width))
        self.canvas.configure(yscrollcommand=sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y", padx=(px(6), 0))
        self.bind("<Enter>", lambda _e: self.canvas.bind_all("<MouseWheel>", self._wheel))
        self.bind("<Leave>", lambda _e: self.canvas.unbind_all("<MouseWheel>"))

    def _wheel(self, e):
        if self.inner.winfo_height() > self.canvas.winfo_height():
            self.canvas.yview_scroll(int(-e.delta / 120), "units")


def ago(ts):
    s = max(0, time.time() - ts)
    if s < 90:
        return "just now"
    if s < 3600:
        return f"{int(s // 60)} minutes ago"
    if s < 86400:
        h = int(s // 3600)
        return f"{h} hour{'s' if h > 1 else ''} ago"
    d = int(s // 86400)
    return f"{d} day{'s' if d > 1 else ''} ago"


def badge(parent, text, tone="info"):
    return tk.Label(parent, text=f"●  {text}", font=F["caption"], fg=TONES[tone][0], bg=parent["bg"], pady=px(2))


def setting_row(parent, title, desc=None, first=False):
    """A settings line: title/description on the left, returns the right-hand frame for controls."""
    if not first:
        divider(parent)
    row = frame(parent, pady=px(12))
    row.pack(fill="x")
    left = frame(row)
    left.pack(side="left", fill="x", expand=True)
    label(left, title, "body_b").pack(anchor="w")
    if desc:
        label(left, desc, "small", MUTED).pack(anchor="w", pady=(px(2), 0))
    right = frame(row)
    right.pack(side="right")
    return right


def table(parent, columns, height=None, tree_column=None):
    """Dark Treeview with a scrollbar. tree_column=(title, width) adds the expandable first column."""
    box = frame(parent)
    box.pack(fill="both", expand=True)
    tree = ttk.Treeview(box, columns=[c[0] for c in columns], show="tree headings" if tree_column else "headings",
                        height=height or 10)
    if tree_column:
        tree.heading("#0", text=tree_column[0], anchor="w")
        tree.column("#0", width=px(tree_column[1]), anchor="w", stretch=True)
    for key, title, width, stretch in columns:
        tree.heading(key, text=title, anchor="w")
        tree.column(key, width=px(width), anchor="w", stretch=stretch)
    sb = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    for tone, (fg, _bg) in TONES.items():
        tree.tag_configure(tone, foreground=fg)
    tree.tag_configure("muted", foreground=MUTED)
    tree.empty = tk.Label(box, font=F["body"], fg=SUBTLE, bg=SURFACE)
    return tree


def set_empty(tree, text):
    """Show a centred placeholder when a table has no rows."""
    if tree.get_children():
        tree.empty.place_forget()
    else:
        tree.empty.configure(text=text)
        tree.empty.place(relx=0.5, rely=0.45, anchor="center")


CLEAN_INFO = {
    "User temporary files": "Leftovers from installers and apps in your Temp folder",
    "Windows temporary files": "System temp files in the Windows folder",
    "Google Chrome cache": "Cached pages and images — sites re-download them when needed",
    "Microsoft Edge cache": "Cached pages and images — sites re-download them when needed",
    "Firefox cache": "Cached pages and images — sites re-download them when needed",
    "Thumbnail cache": "Picture previews; Windows rebuilds them automatically",
    "Crash dumps & error reports": "Diagnostic files left behind by crashed apps",
    "Windows Update download cache": "Setup files from updates that are already installed",
    "Recycle Bin": "Files you have already deleted",
}

THREAT_STATUS = {0: "Unknown", 1: "Detected", 2: "Cleaned", 3: "Quarantined", 4: "Removed", 5: "Allowed",
                 6: "Blocked", 102: "Quarantine failed", 103: "Remove failed", 104: "Allow failed",
                 105: "Abandoned", 107: "Block failed"}
THREAT_ACTIVE = (1, 102, 103, 105, 107)


# ---------------------------------------------------------------- app

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        init_fonts(self)
        self.title("Kavacham")
        try:
            self.iconbitmap(os.path.join(ASSETS, "logo.ico"))
        except tk.TclError:
            pass
        self.geometry(f"{px(1180)}x{px(760)}")
        self.minsize(px(1020), px(680))
        self.configure(bg=BG)
        self.q = queue.Queue()
        self.scan_proc = None
        self._cancelled = False
        self._scan_t0 = None
        self.mpcmd = find_mpcmdrun()
        self.settings = load_settings()
        self._style()
        self._layout()
        dark_titlebar(self)
        self.after(100, self._drain)
        self.show("dashboard")
        self.after(2000, lambda: self.bg(self._engine_startup))

    def _engine_startup(self):
        """Keep the engine fresh: update stale feeds and make sure the monitor runs if it's switched on."""
        try:  # one background checkup so the Overview can show the security score
            self.ui(self._show_security, security.run_checks())
        except Exception as e:
            engine.log_event("protection", "warn", "Security checkup failed", str(e)[:200])
        cfg = self.settings["engine"]
        if engine.monitor_wanted(self.settings):
            if not engine.monitor_task_exists():
                engine.set_monitor(True)  # registers start-at-sign-in and starts it now
            elif not engine.monitor_running():
                engine.start_monitor()
        try:
            self._alerts = alerts.run_checks()[1]  # also toasts new problems (at most once a day each)
        except Exception:
            pass
        if cfg["auto_update"] and engine.needs_update():
            try:
                engine.update()
            except Exception:
                pass

    # ---- plumbing
    def ui(self, fn, *args):
        self.q.put((fn, args))

    def _drain(self):
        try:
            while True:
                fn, args = self.q.get_nowait()
                try:
                    fn(*args)
                except Exception:  # one failed update mustn't stop every later one
                    self.report_callback_exception(*sys.exc_info())
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def bg(self, fn, *args):
        threading.Thread(target=fn, args=args, daemon=True).start()

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT, font=F["body"], bordercolor=BORDER,
                    troughcolor=SURFACE, focuscolor=ACCENT)
        field = dict(fieldbackground=SURFACE_2, background=SURFACE_2, foreground=TEXT, bordercolor=BORDER,
                     lightcolor=SURFACE_2, darkcolor=SURFACE_2, arrowcolor=MUTED, insertcolor=TEXT,
                     selectbackground=ACCENT_DIM, selectforeground=TEXT, padding=px(6))
        for name in ("TCombobox", "TSpinbox", "TEntry"):
            s.configure(name, **field)
            s.map(name, fieldbackground=[("readonly", SURFACE_2), ("disabled", SURFACE)],
                  foreground=[("disabled", SUBTLE)], arrowcolor=[("disabled", SUBTLE), ("active", TEXT)],
                  background=[("active", HOVER), ("disabled", SURFACE)], bordercolor=[("focus", ACCENT)],
                  lightcolor=[("focus", SURFACE_2)])
        s.configure("TSpinbox", arrowsize=px(12))
        self.option_add("*TCombobox*Listbox.background", SURFACE_2)
        self.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT_DIM)
        self.option_add("*TCombobox*Listbox.selectForeground", TEXT)
        self.option_add("*TCombobox*Listbox.font", F["body"])
        self.option_add("*TCombobox*Listbox.borderWidth", 0)
        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=TEXT, rowheight=px(36),
                    borderwidth=0, font=F["body"])
        s.map("Treeview", background=[("selected", ACCENT_DIM)], foreground=[("selected", TEXT)])
        s.configure("Treeview.Heading", background=SURFACE, foreground=MUTED, relief="flat", borderwidth=0,
                    font=F["caption"], padding=(px(6), px(8)))
        s.map("Treeview.Heading", background=[("active", SURFACE)], foreground=[("active", TEXT)])
        s.configure("Vertical.TScrollbar", background=SURFACE_2, troughcolor=SURFACE, bordercolor=SURFACE,
                    lightcolor=SURFACE_2, darkcolor=SURFACE_2, arrowcolor=MUTED, gripcount=0, arrowsize=px(12))
        s.map("Vertical.TScrollbar", background=[("active", HOVER)])

    def _layout(self):
        side = tk.Frame(self, bg=SIDEBAR, width=px(236))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(self, bg=BORDER, width=1).pack(side="left", fill="y")

        brand = frame(side, padx=px(22), pady=px(16))
        brand.pack(fill="x")
        logo = tk.Canvas(brand, width=px(38), height=px(38), bg=SIDEBAR, highlightthickness=0)
        logo_file = os.path.join(ASSETS, "logo.png")
        if Image and os.path.exists(logo_file):
            img = Image.open(logo_file).convert("RGBA").resize((px(38), px(38)), Image.LANCZOS)
            mask = Image.new("L", img.size, 0)
            ImageDraw.Draw(mask).rounded_rectangle((0, 0, img.size[0] - 1, img.size[1] - 1), px(10), fill=255)
            img.putalpha(mask)
            self.logo_photo = ImageTk.PhotoImage(img)
            logo.create_image(0, 0, image=self.logo_photo, anchor="nw")
        else:
            round_rect(logo, 0, 0, px(38), px(38), px(10), fill=ACCENT, outline=ACCENT)
            logo.create_text(px(19), px(20), text=ICONS["shield"], font=F["icon_lg"], fill=ON_ACCENT)
        logo.pack(side="left")
        names = frame(brand)
        names.pack(side="left", padx=px(12))
        label(names, "Kavacham", "brand").pack(anchor="w")
        label(names, "YOUR DIGITAL SHIELD", "caption", GOLD).pack(anchor="w", pady=(px(1), 0))

        gold_rule(side, height=1, center=True).pack(fill="x", padx=px(22))
        label(side, "MENU", "caption", SUBTLE).pack(anchor="w", padx=px(26), pady=(px(14), px(6)))
        foot = Card(side, padding=14, bg=SURFACE)
        foot.pack(side="bottom", fill="x", padx=px(16), pady=px(16))
        if is_admin():
            row = frame(foot)
            row.pack(fill="x")
            label(row, ICONS["admin"], "icon_sm", OK).pack(side="left")
            label(row, "Administrator mode", "small_b").pack(side="left", padx=px(8))
            label(foot, "All features are unlocked.", "small", MUTED).pack(anchor="w", pady=(px(4), 0))
        else:
            label(foot, "Standard mode", "small_b").pack(anchor="w")
            label(foot, "Some cleanup and removal tasks need administrator rights.", "small", MUTED,
                  wraplength=px(180), justify="left").pack(anchor="w", pady=(px(3), px(10)))
            Button(foot, "Restart as admin", self._elevate, "secondary", icon="admin",
                   width=px(176), height=32).pack(anchor="w")
        self.nav = {}
        for key, icon, text in [("dashboard", "home", "Overview"), ("security", "lock", "Security checkup"),
                                ("privacy", "camera", "Privacy"),
                                ("scan", "scan", "Virus scan"),
                                ("engine", "search", "Engine scan"), ("usb", "drive", "USB & phone"),
                                ("threats", "history", "Threat history"),
                                ("quarantine", "shield", "Quarantine"), ("events", "file", "Security activity"),
                                ("cleaner", "clean", "Storage cleaner"),
                                ("large", "folder", "Large files"), ("duplicates", "copy", "Duplicate files"),
                                ("schedule", "calendar", "Automation")]:
            item = NavItem(side, icon, text, lambda k=key: self.show(k))
            item.pack(fill="x", pady=1)
            self.nav[key] = item

        self.body = frame(self, bg=BG, padx=px(36), pady=px(28))
        self.body.pack(side="left", fill="both", expand=True)
        self.pages = {
            "dashboard": self._page_dashboard(),
            "security": self._page_security(),
            "privacy": self._page_privacy(),
            "scan": self._page_scan(),
            "engine": self._page_engine(),
            "usb": self._page_usb(),
            "threats": self._page_threats(),
            "quarantine": self._page_quarantine(),
            "events": self._page_events(),
            "cleaner": self._page_cleaner(),
            "large": self._page_large(),
            "duplicates": self._page_duplicates(),
            "schedule": self._page_schedule(),
        }

    def _elevate(self):
        if relaunch_as_admin():
            self.destroy()

    def show(self, key):
        for k, page in self.pages.items():
            page.pack_forget()
            self.nav[k].set_active(k == key)
        self.pages[key].pack(fill="both", expand=True)
        if key == "dashboard":
            self.refresh_status()
        elif key == "threats":
            self.refresh_threats()
        elif key == "engine":
            self.refresh_engine()
        elif key == "quarantine":
            self.refresh_quarantine()
        elif key == "events":
            self.refresh_events()
        elif key == "usb":
            self.refresh_usb()
        elif key == "schedule":
            self.refresh_schedule()
        elif key == "security":
            self.refresh_security()
        elif key == "privacy":
            self.refresh_privacy()
            self.bg(lambda: self.ui(self._show_cam, privacy.usage()))
        elif key == "cleaner" and not self._cleaner_ready:
            self._cleaner_ready = True  # measuring is read-only, so analyze automatically on first visit
            self.analyze()

    def page(self, title, subtitle):
        p = frame(self.body)
        head = frame(p)
        head.pack(fill="x", pady=(0, px(22)))
        label(head, title, "h1").pack(anchor="w")
        gold_rule(head, px(120)).pack(anchor="w", pady=(px(4), px(8)))
        label(head, subtitle, "body", MUTED).pack(anchor="w")
        return p

    # ---------------------------------------------------------- security checkup
    def _page_security(self):
        p = self.page("Security checkup", "How well Windows is set up to protect you, and one-click fixes for the "
                                          "weak spots. Everything is checked on this PC.")
        self._sec, self._sec_busy, self._blocked = None, False, None  # None: blocked list not loaded yet
        scroll = ScrollFrame(p)
        scroll.pack(fill="both", expand=True)
        body = scroll.inner

        top = Card(body, padding=26)
        top.pack(fill="x", padx=(0, px(4)))
        row = frame(top)
        row.pack(fill="x")
        num = frame(row)
        num.pack(side="left")
        self.sec_score = label(num, "—", "big")
        self.sec_score.pack(side="left", anchor="s")
        label(num, " / 100", "body", MUTED).pack(side="left", anchor="s", pady=(0, px(8)))
        mid = frame(row)
        mid.pack(side="left", fill="x", expand=True, padx=(px(26), 0))
        self.sec_badge = badge(mid, "CHECKING", "info")
        self.sec_badge.pack(anchor="w")
        self.sec_title = label(mid, "Checking your security settings…", "h3")
        self.sec_title.pack(anchor="w", pady=(px(4), 0))
        self.sec_when = label(mid, "", "small", MUTED)
        self.sec_when.pack(anchor="w")
        self.sec_again = Button(row, "Check again", lambda: self.refresh_security(force=True), "secondary",
                                icon="refresh")
        self.sec_again.pack(side="right", anchor="n")
        self.sec_bar = Bar(top, height=6)
        self.sec_bar.pack(fill="x", pady=(px(18), 0))

        shield = Card(body, padding=22)
        shield.pack(fill="x", padx=(0, px(4)), pady=(px(16), 0))
        head = frame(shield)
        head.pack(fill="x")
        label(head, ICONS["lock"], "icon", ACCENT).pack(side="left")
        label(head, "Ransomware shield", "h2").pack(side="left", padx=px(10))
        self.shield_badge = badge(head, "…", "info")
        self.shield_badge.pack(side="left")
        self.shield_btn = Button(head, "Turn on", self.toggle_shield, "primary", width=px(110))
        self.shield_btn.pack(side="right")
        label(shield, "Only apps you trust can change files in Documents, Pictures, Videos, Music and Desktop. Even "
                      "ransomware that antivirus misses can't lock your personal files. Uses Windows' built-in "
                      "Controlled folder access.", "small", MUTED, wraplength=px(780), justify="left").pack(
            anchor="w", pady=(px(8), px(10)))
        label(shield, "BLOCKED IN THE LAST 30 DAYS", "caption", SUBTLE).pack(anchor="w", pady=(px(4), px(4)))
        self.shield_tree = table(shield, [("time", "WHEN", 130, False), ("app", "APP", 300, True),
                                          ("file", "TRIED TO CHANGE", 320, True)], height=4)
        set_empty(self.shield_tree, "Nothing blocked. If a trusted app can't save your files, it shows up here.")
        acts = frame(shield)
        acts.pack(fill="x", pady=(px(10), 0))
        Button(acts, "Allow selected app", self.shield_allow, "secondary", icon="check").pack(side="left")
        label(acts, "Allowing needs administrator permission", "small", SUBTLE).pack(side="left", padx=px(12))

        checks = Card(body, padding=22)
        checks.pack(fill="x", padx=(0, px(4)), pady=(px(16), px(4)))
        label(checks, "Checklist", "h2").pack(anchor="w")
        label(checks, "Most important first. Fixes with a shield icon ask Windows for administrator permission.",
              "small", MUTED).pack(anchor="w", pady=(px(4), px(4)))
        self.sec_list = frame(checks)
        self.sec_list.pack(fill="x")
        return p

    def refresh_security(self, force=False):
        if self._sec_busy:
            return
        if self._sec and not force and time.time() - self._sec["time"] < 120 and self._blocked is not None:
            self._show_security(self._sec)
            return
        self._sec_busy = True
        self.sec_again.configure(state="disabled")
        self.sec_when.configure(text="Checking…")

        def work():
            try:
                result, blocked = security.run_checks(), security.blocked_apps()
                self.ui(self._show_security, result, blocked)
            except Exception as e:
                self.ui(lambda m=str(e): self.sec_when.configure(text=f"Couldn't check: {m}"))
            finally:
                self._sec_busy = False
                self.ui(lambda: self.sec_again.configure(state="normal"))
        self.bg(work)

    def _show_security(self, result, blocked=None):
        self._sec = result
        score, checks = result["score"], result["checks"]
        todo = [c for c in checks if c["status"] in ("bad", "warn")]
        tone = "ok" if score >= 75 else "warn" if score >= 50 else "bad"
        word = "Excellent" if score >= 90 else "Good" if score >= 75 else "Needs attention" if score >= 50 else "At risk"
        many = "s" if len(todo) != 1 else ""
        title = f"{word}, nothing to fix" if not todo else f"{word}, {len(todo)} thing{many} to improve"
        self.sec_line.configure(text=f"Security score {score}/100  ·  " +
                                (f"{len(todo)} to improve  ›" if todo else "all good  ›"), fg=TONES[tone][0])
        self.sec_score.configure(text=str(score), fg=TONES[tone][0])
        self.sec_badge.configure(text="●  " + word.upper(),
                                 fg=TONES[tone][0])
        self.sec_title.configure(text=title)
        self.sec_when.configure(text=security.checked_ago(result).capitalize())
        self.sec_bar.set(score / 100, TONES[tone][0])

        on = result["cfa"] == 1
        self.shield_badge.configure(text="●  ON" if on else "●  AUDIT ONLY" if result["cfa"] == 2 else "●  OFF",
                                    fg=OK if on else WARN)
        self.shield_btn.kind = "secondary" if on else "primary"
        self.shield_btn.configure(text="Turn off" if on else "Turn on")
        if blocked is not None:
            self._blocked = blocked
            self.shield_tree.delete(*self.shield_tree.get_children())
            for i, b in enumerate(blocked):
                self.shield_tree.insert("", "end", iid=str(i), values=(b["time"], b["app"], b["file"]))

        self._render_checks(self.sec_list, checks, security.FIXES, self.security_fix)

    def _render_checks(self, box, checks, fixes, on_fix):
        """Checklist rows, most important problems first, with a Fix / Open settings button each."""
        for w in box.winfo_children():
            w.destroy()
        order = {"bad": 0, "warn": 1, "ok": 2, "na": 3}
        for i, c in enumerate(sorted(checks, key=lambda c: (order[c["status"]], -c["weight"]))):
            if i:
                divider(box)
            row = frame(box, pady=px(12))
            row.pack(fill="x")
            right = frame(row)
            right.pack(side="right")
            left = frame(row)
            left.pack(side="left", fill="x", expand=True)
            color = {"ok": OK, "warn": WARN, "bad": BAD, "na": SUBTLE}[c["status"]]
            line = frame(left)
            line.pack(anchor="w")
            label(line, "●", "small", color).pack(side="left")
            label(line, c["title"], "body_b").pack(side="left", padx=(px(8), 0))
            label(left, c["detail"], "small", MUTED, wraplength=px(620), justify="left").pack(
                anchor="w", padx=(px(20), 0), pady=(px(2), 0))
            if c["fix"]:
                script, admin = fixes[c["fix"]]
                text = "Open settings" if script.startswith("open:") else "Turn on" if script.startswith("kavacham:") \
                    else "Fix"
                Button(right, text, lambda f=c["fix"]: on_fix(f),
                       "primary" if c["status"] == "bad" else "secondary",
                       icon="admin" if admin and not is_admin() else None).pack(side="right")
            elif c["status"] == "ok":
                label(right, ICONS["check"], "icon_sm", OK).pack(side="right")
            elif c["status"] == "na":
                label(right, "Not available on this PC", "small", SUBTLE).pack(side="right")

    def security_fix(self, fix_id):
        def work():
            res = security.apply_fix(fix_id)
            if res == "failed":
                self.ui(messagebox.showwarning, "Kavacham", "That couldn't be changed. If Windows asked for "
                                                            "permission, choose Yes and try again.")
            elif res == "opened":
                self.ui(messagebox.showinfo, "Kavacham", "Windows Security opened. Switch the setting on there, "
                                                         "then click Check again.")
            self.ui(self.refresh_security, True)
        self.bg(work)

    def toggle_shield(self):
        on = bool(self._sec and self._sec["cfa"] == 1)
        if on and not messagebox.askyesno("Kavacham", "Turn off the ransomware shield?\n\nAny program will be able "
                                                       "to change your personal files again."):
            return
        self.security_fix("cfa_off" if on else "cfa")

    def shield_allow(self):
        sel = self.shield_tree.selection()
        if not sel or not self._blocked:
            messagebox.showinfo("Kavacham", "Select a blocked app in the list first.")
            return
        app = self._blocked[int(sel[0])]["app"]
        if not app or not messagebox.askyesno("Kavacham", "Allow this app to change your protected folders?\n\n"
                                                          f"{app}\n\nOnly do this for apps you trust."):
            return

        def work():
            ok = security.allow_app(app)
            self.ui(messagebox.showinfo if ok else messagebox.showwarning, "Kavacham",
                    "Allowed. It can save to your folders now." if ok else "Couldn't allow it.")
        self.bg(work)

    # ---------------------------------------------------------- privacy
    def _page_privacy(self):
        p = self.page("Privacy", "Know when apps use your camera or microphone, and keep Windows from sharing more than "
                                 "it needs to. Everything is checked on this PC.")
        self._priv, self._priv_busy, self._cam_rows = None, False, []
        scroll = ScrollFrame(p)
        scroll.pack(fill="both", expand=True)
        body = scroll.inner

        cam = Card(body, padding=22)
        cam.pack(fill="x", padx=(0, px(4)))
        head = frame(cam)
        head.pack(fill="x")
        label(head, ICONS["camera"], "icon", ACCENT).pack(side="left")
        label(head, "Camera & microphone", "h2").pack(side="left", padx=px(10))
        self.cam_watch = tk.BooleanVar(value=self.settings["privacy"]["watch"])
        Toggle(head, self.cam_watch, command=self.privacy_toggle_watch).pack(side="right")
        label(head, "Alert me", "small_b", MUTED).pack(side="right", padx=px(8))
        label(cam, "Kavacham pops up a notice whenever an app turns on your camera or microphone, even when Kavacham "
                   "is closed. Apps you trust are still listed here but don't pop up.", "small", MUTED,
              wraplength=px(780), justify="left").pack(anchor="w", pady=(px(8), px(12)))
        live = frame(cam)
        live.pack(fill="x", pady=(0, px(12)))
        self.cam_live_dot = label(live, "●", "body", OK)
        self.cam_live_dot.pack(side="left")
        self.cam_live = label(live, "Checking…", "body_b")
        self.cam_live.pack(side="left", padx=px(8))
        self.cam_tree = table(cam, [("camera", "CAMERA", 170, False), ("mic", "MICROPHONE", 170, False),
                                    ("trust", "", 90, False)], height=6, tree_column=("APP", 330))
        self.cam_tree.tag_configure("live", foreground=BAD)
        set_empty(self.cam_tree, "No app has used your camera or microphone yet.")
        acts = frame(cam)
        acts.pack(fill="x", pady=(px(12), 0))
        Button(acts, "Trust", lambda: self.privacy_trust(True), "secondary", icon="check").pack(side="left")
        Button(acts, "Stop trusting", lambda: self.privacy_trust(False), "secondary").pack(side="left", padx=px(8))
        Button(acts, "Close app", self.privacy_close_app, "danger", icon="stop").pack(side="left")
        Button(acts, "Microphone settings", lambda: os.startfile("ms-settings:privacy-microphone"), "ghost",
               icon="open").pack(side="right")
        Button(acts, "Camera settings", lambda: os.startfile("ms-settings:privacy-webcam"), "ghost",
               icon="open").pack(side="right", padx=px(8))

        top = Card(body, padding=26)
        top.pack(fill="x", padx=(0, px(4)), pady=(px(16), 0))
        row = frame(top)
        row.pack(fill="x")
        num = frame(row)
        num.pack(side="left")
        self.priv_score = label(num, "—", "big")
        self.priv_score.pack(side="left", anchor="s")
        label(num, " / 100", "body", MUTED).pack(side="left", anchor="s", pady=(0, px(8)))
        mid = frame(row)
        mid.pack(side="left", fill="x", expand=True, padx=(px(26), 0))
        self.priv_badge = badge(mid, "CHECKING", "info")
        self.priv_badge.pack(anchor="w")
        self.priv_title = label(mid, "Checking your privacy settings…", "h3")
        self.priv_title.pack(anchor="w", pady=(px(4), 0))
        self.priv_when = label(mid, "", "small", MUTED)
        self.priv_when.pack(anchor="w")
        self.priv_again = Button(row, "Check again", lambda: self.refresh_privacy(force=True), "secondary",
                                 icon="refresh")
        self.priv_again.pack(side="right", anchor="n")
        self.priv_bar = Bar(top, height=6)
        self.priv_bar.pack(fill="x", pady=(px(18), 0))

        checks = Card(body, padding=22)
        checks.pack(fill="x", padx=(0, px(4)), pady=(px(16), px(4)))
        label(checks, "Privacy checklist", "h2").pack(anchor="w")
        label(checks, "Most important first. Fixes change only privacy settings; your files and apps aren't touched. "
                      "Fixes with a shield icon ask Windows for administrator permission.", "small", MUTED,
              wraplength=px(780), justify="left").pack(anchor="w", pady=(px(4), px(4)))
        self.priv_list = frame(checks)
        self.priv_list.pack(fill="x")
        self.after(2000, self._privacy_tick)
        return p

    def _privacy_tick(self):
        """Live camera & microphone status while the Privacy page is open."""
        if self.pages["privacy"].winfo_ismapped():
            self.bg(lambda: self.ui(self._show_cam, privacy.usage()))
        self.after(2000, self._privacy_tick)

    def _show_cam(self, rows):
        self._cam_rows = rows
        trusted = set(self.settings["privacy"]["trusted"])
        sel = set(self.cam_tree.selection())
        when = lambda u: "● In use now" if u and u["in_use"] else ago(u["start"]) if u else "—"  # noqa: E731
        self.cam_tree.delete(*self.cam_tree.get_children())
        for a in rows:
            live = any(a[k] and a[k]["in_use"] for k in ("camera", "microphone"))
            self.cam_tree.insert("", "end", iid=a["id"], text=a["name"], tags=("live",) if live else (),
                                 values=(when(a["camera"]), when(a["microphone"]),
                                         "Trusted" if a["id"] in trusted else ""))
        self.cam_tree.selection_set([i for i in sel if self.cam_tree.exists(i)])
        set_empty(self.cam_tree, "No app has used your camera or microphone yet.")
        now = privacy.in_use(rows)
        if now:
            names = {}
            for a, k in now:
                names.setdefault(a["name"], []).append(k)
            text = "  ·  ".join(f"{n} is using your {' and '.join(ks)}" for n, ks in names.items())
            self.cam_live.configure(text=text, fg=BAD)
            self.cam_live_dot.configure(fg=BAD)
        else:
            self.cam_live.configure(text="Nothing is using your camera or microphone right now.", fg=TEXT)
            self.cam_live_dot.configure(fg=OK)

    def _cam_selected(self):
        ids = set(self.cam_tree.selection())
        return [a for a in self._cam_rows if a["id"] in ids]

    def privacy_toggle_watch(self):
        on = self.cam_watch.get()
        self.settings["privacy"]["watch"] = on
        write_json(SETTINGS_FILE, self.settings)
        engine.log_event("privacy", "info", f"Camera & microphone alerts turned {'on' if on else 'off'}")
        wanted = engine.monitor_wanted(self.settings)

        def work():
            err = engine.set_monitor(wanted) if on or not wanted else None
            if err:
                self.ui(messagebox.showwarning, "Kavacham", "Alerts are working now, but couldn't be set to start "
                                                            f"when you sign in:\n\n{err}")
            self.ui(self.refresh_privacy, True)
        self.bg(work)

    def privacy_trust(self, trust):
        rows = self._cam_selected()
        if not rows:
            messagebox.showinfo("Kavacham", "Select an app in the list first.")
            return
        trusted = self.settings["privacy"]["trusted"]
        for a in rows:
            if trust and a["id"] not in trusted:
                trusted.append(a["id"])
            elif not trust and a["id"] in trusted:
                trusted.remove(a["id"])
        write_json(SETTINGS_FILE, self.settings)
        self._show_cam(self._cam_rows)

    def privacy_close_app(self):
        rows = [a for a in self._cam_selected() if a["path"]]
        if not rows:
            messagebox.showinfo("Kavacham", "Select a desktop app in the list first.\n\nStore apps (like Camera) close "
                                            "like any window; you can also block them in Camera settings.")
            return
        a = rows[0]
        if not messagebox.askyesno("Kavacham", f"Close {a['name']} now?\n\n{a['path']}\n\nAnything unsaved in it is "
                                               "lost. To stop it using the camera or microphone for good, switch it "
                                               "off in Camera settings or Microphone settings."):
            return

        def work():
            n = privacy.close_app(a["path"])
            self.ui(messagebox.showinfo, "Kavacham", f"{a['name']} was closed." if n else
                    f"{a['name']} isn't running, or Windows didn't let Kavacham close it.")
        self.bg(work)

    def refresh_privacy(self, force=False):
        if self._priv_busy:
            return
        if self._priv and not force and time.time() - self._priv["time"] < 120:
            return
        self._priv_busy = True
        self.priv_again.configure(state="disabled")
        self.priv_when.configure(text="Checking…")

        def work():
            try:
                self.ui(self._show_privacy, privacy.run_checks(self.settings["privacy"]["watch"]))
            except Exception as e:
                self.ui(lambda m=str(e): self.priv_when.configure(text=f"Couldn't check: {m}"))
            finally:
                self._priv_busy = False
                self.ui(lambda: self.priv_again.configure(state="normal"))
        self.bg(work)

    def _show_privacy(self, result):
        self._priv = result
        score, checks = result["score"], result["checks"]
        todo = [c for c in checks if c["status"] in ("bad", "warn")]
        tone = "ok" if score >= 75 else "warn" if score >= 50 else "bad"
        word = "Private" if score >= 90 else "Good" if score >= 75 else "Could be better" if score >= 50 else "Sharing a lot"
        many = "s" if len(todo) != 1 else ""
        self.priv_score.configure(text=str(score), fg=TONES[tone][0])
        self.priv_badge.configure(text="●  " + word.upper(), fg=TONES[tone][0])
        self.priv_title.configure(text=f"{word}, nothing to fix" if not todo else
                                  f"{word}, {len(todo)} setting{many} to tighten")
        self.priv_when.configure(text=security.checked_ago(result).capitalize())
        self.priv_bar.set(score / 100, TONES[tone][0])
        self._render_checks(self.priv_list, checks, privacy.FIXES, self.privacy_fix)

    def privacy_fix(self, fix_id):
        if fix_id == "watch":
            self.cam_watch.set(True)
            self.privacy_toggle_watch()
            return

        def work():
            res = privacy.apply_fix(fix_id)
            if res == "failed":
                self.ui(messagebox.showwarning, "Kavacham", "That couldn't be changed. If Windows asked for "
                                                            "permission, choose Yes and try again.")
            elif res == "opened":
                self.ui(messagebox.showinfo, "Kavacham", "Windows Settings opened. Change the setting there, then "
                                                         "click Check again.")
            self.ui(self.refresh_privacy, True)
        self.bg(work)

    # ---------------------------------------------------------- overview
    def _page_dashboard(self):
        p = self.page("Overview", "Your protection and storage at a glance.")

        hero = Card(p, padding=26, border=ACCENT_LINE)
        hero.pack(fill="x")
        self.ring = StatusRing(hero)
        self.ring.pack(side="left")
        text = frame(hero)
        text.pack(side="left", fill="x", expand=True, padx=(px(28), 0))
        self.status_badge = badge(text, "CHECKING", "info")
        self.status_badge.pack(anchor="w")
        self.status_title = label(text, "Checking your protection…", "hero")
        self.status_title.pack(anchor="w", pady=(px(8), px(2)))
        self.status_sub = label(text, "", "body", MUTED, wraplength=px(560), justify="left")
        self.status_sub.pack(anchor="w")
        self.sec_line = label(text, "", "small_b", ACCENT, cursor="hand2")
        self.sec_line.pack(anchor="w", pady=(px(8), 0))
        self.sec_line.bind("<Button-1>", lambda _e: self.show("security"))
        actions = frame(text)
        actions.pack(anchor="w", pady=(px(18), 0))
        Button(actions, "Quick scan", lambda: (self.show("scan"), self.start_scan(1)), "primary",
               icon="play").pack(side="left")
        Button(actions, "Update definitions", self.update_defs, "secondary", icon="download").pack(
            side="left", padx=px(10))
        Button(actions, "Refresh", self.refresh_status, "ghost", icon="refresh").pack(side="left")

        tiles = frame(p)
        tiles.pack(fill="x", pady=px(16))
        self.tiles = {}
        for i, (key, icon, title) in enumerate([("rtp", "bolt", "Real-time protection"),
                                                ("defs", "download", "Virus definitions"),
                                                ("last", "check", "Last scan"),
                                                ("next", "calendar", "Next scheduled scan")]):
            tiles.columnconfigure(i, weight=1, uniform="tile")
            card = Card(tiles, padding=18)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else px(8), 0 if i == 3 else px(8)))
            top = frame(card)
            top.pack(fill="x")
            medal = tk.Canvas(top, width=px(28), height=px(28), bg=card["bg"], highlightthickness=0)
            medal.create_oval(1, 1, px(28) - 1, px(28) - 1, fill=ACCENT_DIM, outline=ACCENT_LINE)
            medal.create_text(px(14), px(15), text=ICONS[icon], font=F["icon_sm"], fill=GOLD)
            medal.pack(side="left")
            label(top, title, "small", MUTED).pack(side="left", padx=px(10))
            value = label(card, "—", "h3")
            value.pack(anchor="w", pady=(px(12), px(2)))
            sub = label(card, "", "small", MUTED)
            sub.pack(anchor="w")
            self.tiles[key] = (value, sub)

        storage = Card(p, padding=22)
        storage.pack(fill="x")
        head = frame(storage)
        head.pack(fill="x", pady=(0, px(12)))
        label(head, "Storage", "h2").pack(side="left")
        Button(head, "Free up space", lambda: self.show("cleaner"), "ghost", icon="clean").pack(side="right")
        self.disk_frame = frame(storage)
        self.disk_frame.pack(fill="x")
        return p

    def refresh_status(self):
        self._draw_disks()
        if not self.mpcmd:
            self._set_status("bad", "DEFENDER MISSING", "Microsoft Defender not found",
                             "Kavacham uses Microsoft Defender to scan. Make sure Windows Security is installed.")
            return
        self.bg(self._load_status)

    def _set_status(self, tone, tag, title, sub):
        fg, bgc = TONES[tone]
        self.ring.set(tone)
        self.status_badge.configure(text=f"●  {tag}", fg=fg)
        self.status_title.configure(text=title)
        self.status_sub.configure(text=sub)

    def _draw_disks(self):
        for w in self.disk_frame.winfo_children():
            w.destroy()
        for root in fixed_drives():
            try:
                u = shutil.disk_usage(root)
            except OSError:
                continue
            used = u.used / u.total
            color = BAD if used > 0.9 else WARN if used > 0.75 else ACCENT
            row = frame(self.disk_frame, pady=px(6))
            row.pack(fill="x")
            top = frame(row)
            top.pack(fill="x", pady=(0, px(8)))
            label(top, ICONS["drive"], "icon_sm", MUTED).pack(side="left")
            label(top, f"Local Disk ({root[:2]})", "body_b").pack(side="left", padx=px(10))
            label(top, f"{human(u.free)} free of {human(u.total)}", "small", MUTED).pack(side="right")
            label(top, f"{used:.0%} used", "small_b", color).pack(side="right", padx=px(12))
            bar = Bar(row, height=8, color=color)
            bar.pack(fill="x")
            bar.after(50, bar.set, used, color)

    def _load_status(self):
        script = (
            "$s=Get-MpComputerStatus; $f={param($d) if($d){$d.ToString('dd MMM yyyy, HH:mm')}else{'Never'}};"
            "[pscustomobject]@{AV=$s.AntivirusEnabled; RTP=$s.RealTimeProtectionEnabled;"
            "Ver=$s.AntivirusSignatureVersion; Age=$s.AntivirusSignatureAge;"
            "Upd=(& $f $s.AntivirusSignatureLastUpdated); Quick=(& $f $s.QuickScanEndTime);"
            "Full=(& $f $s.FullScanEndTime);"
            f"Next=$($i=Get-ScheduledTask -TaskName {ps_quote(TASK_NAMES['scan'])} -ErrorAction SilentlyContinue |"
            " Get-ScheduledTaskInfo; if(-not $i){'Not scheduled'}elseif($i.NextRunTime){& $f $i.NextRunTime}"
            "else{'At sign-in'})} | ConvertTo-Json -Compress"
        )
        try:
            s = powershell_json(script)
        except Exception as e:
            msg = str(e)[:200]
            self.ui(self._set_status, "warn", "UNKNOWN", "Could not read protection status", msg)
            return

        def apply():
            if self.scan_proc:
                pass  # keep the "scanning" hero while a scan runs
            elif not (s["AV"] and s["RTP"]):
                self._set_status("bad", "AT RISK", "Your PC is at risk",
                                 "Real-time protection is turned off. Turn it back on in Windows Security.")
            elif (s["Age"] or 0) > 3:
                self._set_status("warn", "ATTENTION", "Virus definitions are out of date",
                                 f"Definitions were last updated {s['Age']} days ago. Update them to stay protected.")
            else:
                self._set_status("ok", "PROTECTED", "Your PC is protected",
                                 "Real-time protection is on and virus definitions are up to date.")
            tiles = {"rtp": ("On" if s["RTP"] else "Off", "Microsoft Defender engine"),
                     "defs": (f"v{s['Ver']}", f"Updated {s['Upd']}"),
                     "last": (s["Quick"] if s["Quick"] != "Never" else "Never", f"Full scan: {s['Full']}"),
                     "next": (s["Next"], "Change it in Automation")}
            for key, (value, sub) in tiles.items():
                self.tiles[key][0].configure(text=value, fg=(BAD if key == "rtp" and not s["RTP"] else TEXT))
                self.tiles[key][1].configure(text=sub)
        self.ui(apply)

    def update_defs(self):
        self.show("scan")
        self._run_mpcmd(["-SignatureUpdate"], "Updating virus definitions…")

    # ---------------------------------------------------------- scan
    def _page_scan(self):
        p = self.page("Virus scan", "Scans use the Microsoft Defender engine. Threats are quarantined automatically.")
        opts = frame(p)
        opts.pack(fill="x")
        self.scan_buttons = []
        for i, (icon, title, desc, cmd, kind) in enumerate([
            ("bolt", "Quick scan", "Checks the places malware usually hides.\nAbout 5 minutes.",
             lambda: self.start_scan(1), "primary"),
            ("shield", "Full scan", "Checks every file on every drive.\nCan take an hour or more.",
             lambda: self.start_scan(2), "secondary"),
            ("folder", "Custom scan", "Pick a folder or a single file,\nsuch as a new download.",
             self.custom_scan, "secondary"),
        ]):
            opts.columnconfigure(i, weight=1, uniform="opt")
            card = Card(opts, padding=22)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else px(8), 0 if i == 2 else px(8)))
            ic = tk.Canvas(card, width=px(44), height=px(44), bg=SURFACE, highlightthickness=0)
            round_rect(ic, 0, 0, px(44), px(44), px(12), fill=ACCENT_DIM, outline=ACCENT_DIM)
            ic.create_text(px(22), px(23), text=ICONS[icon], font=F["icon"], fill=ACCENT)
            ic.pack(anchor="w")
            label(card, title, "h2").pack(anchor="w", pady=(px(14), px(4)))
            label(card, desc, "small", MUTED, justify="left").pack(anchor="w")
            b = Button(card, "Start scan", cmd, kind, icon="play")
            b.pack(anchor="w", pady=(px(16), 0))
            self.scan_buttons.append(b)

        prog = Card(p, padding=22)
        prog.pack(fill="both", expand=True, pady=(px(16), 0))
        top = frame(prog)
        top.pack(fill="x")
        self.scan_icon = label(top, ICONS["shield"], "icon", MUTED)
        self.scan_icon.pack(side="left")
        self.scan_status = label(top, "Ready to scan", "h2")
        self.scan_status.pack(side="left", padx=px(10))
        self.cancel_btn = Button(top, "Cancel", self.cancel_scan, "danger", icon="stop")
        self.cancel_btn.configure(state="disabled")
        self.cancel_btn.pack(side="right")
        self.scan_elapsed = label(top, "", "small", MUTED)
        self.scan_elapsed.pack(side="right", padx=px(14))
        self.scan_bar = Bar(prog, height=6)
        self.scan_bar.pack(fill="x", pady=(px(16), px(16)))
        label(prog, "ACTIVITY", "caption", SUBTLE).pack(anchor="w", pady=(0, px(6)))
        logbox = tk.Frame(prog, bg=BG, highlightthickness=1, highlightbackground=BORDER)
        logbox.pack(fill="both", expand=True)
        self.scan_log = tk.Text(logbox, height=6, bd=0, bg=BG, fg=MUTED, font=F["mono"], wrap="word",
                                padx=px(14), pady=px(10), insertbackground=TEXT, highlightthickness=0,
                                selectbackground=ACCENT_DIM)
        self.scan_log.pack(fill="both", expand=True)
        self._log("Scan output appears here.\n")
        return p

    def custom_scan(self):
        path = filedialog.askdirectory(title="Choose a folder to scan")
        if not path:
            path = filedialog.askopenfilename(title="…or choose a single file to scan")
        if path:
            self.start_scan(3, os.path.normpath(path))

    def start_scan(self, scan_type, path=None):
        self._scan_name = {1: "Quick scan", 2: "Full scan", 3: f"Custom scan: {path}"}[scan_type]
        args = ["-Scan", "-ScanType", str(scan_type)]
        if path:
            args += ["-File", path]
        label_ = f"Scanning {os.path.basename(path) or path}…" if path else self._scan_name + " in progress…"
        self._run_mpcmd(args, label_, is_scan=True)

    def _run_mpcmd(self, args, text, is_scan=False):
        if self.scan_proc:
            messagebox.showinfo("Kavacham", "A scan or update is already running.")
            return
        if not self.mpcmd:
            messagebox.showerror("Kavacham", "Microsoft Defender (MpCmdRun.exe) was not found.")
            return
        self.scan_log.delete("1.0", "end")
        self.scan_status.configure(text=text, fg=TEXT)
        self.scan_icon.configure(text=ICONS["refresh"], fg=ACCENT)
        self.scan_bar.start()
        for b in self.scan_buttons:
            b.configure(state="disabled")
        self.cancel_btn.configure(state="normal" if is_scan else "disabled")
        self._scan_t0 = time.time()
        self._tick_elapsed()
        if is_scan:
            self.ring.spin(True)
            self._set_status("info", "SCANNING", "Scan in progress", text)
        self.bg(self._mpcmd_worker, args, is_scan)

    def _tick_elapsed(self):
        if self._scan_t0 is None:
            return
        m, s = divmod(int(time.time() - self._scan_t0), 60)
        self.scan_elapsed.configure(text=f"Elapsed {m:02d}:{s:02d}")
        self.after(1000, self._tick_elapsed)

    def _mpcmd_worker(self, args, is_scan):
        rc = -1
        try:
            self.scan_proc = subprocess.Popen([self.mpcmd] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                              text=True, errors="replace", creationflags=NO_WINDOW)
            for line in self.scan_proc.stdout:
                if line.strip():
                    self.ui(self._log, line)
            rc = self.scan_proc.wait()
        except Exception as e:
            self.ui(self._log, f"Error: {e}\n")
        cancelled, self._cancelled = self._cancelled, False
        self.scan_proc = None
        self.ui(self._scan_done, rc, is_scan, cancelled)

    def _log(self, line):
        self.scan_log.insert("end", line)
        self.scan_log.see("end")

    def _scan_done(self, rc, is_scan, cancelled):
        self.scan_bar.stop()
        self._scan_t0 = None
        self.ring.spin(False)
        for b in self.scan_buttons:
            b.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        if is_scan:
            result, level = ("Cancelled", "warn") if cancelled else {
                0: ("No threats found", "ok"), 2: ("Threats found and quarantined", "bad")
            }.get(rc, (f"Scan error (code {rc})", "warn"))
            add_history("Manual scan", result, self._scan_name, level)
        if cancelled:
            tone, text = "warn", "Scan cancelled"
        elif is_scan and rc == 0:
            tone, text = "ok", "Scan complete — no threats found"
        elif is_scan and rc == 2:
            tone, text = "bad", "Threats were found and quarantined"
            self.after(800, lambda: self.show("threats"))
        elif rc == 0:
            tone, text = "ok", "Done"
        else:
            tone = "warn"
            text = f"Finished with error code {rc}" + ("" if is_admin() else " — try Restart as admin")
        self.scan_status.configure(text=text, fg=TONES[tone][0])
        self.scan_icon.configure(text=ICONS["check"] if tone == "ok" else ICONS["warning"], fg=TONES[tone][0])
        self.scan_bar.set(1.0, TONES[tone][0])
        self.refresh_status()

    def cancel_scan(self):
        if self.scan_proc:
            self._cancelled = True
            subprocess.Popen([self.mpcmd, "-Scan", "-Cancel"], creationflags=NO_WINDOW)
            self.scan_proc.terminate()

    # ---------------------------------------------------------- threats
    def _page_threats(self):
        p = self.page("Threat history", "Everything Microsoft Defender has detected on this PC.")
        banner = Card(p, padding=20)
        banner.pack(fill="x")
        self.threat_icon = label(banner, ICONS["shield"], "icon_lg", MUTED)
        self.threat_icon.pack(side="left")
        text = frame(banner)
        text.pack(side="left", padx=px(14))
        self.threat_summary = label(text, "Loading…", "h2")
        self.threat_summary.pack(anchor="w")
        self.threat_sub = label(text, "", "small", MUTED)
        self.threat_sub.pack(anchor="w")
        Button(banner, "Remove active threats", self.remove_threats, "danger", icon="clean").pack(side="right")
        Button(banner, "Refresh", self.refresh_threats, "secondary", icon="refresh").pack(side="right", padx=px(10))

        box = Card(p, padding=8)
        box.pack(fill="both", expand=True, pady=(px(16), 0))
        self.threat_tree = table(box, [("name", "THREAT", 240, False), ("time", "DETECTED", 150, False),
                                       ("status", "STATUS", 130, False), ("files", "AFFECTED FILES", 400, True)])
        return p

    def refresh_threats(self):
        self.threat_summary.configure(text="Loading…", fg=TEXT)
        self.bg(self._load_threats)

    def _load_threats(self):
        script = (
            "$n=@{}; Get-MpThreat | % { $n[[string]$_.ThreatID]=$_.ThreatName };"
            "$r=@(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | % {"
            "[pscustomobject]@{Name=$n[[string]$_.ThreatID]; Time=$_.InitialDetectionTime.ToString('dd MMM yyyy HH:mm');"
            "Status=[int]$_.ThreatStatusID; Files=(($_.Resources | % { $_ -replace '^\\w+:_','' }) -join '; ')} });"
            "ConvertTo-Json -InputObject $r -Compress"
        )
        try:
            rows = powershell_json(script) or []
        except Exception as e:
            msg = str(e)[:150]
            self.ui(lambda: (self.threat_summary.configure(text="Could not load history", fg=BAD),
                             self.threat_sub.configure(text=msg)))
            return

        def apply():
            self.threat_tree.delete(*self.threat_tree.get_children())
            for r in rows:
                active = r["Status"] in THREAT_ACTIVE
                self.threat_tree.insert("", "end", tags=("bad" if active else "",), values=(
                    r.get("Name") or "Unknown", r["Time"], THREAT_STATUS.get(r["Status"], str(r["Status"])),
                    r["Files"]))
            set_empty(self.threat_tree, "Nothing has been detected. Your threat history is clean.")
            active = sum(1 for r in rows if r["Status"] in THREAT_ACTIVE)
            if not rows:
                tone, title, sub = "ok", "No threats detected", "Defender hasn't found anything harmful on this PC."
            elif active:
                tone, title, sub = "bad", f"{active} threat(s) need attention", "Click 'Remove active threats'."
            else:
                tone, title, sub = "ok", f"{len(rows)} past threat(s), all handled", "Nothing needs your attention."
            self.threat_icon.configure(text=ICONS["shield"] if tone == "ok" else ICONS["warning"], fg=TONES[tone][0])
            self.threat_summary.configure(text=title, fg=TEXT)
            self.threat_sub.configure(text=sub)
        self.ui(apply)

    def remove_threats(self):
        if not is_admin():
            if messagebox.askyesno("Kavacham", "Removing threats needs administrator rights.\nRestart as admin now?"):
                self._elevate()
            return
        self.threat_summary.configure(text="Removing threats…")

        def work():
            run_ps("Remove-MpThreat", timeout=600)
            self._load_threats()
        self.bg(work)

    # ---------------------------------------------------------- Kavacham engine
    def _page_engine(self):
        p = self.page("Kavacham engine", "Kavacham's own detection layer: malware signatures, heuristic rules and "
                                         "link checks, working alongside Microsoft Defender.")
        self.eng_results, self.eng_busy, self._eng_cancel = [], False, False
        holder = frame(p)
        self.eng_frames = {}
        self.eng_tabs = Segmented(p, [("scan", "Scan"), ("protect", "Real-time & downloads"),
                                      ("links", "Web protection")], self._switch_engine)
        self.eng_tabs.pack(anchor="w", pady=(0, px(16)))
        holder.pack(fill="both", expand=True)

        # -- scan tab
        tab = frame(holder)
        self.eng_frames["scan"] = tab
        ctl = Card(tab, padding=22)
        ctl.pack(fill="x")
        top = frame(ctl)
        top.pack(fill="x")
        left = frame(top)
        left.pack(side="left", fill="x", expand=True)
        self.eng_status = label(left, "Ready to scan", "h2")
        self.eng_status.pack(anchor="w")
        self.eng_sub = label(left, "Quick checks Downloads, Desktop, Documents, Temp, AppData and Startup.",
                             "small", MUTED)
        self.eng_sub.pack(anchor="w", pady=(px(2), 0))
        btns = frame(top)
        btns.pack(side="right", anchor="n")
        self.eng_buttons = [
            Button(btns, "Quick scan", lambda: self.engine_scan("quick"), "primary", icon="bolt"),
            Button(btns, "Full scan", lambda: self.engine_scan("full"), "secondary", icon="shield"),
            Button(btns, "Scan folder", lambda: self.engine_scan("custom"), "secondary", icon="folder"),
        ]
        for i, b in enumerate(self.eng_buttons):
            b.pack(side="left", padx=(0 if i == 0 else px(8), 0))
        self.eng_cancel_btn = Button(btns, "Cancel", self.engine_cancel, "danger", icon="stop")
        self.eng_bar = Bar(ctl, height=4)

        res = Card(tab, padding=8)
        res.pack(fill="both", expand=True, pady=(px(16), 0))
        self.eng_tree = table(res, [("verdict", "VERDICT", 110, False), ("name", "FILE", 230, False),
                                    ("why", "WHY IT WAS FLAGGED", 380, True), ("action", "STATUS", 120, False)])
        self.eng_tree.bind("<Double-1>", lambda _e: self.engine_open_location())
        set_empty(self.eng_tree, "Run a scan to see results here.")
        acts = frame(res, padx=px(10), pady=px(10))
        acts.pack(fill="x")
        Button(acts, "Quarantine selected", self.engine_quarantine_selected, "danger", icon="stop").pack(side="left")
        Button(acts, "Mark as safe", self.engine_mark_safe, "secondary", icon="check").pack(side="left",
                                                                                            padx=px(8))
        Button(acts, "What does this mean?", self.engine_explain_selected, "secondary", icon="search").pack(
            side="left", padx=(0, px(8)))
        Button(acts, "Open file location", self.engine_open_location, "ghost", icon="open").pack(side="left")


        # -- real-time & updates tab
        tab = ScrollFrame(holder)
        self.eng_frames["protect"] = tab
        body = tab.inner
        db_card = Card(body, padding=22)
        db_card.pack(fill="x", padx=(0, px(4)))
        head = frame(db_card)
        head.pack(fill="x")
        label(head, ICONS["download"], "icon", ACCENT).pack(side="left")
        label(head, "Threat intelligence", "h2").pack(side="left", padx=px(10))
        self.eng_update_btn = Button(head, "Update now", self.engine_update, "secondary", icon="refresh")
        self.eng_update_btn.pack(side="right")
        self.eng_db_status = label(db_card, "Loading…", "small", MUTED)
        self.eng_db_status.pack(anchor="w", pady=(px(8), px(14)))
        stats = frame(db_card)
        stats.pack(fill="x")
        self.eng_stats = {}
        for i, (key, title) in enumerate([("hashes", "MALWARE SIGNATURES"), ("urls", "MALICIOUS LINKS"),
                                          ("hosts", "MALWARE DOMAINS"), ("rules", "HEURISTIC RULES")]):
            stats.columnconfigure(i, weight=1, uniform="stat")
            cell = frame(stats)
            cell.grid(row=0, column=i, sticky="w")
            label(cell, title, "caption", SUBTLE).pack(anchor="w")
            self.eng_stats[key] = label(cell, "—", "h3")
            self.eng_stats[key].pack(anchor="w")
        label(db_card, "Sources: MalwareBazaar and URLhaus (abuse.ch), OpenPhish, stalkerware indicators. Free "
                       "community feeds, refreshed every 6 hours.", "small", SUBTLE).pack(anchor="w", pady=(px(14), 0))
        right = setting_row(db_card, "abuse.ch key", "Free, needed for MalwareBazaar and URLhaus. Get one at "
                                                     "auth.abuse.ch; stored encrypted with Windows")
        self.abusech_key = tk.StringVar()
        ttk.Entry(right, textvariable=self.abusech_key, show="•", width=26, font=F["body"]).pack(side="left")
        Button(right, "Save key", self.abusech_save_key, "primary", icon="check").pack(side="left", padx=(px(8), 0))
        Button(right, "Get key", lambda: webbrowser.open(engine.ABUSECH_SIGNUP), "ghost").pack(side="left",
                                                                                              padx=(px(6), 0))
        ecfg = self.settings["engine"]
        self.eng_vars = {k: tk.BooleanVar(value=ecfg[k]) for k in ("realtime", "auto_update", "auto_quarantine",
                                                                    "download_protection", "hold_downloads")}
        right = setting_row(db_card, "Update automatically", "Downloads new signatures in the background")
        Toggle(right, self.eng_vars["auto_update"], command=self._save_engine_settings).pack()

        rt = Card(body, padding=22)
        rt.pack(fill="x", padx=(0, px(4)), pady=(px(16), 0))
        head = frame(rt)
        head.pack(fill="x")
        label(head, ICONS["bolt"], "icon", ACCENT).pack(side="left")
        label(head, "Real-time monitoring", "h2").pack(side="left", padx=px(10))
        self.eng_rt_badge = badge(head, "OFF", "warn")
        self.eng_rt_badge.pack(side="left")
        Toggle(head, self.eng_vars["realtime"], command=self.engine_toggle_realtime).pack(side="right")
        label(rt, "New and changed files in the folders below are checked the moment they finish downloading or "
                  "copying. Runs in the background, also when Kavacham is closed, and starts when you sign in.",
              "small", MUTED, wraplength=px(720), justify="left").pack(anchor="w", pady=(px(8), 0))
        right = setting_row(rt, "Watched folders", None)
        Button(right, "Add folder", self.engine_add_folder, "secondary", icon="folder").pack(side="left")
        Button(right, "Reset", self.engine_reset_folders, "ghost").pack(side="left", padx=(px(8), 0))
        self.eng_folders = label(rt, "", "small", MUTED, justify="left")
        self.eng_folders.pack(anchor="w")
        right = setting_row(rt, "Quarantine known malware automatically",
                            "Files matching a malware signature are isolated right away")
        Toggle(right, self.eng_vars["auto_quarantine"], command=self._save_engine_settings).pack()

        dl = Card(body, padding=22)
        dl.pack(fill="x", padx=(0, px(4)), pady=(px(16), 0))
        head = frame(dl)
        head.pack(fill="x")
        label(head, ICONS["download"], "icon", ACCENT).pack(side="left")
        label(head, "Download protection", "h2").pack(side="left", padx=px(10))
        label(dl, "Works with real-time monitoring. Each finished download is checked before you open it: Kavacham's "
                  "engine, the website it came from, and a Microsoft Defender scan for programs, scripts, archives "
                  "and macro documents. Files still downloading are left alone until complete.", "small", MUTED,
              wraplength=px(720), justify="left").pack(anchor="w", pady=(px(8), 0))
        right = setting_row(dl, "Check new downloads", "Engine + source website + Defender second opinion")
        Toggle(right, self.eng_vars["download_protection"], command=self._save_engine_settings).pack()
        right = setting_row(dl, "Hold suspicious downloads for review",
                            "Moved to Quarantine until you decide; restore in one click if it's fine")
        Toggle(right, self.eng_vars["hold_downloads"], command=self._save_engine_settings).pack()

        # -- web protection (link checker) tab
        tab = ScrollFrame(holder)
        self.eng_frames["links"] = tab
        lc = Card(tab.inner, padding=22)
        lc.pack(fill="x", padx=(0, px(4)))
        label(lc, "Check a link before you open it", "h2").pack(anchor="w")
        label(lc, "Paste a link from an email, message or website. It's checked against live lists of phishing and "
                  "malware sites, then the page itself is inspected for fake sign-in forms and other tricks.",
              "small", MUTED, wraplength=px(760), justify="left").pack(anchor="w", pady=(px(4), px(14)))
        row = frame(lc)
        row.pack(fill="x")
        self.link_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.link_var, font=F["body"])
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self.engine_check_link())
        Button(row, "Check link", self.engine_check_link, "primary", icon="search").pack(side="left", padx=(px(10), 0))
        opt = frame(lc)
        opt.pack(fill="x", pady=(px(10), 0))
        self.link_inspect = tk.BooleanVar(value=True)
        Toggle(opt, self.link_inspect).pack(side="left")
        label(opt, "Inspect the page too  ·  read as text only: no scripts run, nothing is saved, you stay anonymous",
              "small", MUTED).pack(side="left", padx=(px(10), 0))
        self.link_result = frame(lc)
        self.link_result.pack(fill="x", pady=(px(16), 0))
        self.eng_tabs.select("scan")
        return p

    def _switch_engine(self, key):
        for f in self.eng_frames.values():
            f.pack_forget()
        self.eng_frames[key].pack(fill="both", expand=True)
        if key == "protect":
            self.refresh_engine()

    # ---- scanning
    def engine_scan(self, mode):
        if self.eng_busy:
            return
        if mode == "custom":
            path = filedialog.askdirectory(title="Choose a folder to scan")
            if not path:
                return
            roots, name = [os.path.normpath(path)], f"Engine scan: {os.path.basename(path) or path}"
        else:
            roots = engine.quick_paths() if mode == "quick" else engine.full_paths()
            name = "Engine quick scan" if mode == "quick" else "Engine full scan"
        self.eng_busy, self._eng_cancel = True, False
        for b in self.eng_buttons:
            b.configure(state="disabled")
        self.eng_cancel_btn.pack(side="left", padx=(px(8), 0))
        self.eng_bar.pack(fill="x", pady=(px(16), 0))
        self.eng_bar.start()
        self.eng_status.configure(text=f"{name}…", fg=TEXT)
        self.eng_sub.configure(text="Starting…")
        self.eng_tree.delete(*self.eng_tree.get_children())
        set_empty(self.eng_tree, "Scanning…")
        t0 = time.time()

        def progress(n, path, hits):
            self.ui(self.eng_sub.configure, {"text": f"{n:,} files checked · {hits} flagged · "
                                                     f"{int(time.time() - t0)} s   {path[-90:]}"})

        def work():
            try:
                hits, n, secs = engine.scan_and_act(roots, name, self.settings["engine"]["auto_quarantine"],
                                                    progress, lambda: self._eng_cancel)
                self.ui(self._engine_done, name, hits, n, secs)
            except Exception as e:
                self.ui(self._engine_done, name, [], 0, 0, str(e))
        self.bg(work)

    def engine_cancel(self):
        self._eng_cancel = True
        self.eng_sub.configure(text="Cancelling…")

    def _engine_done(self, name, hits, n, secs, error=None):
        self.eng_busy = False
        self.eng_bar.stop()
        self.eng_bar.pack_forget()
        self.eng_cancel_btn.pack_forget()
        for b in self.eng_buttons:
            b.configure(state="normal")
        self.eng_results = hits
        self._fill_engine_results()
        malware = sum(1 for h in hits if h["signature"])
        m, s = divmod(int(secs), 60)
        took = f"{n:,} files in {m} min {s} s" if m else f"{n:,} files in {s} s"
        if error:
            tone, title, sub = "warn", "Scan failed", error[:150]
        elif self._eng_cancel:
            tone, title, sub = "warn", "Scan cancelled", took
        elif malware:
            tone, title, sub = "bad", f"{malware} known malware file(s) found", took + " · see the list below"
        elif hits:
            tone, title, sub = "warn", f"{len(hits)} suspicious file(s) found", took + " · nothing matched known malware"
        else:
            tone, title, sub = "ok", "No threats found", took
        self.eng_status.configure(text=title, fg=TONES[tone][0])
        self.eng_sub.configure(text=sub)
        level = "bad" if malware else "warn" if hits or error else "ok"
        add_history("Engine scan", title, f"{name} · {sub}", level)

    def _fill_engine_results(self):
        self.eng_tree.delete(*self.eng_tree.get_children())
        for i, r in enumerate(self.eng_results):
            action = r.get("action", "Needs review" if r["verdict"] != "Worth a look" else "Your call")
            tone = "ok" if action == "Quarantined" or action == "Marked safe" else \
                "bad" if r["verdict"] in ("Malware", "Suspicious") else "warn"
            self.eng_tree.insert("", "end", iid=str(i), tags=(tone,),
                                 values=(r["verdict"], r["name"], "; ".join(r["reasons"]), action))
        set_empty(self.eng_tree, "Nothing suspicious found. Your files look clean.")

    def _selected_results(self):
        return [(int(i), self.eng_results[int(i)]) for i in self.eng_tree.selection()]

    def engine_quarantine_selected(self):
        rows = [(i, r) for i, r in self._selected_results() if r.get("action") != "Quarantined"]
        if not rows:
            messagebox.showinfo("Kavacham", "Select one or more files in the list first.")
            return
        names = "\n".join(f"•  {r['name']}" for _i, r in rows[:12])
        if not messagebox.askyesno("Kavacham", f"Move {len(rows)} file(s) to quarantine?\n\n{names}\n\n"
                                               "They can be restored from the Quarantine page."):
            return
        for _i, r in rows:
            ok = engine.quarantine(r["path"], "; ".join(r["reasons"]), r["sha256"])
            r["action"] = "Quarantined" if ok else "Could not quarantine"
        self._fill_engine_results()

    def engine_mark_safe(self):
        rows = self._selected_results()
        if not rows:
            messagebox.showinfo("Kavacham", "Select one or more files in the list first.")
            return
        if not messagebox.askyesno("Kavacham", f"Trust {len(rows)} file(s)? They won't be flagged again unless "
                                               "they change."):
            return
        for _i, r in rows:
            if r["sha256"]:
                engine.ignore(r["sha256"], r["path"])
            r["action"] = "Marked safe"
        self._fill_engine_results()

    def engine_open_location(self):
        rows = self._selected_results()
        if rows and os.path.exists(rows[0][1]["path"]):
            subprocess.Popen(["explorer", "/select,", rows[0][1]["path"]])

    # ---- real-time & updates
    def refresh_engine(self):
        def work():
            st = engine.engine_status()
            running = engine.monitor_running()

            def apply():
                for k in self.eng_stats:
                    self.eng_stats[k].configure(text=f"{st[k]:,}")
                if st["updated"]:
                    self.eng_db_status.configure(text=f"Last updated {ago(st['updated'])}", fg=MUTED)
                else:
                    self.eng_db_status.configure(text="Never updated — click Update now to download the "
                                                      "signatures.", fg=WARN)
                if not engine.abusech_key():
                    self.eng_db_status.configure(text=self.eng_db_status.cget("text") + "  ·  MalwareBazaar and "
                                                 "URLhaus are paused until you add your free abuse.ch key below.",
                                                 fg=WARN)
                on = self.settings["engine"]["realtime"]
                text, tone = ("ON", "ok") if on and running else ("STARTING", "info") if on else ("OFF", "warn")
                fg, bgc = TONES[tone]
                self.eng_rt_badge.configure(text=f"●  {text}", fg=fg)
                self.eng_folders.configure(text="\n".join(self.settings["engine"]["folders"]) or "No folders")
            self.ui(apply)
        self.bg(work)

    def engine_update(self):
        self.eng_update_btn.configure(state="disabled")

        def work():
            summary, errors = engine.update(lambda t: self.ui(self.eng_db_status.configure, {"text": t,
                                                                                               "fg": TEXT}))

            def done():
                self.eng_update_btn.configure(state="normal")
                self.refresh_engine()
                if errors and not summary:
                    messagebox.showwarning("Kavacham", "Could not reach the threat feeds:\n\n" + "\n".join(errors))
            self.ui(done)
        self.bg(work)

    def abusech_save_key(self):
        key = self.abusech_key.get().strip()
        if not key:
            return
        engine.save_abusech_key(key)
        self.settings = load_settings()
        self.abusech_key.set("")
        messagebox.showinfo("Kavacham", "abuse.ch key saved. Kavacham will now download the latest signatures.")
        self.engine_update()

    def _save_engine_settings(self):
        for k, v in self.eng_vars.items():
            self.settings["engine"][k] = v.get()
        write_json(SETTINGS_FILE, self.settings)

    def engine_toggle_realtime(self):
        self._save_engine_settings()
        on = engine.monitor_wanted(self.settings)  # camera & microphone alerts also need the monitor

        def work():
            err = engine.set_monitor(on)
            if err:
                self.ui(messagebox.showwarning, "Kavacham", "Monitoring is running now, but it couldn't be set to "
                                                            f"start at sign-in:\n\n{err}")
            time.sleep(2.5)
            self.refresh_engine()
        self.bg(work)
        self.refresh_engine()

    def engine_add_folder(self):
        path = filedialog.askdirectory(title="Choose a folder to watch")
        if path and os.path.normpath(path) not in self.settings["engine"]["folders"]:
            self.settings["engine"]["folders"].append(os.path.normpath(path))
            write_json(SETTINGS_FILE, self.settings)
            self.refresh_engine()

    def engine_reset_folders(self):
        self.settings["engine"]["folders"] = list(DEFAULT_SETTINGS["engine"]["folders"])
        write_json(SETTINGS_FILE, self.settings)
        self.refresh_engine()

    # ---- link checker
    def engine_check_link(self):
        text = self.link_var.get().strip()
        if not text:
            return

        for w in self.link_result.winfo_children():
            w.destroy()
        label(self.link_result, "Checking…" + ("  Inspecting the page can take a few seconds."
                                              if self.link_inspect.get() else ""), "body", MUTED).pack(anchor="w")
        inspect = self.link_inspect.get()

        def work():
            r = engine.check_link(text, inspect)
            self.ui(self._show_link_result, r)
        self.bg(work)

    def _show_link_result(self, r):
        self._last_link = r
        for w in self.link_result.winfo_children():
            w.destroy()
        tone, title = {"malicious": ("bad", "Dangerous — don't open this link"),
                       "suspicious": ("warn", "Suspicious — be careful")}.get(r["verdict"],
                                                                         ("ok", "No known threats"))
        row = frame(self.link_result)
        row.pack(anchor="w")
        label(row, ICONS["check"] if tone == "ok" else ICONS["warning"], "icon", TONES[tone][0]).pack(side="left")
        label(row, title, "h2", TONES[tone][0]).pack(side="left", padx=px(10))
        label(self.link_result, r["url"], "mono", MUTED).pack(anchor="w", pady=(px(6), px(2)))
        page = r.get("page") or {}
        if page.get("title") or page.get("redirects"):
            info = f"Page title: {page.get('title') or '(none)'}"
            if page.get("redirects"):
                info += f"   ·   ends up at {page['final_url'][:90]}"
            label(self.link_result, info, "small", MUTED).pack(anchor="w")
        tk.Frame(self.link_result, bg=SURFACE, height=px(8)).pack()
        if not r["reasons"]:
            label(self.link_result, "•  No warning signs found", "body").pack(anchor="w", pady=px(1))
        for reason, meaning in explain.explain(r["verdict"], r["reasons"])["items"]:
            label(self.link_result, f"•  {reason}", "body").pack(anchor="w", pady=(px(4), 0))
            label(self.link_result, meaning, "small", MUTED, wraplength=px(720), justify="left").pack(
                anchor="w", padx=(px(16), 0))
        if r["verdict"] != "malicious":
            label(self.link_result, "Not being on a threat list doesn't prove a link is safe. If a message is "
                                    "unexpected or urgent, go to the site yourself instead of clicking.",
                  "small", SUBTLE).pack(anchor="w", pady=(px(10), 0))

    # ---------------------------------------------------------- quarantine
    def _page_quarantine(self):
        p = self.page("Quarantine", "Files Kavacham's engine has isolated. They're encoded so they can't run, and "
                                    "can be restored if they turn out to be safe.")
        banner = Card(p, padding=20)
        banner.pack(fill="x")
        label(banner, ICONS["shield"], "icon_lg", ACCENT).pack(side="left")
        text = frame(banner)
        text.pack(side="left", padx=px(14))
        self.q_summary = label(text, "Loading…", "h2")
        self.q_summary.pack(anchor="w")
        self.q_sub = label(text, "", "small", MUTED)
        self.q_sub.pack(anchor="w")
        Button(banner, "Delete all", lambda: self.quarantine_delete(all_=True), "danger", icon="clean").pack(
            side="right")
        Button(banner, "Delete", self.quarantine_delete, "secondary", icon="stop").pack(side="right", padx=px(8))
        Button(banner, "Restore", self.quarantine_restore, "secondary", icon="refresh").pack(side="right")
        box = Card(p, padding=8)
        box.pack(fill="both", expand=True, pady=(px(16), 0))
        self.q_tree = table(box, [("name", "FILE", 200, False), ("reason", "REASON", 300, True),
                                  ("time", "QUARANTINED", 140, False), ("path", "ORIGINAL LOCATION", 300, True)])
        return p

    def refresh_quarantine(self):
        items = engine.quarantine_list()
        self.q_tree.delete(*self.q_tree.get_children())
        for it in items:
            self.q_tree.insert("", "end", iid=it["id"], values=(it["name"], it["reason"], it["time"], it["path"]))
        set_empty(self.q_tree, "Quarantine is empty.")
        total = sum(i.get("size", 0) for i in items)
        self.q_summary.configure(text=f"{len(items)} file(s) in quarantine" if items else "Quarantine is empty")
        self.q_sub.configure(text=f"{human(total)} isolated · select a file to restore or delete it" if items
                             else "Detected files you quarantine will appear here.")

    def quarantine_restore(self):
        sel = self.q_tree.selection()
        if not sel:
            messagebox.showinfo("Kavacham", "Select a file in the list first.")
            return
        if not messagebox.askyesno("Kavacham", f"Restore {len(sel)} file(s) to where they came from?\n\nOnly do this "
                                               "if you're sure they're safe. They won't be flagged again."):
            return
        for qid in sel:
            try:
                engine.restore(qid)
            except Exception as e:
                messagebox.showerror("Kavacham", f"Could not restore: {e}")
        self.refresh_quarantine()

    def quarantine_delete(self, all_=False):
        sel = self.q_tree.get_children() if all_ else self.q_tree.selection()
        if not sel:
            if not all_:
                messagebox.showinfo("Kavacham", "Select a file in the list first.")
            return
        if not messagebox.askyesno("Kavacham", f"Permanently delete {len(sel)} quarantined file(s)?\n\n"
                                               "This can't be undone."):
            return
        for qid in sel:
            engine.delete_quarantined(qid)
        self.refresh_quarantine()

    # ---------------------------------------------------------- USB & phone
    def _page_usb(self):
        p = self.page("USB & phone", "Pendrives, USB disks and Android phones connected with a USB cable. They get "
                                     "the same protection as this PC: engine, Defender and quarantine.")
        self.usb_results, self.usb_busy, self._usb_cancel, self._usb_info = [], False, False, {}
        devices = Card(p, padding=18)
        devices.pack(fill="x")
        head = frame(devices)
        head.pack(fill="x")
        label(head, "CONNECTED DEVICES", "caption", SUBTLE).pack(side="left")
        Button(head, "Refresh", self.refresh_usb, "ghost", icon="refresh", height=30).pack(side="right")
        self.usb_auto = tk.BooleanVar(value=self.settings["usb"]["auto_scan"])
        Toggle(head, self.usb_auto, command=self._save_usb_settings).pack(side="right", padx=(0, px(14)))
        label(head, "Scan pendrives automatically when plugged in", "small", MUTED).pack(side="right",
                                                                                         padx=(0, px(8)))
        self.usb_list = frame(devices)
        self.usb_list.pack(fill="x", pady=(px(10), 0))

        self.usb_tabs = Segmented(p, [("security", "Security scan"), ("storage", "Phone storage: large & duplicates")],
                                  self._switch_usb)
        self.usb_tabs.pack(anchor="w", pady=(px(14), 0))
        holder = frame(p)
        holder.pack(fill="both", expand=True)
        sec, stor = frame(holder), frame(holder)
        self.usb_frames = {"security": sec, "storage": stor}

        ctl = Card(sec, padding=18)
        ctl.pack(fill="x", pady=(px(14), 0))
        top = frame(ctl)
        top.pack(fill="x")
        left = frame(top)
        left.pack(side="left", fill="x", expand=True)
        self.usb_status = label(left, "Ready", "h2")
        self.usb_status.pack(anchor="w")
        self.usb_sub = label(left, "Pick a device above to scan it.", "small", MUTED)
        self.usb_sub.pack(anchor="w", pady=(px(2), 0))
        self.usb_cancel_btn = Button(top, "Cancel", self.usb_cancel, "danger", icon="stop")
        self.usb_bar = Bar(ctl, height=4)

        res = Card(sec, padding=8)
        res.pack(fill="both", expand=True, pady=(px(14), 0))
        self.usb_tree = table(res, [("device", "DEVICE", 150, False), ("item", "ITEM", 220, False),
                                    ("verdict", "VERDICT", 105, False), ("why", "WHY", 360, True),
                                    ("action", "STATUS", 120, False)])
        set_empty(self.usb_tree, "Scan results for USB drives and phones appear here.")
        acts = frame(res, padx=px(10), pady=px(10))
        acts.pack(fill="x")
        Button(acts, "Remove", self.usb_remove_selected, "danger", icon="stop").pack(side="left")
        Button(acts, "What does this mean?", self.usb_explain_selected, "secondary", icon="search").pack(
            side="left", padx=(px(8), 0))
        Button(acts, "Mark as safe", self.usb_mark_safe, "ghost", icon="check").pack(side="left", padx=px(8))
        label(acts, "Remove = quarantine (drives), delete (phone files) or uninstall (phone apps)", "small",
              SUBTLE).pack(side="right")
        stor.configure(pady=px(14))
        self._build_phone_storage(stor)
        self.usb_tabs.select("security")
        self.usb_watch = usb.Watcher()
        self.after(3000, self._usb_watch_tick)
        return p

    def _switch_usb(self, key):
        for f in self.usb_frames.values():
            f.pack_forget()
        self.usb_frames[key].pack(fill="both", expand=True)

    # ---- phone storage: large files and duplicates
    def _build_phone_storage(self, parent):
        cfg = self.settings["usb"].setdefault("storage", {"scope": "Whole phone", "large": "100 MB", "dup": "1 MB",
                                                           "hidden": False, "app_folders": False})
        self._ps_phones, self.ps_busy, self._ps_cancel, self.ps_meta, self.ps_mode = {}, False, False, {}, None
        opts = Card(parent, padding=18)
        opts.pack(fill="x")
        row1 = frame(opts)
        row1.pack(fill="x")
        self.ps_vars = {"phone": tk.StringVar(), "scope": tk.StringVar(value=cfg["scope"]),
                        "large": tk.StringVar(value=cfg["large"]), "dup": tk.StringVar(value=cfg["dup"]),
                        "hidden": tk.BooleanVar(value=cfg["hidden"]), "app_folders": tk.BooleanVar(value=cfg["app_folders"])}
        for text, key, values, width in (("Phone", "phone", [], 22), ("Look in", "scope", list(usb.PHONE_SCOPES), 18),
                                         ("Large files over", "large", list(usb.LARGE_SIZES), 8),
                                         ("Duplicates over", "dup", list(usb.DUP_SIZES), 8)):
            label(row1, text, "small_b", MUTED).pack(side="left", padx=(0 if key == "phone" else px(16), px(6)))
            box = ttk.Combobox(row1, textvariable=self.ps_vars[key], values=values, state="readonly", width=width,
                               font=F["small"])
            box.pack(side="left")
            box.bind("<<ComboboxSelected>>", lambda _e: self._save_ps_settings())
            if key == "phone":
                self.ps_phone_box = box
        row2 = frame(opts)
        row2.pack(fill="x", pady=(px(12), 0))
        for key, text in (("hidden", "Include hidden folders"), ("app_folders", "Include private app folders")):
            Toggle(row2, self.ps_vars[key], command=self._save_ps_settings).pack(side="left")
            label(row2, text, "small", MUTED).pack(side="left", padx=(px(8), px(22)))
        self.ps_stop = Button(row2, "Stop", self._ps_stop, "danger", icon="stop", height=32)
        self.ps_buttons = [Button(row2, "Phone bin", lambda: self.ps_find("bin"), "ghost", icon="undo", height=32),
                           Button(row2, "Find junk", lambda: self.ps_find("junk"), "secondary", icon="clean",
                                  height=32),
                           Button(row2, "Find duplicates", lambda: self.ps_find("dups"), "secondary", icon="copy",
                                  height=32),
                           Button(row2, "Find large files", lambda: self.ps_find("large"), "primary", icon="search",
                                  height=32)]
        for b in self.ps_buttons:
            b.pack(side="right", padx=(px(8), 0))
        label(opts, "Works over the normal USB cable: unlock the phone and choose \"File transfer\". To find "
                    "duplicates, files of the same size are copied to a temporary folder on this PC to compare, then "
                    "deleted (with USB debugging on, they're compared on the phone). Nothing leaves this PC. 'Find "
                    "junk' always looks in hidden and private app folders (Android/data); with USB debugging it also "
                    f"finds leftovers of removed apps and can empty every app's private cache. Deleted files go to "
                    f"the phone's Kavacham bin first: restore them from 'Phone bin' for {phonecare.KEEP_DAYS} days. "
                    "Chat databases and backups are never deleted.", "small", SUBTLE,
              wraplength=px(860), justify="left").pack(anchor="w", pady=(px(12), 0))
        self.ps_bar = Bar(parent, height=4)

        box = Card(parent, padding=8)
        box.pack(fill="both", expand=True, pady=(px(14), 0))
        self.ps_tree = table(box, [("size", "SIZE", 120, False), ("modified", "MODIFIED", 150, False)],
                             tree_column=("FILE ON THE PHONE", 560))
        self.ps_tree.configure(selectmode="extended")
        self.ps_tree.tag_configure("group", font=F["body_b"], background=SURFACE_2)
        self.ps_tree.tag_configure("protected", foreground=SUBTLE)
        self.ps_tree.bind("<<TreeviewSelect>>", lambda _e: self._ps_selection_changed())
        set_empty(self.ps_tree, "Plug in your phone, unlock it and choose \"File transfer\", then find large files "
                                "or duplicates.")
        acts = frame(parent)
        acts.pack(fill="x", pady=(px(14), 0))
        self.ps_delete_btn = Button(acts, "Delete from phone", self.ps_delete, "danger", icon="clean")
        self.ps_delete_btn.pack(side="right")
        self.ps_restore_btn = Button(acts, "Restore", self.ps_restore, "primary", icon="undo")
        self.ps_move_btn = Button(acts, "Move to this PC", self.ps_move, "secondary", icon="download")
        self.ps_move_btn.pack(side="right", padx=px(10))
        self.ps_select_btn = Button(acts, "Select extra copies", self.ps_select_extra, "secondary", icon="check")
        self.ps_select_btn.pack(side="right")
        Button(acts, "Open", self.ps_open, "ghost", icon="open").pack(side="right", padx=(0, px(10)))
        self.ps_bin = {}  # tree row -> bin item, in 'Phone bin' view
        self.ps_status = label(acts, "", "small", MUTED, wraplength=px(380), justify="left")
        self.ps_status.pack(side="left")

    def _save_ps_settings(self):
        for k in ("scope", "large", "dup", "hidden", "app_folders"):
            self.settings["usb"]["storage"][k] = self.ps_vars[k].get()
        write_json(SETTINGS_FILE, self.settings)

    def _ps_set_phones(self, ready, mtp):
        """Phones to choose from: USB debugging ones first (faster duplicates), then plain File transfer ones."""
        self._ps_phones = {}
        for d in ready:
            info = self._usb_info.get(d["serial"], {})
            name = f"{info.get('maker', '')} {info.get('model') or d['model']}".strip()
            how = "Wi-Fi" if phonecare.is_wifi(d["serial"]) else "USB debugging"
            self._ps_phones[f"{name} ({how})"] = ("adb", d["serial"])
        for name in mtp:
            self._ps_phones[name] = ("mtp", name)
        self.ps_phone_box.configure(values=list(self._ps_phones))
        if self.ps_vars["phone"].get() not in self._ps_phones:
            self.ps_vars["phone"].set(next(iter(self._ps_phones), ""))

    def _ps_phone(self):
        """("adb", serial) or ("mtp", device name) for the chosen phone."""
        phone = self._ps_phones.get(self.ps_vars["phone"].get())
        if not phone:
            messagebox.showinfo("Kavacham", "Plug in your Android phone with a USB cable first.\n\nThen unlock it, pull "
                                            "down the notifications, tap the USB notification and choose \"File "
                                            "transfer\". The phone shows up here in a few seconds.")
        return phone

    def _ps_stop(self):
        self._ps_cancel = True
        self.ps_status.configure(text="Stopping…")

    def ps_find(self, mode):
        phone = self._ps_phone()
        if not phone or self.ps_busy:
            return
        self.ps_busy, self._ps_cancel, self.ps_mode = True, False, mode
        for b in self.ps_buttons:
            b.configure(state="disabled")
        self.ps_stop.pack(side="right", padx=(px(8), 0))
        self.ps_bar.pack(fill="x", pady=(px(10), 0), before=self.ps_tree.master.master)
        self.ps_bar.start()
        self.ps_tree.delete(*self.ps_tree.get_children())
        self.ps_meta.clear()
        self.ps_bin.clear()
        self._ps_mode_buttons(mode)
        set_empty(self.ps_tree, "Opening the phone's Kavacham bin…" if mode == "bin" else "Searching the phone…")
        v = {k: self.ps_vars[k].get() for k in self.ps_vars}
        self.ps_status.configure(text="Listing files on the phone…")

        def progress(stage, done, total):
            if stage == "listing":
                text = f"Listing files on the phone… {done:,} found" if phone[0] == "mtp" else \
                    "Listing files on the phone…"
            elif stage == "copying":
                text = f"Comparing files of the same size… {done:,} of {total:,}"
            else:
                text = f"Comparing contents on the phone… {done:,} of {total:,} possible matches"
            self.ui(self.ps_status.configure, {"text": text})

        def work():
            kind, ident = phone
            cancelled = lambda: self._ps_cancel  # noqa: E731
            try:
                with phonecare.awake(phone):
                    result = find(kind, ident, cancelled)
                self.ui(self._ps_done, mode, result, None)
            except Exception as e:
                self.ui(self._ps_done, mode, [], str(e))

        def find(kind, ident, cancelled):
            if mode == "bin":
                phonecare.purge(phone)  # older than KEEP_DAYS
                return phonecare.bin_items(phone)
            if mode == "large" and kind == "adb":
                return usb.phone_large_files(ident, v["scope"], usb.LARGE_SIZES[v["large"]], v["hidden"],
                                             v["app_folders"])
            if mode == "large":
                return usb.mtp_large_files(ident, v["scope"], usb.LARGE_SIZES[v["large"]], v["hidden"],
                                           v["app_folders"], progress, cancelled)
            if mode == "junk":
                return (usb.phone_junk if kind == "adb" else usb.mtp_junk)(ident, progress, cancelled)
            if kind == "adb":
                return usb.phone_duplicates(ident, v["scope"], usb.DUP_SIZES[v["dup"]], v["hidden"],
                                            v["app_folders"], progress, cancelled)
            return usb.mtp_duplicates(ident, v["scope"], usb.DUP_SIZES[v["dup"]], v["hidden"], v["app_folders"],
                                      progress, cancelled)
        self.bg(work)

    def _ps_done(self, mode, result, error):
        self.ps_busy = False
        self.ps_bar.stop()
        self.ps_bar.pack_forget()
        self.ps_stop.pack_forget()
        for b in self.ps_buttons:
            b.configure(state="normal")
        fmt = lambda t: time.strftime("%d %b %Y %H:%M", time.localtime(t)) if t else ""  # noqa: E731

        def add(parent, size, mtime, path):
            safe = phonecare.is_protected(path)
            iid = self.ps_tree.insert(parent, "end", text=path + ("   · kept safe: chat backup" if safe else ""),
                                      values=(human(size), fmt(mtime)), tags=("protected",) if safe else ())
            self.ps_meta[iid] = (size, path)
        if mode == "bin":
            stamps = {}
            for item in result:
                stamps.setdefault(item["stamp"], []).append(item)
            for stamp, items in stamps.items():
                when = items[0]["when"]
                gone = fmt(when + phonecare.KEEP_DAYS * 86400).rsplit(" ", 1)[0] if when else "soon"
                gid = self.ps_tree.insert("", "end", text=f"Deleted {fmt(when)} · {len(items)} file(s) · emptied "
                                                          f"on {gone}", values=(human(sum(i["size"] for i in items)),
                                                                                ""), open=True, tags=("group",))
                for item in items:
                    iid = self.ps_tree.insert(gid, "end", text=item["original"], values=(human(item["size"]),
                                                                                         fmt(item["when"])))
                    self.ps_meta[iid] = (item["size"], item["path"])
                    self.ps_bin[iid] = item
            total = sum(i["size"] for i in result)
            summary = (f"{len(result):,} file(s) in the bin · {human(total)}. Select files to restore them, or to "
                       "delete them for good and free the space now.") if result else \
                "The phone's Kavacham bin is empty."
        elif mode == "large":
            for size, mtime, path in result:
                add("", size, mtime, path)
            total = sum(s for s, _m, _p in result)
            summary = f"{len(result):,} large files · {human(total)} in total" if result else "No files that big."
        elif mode == "junk":
            picked, total = [], 0
            for kind, default, items in result:
                size = sum(s for s, _p in items)
                total += size
                gid = self.ps_tree.insert("", "end", text=f"{kind} · {len(items)} item(s)", values=(human(size), ""),
                                          open=len(items) <= 12, tags=("group",))
                for s, path in items:
                    iid = self.ps_tree.insert(gid, "end", text=path, values=(human(s) if s else "size unknown", ""))
                    self.ps_meta[iid] = (s, path)
                    if default:
                        picked.append(iid)
            self.ps_tree.selection_set(picked)
            summary = (f"{human(total)} of junk found. The safe items are selected; app installers (.apk) aren't, in "
                       "case you still need them.") if result else "No junk found. The phone is tidy."
        else:
            wasted = 0
            for size, paths in result:
                wasted += size * (len(paths) - 1)
                gid = self.ps_tree.insert("", "end", text=f"{len(paths)} identical copies · {human(size)} each",
                                          values=(human(size * (len(paths) - 1)) + " extra", ""), open=True,
                                          tags=("group",))
                for mtime, path in paths:
                    add(gid, size, mtime, path)
            summary = (f"{len(result):,} sets of duplicates · {human(wasted)} can be freed. 'Select extra copies' "
                       "keeps the oldest of each.") if result else "No duplicates found."
        if error:
            summary = f"Couldn't finish: {error[:220]}"
        elif self._ps_cancel:
            summary = "Stopped. " + summary
        self.ps_select_btn.text = "Select safe junk" if mode == "junk" else "Select extra copies"
        self.ps_select_btn._draw()
        set_empty(self.ps_tree, summary if not result else "")
        self.ps_status.configure(text=summary)

    def _ps_selected(self):
        return [(iid, *self.ps_meta[iid]) for iid in self.ps_tree.selection() if iid in self.ps_meta]

    def _ps_selection_changed(self):
        sel = self._ps_selected()
        if sel:
            self.ps_status.configure(text=f"{len(sel)} selected · {human(sum(s for _i, s, _p in sel))}")

    def ps_select_extra(self):
        if self.ps_mode == "junk":
            safe = {k for k, default in usb.JUNK_KINDS if default}
            self.ps_tree.selection_set([c for gid in self.ps_tree.get_children()
                                        if self.ps_tree.item(gid, "text").split(" · ")[0] in safe
                                        for c in self.ps_tree.get_children(gid)])
            return
        if self.ps_mode != "dups":
            return
        extra = []
        for gid in self.ps_tree.get_children():
            extra += [c for c in list(self.ps_tree.get_children(gid))[1:]  # children are sorted oldest first
                      if not phonecare.is_protected(self.ps_meta[c][1])]
        self.ps_tree.selection_set(extra)

    def _ps_mode_buttons(self, mode):
        """The bin view has Restore and 'Delete forever' instead of moving and picking copies."""
        in_bin = mode == "bin"
        self.ps_delete_btn.text = "Delete forever" if in_bin else "Delete from phone"
        self.ps_delete_btn._draw()
        if in_bin:
            self.ps_move_btn.pack_forget()
            self.ps_select_btn.pack_forget()
            self.ps_restore_btn.pack(side="right", padx=px(10), after=self.ps_delete_btn)
        elif not self.ps_move_btn.winfo_manager():
            self.ps_restore_btn.pack_forget()
            self.ps_move_btn.pack(side="right", padx=px(10), after=self.ps_delete_btn)
            self.ps_select_btn.pack(side="right", after=self.ps_move_btn)

    def _ps_unprotected(self, rows):
        """Drop chat databases and backups from rows, saying so."""
        keep = [r for r in rows if not phonecare.is_protected(r[2])]
        if len(keep) < len(rows):
            messagebox.showinfo("Kavacham", f"{len(rows) - len(keep)} selected file(s) are chat databases or backups "
                                            "(e.g. WhatsApp/Databases). Kavacham keeps those safe and leaves them "
                                            "out." + ("" if keep else "\n\nNothing else was selected."))
        return keep

    def _ps_apply(self, rows, adb_action, mtp_action, done_text, batch=None):
        """adb_action(serial, path) -> bool, one file at a time; mtp_action(device, rows) -> paths done, all at once;
        or batch(phone, rows) -> paths done, for either kind. done_text gets {ok}, {failed} and {size} (freed/moved)."""
        phone = self._ps_phone()
        if not phone or self.ps_busy:
            return
        self.ps_busy = True  # the list mustn't be replaced while files are being worked on
        for b in self.ps_buttons:
            b.configure(state="disabled")
        self.ps_status.configure(text=f"Working on {len(rows)} file(s)… keep the phone unlocked.")

        def finished(text):
            self.ps_busy = False
            for b in self.ps_buttons:
                b.configure(state="normal")
            self.ps_status.configure(text=text)

        def work():
            kind, ident = phone
            try:
                with phonecare.awake(phone):
                    if batch:
                        done = set(batch(phone, rows))
                    elif kind == "adb":
                        done = {p for _i, _s, p in rows if adb_action(ident, p)}
                    else:
                        done = set(mtp_action(ident, rows))
                size = human(sum(s for _i, s, p in rows if p in done))
                text = done_text.format(ok=len(done), failed=len(rows) - len(done), size=size)
                if len(done) == len(rows):
                    text = re.sub(r" · 0 \w.*?(?= · |$)", "", text)  # no "· 0 couldn't be …"
            except Exception as e:
                done, text = set(), f"Couldn't finish: {str(e)[:200]}"
            gone = [iid for iid, _size, path in rows if path in done]

            def update():
                for iid in gone:
                    if self.ps_tree.exists(iid):
                        self.ps_tree.delete(iid)
                    self.ps_meta.pop(iid, None)
                    self.ps_bin.pop(iid, None)
                self.ps_tree.delete(*[g for g in self.ps_tree.get_children()
                                      if g not in self.ps_meta and not self.ps_tree.get_children(g)])
                finished(text)
            self.ui(update)
        self.bg(work)

    def _ps_need_selection(self):
        if self.ps_busy:
            messagebox.showinfo("Kavacham", "Kavacham is still working on the phone. Wait for it to finish.")
            return []
        rows = self._ps_selected()
        if not rows:
            messagebox.showinfo("Kavacham", "Select one or more files in the list first.")
        return rows

    def ps_move(self):
        rows = self._ps_need_selection()
        rows = rows and self._ps_unprotected(rows)
        if not rows:
            return
        name = re.sub(r'[\\/:*?"<>|]', "_", self.ps_vars["phone"].get() or "Phone")
        dest = os.path.join(os.path.expanduser("~"), "Pictures", "From phone", name)
        if not messagebox.askyesno("Kavacham", f"Move {len(rows)} file(s) ({human(sum(s for _i, s, _p in rows))}) "
                                               f"to this PC?\n\nThey'll be saved in:\n{dest}\n\nEach file is removed "
                                               "from the phone only after its copy on the PC is checked complete."):
            return
        self._ps_apply(rows, lambda serial, path: usb.move_to_pc(serial, path, dest),
                       lambda device, rows: usb.mtp_move_to_pc(device, [(p, s) for _i, s, p in rows], dest),
                       "{ok} file(s) moved to Pictures\\From phone ({size})" + " · {failed} couldn't be moved")

    def ps_delete(self):
        rows = self._ps_need_selection()
        if not rows:
            return
        total = human(sum(s for _i, s, _p in rows))
        if self.ps_mode == "bin":
            if not messagebox.askyesno("Kavacham", f"Delete {len(rows)} file(s) ({total}) for good?\n\nThis frees the "
                                                   "space on the phone now. They can't be restored after this."):
                return
            self._ps_apply(rows, None, None, "{ok} file(s) deleted for good · {size} freed · {failed} couldn't be "
                                             "deleted",
                           batch=lambda phone, rows: phonecare.empty(phone, [self.ps_bin[i] for i, _s, _p in rows]))
            return
        names = "\n".join(f"•  {os.path.basename(p)}" for _i, _s, p in rows[:10])
        more = f"\n…and {len(rows) - 10} more" if len(rows) > 10 else ""
        if self.ps_mode == "junk":
            if not messagebox.askyesno("Kavacham", f"Clean {len(rows)} junk item(s) ({total}) from the phone?\n\n"
                                                   f"{names}{more}\n\nCaches and thumbnails are rebuilt by the apps "
                                                   "when needed. Your photos, chats and documents aren't touched."):
                return
            self._ps_apply(rows, usb.clean_junk_adb,
                           lambda device, rows: usb.clean_junk_mtp(device, [p for _i, _s, p in rows]),
                           "{ok} junk item(s) cleaned · {failed} couldn't be cleaned")
            return
        rows = self._ps_unprotected(rows)
        if not rows:
            return
        total = human(sum(s for _i, s, _p in rows))
        names = "\n".join(f"•  {os.path.basename(p)}" for _i, _s, p in rows[:10])
        more = f"\n…and {len(rows) - 10} more" if len(rows) > 10 else ""
        days = phonecare.KEEP_DAYS
        if not messagebox.askyesno("Kavacham", f"Delete {len(rows)} file(s) ({total}) from the phone?\n\n{names}{more}"
                                               f"\n\nThey go to the phone's Kavacham bin first: you can restore them "
                                               f"from 'Phone bin' for {days} days, then they're deleted for good. To "
                                               "free the space right away, open 'Phone bin' and choose 'Delete "
                                               "forever'."):
            return

        def to_bin(phone, rows):
            moved = phonecare.to_bin(phone, [p for _i, _s, p in rows])
            try:
                phonecare.purge(phone)  # what's been there longer than KEEP_DAYS
            except Exception:
                pass
            return moved
        self._ps_apply(rows, None, None, "{ok} file(s) moved to the phone's Kavacham bin ({size}). Restore them from "
                                         f"'Phone bin' within {days} days · " + "{failed} couldn't be moved",
                       batch=to_bin)

    def ps_restore(self):
        rows = self._ps_need_selection()
        if not rows or self.ps_mode != "bin":
            return
        self._ps_apply(rows, None, None, "{ok} file(s) put back where they were · {failed} couldn't be restored",
                       batch=lambda phone, rows: phonecare.restore(phone, [self.ps_bin[i] for i, _s, _p in rows]))

    def ps_open(self):
        """Look at a file before deciding: it's copied to a temporary folder on this PC and opened there."""
        rows = self._ps_need_selection()
        phone = rows and self._ps_phone()
        if not phone:
            return
        _iid, size, path = rows[0]
        self.ps_status.configure(text=f"Copying {os.path.basename(path)} ({human(size)}) to open it…")

        def work():
            try:
                local = phonecare.preview(phone, path)
            except Exception:
                local = None
            if local:
                os.startfile(local)
                self.ui(self.ps_status.configure, {"text": f"Opened {os.path.basename(path)} (a temporary copy)."})
            else:
                self.ui(self.ps_status.configure, {"text": "Couldn't copy that file. Unlock the phone and try again."})
        self.bg(work)

    def _save_usb_settings(self):
        self.settings["usb"]["auto_scan"] = self.usb_auto.get()
        write_json(SETTINGS_FILE, self.settings)

    def _usb_watch_tick(self):
        """Plug-in watching while Kavacham is open; the background monitor does it when it's running."""
        if not engine.monitor_running():
            try:
                self.usb_watch.step(on_new=self._usb_plugged)
            except Exception:
                pass
        visible = self.pages["usb"].winfo_ismapped()
        if visible and not self.usb_busy and time.time() - getattr(self, "_usb_listed", 0) > 8:
            self.refresh_usb()
        self.after(3000, self._usb_watch_tick)

    def _usb_plugged(self, root):
        self.refresh_usb()
        if self.settings["usb"]["auto_scan"] and not self.usb_busy:
            self.bg(notify, "Kavacham: USB drive connected", f"Scanning {root[:2]} for threats…")
            self.usb_scan_drive(root, auto=True)

    def refresh_usb(self):
        self._usb_listed = time.time()

        busy = self.usb_busy or self.ps_busy

        def work():
            drives = usb.usb_drives()
            status = phonecare.connection_status(check_files=not busy)  # don't interrupt a phone that's being read
            for d in status["adb"]:
                if d["state"] != "device":
                    continue
                if d["serial"] not in self._usb_info:
                    try:
                        self._usb_info[d["serial"]] = usb.phone_info(d["serial"])
                    except Exception:
                        pass
                if not busy:
                    phonecare.restore_awake(d["serial"])
            self.ui(self._show_usb_devices, drives, status)
        self.bg(work)

    def _show_usb_devices(self, drives, status):
        for w in self.usb_list.winfo_children():
            w.destroy()

        def row(icon, title, sub, buttons, first):
            if not first:
                divider(self.usb_list, pady=px(8))
            r = frame(self.usb_list)
            r.pack(fill="x")
            label(r, ICONS[icon], "icon", ACCENT).pack(side="left", anchor="n", pady=(px(2), 0))
            t = frame(r)
            t.pack(side="left", padx=px(12), fill="x", expand=True)
            label(t, title, "body_b").pack(anchor="w")
            if sub:
                label(t, sub, "small", MUTED, wraplength=px(560), justify="left").pack(anchor="w")
            for i, (text, cmd, kind) in enumerate(reversed(buttons)):
                b = Button(r, text, cmd, kind, height=32)
                b.pack(side="right", padx=(px(8) if i else 0, 0))
                if self.usb_busy:
                    b.configure(state="disabled")
        n = 0
        for d in drives:
            row("drive", f"{d['root'][:2]}  {d['label']}",
                f"{human(d['size'])} · {human(d['free'])} free",
                [("Scan", lambda r=d["root"]: self.usb_scan_drive(r), "primary"),
                 ("Repair", lambda r=d["root"]: self.usb_repair(r), "secondary")], n == 0)
            n += 1
        adb_devs = status["adb"]
        ready = [d for d in adb_devs if d["state"] == "device"]
        waiting = [d for d in adb_devs if d["state"] != "device"]
        self._ps_set_phones(ready, status["files"])
        for d in adb_devs:
            info = self._usb_info.get(d["serial"], {})
            if d["state"] == "device":
                title = f"{info.get('maker', '')} {info.get('model') or d['model']}".strip() + " · apps"
                sub = (f"Android {info.get('android', '?')} · security patch {info.get('patch', '?')} · connected "
                       + ("over Wi-Fi" if phonecare.is_wifi(d["serial"]) else "with USB debugging") +
                       " · kept awake during scans")
                row("shield", title, sub, [("Check installed apps", lambda s=d["serial"]: self.usb_check_apps(s),
                                            "primary"),
                                           ("Deep scan storage", lambda s=d["serial"]: self.usb_deep_scan(s),
                                            "secondary")], n == 0)
            elif d["state"] == "unauthorized":
                row("warning", d["model"] or "Phone waiting for permission", "Unlock the phone and tap Allow on "
                    "\"Allow USB debugging?\" (tick \"Always allow from this computer\"). No box? Unplug the cable "
                    "and plug it in again.", [("Refresh", self.refresh_usb, "secondary")], n == 0)
            else:
                row("warning", d["model"] or d["serial"], "The phone isn't answering over USB debugging. Unplug the "
                    "cable, plug it in again and unlock the phone.", [("Refresh", self.refresh_usb, "secondary")],
                    n == 0)
            n += 1
        for name in status["driver"]:
            row("warning", "USB debugging needs a driver", f"Windows found the phone's debugging connection ({name}) "
                "but has no driver for it. Kavacham can install Google's free USB driver (about 8 MB, from "
                "dl.google.com; Windows asks for permission).",
                [("Install driver", self.usb_install_driver, "primary")], n == 0)
            n += 1
        for name in status["files"]:
            row("file", f"{name} · files", "Files over USB (File transfer).",
                [("Scan phone files", lambda m=name: self.usb_scan_phone(m), "primary")], n == 0)
            n += 1
        for name in status["hidden"]:
            row("warning", f"{name} · files hidden", "Connected, but the phone isn't sharing its files. Unlock it, tap "
                "the USB notification and choose \"File transfer\". Still nothing? Unplug the cable and plug it in "
                "again.", [("Refresh", self.refresh_usb, "secondary")], n == 0)
            n += 1
        if (status["files"] or status["hidden"]) and not ready and not waiting and not status["driver"]:
            row("bolt", "Make phone scans much faster: turn on USB debugging",
                "File transfer reads one file at a time and phones often drop it during long scans. With USB debugging "
                "the phone searches itself, stays awake while Kavacham works, and installed apps can be checked. "
                "Once: Settings → About phone → tap Build number (on Xiaomi: MIUI version) 7 times → Developer "
                "options (in System, or Additional settings on Xiaomi) → USB debugging on. Then plug the cable in "
                "again and tap Allow on the phone.",
                [("Set up", self.usb_setup_adb, "secondary"), ("Use Wi-Fi", self.usb_wifi_dialog, "ghost")], n == 0)
            n += 1
        if not n:
            label(self.usb_list, "Plug in a pendrive, USB disk or Android phone with a USB cable. Phones: unlock the "
                                 "screen and choose \"File transfer\".", "body", MUTED).pack(anchor="w")
            if status["tools"]:
                Button(self.usb_list, "Connect a phone over Wi-Fi", self.usb_wifi_dialog, "ghost", icon="wifi",
                       height=30).pack(anchor="w", pady=(px(8), 0))

    # ---- running scans
    def _usb_run(self, title, fn):
        if self.usb_busy:
            messagebox.showinfo("Kavacham", "A USB scan is already running.")
            return
        self.usb_busy, self._usb_cancel = True, False
        self.usb_status.configure(text=title, fg=TEXT)
        self.usb_sub.configure(text="Starting…")
        self.usb_cancel_btn.pack(side="right")
        self.usb_bar.pack(fill="x", pady=(px(14), 0))
        self.usb_bar.start()
        self.refresh_usb()
        t0 = time.time()

        def progress(n, path, hits):
            self.ui(self.usb_sub.configure, {"text": f"{n:,} checked · {hits} flagged · {int(time.time() - t0)} s   "
                                                     f"{str(path)[-80:]}"})

        def work():
            try:
                hits, summary = fn(progress, lambda: self._usb_cancel)
                self.ui(self._usb_done, title, hits, summary, None)
            except Exception as e:
                self.ui(self._usb_done, title, [], "", str(e))
        self.bg(work)

    def usb_cancel(self):
        self._usb_cancel = True
        self.usb_sub.configure(text="Cancelling…")

    def _usb_done(self, title, hits, summary, error):
        self.usb_busy = False
        self.usb_bar.stop()
        self.usb_bar.pack_forget()
        self.usb_cancel_btn.pack_forget()
        self.usb_results = hits + [r for r in self.usb_results if r.get("device") not in {h.get("device") for h in hits}]
        self._fill_usb()
        flagged = [h for h in hits if h["verdict"] in ("Malware", "Suspicious")]
        if error:
            tone, head = "warn", f"{title} failed"
            summary = error[:160]
        elif self._usb_cancel:
            tone, head = "warn", f"{title} cancelled"
        elif flagged:
            tone, head = "bad", f"{len(flagged)} threat(s) found"
        elif hits and any(h.get("kind") != "advice" for h in hits):
            tone, head = "warn", "Some items are worth a look"
        else:
            tone, head = "ok", "No threats found"
        self.usb_status.configure(text=head, fg=TONES[tone][0])
        self.usb_sub.configure(text=summary)
        add_history("USB scan", head, f"{title} · {summary}", "bad" if tone == "bad" else tone)
        self.refresh_usb()

    def _fill_usb(self):
        self.usb_tree.delete(*self.usb_tree.get_children())
        for i, r in enumerate(self.usb_results):
            action = r.get("action") or ("Advice" if r.get("kind") == "advice" else
                                         "Needs review" if r["verdict"] in ("Malware", "Suspicious") else "Your call")
            tone = "ok" if action in ("Quarantined", "Deleted", "Uninstalled", "Marked safe", "Unhidden") else \
                "muted" if r.get("kind") == "advice" else \
                "bad" if r["verdict"] in ("Malware", "Suspicious") else "warn"
            self.usb_tree.insert("", "end", iid=str(i), tags=(tone,), values=(
                r.get("device", ""), r["name"], r["verdict"], "; ".join(r["reasons"]), action))
        set_empty(self.usb_tree, "Nothing suspicious found.")

    def usb_scan_drive(self, root, auto=False):
        def fn(progress, cancelled):
            hits, n, secs = usb.scan_drive(root, progress, cancelled, self.settings["engine"]["auto_quarantine"])
            if auto:
                malware = sum(1 for h in hits if h["verdict"] == "Malware")
                notify("Kavacham: USB scan finished", f"{root[:2]}: {len(hits)} finding(s), {malware} malware"
                       if hits else f"{root[:2]} is clean")
            return hits, f"{n:,} files on {root[:2]} in {int(secs)} s"
        self._usb_run(f"Scanning USB drive {root[:2]}", fn)

    def usb_repair(self, root):
        if not messagebox.askyesno("Kavacham", f"Repair {root[:2]}?\n\nThis quarantines shortcut-virus files "
                                               "(fake shortcuts, autorun.inf, hidden scripts) and makes your hidden "
                                               "files visible again. Your own files aren't deleted."):
            return

        def fn(progress, cancelled):
            fixed, unhidden = usb.repair_drive(root)
            return [], f"{len(fixed)} infected item(s) quarantined, {unhidden} hidden item(s) made visible"
        self._usb_run(f"Repairing {root[:2]}", fn)

    def usb_scan_phone(self, name):
        def fn(progress, cancelled):
            hits, n = usb.scan_phone_files(name, progress, cancelled)
            return hits, f"{n} downloaded/shared file(s) checked on {name}"
        self._usb_run(f"Scanning files on {name}", fn)

    def usb_check_apps(self, serial):
        def fn(progress, cancelled):
            with phonecare.awake(("adb", serial)):
                hits, n, info = usb.check_apps(serial, progress, cancelled)
            return hits, f"{n} installed apps checked · Android {info['android']}, patch {info['patch']}"
        self._usb_run("Checking installed apps", fn)

    def usb_deep_scan(self, serial):
        consented = self.settings["usb"].setdefault("deep_consent", [])
        if serial not in consented:
            if not messagebox.askyesno(
                    "Kavacham: allow a deep scan of this phone?",
                    "Kavacham will look through ALL of this phone's storage over USB debugging, including:\n\n"
                    "•  hidden folders (names starting with a dot)\n"
                    "•  app folders (Android/data and Android/obb), which file managers can't show\n"
                    "•  SD cards\n\n"
                    "Fingerprints are computed on the phone. Only programs, scripts and documents are copied to a "
                    "temporary folder on this PC for a closer look, then deleted. Nothing leaves this PC.\n\n"
                    "Apps' fully private data (/data/data) can't be read: Android blocks it unless the phone is "
                    "rooted.\n\nAllow deep scans for this phone?"):
                return
            consented.append(serial)
            write_json(SETTINGS_FILE, self.settings)
            engine.log_event("usb", "info", "Deep scan permission given", f"phone {serial}")

        def fn(progress, cancelled):
            with phonecare.awake(("adb", serial)):
                hits, n, name = usb.deep_scan_storage(serial, progress, cancelled)
            return hits, f"{n:,} risky-type files fingerprinted on {name}, including app and hidden folders"
        self._usb_run("Deep scanning phone storage", fn)

    def usb_setup_adb(self):
        if usb.adb_path():
            messagebox.showinfo("Kavacham", "Android tools are ready. On the phone:\n\n1.  Settings → About phone → "
                                            "tap Build number 7 times (on Xiaomi: tap MIUI version).\n2.  Developer "
                                            "options (in Settings → System, or Additional settings on Xiaomi) → turn "
                                            "on USB debugging.\n3.  Unplug the cable, plug it in again, unlock the "
                                            "phone and tap Allow (tick \"Always allow from this computer\").")
            self.refresh_usb()
            return
        if not messagebox.askyesno("Kavacham", "Checking installed apps needs Google's free Android tools (adb, about "
                                               "7 MB, downloaded from dl.google.com).\n\nDownload them now?"):
            return

        def fn(progress, cancelled):
            usb.setup_adb(lambda t: progress(0, t, 0))
            return [], "Android tools installed. Now switch on USB debugging on the phone and tap Allow."
        self._usb_run("Installing Android tools", fn)

    def usb_install_driver(self):
        def fn(progress, cancelled):
            ok = phonecare.install_driver(lambda t: progress(0, t, 0))
            if not ok:
                raise RuntimeError("The driver wasn't installed (permission was declined, or Windows refused it).")
            return [], "USB driver installed. Unplug the phone, plug it in again and tap Allow on the phone."
        self._usb_run("Installing the USB driver", fn)

    def usb_wifi_dialog(self):
        """Wireless debugging (Android 11+): pair once with a code, after that the phone connects over Wi-Fi."""
        if not usb.adb_path():
            self.usb_setup_adb()
            return
        win = tk.Toplevel(self, bg=SURFACE, padx=px(26), pady=px(22))
        win.title("Connect a phone over Wi-Fi")
        win.transient(self)
        dark_titlebar(win)
        wrap = px(520)
        label(win, "Connect a phone over Wi-Fi", "h2").pack(anchor="w")
        label(win, "Needs Android 11 or newer, with the phone and this PC on the same Wi-Fi.\n\n1.  On the phone: "
                   "Developer options → Wireless debugging → turn it on.\n2.  Tap \"Pair device with pairing code\" "
                   "and type what it shows here:", "body", MUTED, wraplength=wrap, justify="left").pack(
            anchor="w", pady=(px(6), px(10)))
        fields = {}
        for key, text, hint in (("pair", "IP address & port", "e.g. 192.168.1.5:37099"),
                                ("code", "Wi-Fi pairing code", "6 digits")):
            r = frame(win, bg=SURFACE)
            r.pack(fill="x", pady=px(3))
            label(r, text, "small_b", MUTED, width=18, anchor="w").pack(side="left")
            fields[key] = tk.StringVar()
            ttk.Entry(r, textvariable=fields[key], font=F["body"], width=24).pack(side="left")
            label(r, hint, "small", SUBTLE).pack(side="left", padx=px(8))
        status = label(win, "", "small", MUTED, wraplength=wrap, justify="left")

        def run(fn, *args):
            status.configure(text="Working…", fg=MUTED)

            def work():
                ok, msg = fn(*args)
                self.ui(status.configure, {"text": msg, "fg": TONES["ok" if ok else "warn"][0]})
                if ok:
                    self.ui(self.refresh_usb)
                    self.ui(lambda: self.after(1500, win.destroy))
            self.bg(work)
        Button(win, "Pair and connect", lambda: run(phonecare.wifi_pair, fields["pair"].get(), fields["code"].get()),
               "primary", icon="wifi").pack(anchor="w", pady=(px(10), px(16)))
        label(win, "Already paired? Type the IP address & port shown at the top of the Wireless debugging screen:",
              "body", MUTED, wraplength=wrap, justify="left").pack(anchor="w")
        r = frame(win, bg=SURFACE)
        r.pack(fill="x", pady=px(6))
        fields["connect"] = tk.StringVar()
        ttk.Entry(r, textvariable=fields["connect"], font=F["body"], width=24).pack(side="left")
        Button(r, "Connect", lambda: run(phonecare.wifi_connect, fields["connect"].get()), "secondary",
               height=32).pack(side="left", padx=px(10))
        status.pack(anchor="w", pady=(px(8), 0))
        Button(win, "Close", win.destroy, "ghost").pack(anchor="e", pady=(px(12), 0))

    # ---- result actions
    def _usb_selected(self):
        return [(int(i), self.usb_results[int(i)]) for i in self.usb_tree.selection()]

    def usb_remove_selected(self):
        rows = [(i, r) for i, r in self._usb_selected() if r.get("kind") != "advice" and not r.get("action")]
        if not rows:
            messagebox.showinfo("Kavacham", "Select one or more flagged items in the list first.")
            return
        names = "\n".join(f"•  {r['name']}  ({r.get('device', '')})" for _i, r in rows[:12])
        if not messagebox.askyesno("Kavacham", f"Remove {len(rows)} item(s)?\n\n{names}\n\nDrive files go to "
                                               "Quarantine; phone files are deleted; phone apps are uninstalled."):
            return

        def work():
            for _i, r in rows:
                fix = r.get("fix")
                if fix == "uninstall":
                    ok, _out = usb.uninstall_app(r["serial"], r["package"])
                    r["action"] = "Uninstalled" if ok else "Couldn't uninstall"
                    if not ok:
                        self.ui(messagebox.showwarning, "Kavacham", f"{r['name']} couldn't be uninstalled.\n\nIf it's "
                                "a device administrator, remove that first: Settings → Security → Device admin apps "
                                "(or 'Device administrators'), switch it off, then try again.")
                elif fix == "adb_delete":
                    r["action"] = "Deleted" if usb.adb_delete(r["serial"], r["path"]) else "Couldn't delete"
                elif fix == "phone_delete":
                    r["action"] = "Deleted" if usb.delete_from_phone(r["device"], r["phone_path"]) else \
                        "Delete it on the phone"
                elif fix == "unhide":
                    a = usb._attrs(r["path"])
                    ok = ctypes.windll.kernel32.SetFileAttributesW(r["path"], a & ~(usb.HIDDEN | usb.SYSTEM))
                    r["action"] = "Unhidden" if ok else "Couldn't unhide"
                else:
                    ok = engine.quarantine(r["path"], "; ".join(r["reasons"]), r.get("sha256", ""))
                    r["action"] = "Quarantined" if ok else "Couldn't quarantine"
            self.ui(self._fill_usb)
        self.bg(work)

    def usb_mark_safe(self):
        rows = [(i, r) for i, r in self._usb_selected() if r.get("sha256")]
        if not rows:
            messagebox.showinfo("Kavacham", "Select a flagged file or app in the list first.")
            return
        for _i, r in rows:
            engine.ignore(r["sha256"], r.get("phone_path") or r["path"])
            r["action"] = "Marked safe"
        self._fill_usb()

    # ---------------------------------------------------------- plain-language explanations
    def engine_explain_selected(self):
        rows = self._selected_results()
        if not rows:
            messagebox.showinfo("Kavacham", "Select a file in the list first.")
            return
        self._explain_dialog(rows[0][1])

    def usb_explain_selected(self):
        rows = self._usb_selected()
        if not rows:
            messagebox.showinfo("Kavacham", "Select an item in the list first.")
            return
        self._explain_dialog(rows[0][1])

    def _explain_dialog(self, r):
        data = explain.explain(r["verdict"], r["reasons"])
        win = tk.Toplevel(self, bg=SURFACE, padx=px(26), pady=px(22))
        win.title(f"What does this mean? {r['name']}")
        win.geometry(f"{px(640)}x{px(540)}")
        win.transient(self)
        dark_titlebar(win)
        wrap = px(570)
        label(win, r["name"], "small", MUTED, wraplength=wrap, justify="left").pack(anchor="w")
        label(win, data["title"], "h2", TONES[data["tone"]][0]).pack(anchor="w", pady=(px(2), 0))
        label(win, data["summary"], "body", TEXT, wraplength=wrap, justify="left").pack(
            anchor="w", pady=(px(6), px(8)))
        Button(win, "Close", win.destroy, "secondary").pack(side="bottom", anchor="e", pady=(px(12), 0))
        body = ScrollFrame(win)
        body.pack(fill="both", expand=True)
        inner = body.inner
        label(inner, "WHY IT WAS FLAGGED", "caption", SUBTLE).pack(anchor="w", pady=(px(6), px(2)))
        for reason, meaning in data["items"]:
            label(inner, f"•  {reason}", "body", TEXT, wraplength=wrap, justify="left").pack(anchor="w",
                                                                                         pady=(px(6), 0))
            label(inner, meaning, "small", MUTED, wraplength=wrap - px(16), justify="left").pack(
                anchor="w", padx=(px(16), 0))
        if data["what_to_do"]:
            label(inner, "WHAT TO DO", "caption", SUBTLE).pack(anchor="w", pady=(px(16), px(2)))
            for step in data["what_to_do"]:
                label(inner, f"•  {step}", "body", TEXT, wraplength=wrap, justify="left").pack(anchor="w",
                                                                                           pady=px(2))
        label(inner, "Explained by Kavacham on this PC. Nothing was sent anywhere.", "small", SUBTLE,
              wraplength=wrap, justify="left").pack(anchor="w", pady=(px(16), 0))

    # ---------------------------------------------------------- security activity
    def _page_events(self):
        p = self.page("Security activity", "Protection status, alerts, and every scan, detection and change — "
                                           "Kavacham's and Windows Defender's — newest first.")
        tiles = frame(p)
        tiles.pack(fill="x")
        self.act_tiles = {}
        for i, (key, title) in enumerate([("rtp", "DEFENDER REAL-TIME"), ("fw", "WINDOWS FIREWALL"),
                                          ("sigs", "ENGINE SIGNATURES"), ("mon", "KAVACHAM MONITOR")]):
            tiles.columnconfigure(i, weight=1, uniform="tile")
            card = Card(tiles, padding=16)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else px(6), 0 if i == 3 else px(6)))
            label(card, title, "caption", SUBTLE).pack(anchor="w")
            value = label(card, "…", "h3")
            value.pack(anchor="w", pady=(px(2), 0))
            sub = label(card, "", "small", MUTED)
            sub.pack(anchor="w")
            self.act_tiles[key] = (value, sub)
        self.act_counts = label(p, "", "small", MUTED)
        self.act_counts.pack(anchor="w", pady=(px(10), px(10)))
        self.act_alerts = Card(p, padding=14)
        self.act_alerts.pack(fill="x")

        bar = frame(p)
        bar.pack(fill="x", pady=(px(14), px(10)))
        self.ev_filter = "all"
        self.ev_tabs = Segmented(bar, [("all", "All"), ("detection", "Detections"), ("scan", "Scans"),
                                       ("quarantine", "Quarantine"), ("protection", "Protection"),
                                       ("system", "Windows Defender"), ("usb", "USB"), ("url", "Links"),
                                       ("update", "Updates")], self._filter_events)
        self.ev_tabs.pack(side="left")
        Button(bar, "Refresh", self.refresh_events, "secondary", icon="refresh").pack(side="right")
        box = Card(p, padding=8)
        box.pack(fill="both", expand=True)
        self.ev_tree = table(box, [("time", "TIME", 140, False), ("cat", "TYPE", 120, False),
                                   ("title", "EVENT", 290, False), ("details", "DETAILS", 400, True)])
        self._sys_events, self._alerts = [], getattr(self, "_alerts", None)
        return p

    def _filter_events(self, key):
        self.ev_filter = key
        self._fill_events()

    def refresh_events(self):
        if not hasattr(self, "ev_tree"):
            return
        self._fill_events()
        self.act_counts.configure(text="Checking protection status…")

        def work():
            sys_events = alerts.defender_events()
            st, found = alerts.run_checks(send=False)

            def apply():
                self._sys_events, self._alerts = sys_events, found
                self._fill_events()
                self._show_status(st, found)
            self.ui(apply)
        self.bg(work)

    def _fill_events(self):
        self.ev_tree.delete(*self.ev_tree.get_children())
        cats = {"protection": ("protection", "alert", "engine", "monitor")}.get(self.ev_filter, (self.ev_filter,))
        names = {"url": "Link", "system": "Windows Defender", "usb": "USB"}
        events = sorted(engine.read_events() + self._sys_events, key=lambda e: e["time"], reverse=True)
        for e in events[:1500]:
            if self.ev_filter == "all" or e["category"] in cats:
                tone = {"info": "muted"}.get(e["level"], e["level"])
                self.ev_tree.insert("", "end", tags=(tone,), values=(
                    e["time"], names.get(e["category"], e["category"].title()), e["title"], e["details"]))
        set_empty(self.ev_tree, "No events yet.")
        c = alerts.summary(engine.read_events())
        self.act_counts.configure(text=f"Last 7 days:  {c['scans']} scans  ·  {c['detections']} detections  ·  "
                                       f"{c['quarantined']} quarantined  ·  {c['links']} links checked")

    def _show_status(self, st, found):
        def tile(key, text, tone, sub):
            value, subl = self.act_tiles[key]
            value.configure(text=text, fg=TONES[tone][0])
            subl.configure(text=sub)
        if "Rtp" in st:
            tile("rtp", "On" if st["Rtp"] else "Off", "ok" if st["Rtp"] else "bad",
                 f"Definitions {st.get('SigAge', 0)} day(s) old")
        else:
            tile("rtp", "Unknown", "warn", "Couldn't read Defender status")
        off = st["firewall_off"]
        tile("fw", "Off" if off else "On", "bad" if off else "ok", f"Off for {', '.join(off)}" if off else
             "All network profiles")
        if st["engine_updated"]:
            days = (time.time() - st["engine_updated"]) / 86400
            tile("sigs", f"{st['engine_hashes']:,}", "ok" if days <= 2 else "warn", f"Updated {ago(st['engine_updated'])}")
        else:
            tile("sigs", "None yet", "warn", "Update the threat feeds")
        if st["realtime"]:
            tile("mon", "Running" if st["monitor"] else "Stopped", "ok" if st["monitor"] else "bad",
                 ", ".join(os.path.basename(f) for f in self.settings["engine"]["folders"])[:40])
        else:
            tile("mon", "Off", "warn", "Turn on in Engine scan")
        for w in self.act_alerts.winfo_children():
            w.destroy()
        if not found:
            row = frame(self.act_alerts)
            row.pack(fill="x")
            label(row, ICONS["check"], "icon", OK).pack(side="left")
            label(row, "All clear — no protection problems right now", "body_b").pack(side="left", padx=px(10))
            return
        for i, a in enumerate(found):
            if i:
                divider(self.act_alerts, pady=px(8))
            row = frame(self.act_alerts)
            row.pack(fill="x")
            label(row, ICONS["warning"], "icon", TONES[a["level"]][0]).pack(side="left", anchor="n")
            text = frame(row)
            text.pack(side="left", padx=px(10), fill="x", expand=True)
            label(text, a["title"], "body_b").pack(anchor="w")
            label(text, a["detail"], "small", MUTED).pack(anchor="w")
            fix = self._alert_fix(a["fix"])
            if fix:
                Button(row, fix[0], fix[1], "secondary").pack(side="right")

    def _alert_fix(self, kind):
        def page(key, tab=None):
            def go():
                self.show(key)
                if tab:
                    self.eng_tabs.select(tab)
            return go
        return {
            "windows_security": ("Open Windows Security", lambda: os.startfile("windowsdefender://threatsettings")),
            "firewall": ("Open firewall settings", lambda: os.startfile("windowsdefender://network")),
            "threats": ("Review threats", page("threats")),
            "engine": ("Open engine", page("engine", "protect")),
            "update_defender": ("Update now", lambda: (self.show("scan"), self.update_defs())),
            "schedule": ("Open Automation", page("schedule")),
        }.get(kind)

    # ---------------------------------------------------------- cleaner
    def _page_cleaner(self):
        p = self.page("Storage cleaner", "Remove junk that Windows and your browsers leave behind.")
        self._clean_sizes, self._clean_busy, self._cleaner_ready = {}, False, False
        self.clean_targets = {n: (pats, admin) for n, pats, admin in CLEAN_TARGETS}
        self.clean_targets["Recycle Bin"] = (None, False)

        # summary: headline number, composition bar, legend, before -> after result
        hero = Card(p, padding=24)
        hero.pack(fill="x")
        top = frame(hero)
        top.pack(fill="x")
        left = frame(top)
        left.pack(side="left", fill="x", expand=True)
        self.clean_caption = label(left, "JUNK SELECTED", "caption", SUBTLE)
        self.clean_caption.pack(anchor="w")
        self.clean_total = label(left, "—", "big")
        self.clean_total.pack(anchor="w")
        self.clean_sub = label(left, "Open this page to analyze your PC.", "small", MUTED)
        self.clean_sub.pack(anchor="w")
        btns = frame(top)
        btns.pack(side="right", anchor="n")
        self.analyze_btn = Button(btns, "Re-analyze", self.analyze, "secondary", icon="refresh")
        self.analyze_btn.pack(side="left")
        self.clean_btn = Button(btns, "Clean selected", self.do_clean, "primary", icon="clean")
        self.clean_btn.configure(state="disabled")
        self.clean_btn.pack(side="left", padx=(px(10), 0))
        self.clean_stack = StackedBar(hero, height=14)
        self.clean_stack.pack(fill="x", pady=(px(20), px(12)))
        self.clean_legend = frame(hero)
        self.clean_legend.pack(fill="x")
        self.clean_result = frame(hero)  # shown after a clean
        self.clean_bar = Bar(hero, height=3)
        self.clean_funnel = SpiralFunnel(hero, [(g, c) for g, c, _i in CLEAN_GROUPS]) if Image else None

        # categories, grouped
        scroll = ScrollFrame(p)
        scroll.pack(fill="both", expand=True, pady=(px(16), 0))
        self.clean_vars, self.clean_rows, self.clean_groups = {}, {}, {}
        for gname, color, items in CLEAN_GROUPS:
            card = Card(scroll.inner, padding=0)
            card.pack(fill="x", pady=(0, px(14)), padx=(0, px(4)))
            head = frame(card, padx=px(20), pady=px(14))
            head.pack(fill="x")
            dot = tk.Canvas(head, width=px(12), height=px(12), bg=SURFACE, highlightthickness=0)
            dot.create_oval(1, 1, px(11), px(11), fill=color, outline=color)
            dot.pack(side="left")
            label(head, gname, "h2").pack(side="left", padx=px(10))
            gvar = tk.BooleanVar(value=True)
            Toggle(head, gvar, command=lambda g=gname: self._toggle_clean_group(g)).pack(side="right")
            label(head, "All", "small", MUTED).pack(side="right", padx=px(8))
            gtotal = label(head, "", "body_b", MUTED)
            gtotal.pack(side="right", padx=px(18))
            self.clean_groups[gname] = (gvar, gtotal, items, color)
            for name in items:
                divider(card)
                locked = self.clean_targets[name][1] and not is_admin()
                row = frame(card, padx=px(20), pady=px(12))
                row.pack(fill="x")
                v = tk.BooleanVar(value=not locked)
                t = Toggle(row, v, command=self._clean_selection_changed)
                t.pack(side="left")
                if locked:
                    t.configure(state="disabled")
                text = frame(row)
                text.pack(side="left", padx=px(16), fill="x", expand=True)
                tl = frame(text)
                tl.pack(anchor="w")
                label(tl, name, "body_b", SUBTLE if locked else TEXT).pack(side="left")
                if locked:
                    badge(tl, "NEEDS ADMIN", "warn").pack(side="left", padx=px(8))
                label(text, CLEAN_INFO[name], "small", MUTED).pack(anchor="w")
                sizes = frame(row)
                sizes.pack(side="right")
                size = label(sizes, "…", "body_b", MUTED, anchor="e", width=11)
                size.pack(anchor="e")
                count = label(sizes, "", "small", SUBTLE, anchor="e")
                count.pack(anchor="e")
                mini = Bar(row, height=6, color=color)
                mini.configure(width=px(140))
                mini.pack(side="right", padx=(px(16), px(8)))
                self.clean_vars[name] = v
                self.clean_rows[name] = (size, count, mini, locked)
        return p

    def _toggle_clean_group(self, gname):
        gvar, _total, items, _color = self.clean_groups[gname]
        for n in items:
            if not self.clean_rows[n][3]:
                self.clean_vars[n].set(gvar.get())
        self._clean_selection_changed()

    def _clean_selection_changed(self):
        for gvar, _total, items, _color in self.clean_groups.values():
            available = [n for n in items if not self.clean_rows[n][3]]
            gvar.set(bool(available) and all(self.clean_vars[n].get() for n in available))
        self._update_clean_summary()

    def _update_clean_summary(self):
        if not self._clean_sizes:
            return
        parts, selected, found = [], 0, 0
        for gname, (_gvar, gtotal, items, color) in self.clean_groups.items():
            g_sel = sum(self._clean_sizes[n][0] for n in items if self.clean_vars[n].get())
            g_all = sum(self._clean_sizes[n][0] for n in items)
            selected, found = selected + g_sel, found + g_all
            gtotal.configure(text=human(g_all))
            parts.append((gname, g_sel, color))
        self.clean_stack.set(parts)
        for w in self.clean_legend.winfo_children():
            w.destroy()
        for gname, value, color in parts:
            item = frame(self.clean_legend)
            item.pack(side="left", padx=(0, px(24)))
            dot = tk.Canvas(item, width=px(10), height=px(10), bg=SURFACE, highlightthickness=0)
            dot.create_oval(1, 1, px(9), px(9), fill=color, outline=color)
            dot.pack(side="left")
            label(item, gname, "small_b").pack(side="left", padx=(px(7), px(5)))
            label(item, human(value), "small", MUTED).pack(side="left")
        self.clean_caption.configure(text="JUNK SELECTED")
        self.clean_total.configure(text=human(selected), fg=TEXT)
        self.clean_sub.configure(text=f"selected to clean   ·   {human(found)} found in total")
        self.clean_btn.configure(state="normal" if selected and not self._clean_busy else "disabled")

    def _busy_clean(self, busy, funnel=False):
        self._clean_busy = busy
        funnel = funnel and self.clean_funnel is not None
        if busy and funnel:
            self.clean_funnel.pack(fill="x", pady=(px(16), 0), before=self.clean_stack)
        elif self.clean_funnel:
            self.clean_funnel.stop()
            self.clean_funnel.pack_forget()
        self.analyze_btn.configure(state="disabled" if busy else "normal")
        self.clean_btn.configure(state="disabled")
        if busy and not funnel:
            self.clean_bar.pack(fill="x", pady=(px(16), 0))
            self.clean_bar.start()
        else:
            self.clean_bar.stop()
            self.clean_bar.pack_forget()

    def analyze(self):
        self._busy_clean(True)
        self.clean_result.pack_forget()
        self.clean_caption.configure(text="ANALYZING")
        self.clean_total.configure(text="Scanning…", fg=MUTED)
        self.clean_sub.configure(text="Measuring junk files. Nothing is deleted until you click Clean selected.")
        for size, count, mini, _locked in self.clean_rows.values():
            size.configure(text="…", fg=MUTED)
            count.configure(text="")
            mini.set(0)

        def work():
            sizes = {}
            for name, (pats, _admin) in self.clean_targets.items():
                sizes[name] = recycle_bin_info() if pats is None else measure(pats)
                self.ui(self._show_clean_size, name, sizes[name])
            self.ui(self._analysis_done, sizes)
        self.bg(work)

    def _show_clean_size(self, name, measured):
        size, count = measured
        s, c, _mini, _locked = self.clean_rows[name]
        s.configure(text=human(size), fg=TEXT if size else SUBTLE)
        c.configure(text=f"{count:,} files" if count else "nothing to clean")

    def _analysis_done(self, sizes):
        self._clean_sizes = sizes
        biggest = max([s for s, _c in sizes.values()] + [1])
        for name, (size, _count) in sizes.items():
            self.clean_rows[name][2].set(size / biggest)
        self._busy_clean(False)
        self._update_clean_summary()

    def do_clean(self):
        chosen = [n for n in self.clean_targets if self.clean_vars[n].get() and self._clean_sizes.get(n, (0, 0))[0]]
        if not chosen:
            return
        total = sum(self._clean_sizes[n][0] for n in chosen)
        names = "\n".join(f"•  {n}  ({human(self._clean_sizes[n][0])})" for n in chosen)
        if not messagebox.askyesno("Kavacham", f"Permanently delete {human(total)} of junk files?\n\n{names}\n\n"
                                               "Tip: close your browsers first so their caches can be cleared."):
            return
        self._busy_clean(True, funnel=True)
        self.clean_caption.configure(text="CLEANING")
        self.clean_sub.configure(text="Deleting junk files. Files in use are skipped.")
        drive = os.environ.get("SystemDrive", "C:") + "\\"
        free_before = shutil.disk_usage(drive).free
        group_of = {n: g for g, (_gn, _c, items) in enumerate(CLEAN_GROUPS) for n in items}
        funnel = self.clean_funnel
        if funnel:
            funnel.begin({group_of[n] for n in chosen}, total)

        def work():
            freed = skipped = 0
            for name in chosen:
                if funnel:
                    self.ui(funnel.progress, freed, f"Cleaning {name}…", group_of[name])
                pats, _admin = self.clean_targets[name]
                if pats is None:
                    f, s = recycle_bin_info()[0], 0
                    empty_recycle_bin()
                else:
                    f, _r, s = clean(pats)
                freed, skipped = freed + f, skipped + s
                self.ui(self._item_cleaned, name, f)
                if funnel:
                    self.ui(funnel.progress, freed, None, group_of[name])
            free_after = shutil.disk_usage(drive).free
            add_history("Manual cleaning", f"Freed {human(freed)}", ", ".join(chosen))
            done = lambda: self._clean_done(freed, skipped, drive, free_before, free_after)
            if funnel:
                self.ui(funnel.finish, done)  # the funnel plays its finale, then shows the result
            else:
                self.ui(done)
        self.bg(work)

    def _item_cleaned(self, name, freed):
        s, c, mini, _locked = self.clean_rows[name]
        s.configure(text="Cleaned", fg=OK)
        c.configure(text=f"{human(freed)} freed")
        mini.set(0)
        size, count = self._clean_sizes[name]
        self._clean_sizes[name] = (max(0, size - freed), count)  # what remains is files that were in use

    def _clean_done(self, freed, skipped, drive, free_before, free_after):
        self._busy_clean(False)
        self._update_clean_summary()
        self.clean_caption.configure(text="FREED")
        self.clean_total.configure(text=human(freed), fg=OK)
        self.clean_sub.configure(text="of junk removed" + (f"   ·   {skipped:,} files in use were skipped"
                                                         if skipped else ""))
        for w in self.clean_result.winfo_children():
            w.destroy()
        divider(self.clean_result, pady=(0, px(14)))
        row = frame(self.clean_result)
        row.pack(anchor="w")
        label(row, ICONS["drive"], "icon_sm", MUTED).pack(side="left")
        label(row, f"Free space on {drive[:2]}", "small", MUTED).pack(side="left", padx=(px(8), px(14)))
        label(row, human(free_before), "body_b", MUTED).pack(side="left")
        label(row, ICONS["arrow"], "icon_sm", SUBTLE).pack(side="left", padx=px(10))
        label(row, human(free_after), "body_b", OK).pack(side="left")
        gained = free_after - free_before
        if gained > 0:
            label(row, f"+{human(gained)}", "small_b", OK).pack(side="left", padx=px(10))
        self.clean_result.pack(fill="x", pady=(px(16), 0))

    # ---------------------------------------------------------- large files
    def _page_large(self):
        p = self.page("Large files", "Find the biggest files in a folder and send the ones you don't need to the "
                                     "Recycle Bin.")
        bar = Card(p, padding=16)
        bar.pack(fill="x")
        label(bar, ICONS["folder"], "icon", MUTED).pack(side="left")
        self.large_path = tk.StringVar(value=os.path.expanduser("~"))
        ttk.Entry(bar, textvariable=self.large_path, font=F["body"]).pack(side="left", fill="x", expand=True,
                                                                         padx=px(12))
        Button(bar, "Browse", lambda: self.large_path.set(
            filedialog.askdirectory(initialdir=self.large_path.get()) or self.large_path.get()),
               "secondary").pack(side="left")
        self.large_btn = Button(bar, "Find large files", self.find_large, "primary", icon="search")
        self.large_btn.pack(side="left", padx=(px(10), 0))

        box = Card(p, padding=8)
        box.pack(fill="both", expand=True, pady=px(16))
        self.large_tree = table(box, [("size", "SIZE", 110, False), ("path", "FILE", 700, True)])
        self.large_tree.configure(selectmode="extended")
        self.large_tree.bind("<Double-1>", lambda _e: self.open_location())
        set_empty(self.large_tree, "Choose a folder and click 'Find large files'.")

        actions = frame(p)
        actions.pack(fill="x")
        self.large_status = label(actions, "Shows the 200 biggest files. Double-click a file to open its folder.",
                                  "small", MUTED)
        self.large_status.pack(side="left")
        Button(actions, "Move to Recycle Bin", self.recycle_selected, "danger", icon="clean").pack(side="right")
        Button(actions, "Open location", self.open_location, "secondary", icon="open").pack(side="right",
                                                                                           padx=px(10))
        return p

    def find_large(self):
        root = self.large_path.get()
        if not os.path.isdir(root):
            messagebox.showerror("Kavacham", "That folder does not exist.")
            return
        self.large_btn.configure(state="disabled")
        self.large_tree.delete(*self.large_tree.get_children())
        set_empty(self.large_tree, "Searching…")
        self.large_status.configure(text="Searching… this can take a minute on big folders.")

        def work():
            heap, scanned, stack = [], 0, [root]
            while stack:
                d = stack.pop()
                try:
                    with os.scandir(d) as it:
                        for e in it:
                            try:
                                if e.is_symlink():
                                    continue
                                if e.is_dir():
                                    stack.append(e.path)
                                elif e.is_file():
                                    scanned += 1
                                    item = (e.stat().st_size, e.path)
                                    if len(heap) < 200:
                                        heapq.heappush(heap, item)
                                    elif item > heap[0]:
                                        heapq.heapreplace(heap, item)
                            except OSError:
                                pass
                except OSError:
                    pass
            result = sorted(heap, reverse=True)

            def apply():
                for size, path in result:
                    tone = "bad" if size > 4 * 1024 ** 3 else "warn" if size > 1024 ** 3 else ""
                    self.large_tree.insert("", "end", values=(human(size), path), tags=(tone,))
                set_empty(self.large_tree, "No files found in this folder.")
                total = sum(s for s, _ in result)
                self.large_status.configure(text=f"Checked {scanned:,} files · top {len(result)} use {human(total)}")
                self.large_btn.configure(state="normal")
            self.ui(apply)
        self.bg(work)

    def _selected_paths(self):
        return [self.large_tree.item(i, "values")[1] for i in self.large_tree.selection()]

    def open_location(self):
        paths = self._selected_paths()
        if paths:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(paths[0])])

    def recycle_selected(self):
        paths = self._selected_paths()
        if not paths:
            return
        if not messagebox.askyesno("Kavacham", f"Move {len(paths)} file(s) to the Recycle Bin?\n"
                                               "You can restore them from the Recycle Bin later."):
            return
        for item in list(self.large_tree.selection()):
            if send_to_recycle_bin(self.large_tree.item(item, "values")[1]):
                self.large_tree.delete(item)
        self.large_status.configure(text="Moved to Recycle Bin.")

    # ---------------------------------------------------------- duplicate files
    def _page_duplicates(self):
        p = self.page("Duplicate files", "Find identical copies and keep just one. Files are compared by their "
                                         "content, not their names.")
        bar = Card(p, padding=16)
        bar.pack(fill="x")
        label(bar, ICONS["folder"], "icon", MUTED).pack(side="left")
        self.dup_path = tk.StringVar(value=os.path.expanduser("~"))
        ttk.Entry(bar, textvariable=self.dup_path, font=F["body"]).pack(side="left", fill="x", expand=True,
                                                                       padx=px(12))
        Button(bar, "Browse", lambda: self.dup_path.set(
            filedialog.askdirectory(initialdir=self.dup_path.get()) or self.dup_path.get()),
               "secondary").pack(side="left")
        self.dup_btn = Button(bar, "Find duplicates", self.find_dups, "primary", icon="search")
        self.dup_btn.pack(side="left", padx=(px(10), 0))

        opts = frame(p)
        opts.pack(fill="x", pady=(px(14), px(10)))
        label(opts, "Minimum size", "small_b", MUTED).pack(side="left")
        self.dup_min = tk.StringVar(value="1 MB")
        ttk.Combobox(opts, textvariable=self.dup_min, values=list(DUP_MIN_SIZES), state="readonly", width=9,
                     font=F["small"]).pack(side="left", padx=px(10))
        self.dup_skip = tk.BooleanVar(value=True)
        Toggle(opts, self.dup_skip).pack(side="left", padx=(px(22), px(10)))
        label(opts, "Skip system, app and hidden folders (recommended)", "small", MUTED).pack(side="left")
        self.dup_cancel_btn = Button(opts, "Stop", self._cancel_dups, "danger", icon="stop", height=32)
        self.dup_cancel_btn.configure(state="disabled")
        self.dup_cancel_btn.pack(side="right")
        self.dup_bar = Bar(p, height=4)
        self.dup_bar.pack(fill="x", pady=(0, px(12)))

        box = Card(p, padding=8)
        box.pack(fill="both", expand=True)
        self.dup_tree = table(box, [("size", "SIZE", 130, False), ("modified", "MODIFIED", 160, False)],
                              tree_column=("FILE", 560))
        self.dup_tree.configure(selectmode="extended")
        self.dup_tree.tag_configure("group", font=F["body_b"], background=SURFACE_2)
        self.dup_tree.bind("<<TreeviewSelect>>", lambda _e: self._dup_selection_changed())
        self.dup_tree.bind("<Double-1>", lambda _e: self._open_dup_location())
        self.dup_meta = {}  # child row id -> (size, path)
        set_empty(self.dup_tree, "Choose a folder and click 'Find duplicates'.")

        actions = frame(p)
        actions.pack(fill="x", pady=(px(16), 0))
        # buttons are packed first so a long status message wraps instead of squeezing them
        Button(actions, "Move to Recycle Bin", self.recycle_dups, "danger", icon="clean").pack(side="right")
        Button(actions, "Open location", self._open_dup_location, "secondary", icon="open").pack(side="right",
                                                                                                padx=px(10))
        Button(actions, "Select extra copies", self.auto_select_dups, "secondary", icon="check").pack(side="right")
        self.dup_status = label(actions, "Tip: 'Select extra copies' keeps the oldest file in each set.",
                                "small", MUTED, wraplength=px(380), justify="left")
        self.dup_status.pack(side="left")
        return p

    def find_dups(self):
        root = self.dup_path.get()
        if not os.path.isdir(root):
            messagebox.showerror("Kavacham", "That folder does not exist.")
            return
        self._dup_cancel = False
        self._dup_root = root
        self.dup_btn.configure(state="disabled")
        self.dup_cancel_btn.configure(state="normal")
        self.dup_tree.delete(*self.dup_tree.get_children())
        self.dup_meta.clear()
        set_empty(self.dup_tree, "Searching…")
        self.dup_bar.start()
        min_size, skip = DUP_MIN_SIZES[self.dup_min.get()], self.dup_skip.get()
        last = [0.0]

        def progress(stage, done, total):
            if time.time() - last[0] < 0.25:
                return
            last[0] = time.time()
            text = (f"Listing files… {done:,} found" if stage == "listing"
                    else f"Comparing contents… {done:,} of {total:,} possible matches")
            self.ui(self.dup_status.configure, {"text": text})

        def work():
            groups, scanned = find_duplicates(root, min_size, skip, progress, lambda: self._dup_cancel)
            rows = []
            for size, paths in groups[:500]:
                files = []
                for path in paths:
                    try:
                        files.append((os.path.getmtime(path), path))
                    except OSError:
                        pass
                if len(files) > 1:
                    rows.append((size, sorted(files)))  # oldest first: usually the original
            self.ui(self._show_dups, rows, scanned, len(groups), self._dup_cancel)
        self.bg(work)

    def _cancel_dups(self):
        self._dup_cancel = True
        self.dup_status.configure(text="Stopping…")

    def _show_dups(self, rows, scanned, group_count, cancelled):
        self.dup_bar.stop()
        self.dup_btn.configure(state="normal")
        self.dup_cancel_btn.configure(state="disabled")
        tree = self.dup_tree
        tree.heading("#0", text=f"FILE  (in {self._dup_root})")
        wasted_total = 0
        for size, files in rows:
            wasted = size * (len(files) - 1)
            wasted_total += wasted
            name = os.path.basename(files[0][1])
            g = tree.insert("", "end", open=True, tags=("group",),
                            text=f"{name}   ·   {len(files)} copies of {human(size)}",
                            values=(f"{human(wasted)} extra", ""))
            for mtime, path in files:
                shown = os.path.relpath(path, self._dup_root)  # the full path stays in dup_meta
                item = tree.insert(g, "end", text=shown,
                                   values=(human(size), time.strftime("%d %b %Y %H:%M", time.localtime(mtime))))
                self.dup_meta[item] = (size, path)
        set_empty(tree, "Search stopped." if cancelled and not rows else "No duplicate files found.")
        text = f"Checked {scanned:,} files · {group_count:,} sets of duplicates · {human(wasted_total)} in extra copies"
        if group_count > len(rows):
            text += f" (showing the biggest {len(rows)})"
        self.dup_status.configure(text=("Stopped early · " if cancelled else "") + text)

    def _dup_selection_changed(self):
        chosen = [i for i in self.dup_tree.selection() if i in self.dup_meta]
        if chosen:
            total = sum(self.dup_meta[i][0] for i in chosen)
            self.dup_status.configure(text=f"{len(chosen)} file(s) selected · {human(total)}")

    def auto_select_dups(self):
        extra = []
        for g in self.dup_tree.get_children():
            extra += list(self.dup_tree.get_children(g))[1:]  # keep the oldest copy
        self.dup_tree.selection_set(extra)
        if extra:
            self.dup_tree.see(extra[0])

    def _open_dup_location(self):
        chosen = [i for i in self.dup_tree.selection() if i in self.dup_meta]
        if chosen:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(self.dup_meta[chosen[0]][1])])

    def recycle_dups(self):
        tree = self.dup_tree
        chosen = [i for i in tree.selection() if i in self.dup_meta]
        if not chosen:
            messagebox.showinfo("Kavacham", "Select the copies to remove first, or click 'Select extra copies'.")
            return
        by_group = {}
        for i in chosen:
            by_group.setdefault(tree.parent(i), []).append(i)
        for g, items in by_group.items():
            kept = [i for i in tree.get_children(g) if i not in items]
            if not any(os.path.exists(self.dup_meta[i][1]) for i in kept):
                messagebox.showerror("Kavacham", "You selected every copy of a file.\n\n"
                                                 "Leave at least one copy unselected in each set.")
                tree.see(items[0])
                return
        total = sum(self.dup_meta[i][0] for i in chosen)
        if not messagebox.askyesno("Kavacham", f"Move {len(chosen)} duplicate file(s) ({human(total)}) to the "
                                               "Recycle Bin?\n\nAt least one copy of each file is kept, and you "
                                               "can restore these from the Recycle Bin."):
            return
        moved = moved_size = 0
        for i in chosen:
            size, path = self.dup_meta[i]
            if send_to_recycle_bin(path):
                moved, moved_size = moved + 1, moved_size + size
                tree.delete(i)
                del self.dup_meta[i]
        for g in by_group:
            left = tree.get_children(g)
            if len(left) <= 1:  # no longer a duplicate set
                for i in left:
                    self.dup_meta.pop(i, None)
                tree.delete(g)
        set_empty(tree, "All duplicates handled.")
        add_history("Duplicate cleanup", f"Moved {human(moved_size)} to Recycle Bin",
                    f"{moved} duplicate file(s) from {self.dup_path.get()}")
        failed = len(chosen) - moved
        self.dup_status.configure(text=f"Moved {moved} file(s) · {human(moved_size)} to the Recycle Bin"
                                       + (f" · {failed} could not be moved" if failed else "")
                                       + ". Empty the Recycle Bin to free the space.")

    # ---------------------------------------------------------- automation
    def _page_schedule(self):
        p = self.page("Automation", "Scan and clean on a schedule. Tasks run through Windows Task Scheduler, "
                                    "even when Kavacham is closed.")
        self.sched, self.sched_frames = {}, {}
        holder = frame(p)
        self.sched_tabs = Segmented(p, [("scan", "Automatic scan"), ("clean", "Automatic cleaning"),
                                        ("reports", "Reports")], self._switch_sched)
        self.sched_tabs.pack(anchor="w", pady=(0, px(16)))
        holder.pack(fill="both", expand=True)
        for kind in ("scan", "clean"):
            sf = ScrollFrame(holder)
            self._schedule_form(sf.inner, kind)
            self.sched_frames[kind] = sf
        rep = frame(holder)
        self._reports(rep)
        self.sched_frames["reports"] = rep
        self.sched_tabs.select("scan")
        return p

    def _switch_sched(self, key):
        for k, f in self.sched_frames.items():
            f.pack_forget()
        self.sched_frames[key].pack(fill="both", expand=True)
        if key == "reports":
            self.refresh_reports()

    def _schedule_form(self, parent, kind):
        cfg = self.settings[kind]
        v = {"widgets": [], "day_widgets": [], "time_widgets": []}
        self.sched[kind] = v

        def track(w, *groups):
            v["widgets"].append(w)
            for g in groups:
                v[g].append(w)
            return w

        # header card with the master switch and live status
        head = Card(parent, padding=22)
        head.pack(fill="x", padx=(0, px(4)))
        ic = tk.Canvas(head, width=px(48), height=px(48), bg=SURFACE, highlightthickness=0)
        round_rect(ic, 0, 0, px(48), px(48), px(12), fill=ACCENT_DIM, outline=ACCENT_DIM)
        ic.create_text(px(24), px(25), text=ICONS["shield" if kind == "scan" else "clean"], font=F["icon"],
                       fill=ACCENT)
        ic.pack(side="left")
        text = frame(head)
        text.pack(side="left", padx=px(16), fill="x", expand=True)
        label(text, "Automatic scan" if kind == "scan" else "Automatic cleaning", "h2").pack(anchor="w")
        st = frame(text)
        st.pack(anchor="w", pady=(px(3), 0))
        label(st, ICONS["clock"], "icon_sm", MUTED).pack(side="left")
        v["status"] = label(st, "Checking…", "small", MUTED)
        v["status"].pack(side="left", padx=px(6))
        v["enabled"] = tk.BooleanVar(value=cfg["enabled"])
        Toggle(head, v["enabled"], command=lambda: self._sync_form(kind)).pack(side="right")
        label(head, "Enabled", "small_b", MUTED).pack(side="right", padx=px(10))

        # when
        when = Card(parent, padding=22)
        when.pack(fill="x", pady=(px(14), 0), padx=(0, px(4)))
        label(when, "SCHEDULE", "caption", SUBTLE).pack(anchor="w", pady=(0, px(2)))
        right = setting_row(when, "Frequency", "How often the task runs", first=True)
        v["frequency"] = tk.StringVar(value=cfg["frequency"])
        freq = track(ttk.Combobox(right, textvariable=v["frequency"], values=["Daily", "Weekly", "At logon"],
                                  state="readonly", width=14, font=F["body"]))
        freq.pack()
        freq.bind("<<ComboboxSelected>>", lambda _e: self._sync_form(kind))

        right = setting_row(when, "Days", "Used when the frequency is Weekly")
        v["days"] = {}
        for d in DAYS:
            v["days"][d] = tk.BooleanVar(value=d in cfg["days"])
            track(Chip(right, d[:3], v["days"][d], width=px(50)), "day_widgets").pack(side="left", padx=px(3))

        right = setting_row(when, "Time", "24-hour clock. At logon runs 5 minutes after you sign in")
        hh, mm = cfg["time"].split(":")
        v["hour"], v["minute"] = tk.StringVar(value=hh), tk.StringVar(value=mm)
        track(ttk.Spinbox(right, from_=0, to=23, width=4, format="%02.0f", wrap=True, textvariable=v["hour"],
                          font=F["body"]), "time_widgets").pack(side="left")
        label(right, ":", "body_b", MUTED).pack(side="left", padx=px(6))
        track(ttk.Spinbox(right, from_=0, to=59, increment=5, width=4, format="%02.0f", wrap=True,
                          textvariable=v["minute"], font=F["body"]), "time_widgets").pack(side="left")

        # what
        what = Card(parent, padding=22)
        what.pack(fill="x", pady=(px(14), 0), padx=(0, px(4)))
        label(what, "TASK", "caption", SUBTLE).pack(anchor="w", pady=(0, px(2)))
        if kind == "scan":
            right = setting_row(what, "Scan type", "Quick checks common hiding places; Full checks every file",
                                first=True)
            v["type"] = tk.StringVar(value=cfg["type"])
            track(ttk.Combobox(right, textvariable=v["type"], values=["Quick", "Full"], state="readonly",
                               width=14, font=F["body"])).pack()
            right = setting_row(what, "Update virus definitions first", "Gets the latest signatures before scanning")
            v["update_first"] = tk.BooleanVar(value=cfg["update_first"])
            track(Toggle(right, v["update_first"])).pack()
            right = setting_row(what, "Also scan with the Kavacham engine",
                                "A second opinion after Defender; known malware is quarantined")
            v["engine"] = tk.BooleanVar(value=cfg["engine"])
            track(Toggle(right, v["engine"])).pack()
        else:
            setting_row(what, "What to clean", "Items marked * need Kavacham to be saved while running as admin",
                        first=True)
            grid = frame(what)
            grid.pack(fill="x", pady=(0, px(12)))
            v["categories"] = {}
            names = [(n, a) for n, _p, a in CLEAN_TARGETS] + [("Recycle Bin", False)]
            for i, (n, admin_only) in enumerate(names):
                grid.columnconfigure(i % 3, weight=1, uniform="cat")
                v["categories"][n] = tk.BooleanVar(value=n in cfg["categories"])
                chip = track(Chip(grid, n + (" *" if admin_only else ""), v["categories"][n], height=34))
                chip.grid(row=i // 3, column=i % 3, sticky="ew", padx=px(3), pady=px(3))
            right = setting_row(what, "Only when space is low", "Skip cleaning while free space on C: is above "
                                                               "this. 0 = always clean")
            v["min_free_gb"] = tk.StringVar(value=str(cfg["min_free_gb"]))
            track(ttk.Spinbox(right, from_=0, to=2000, width=6, textvariable=v["min_free_gb"],
                              font=F["body"])).pack(side="left")
            label(right, "GB", "body", MUTED).pack(side="left", padx=(px(8), 0))

        # conditions
        cond = Card(parent, padding=22)
        cond.pack(fill="x", pady=(px(14), 0), padx=(0, px(4)))
        label(cond, "CONDITIONS", "caption", SUBTLE).pack(anchor="w", pady=(0, px(2)))
        for i, (key, title, desc) in enumerate([
            ("run_missed", "Catch up on missed runs", "If the PC was off at the scheduled time, run when it's back on"),
            ("skip_on_battery", "Don't run on battery", "Wait until a laptop is plugged in"),
            ("idle", "Only when the PC is idle", "Waits up to 4 hours for 10 minutes of no activity"),
            ("notify", "Notify me when finished", "Threats found are always notified" if kind == "scan" else
             "Shows how much space was freed"),
        ]):
            right = setting_row(cond, title, desc, first=i == 0)
            v[key] = tk.BooleanVar(value=cfg[key])
            track(Toggle(right, v[key])).pack()

        actions = frame(parent)
        actions.pack(fill="x", pady=px(16), padx=(0, px(4)))
        Button(actions, "Save schedule", lambda: self.save_schedule(kind), "primary", icon="check").pack(side="right")
        Button(actions, "Run now", lambda: self.run_task_now(kind), "secondary", icon="play").pack(side="right",
                                                                                                  padx=px(10))
        self._sync_form(kind)

    def _sync_form(self, kind):
        v = self.sched[kind]
        on = v["enabled"].get()
        for w in v["widgets"]:
            w.configure(state=("readonly" if isinstance(w, ttk.Combobox) else "normal") if on else "disabled")
        if on:
            weekly, logon = v["frequency"].get() == "Weekly", v["frequency"].get() == "At logon"
            for w in v["day_widgets"]:
                w.configure(state="normal" if weekly else "disabled")
            for w in v["time_widgets"]:
                w.configure(state="disabled" if logon else "normal")

    def _collect(self, kind):
        v = self.sched[kind]
        try:
            hh, mm = int(v["hour"].get()) % 24, int(v["minute"].get()) % 60
        except ValueError:
            hh, mm = 12, 0
        cfg = {"enabled": v["enabled"].get(), "frequency": v["frequency"].get(),
               "days": [d for d in DAYS if v["days"][d].get()], "time": f"{hh:02d}:{mm:02d}"}
        for key in ("run_missed", "skip_on_battery", "idle", "notify"):
            cfg[key] = v[key].get()
        if kind == "scan":
            cfg["type"], cfg["update_first"], cfg["engine"] = v["type"].get(), v["update_first"].get(), v["engine"].get()
        else:
            cfg["categories"] = [n for n, var in v["categories"].items() if var.get()]
            try:
                cfg["min_free_gb"] = max(0, int(float(v["min_free_gb"].get())))
            except ValueError:
                cfg["min_free_gb"] = 0
        return cfg

    def save_schedule(self, kind):
        cfg = self._collect(kind)
        if cfg["enabled"] and cfg["frequency"] == "Weekly" and not cfg["days"]:
            messagebox.showerror("Kavacham", "Pick at least one day of the week.")
            return
        if kind == "clean" and cfg["enabled"] and not cfg["categories"]:
            messagebox.showerror("Kavacham", "Pick at least one thing to clean.")
            return
        self.settings[kind] = cfg
        write_json(SETTINGS_FILE, self.settings)
        status = self.sched[kind]["status"]
        status.configure(text="Saving…", fg=MUTED)

        def work():
            err = register_task(kind, cfg)
            if err:
                self.ui(status.configure, {"text": f"Could not save: {err[:140]}", "fg": BAD})
                return
            self.ui(self._load_task_info, kind)
            admin_cats = [n for n, _p, a in CLEAN_TARGETS if a and n in cfg.get("categories", [])]
            if cfg["enabled"] and admin_cats and not is_admin():
                self.ui(messagebox.showinfo, "Kavacham",
                        "Saved. These items need administrator rights and will be skipped:\n\n"
                        + "\n".join("•  " + n for n in admin_cats)
                        + "\n\nTo include them, click 'Restart as admin' and save the schedule again.")
        self.bg(work)

    def run_task_now(self, kind):
        self.settings[kind] = {**self._collect(kind), "enabled": self.settings[kind]["enabled"]}
        write_json(SETTINGS_FILE, self.settings)
        self.sched[kind]["status"].configure(text="Started in the background — the result will appear in Reports",
                                             fg=ACCENT)
        self.bg(start_task, kind)

    def refresh_schedule(self):
        for kind in self.sched:
            self._load_task_info(kind)
        self.refresh_reports()

    def _load_task_info(self, kind):
        status = self.sched[kind]["status"]

        def work():
            try:
                info = task_info(kind)
            except Exception:
                info = None
            if not info:
                text, fg = "Not scheduled — turn on the switch and save", MUTED
            elif info["State"] == "Running":
                text, fg = "Running now…", ACCENT
            else:
                nxt = info["Next"] or ("At next sign-in" if self.settings[kind]["frequency"] == "At logon" else "—")
                text, fg = f"Next run {nxt}", OK
                if info["Last"]:
                    text += f"   ·   Last run {info['Last']}" + ("" if info["Result"] == 0 else
                                                                 f" (code {info['Result']:#x})")
            self.ui(status.configure, {"text": text, "fg": fg})
        self.bg(work)

    def _reports(self, parent):
        card = Card(parent, padding=8)
        card.pack(fill="both", expand=True)
        top = frame(card, padx=px(10), pady=px(8))
        top.pack(fill="x")
        label(top, "Every manual and scheduled scan or cleaning is recorded here.", "small", MUTED).pack(side="left")
        Button(top, "Clear", self.clear_reports, "ghost").pack(side="right")
        Button(top, "Refresh", self.refresh_reports, "secondary", icon="refresh", height=32).pack(side="right",
                                                                                                 padx=px(8))
        self.report_tree = table(card, [("time", "WHEN", 150, False), ("task", "TASK", 150, False),
                                        ("result", "RESULT", 220, False), ("details", "DETAILS", 380, True)])

    def refresh_reports(self):
        self.report_tree.delete(*self.report_tree.get_children())
        for r in read_json(HISTORY_FILE, []):
            self.report_tree.insert("", "end", values=(r["time"], r["task"], r["result"], r["details"]),
                                    tags=(r.get("level", "ok") if r.get("level") != "ok" else "",))
        set_empty(self.report_tree, "No activity yet. Scans and cleanups will be listed here.")

    def clear_reports(self):
        if messagebox.askyesno("Kavacham", "Clear all report history?"):
            write_json(HISTORY_FILE, [])
            self.refresh_reports()


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    App().mainloop()
