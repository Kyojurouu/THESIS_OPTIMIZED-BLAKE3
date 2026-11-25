"""Optimized BLAKE3 Forensic Toolkit — standalone application.

Pages (left sidebar)
--------------------
HASHING      Hash Files
EVALUATION   Technique Evaluation (thesis Table 8) · Correctness Verification
ABOUT        Overview · Methodology

All computation lives in the ``dev`` package; this file is presentation only.
The interface is plain Tkinter with a small design system (colour tokens,
cards, flat buttons, stat tiles, banners) and a light/dark theme that can be
switched at any time without losing state.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import queue
import re
import time
import subprocess
import sys
import threading
import tkinter as tk
import traceback
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

_ROOT = Path(__file__).resolve().parent
_MODULE_DIR = _ROOT / "dev"
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))


from benchmark_blake3 import (                                    # noqa: E402
    FORMULAS,
    STATISTICAL_PLAN,
    export_report,
    planned_read_bytes,
    run_configuration_trials,
)
from blake3_validation import (                                   # noqa: E402
    LIMITATIONS,
    run_validation,
)
from dataset_tool import format_size, size_tier                   # noqa: E402
from optimized_blake3 import (                                    # noqa: E402
    BATCH_WINDOW,
    MIB,
    SMALL_FILE_LIMIT,
    TABLE8_CONFIGURATIONS,
    THESIS_TITLE,
    TOOL_NAME,
    TOOL_SHORT_NAME,
    TOOL_SUBTITLE,
    OperationCancelled,
    detected_simd_tier,
    hash_paths,
    make_worker_pool,
    physical_cpu_count,
    system_summary,
    verify_hash_list,
    write_hash_report,
)

RESULTS_DIR = _ROOT / "results"
SETTINGS_PATH = Path.home() / ".optimized_blake3_toolkit.json"

# ─────────────────────────────────────────────────────────────────────────────
# Design system
# ─────────────────────────────────────────────────────────────────────────────
# Every colour in the UI comes from a token. Values must be unique within a
# palette: switching theme recolours widgets by mapping each old value to the
# new value of the same token.

THEMES: Dict[str, Dict[str, str]] = {
    "light": {
        "bg": "#f3f5f9", "surface": "#ffffff", "surface_alt": "#f6f8fb", "hover": "#edf1f6",
        "row_alt": "#fafbfd", "border": "#e2e7ee", "border_strong": "#cdd5e0",
        "text": "#0f172a", "text_soft": "#334155", "muted": "#64748b",
        "accent": "#0f766e", "accent_hover": "#0b5f59", "accent_soft": "#e0f2f0",
        "on_accent": "#fdfefe", "select_bg": "#115e56", "on_select": "#fcfffe",
        "success": "#15803d", "success_soft": "#e6f5ea", "warning": "#b45309",
        "warning_soft": "#fdf2df", "danger": "#b91c1c", "danger_soft": "#fbeaea",
        "info": "#1d4ed8", "info_soft": "#e8eefc", "chart_neutral": "#9aa8ba",
        "sidebar": "#0f1b2d", "sidebar_hover": "#17263c", "sidebar_active": "#1f3350",
        "sidebar_text": "#b8c4d6", "sidebar_muted": "#6f819b", "sidebar_title": "#f8fafc",
        "sidebar_accent": "#2dd4be",
    },
    "dark": {
        "bg": "#0b1120", "surface": "#121a2b", "surface_alt": "#172135", "hover": "#1c2840",
        "row_alt": "#141d30", "border": "#23304a", "border_strong": "#33435f",
        "text": "#e6ebf3", "text_soft": "#c3cddb", "muted": "#8b9ab0",
        "accent": "#2dd4bf", "accent_hover": "#5eead4", "accent_soft": "#123b3a",
        "on_accent": "#062a27", "select_bg": "#1d5f58", "on_select": "#f0fdfa",
        "success": "#4ade80", "success_soft": "#12301f", "warning": "#fbbf24",
        "warning_soft": "#33280f", "danger": "#f87171", "danger_soft": "#3a1717",
        "info": "#60a5fa", "info_soft": "#13284a", "chart_neutral": "#55657e",
        "sidebar": "#070c17", "sidebar_hover": "#101a2c", "sidebar_active": "#16233a",
        "sidebar_text": "#a9b6c9", "sidebar_muted": "#5d6d86", "sidebar_title": "#f1f5f9",
        "sidebar_accent": "#2dd4bd",
    },
}
for _name, _palette in THEMES.items():
    assert len(set(v.lower() for v in _palette.values())) == len(_palette), _name
assert THEMES["light"].keys() == THEMES["dark"].keys()

P: Dict[str, str] = dict(THEMES["light"])   # the active palette (mutated on theme switch)

F = {
    "title": ("Segoe UI Semibold", 20), "h2": ("Segoe UI Semibold", 13),
    "h3": ("Segoe UI Semibold", 10), "body": ("Segoe UI", 10), "small": ("Segoe UI", 9),
    "tiny": ("Segoe UI Semibold", 8), "mono": ("Consolas", 10), "mono_lg": ("Consolas", 12),
    "stat": ("Segoe UI Semibold", 19), "button_lg": ("Segoe UI Semibold", 12),
    "icon": ("Segoe UI Symbol", 16), "icon_lg": ("Segoe UI Symbol", 22),
    "nav": ("Segoe UI", 10), "nav_icon": ("Segoe UI Symbol", 11), "brand": ("Segoe UI Semibold", 13),
}

_TREES: List[ttk.Treeview] = []
_CHARTS: List["SpeedupChart"] = []


def load_settings() -> Dict[str, Any]:
    try:
        return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_settings(settings: Dict[str, Any]) -> None:
    try:
        SETTINGS_PATH.write_text(json.dumps(settings), encoding="utf-8")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def fmt_ms(value: Optional[float]) -> str:
    if value is None:
        return "—"
    return "%.2f s" % (value / 1000.0) if value >= 1000 else "%.2f ms" % value


def fmt_num(value: Optional[float], pattern: str = "%.2f") -> str:
    return "—" if value is None else pattern % value


def fmt_ci(ci: Optional[Sequence[float]], pattern: str = "%.2f") -> str:
    if not ci:
        return "—"
    return "[" + pattern % ci[0] + " – " + pattern % ci[1] + "]"


def fmt_p(value: Optional[float]) -> str:
    if value is None:
        return "—"
    return "< 0.001" if value < 0.001 else "%.3f" % value


def fmt_speedup(value: Optional[float]) -> str:
    return "—" if value is None else "%.2f×" % value


def speed_phrase(value: Optional[float]) -> str:
    if not value:
        return "—"
    return "%.2f× faster" % value if value >= 1 else "%.2f× slower" % (1 / value)


_VERDICT_TAG = {
    "significantly faster": "win",
    "significantly slower": "loss",
    "no significant difference": "neutral",
}
_VERDICT_TONE = {"significantly faster": "success", "significantly slower": "danger"}


def verdict_text(verdict: str, reference: bool = False) -> str:
    if reference:
        return {"significantly faster": "✔ Optimized faster",
                "significantly slower": "✘ Optimized slower",
                "no significant difference": "– No significant difference"}.get(verdict, verdict)
    return {"significantly faster": "✔ Faster",
            "significantly slower": "✘ Slower",
            "no significant difference": "– No significant difference"}.get(verdict, verdict)


def throttled(callback: Callable, interval: float = 0.1) -> Callable:
    """Limit how often a progress callback reaches the UI queue."""
    last = [0.0]

    def wrapper(*args):
        now = time.perf_counter()
        if now - last[0] >= interval:
            last[0] = now
            callback(*args)
    return wrapper


def method_label(record: Dict[str, Any]) -> str:
    """Short, readable description of how the engine hashed one file."""
    method = record.get("method", "")
    found = re.search(r"(\d+) threads", method)
    threads = found.group(1) if found else "?"
    if "background-read" in method:
        reason = "HDD/network storage" if "sequential storage" in method else "mapping unavailable"
        return "Sequential reads (%s) · %s threads" % (reason, threads)
    if "mmap" in method:
        return "Memory-mapped · %s threads" % threads
    if method.startswith("batched"):
        return "Batched · worker pool"
    if method.startswith("single-thread"):
        return "Single-thread"
    return method


def short_cpu_name(name: str) -> str:
    for cut in (" w/", " with ", " Radeon", "(R)", "(TM)", " CPU", " Processor"):
        name = name.replace(cut, " ") if cut in ("(R)", "(TM)", " CPU", " Processor") else name.split(cut)[0]
    return " ".join(name.split())


def open_folder(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception as exc:
        messagebox.showerror("Cannot open folder", str(exc))


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ─────────────────────────────────────────────────────────────────────────────
# Primitive widgets
# ─────────────────────────────────────────────────────────────────────────────

def frame(parent, bg: str = "surface", **kw) -> tk.Frame:
    return tk.Frame(parent, bg=P[bg], **kw)


def label(parent, text: str = "", *, fg: str = "text", bg: str = "surface", font: str = "body",
          **kw) -> tk.Label:
    return tk.Label(parent, text=text, fg=P[fg], bg=P[bg], font=F[font], **kw)


def _cap(parent, text: str = "", bg: str = "surface", **kw) -> tk.Label:
    kw.setdefault("anchor", "w")
    return tk.Label(parent, text=text, bg=P[bg], fg=P["muted"], font=F["small"], **kw)


def entry(parent, variable: tk.StringVar, *, mono: bool = True, **kw) -> tk.Entry:
    return tk.Entry(parent, textvariable=variable, bg=P["surface_alt"], fg=P["text"],
                    insertbackground=P["text"], relief="flat", font=F["mono" if mono else "body"],
                    highlightthickness=1, highlightbackground=P["border"],
                    highlightcolor=P["accent"], readonlybackground=P["surface_alt"],
                    disabledbackground=P["surface_alt"], **kw)


def spinbox(parent, variable, *, from_, to, increment=1, width=6) -> tk.Spinbox:
    return tk.Spinbox(parent, from_=from_, to=to, increment=increment, textvariable=variable,
                      width=width, bg=P["surface_alt"], fg=P["text"],
                      buttonbackground=P["surface_alt"], insertbackground=P["text"],
                      relief="flat", highlightthickness=1, highlightbackground=P["border"],
                      highlightcolor=P["accent"], font=F["body"], justify="center",
                      readonlybackground=P["surface_alt"], disabledbackground=P["surface_alt"])


def check(parent, text: str, variable: tk.BooleanVar, bg: str = "surface") -> tk.Checkbutton:
    return tk.Checkbutton(parent, text=text, variable=variable, bg=P[bg], fg=P["text"],
                          activebackground=P[bg], activeforeground=P["text"],
                          selectcolor=P["surface_alt"], font=F["body"], highlightthickness=0,
                          bd=0, cursor="hand2", anchor="w")


def text_box(parent, height: int = 10, fg: str = "text") -> tk.Text:
    return tk.Text(parent, height=height, bg=P["surface_alt"], fg=P[fg], insertbackground=P["text"],
                   relief="flat", font=F["mono"], wrap="word", highlightthickness=1,
                   highlightbackground=P["border"], highlightcolor=P["border"], padx=12, pady=10,
                   selectbackground=P["select_bg"], selectforeground=P["on_select"])


class FlatButton(tk.Label):
    """Flat, theme-aware button with hover state (works identically in both themes)."""

    KINDS = {
        "primary": ("accent", "on_accent", "accent_hover"),
        "secondary": ("surface_alt", "text", "hover"),
        "ghost": ("surface", "text_soft", "hover"),
        "danger": ("danger_soft", "danger", "hover"),
        "chip_on": ("accent_soft", "accent", "accent_soft"),
        "chip_off": ("surface_alt", "text_soft", "hover"),
    }
    SIZES = {"sm": (10, 4, "small"), "md": (16, 7, "h3"), "lg": (30, 11, "button_lg")}

    def __init__(self, parent, text: str, command: Optional[Callable] = None, *,
                 kind: str = "secondary", size: str = "md"):
        background, foreground, _hover = self.KINDS[kind]
        padx, pady, font = self.SIZES[size]
        super().__init__(parent, text=text, bg=P[background], fg=P[foreground], font=F[font],
                         padx=padx, pady=pady, cursor="hand2",
                         highlightthickness=1 if kind in ("secondary", "chip_off") else 0,
                         highlightbackground=P["border"])
        self._kind = kind
        self._command = command
        self._enabled = True
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.bind("<ButtonRelease-1>", self._click)

    def _tokens(self):
        return self.KINDS[self._kind]

    def _enter(self, _event=None):
        if self._enabled:
            tk.Label.configure(self, bg=P[self._tokens()[2]])

    def _leave(self, _event=None):
        tk.Label.configure(self, bg=P[self._tokens()[0]] if self._enabled else P["surface_alt"])

    def _click(self, event):
        if not self._enabled or self._command is None:
            return
        if 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height():
            self._command()

    def set_kind(self, kind: str) -> None:
        self._kind = kind
        self._apply()

    def _apply(self):
        background, foreground, _hover = self._tokens()
        tk.Label.configure(
            self, bg=P[background] if self._enabled else P["surface_alt"],
            fg=P[foreground] if self._enabled else P["muted"],
            cursor="hand2" if self._enabled else "arrow",
            highlightthickness=1 if self._kind in ("secondary", "chip_off") else 0)

    def configure(self, cnf=None, **kw):
        if isinstance(cnf, dict):
            kw = dict(cnf, **kw)
            cnf = None
        handled = False
        if "state" in kw:
            self._enabled = kw.pop("state") != "disabled"
            self._apply()
            handled = True
        if "command" in kw:
            self._command = kw.pop("command")
            handled = True
        if kw or cnf is not None or not handled:
            return tk.Label.configure(self, cnf, **kw)
        return None

    config = configure


class StatTile(tk.Frame):
    def __init__(self, parent, title: str):
        super().__init__(parent, bg=P["surface"], highlightbackground=P["border"], highlightthickness=1)
        inner = frame(self)
        inner.pack(fill="both", expand=True, padx=16, pady=12)
        label(inner, title.upper(), fg="muted", font="tiny").pack(anchor="w")
        self.value = tk.StringVar(value="—")
        self._value_label = tk.Label(inner, textvariable=self.value, bg=P["surface"], fg=P["text"],
                                     font=F["stat"], anchor="w")
        self._value_label.pack(anchor="w", pady=(2, 0))
        self.sub = tk.StringVar(value="")
        tk.Label(inner, textvariable=self.sub, bg=P["surface"], fg=P["muted"], font=F["small"],
                 anchor="w", justify="left", wraplength=230).pack(anchor="w")

    def set(self, value: str, sub: str = "", tone: Optional[str] = None) -> None:
        self.value.set(value)
        self.sub.set(sub)
        self._value_label.configure(fg=P[tone or "text"])


def tile_row(parent, titles: Sequence[str], bg: str = "bg") -> List[StatTile]:
    row = frame(parent, bg=bg)
    row.pack(fill="x", padx=24, pady=(0, 16))
    tiles = []
    for index, title in enumerate(titles):
        row.columnconfigure(index, weight=1, uniform="tiles")
        tile = StatTile(row, title)
        tile.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 6, 0))
        tiles.append(tile)
    return tiles


class Banner(tk.Frame):
    """Coloured message strip; invisible until ``show`` is called."""

    TONES = {"success": ("success_soft", "success", "✔"), "warning": ("warning_soft", "warning", "!"),
             "danger": ("danger_soft", "danger", "✘"), "info": ("info_soft", "info", "i")}

    def __init__(self, parent, bg: str = "surface"):
        super().__init__(parent, bg=P[bg])
        self._inner = tk.Frame(self, bg=P["info_soft"])
        self._icon = tk.Label(self._inner, text="i", bg=P["info_soft"], fg=P["info"], font=F["h2"], width=2)
        self._icon.pack(side="left", padx=(12, 4), pady=10, anchor="n")
        self._text = tk.Label(self._inner, text="", bg=P["info_soft"], fg=P["info"], font=F["h3"],
                              justify="left", anchor="w", wraplength=940)
        self._text.pack(side="left", fill="x", expand=True, padx=(0, 14), pady=10)

    def show(self, message: str, tone: str = "info") -> None:
        soft, strong, icon = self.TONES[tone]
        for widget in (self._inner, self._icon, self._text):
            widget.configure(bg=P[soft])
        self._icon.configure(fg=P[strong], text=icon)
        self._text.configure(fg=P[strong], text=message)
        if not self._inner.winfo_ismapped():
            self._inner.pack(fill="x")

    def hide(self) -> None:
        self._inner.pack_forget()


def card(parent, *, padx: int = 22, pady: int = 18, margin=(24, 0, 0, 16)) -> tk.Frame:
    """Bordered surface; returns the inner content frame."""
    left, right, top, bottom = margin
    outer = tk.Frame(parent, bg=P["surface"], highlightbackground=P["border"],
                     highlightcolor=P["border"], highlightthickness=1)
    outer.pack(fill="x", padx=(left, right or left), pady=(top, bottom))
    inner = frame(outer)
    inner.pack(fill="both", expand=True, padx=padx, pady=pady)
    return inner


def _section(parent, title: str, subtitle: str = "", step: Optional[int] = None) -> tk.Frame:
    """Card with a heading; the returned frame has a ``header`` attribute for actions."""
    body = card(parent)
    head = frame(body)
    head.pack(fill="x", pady=(0, 14))
    if step is not None:
        tk.Label(head, text=str(step), bg=P["accent_soft"], fg=P["accent"], font=F["h3"],
                 width=3, pady=3).pack(side="left", padx=(0, 12), anchor="n")
    column = frame(head)
    column.pack(side="left", fill="x", expand=True)
    label(column, title, font="h2").pack(anchor="w")
    if subtitle:
        label(column, subtitle, fg="muted", font="small", wraplength=900, justify="left",
              anchor="w").pack(anchor="w", pady=(2, 0))
    content = frame(body)
    content.pack(fill="both", expand=True)
    content.header = head  # type: ignore[attr-defined]
    return content


def _heading(parent, title: str, subtitle: str = "", eyebrow: str = "") -> tk.Frame:
    wrap = frame(parent, bg="bg")
    wrap.pack(fill="x", padx=24, pady=(26, 18))
    if eyebrow:
        label(wrap, eyebrow.upper(), fg="accent", bg="bg", font="tiny").pack(anchor="w")
    label(wrap, title, bg="bg", font="title", wraplength=980, justify="left", anchor="w").pack(anchor="w")
    if subtitle:
        label(wrap, subtitle, fg="muted", bg="bg", wraplength=980, justify="left",
              anchor="w").pack(anchor="w", pady=(4, 0))
    return wrap


class _Scroll(tk.Frame):
    """Vertically scrollable page; put content in ``.inner``."""

    def __init__(self, parent: tk.Widget, **kw):
        super().__init__(parent, bg=P["bg"], **kw)
        self._cv = tk.Canvas(self, bg=P["bg"], highlightthickness=0, bd=0)
        bar = ttk.Scrollbar(self, orient="vertical", command=self._cv.yview)
        self._cv.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self._cv.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self._cv, bg=P["bg"])
        self._wid = self._cv.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda _e: self._cv.configure(scrollregion=self._cv.bbox("all")))
        self._cv.bind("<Configure>", lambda e: self._cv.itemconfig(self._wid, width=e.width))
        self._cv.bind_all("<MouseWheel>", self._on_wheel, add="+")

    def _on_wheel(self, event):
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None:
            if isinstance(widget, (ttk.Treeview, tk.Text, tk.Listbox)):
                return
            if widget == self:
                self._cv.yview_scroll(int(-event.delta / 120), "units")
                return
            widget = widget.master

    def to_top(self):
        self._cv.yview_moveto(0)


def style_tree(tree: ttk.Treeview) -> None:
    tree.tag_configure("odd", background=P["row_alt"])
    tree.tag_configure("win", foreground=P["success"])
    tree.tag_configure("loss", foreground=P["danger"])
    tree.tag_configure("neutral", foreground=P["text"])
    tree.tag_configure("ref", foreground=P["muted"])
    tree.tag_configure("pass", foreground=P["success"])
    tree.tag_configure("fail", foreground=P["danger"])
    tree.tag_configure("pending", foreground=P["muted"])
    tree.tag_configure("base", background=P["accent_soft"])
    tree.tag_configure("match", background=P["success_soft"])


def _table(parent, columns: Sequence[Tuple[str, str, int, str]], height: int = 8) -> ttk.Treeview:
    """columns: (key, heading, width, anchor)."""
    holder = tk.Frame(parent, bg=P["surface"], highlightbackground=P["border"], highlightthickness=1)
    holder.pack(fill="both", expand=True)
    tree = ttk.Treeview(holder, columns=[c[0] for c in columns], show="headings", height=height)
    # Columns keep their designed width so values are never truncated (wide
    # tables scroll horizontally). When the table is wider than its columns, the
    # first column absorbs the spare room.
    widths = {key: width for key, _heading, width, _anchor in columns}
    for key, heading, width, anchor in columns:
        tree.heading(key, text=heading, anchor=anchor)
        tree.column(key, width=width, minwidth=min(width, 60), anchor=anchor, stretch=False)

    def fit(_event=None):
        try:
            shown = tree["displaycolumns"]
            visible = list(widths) if shown in ("#all", ("#all",)) else list(shown)
            spare = tree.winfo_width() - sum(widths[k] for k in visible) - 4
            first = visible[0]
            tree.column(first, width=widths[first] + max(0, spare))
        except tk.TclError:
            pass

    tree.bind("<Configure>", fit, add="+")
    tree.fit_columns = fit  # type: ignore[attr-defined]
    style_tree(tree)
    _TREES.append(tree)
    x_scroll = ttk.Scrollbar(holder, orient="horizontal", command=tree.xview)
    y_scroll = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
    tree.configure(xscrollcommand=x_scroll.set, yscrollcommand=y_scroll.set)
    y_scroll.pack(side="right", fill="y")
    x_scroll.pack(side="bottom", fill="x")
    tree.pack(fill="both", expand=True)
    return tree


def tree_insert(tree: ttk.Treeview, values, tags=(), iid=None) -> str:
    stripe = ("odd",) if len(tree.get_children()) % 2 else ()
    kwargs = {"values": values, "tags": tuple(tags) + stripe}
    if iid is not None:
        kwargs["iid"] = iid
    return tree.insert("", "end", **kwargs)


def set_row_tags(tree: ttk.Treeview, iid: str, tags) -> None:
    keep = tuple(t for t in tree.item(iid, "tags") if t == "odd")
    tree.item(iid, tags=tuple(tags) + keep)


class SpeedupChart(tk.Canvas):
    """Horizontal speedup bars with 95 % CI whiskers and a 1.0× reference line."""

    def __init__(self, parent):
        super().__init__(parent, bg=P["surface"], height=120, highlightthickness=0)
        self._items: List[Tuple[str, float, Optional[Sequence[float]], str]] = []
        self._title = ""
        self.bind("<Configure>", lambda _e: self.redraw())
        _CHARTS.append(self)

    def set_data(self, items, title=""):
        """items: (label, speedup, ci, tone) with tone in success/danger/neutral."""
        self._items = list(items)
        self._title = title
        self.redraw()

    def redraw(self):
        self.delete("all")
        width = max(300, self.winfo_width())
        if not self._items:
            self.configure(height=70)
            self.create_text(width / 2, 35, text="The chart appears after the experiment runs.",
                             fill=P["muted"], font=F["small"])
            return
        label_w, right_pad, top, row_h = 240, 90, 34, 34
        needed = top + row_h * len(self._items) + 34
        if int(float(self["height"])) != needed:
            self.configure(height=needed)
        max_value = max(max(ci[1] if ci else value, value) for _l, value, ci, _t in self._items)
        scale_max = max(1.25, max_value * 1.08)
        plot_w = width - label_w - right_pad

        def x_of(value):
            return label_w + plot_w * value / scale_max

        self.create_text(0, 12, text=self._title, anchor="w", fill=P["text"], font=F["h3"])
        bottom = top + row_h * len(self._items)
        self.create_line(label_w, bottom, label_w + plot_w, bottom, fill=P["border"])
        x_ref = x_of(1.0)
        self.create_line(x_ref, top - 8, x_ref, bottom, fill=P["muted"], dash=(4, 3))
        self.create_text(x_ref, bottom + 14, text="1.0× = baseline", fill=P["muted"], font=F["small"])
        for index, (text, value, ci, tone) in enumerate(self._items):
            y = top + index * row_h + row_h / 2
            color = P[tone] if tone in ("success", "danger") else P["chart_neutral"]
            self.create_text(label_w - 12, y, text=text, anchor="e", fill=P["text_soft"], font=F["small"])
            self.create_rectangle(label_w, y - 10, label_w + plot_w, y + 10, fill=P["surface_alt"], outline="")
            self.create_rectangle(label_w, y - 10, x_of(value), y + 10, fill=color, outline="")
            if ci:
                self.create_line(x_of(ci[0]), y, x_of(ci[1]), y, fill=P["text"], width=1)
                for edge in ci:
                    self.create_line(x_of(edge), y - 6, x_of(edge), y + 6, fill=P["text"])
            self.create_text(x_of(max(value, ci[1] if ci else value)) + 8, y,
                             text="%.2f×" % value, anchor="w", fill=P["text"], font=F["h3"])


class ProgressPanel(tk.Frame):
    """Progress bar, status message and an optional Cancel button."""

    def __init__(self, parent, bg: str = "surface"):
        super().__init__(parent, bg=P[bg])
        self._bar = ttk.Progressbar(self, mode="determinate", maximum=1000, length=340,
                                    style="B3.Horizontal.TProgressbar")
        self._bar.pack(side="left", padx=(0, 12))
        self._cancel = FlatButton(self, "Cancel", self._on_cancel, kind="ghost", size="sm")
        self._message = tk.StringVar(value="")
        tk.Label(self, textvariable=self._message, bg=P[bg], fg=P["muted"], font=F["small"],
                 anchor="w", wraplength=520, justify="left").pack(side="left", fill="x", expand=True)
        self._cancel_event: Optional[threading.Event] = None

    def start(self, cancel_event: Optional[threading.Event] = None, message: str = "Starting…"):
        self._cancel_event = cancel_event
        self._bar["value"] = 0
        self._message.set(message)
        if cancel_event is not None:
            self._cancel.pack(side="right")
            self._cancel.configure(state="normal")

    def update_progress(self, message: str, fraction: float):
        self._bar["value"] = int(max(0.0, min(1.0, fraction)) * 1000)
        self._message.set(message)

    def finish(self, message: str):
        self._bar["value"] = 1000
        self._message.set(message)
        self._cancel.pack_forget()
        self._cancel_event = None

    def _on_cancel(self):
        if self._cancel_event is not None:
            self._cancel_event.set()
            self._cancel.configure(state="disabled")
            self._message.set("Cancelling after the current step…")


class BackgroundTask:
    """Run ``fn(progress, cancel)`` on a worker thread; marshal results via a queue."""

    def __init__(self, widget: tk.Widget, fn, *, on_progress, on_done, on_error, on_cancel=None):
        self.cancel = threading.Event()
        self._queue: "queue.Queue[tuple]" = queue.Queue()
        self._widget = widget
        self._handlers = dict(progress=on_progress, done=on_done, error=on_error,
                              cancelled=on_cancel or (lambda: None))

        def progress(message: str, fraction: float) -> None:
            self._queue.put(("progress", message, fraction))

        def run():
            try:
                self._queue.put(("done", fn(progress, self.cancel)))
            except OperationCancelled:
                self._queue.put(("cancelled",))
            except Exception as exc:  # surfaced to the user, with traceback for diagnosis
                self._queue.put(("error", str(exc), traceback.format_exc()))

        threading.Thread(target=run, daemon=True).start()
        widget.after(100, self._poll)

    def _poll(self):
        finished = False
        try:
            while True:
                item = self._queue.get_nowait()
                kind = item[0]
                if kind == "progress":
                    self._handlers["progress"](item[1], item[2])
                elif kind == "done":
                    self._handlers["done"](item[1])
                    finished = True
                elif kind == "cancelled":
                    self._handlers["cancelled"]()
                    finished = True
                else:
                    self._handlers["error"](item[1], item[2])
                    finished = True
        except queue.Empty:
            pass
        if not finished:
            self._widget.after(100, self._poll)


class _Tab(tk.Frame):
    def __init__(self, parent, app: "Blake3App"):
        super().__init__(parent, bg=P["bg"])
        self.app = app
        self.busy = False
        self.scroll = _Scroll(self)
        self.scroll.pack(fill="both", expand=True)
        self.body = self.scroll.inner

    def finish_page(self):
        frame(self.body, bg="bg", height=24).pack()

    def status(self, text: str) -> None:
        self.app.status_var.set(text)

    def guard_busy(self) -> bool:
        if self.busy:
            messagebox.showinfo("Busy", "Please wait for the current task to finish (or cancel it).")
            return True
        return False

    def report_error(self, message: str, trace: str) -> None:
        print(trace, file=sys.stderr)
        messagebox.showerror("Error", message)


# ─────────────────────────────────────────────────────────────────────────────
# Hash Files
# ─────────────────────────────────────────────────────────────────────────────

class HashFilesTab(_Tab):
    _ALGO_COLUMNS = (("blake3_standard", "Standard BLAKE3"), ("sha256", "SHA-256"), ("md5", "MD5"))

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._paths: List[str] = []
        self._path_set: set = set()
        self._sizes: Dict[str, int] = {}
        self._shown: set = set()       # paths that have a row in the table
        self._report: Optional[Dict[str, Any]] = None
        _heading(self.body, "Hash Files",
                 "Fingerprint evidence with Optimized BLAKE3: adaptive buffer sizing, batching of small "
                 "files, and multithreading of large files on the physical CPU cores.",
                 eyebrow="Hashing")

        # Hero: add evidence
        hero = card(self.body, pady=22)
        top = frame(hero)
        top.pack(fill="x")
        tk.Label(top, text="#", bg=P["accent_soft"], fg=P["accent"], font=F["icon_lg"], width=3,
                 pady=6).pack(side="left", padx=(0, 16))
        text = frame(top)
        text.pack(side="left", fill="x", expand=True)
        label(text, "Add evidence to hash", font="h2").pack(anchor="w")
        self._count_var = tk.StringVar(value="Choose files, or a folder (subfolders included).")
        tk.Label(text, textvariable=self._count_var, bg=P["surface"], fg=P["muted"], font=F["body"],
                 anchor="w").pack(anchor="w", pady=(2, 0))
        FlatButton(top, "Add folder…", self._add_folder, kind="secondary").pack(side="right")
        FlatButton(top, "Add files…", self._add_files, kind="primary").pack(side="right", padx=8)
        tools = frame(hero)
        tools.pack(fill="x", pady=(14, 0))
        FlatButton(tools, "Remove selected", self._remove, kind="ghost", size="sm").pack(side="left")
        FlatButton(tools, "Clear list", self._clear, kind="ghost", size="sm").pack(side="left", padx=6)

        # Algorithms
        algos = _section(self.body, "Algorithms",
                         "Optimized BLAKE3 is always calculated. Each optional extra adds one more full "
                         "pass over the files.")
        main = frame(algos)
        main.pack(fill="x")
        tk.Label(main, text="  ✔  Optimized BLAKE3   ", bg=P["accent_soft"], fg=P["accent"],
                 font=F["h3"], pady=5).pack(side="left")
        _cap(main, "   main hash · always on").pack(side="left")
        extras = frame(algos)
        extras.pack(fill="x", pady=(12, 0))
        self._extra_vars: Dict[str, tk.BooleanVar] = {}
        descriptions = {
            "blake3_standard": ("Standard BLAKE3", "same algorithm without the optimizations; shows "
                                "identical hashes and the speed difference"),
            "sha256": ("SHA-256", "for reports and tools that use it"),
            "md5": ("MD5", "for older references and hash sets"),
        }
        for index, (key, _label) in enumerate(self._ALGO_COLUMNS):
            var = tk.BooleanVar(value=False)
            self._extra_vars[key] = var
            cell = frame(extras)
            cell.grid(row=index // 2, column=index % 2, sticky="w", padx=(0, 28), pady=3)
            name, detail = descriptions[key]
            check(cell, name, var).pack(side="left")
            _cap(cell, "— " + detail).pack(side="left", padx=(4, 0))

        # Run bar
        run = card(self.body, pady=16)
        run_row = frame(run)
        run_row.pack(fill="x")
        self._hash_btn = FlatButton(run_row, "Hash files", self._start, kind="primary", size="lg")
        self._hash_btn.pack(side="left")
        self._progress = ProgressPanel(run_row)
        self._progress.pack(side="left", fill="x", expand=True, padx=18)

        # Summary
        self._tiles = tile_row(self.body, ["Files hashed", "Data", "Optimized BLAKE3 time", "Throughput"])
        banners = frame(self.body, bg="bg")
        banners.pack(fill="x", padx=24)
        self._compare_banner = Banner(banners, bg="bg")
        self._compare_banner.pack(fill="x", pady=(0, 6))
        self._extras_banner = Banner(banners, bg="bg")
        self._extras_banner.pack(fill="x", pady=(0, 10))

        # Results
        results = _section(self.body, "Results",
                           "Click a row to see its full hash. Double-click copies the Optimized BLAKE3 "
                           "hash; right-click for more.")
        self._columns = [("name", "File", 230, "w"), ("size", "Size", 90, "e"),
                         ("blake3", "Optimized BLAKE3", 470, "w")]
        self._columns += [(key, label_, 300, "w") for key, label_ in self._ALGO_COLUMNS]
        self._columns += [("time", "Time", 80, "e"), ("method", "Method", 250, "w"),
                          ("status", "Status", 100, "w"),
                          ("folder", "Folder", 300, "w")]
        self._limit_banner = Banner(results)
        self._limit_banner.pack(fill="x", pady=(0, 8))
        self._table = _table(results, self._columns, height=10)
        self._table.bind("<<TreeviewSelect>>", self._on_select)
        self._table.bind("<Double-1>", lambda _e: self._copy("blake3"))
        self._menu = tk.Menu(self, tearoff=0)
        self._menu.add_command(label="Copy Optimized BLAKE3 hash", command=lambda: self._copy("blake3"))
        for key, label_ in self._ALGO_COLUMNS[1:]:
            self._menu.add_command(label="Copy %s hash" % label_, command=lambda k=key: self._copy(k))
        self._menu.add_command(label="Copy file path", command=lambda: self._copy("path"))
        self._table.bind("<Button-3>", self._popup)

        selected = frame(results, bg="surface_alt", highlightbackground=P["border"], highlightthickness=1)
        selected.pack(fill="x", pady=(14, 0))
        label(selected, "SELECTED FILE", fg="muted", bg="surface_alt", font="tiny").pack(
            anchor="w", padx=14, pady=(10, 0))
        self._sel_name = tk.StringVar(value="Nothing selected")
        tk.Label(selected, textvariable=self._sel_name, bg=P["surface_alt"], fg=P["text"],
                 font=F["h3"], anchor="w").pack(fill="x", padx=14)
        digest_row = frame(selected, bg="surface_alt")
        digest_row.pack(fill="x", padx=14, pady=(6, 12))
        self._sel_digest = tk.StringVar(value="")
        tk.Entry(digest_row, textvariable=self._sel_digest, state="readonly", font=F["mono_lg"],
                 readonlybackground=P["surface_alt"], fg=P["accent"], relief="flat",
                 highlightthickness=0).pack(side="left", fill="x", expand=True, ipady=4)
        FlatButton(digest_row, "Copy hash", lambda: self._copy("blake3"), kind="primary",
                   size="sm").pack(side="left", padx=(10, 0))

        # Check & save
        verify = _section(self.body, "Check and save",
                          "Paste a hash you received (for example from an acquisition report) to find "
                          "a matching file, or save the hashes to check the files again later.")
        check_row = frame(verify)
        check_row.pack(fill="x")
        _cap(check_row, "Expected hash").pack(side="left", padx=(0, 10))
        self._expected = tk.StringVar()
        self._expected.trace_add("write", lambda *_a: self._compare())
        entry(check_row, self._expected).pack(side="left", fill="x", expand=True, ipady=6)
        FlatButton(check_row, "Paste", self._paste_expected, kind="secondary").pack(side="left", padx=(8, 0))
        self._compare_result = Banner(verify)
        self._compare_result.pack(fill="x", pady=(10, 0))
        save_row = frame(verify)
        save_row.pack(fill="x", pady=(14, 0))
        FlatButton(save_row, "Save hashes…", self._save, kind="primary").pack(side="left")
        FlatButton(save_row, "Check files against a saved list…", self._verify_list,
                   kind="secondary").pack(side="left", padx=8)
        _cap(save_row, "Saves a .b3 hash list (b3sum format) plus CSV and JSON.").pack(side="left", padx=6)
        self._saved_var = tk.StringVar(value="")
        tk.Label(verify, textvariable=self._saved_var, bg=P["surface"], fg=P["muted"], font=F["small"],
                 anchor="w", justify="left", wraplength=980).pack(fill="x", pady=(8, 0))
        self.finish_page()
        self._refresh_columns()

    # file list
    def _refresh_columns(self, algorithms: Sequence[str] = ()):
        visible = ["name", "size", "blake3"] + [k for k, _l in self._ALGO_COLUMNS if k in algorithms]
        self._table.configure(displaycolumns=visible + ["time", "method", "status", "folder"])
        self._table.fit_columns()

    def _row(self, record):
        values = {
            "name": record["name"], "size": format_size(record.get("size_bytes", 0)),
            "blake3": record.get("blake3", ""), "time": "", "folder": record.get("folder", ""),
            "status": {"ok": "✔ Hashed", "error": "✘ Error", "ready": "Ready"}.get(
                record["status"], record["status"]),
        }
        if record["status"] == "ok" and record.get("matches_standard"):
            values["status"] = "✔ Identical"
        for key, _label in self._ALGO_COLUMNS:
            values[key] = record.get(key, "")
        values["method"] = method_label(record) if record.get("method") else ""
        if record.get("elapsed_ms") is not None:
            values["time"] = fmt_ms(record["elapsed_ms"])
        elif record.get("method", "").startswith("batched"):
            values["time"] = "batched"
        if record["status"] == "error":
            values["blake3"] = record.get("error", "")
        return [values[c[0]] for c in self._columns]

    DISPLAY_LIMIT = 5000  # rows shown in the table; every file is still hashed and saved

    def _add(self, paths):
        added = 0
        for path in paths:
            path = str(Path(path).resolve())
            if path in self._path_set or not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            self._paths.append(path)
            self._path_set.add(path)
            self._sizes[path] = size
            if len(self._shown) < self.DISPLAY_LIMIT:
                tree_insert(self._table, self._row({
                    "name": os.path.basename(path), "size_bytes": size,
                    "folder": os.path.dirname(path), "status": "ready"}), ("pending",), iid=path)
                self._shown.add(path)
            added += 1
        self._update_count()
        if added:
            self.status("%d file(s) added" % added)

    def _update_count(self):
        if self._paths:
            self._count_var.set("%d file(s) ready · %s" % (len(self._paths),
                                                          format_size(sum(self._sizes.values()))))
        else:
            self._count_var.set("Choose files, or a folder (subfolders included).")
        hidden = len(self._paths) - len(self._shown)
        if hidden > 0:
            self._limit_banner.show("Showing the first %s of %s files. Every file is hashed and included in "
                                    "saved reports and hash lists." % (format(len(self._shown), ","),
                                                                       format(len(self._paths), ",")), "info")
        else:
            self._limit_banner.hide()

    def _add_files(self):
        self._add(filedialog.askopenfilenames(title="Select files to hash"))

    def _add_folder(self):
        folder = filedialog.askdirectory(title="Select a folder (all files inside, including subfolders)")
        if folder:
            self._add(str(p) for p in sorted(Path(folder).rglob("*")) if p.is_file())

    def _remove(self):
        if self.busy:
            return
        selected = set(self._table.selection())
        if not selected:
            return
        self._paths = [p for p in self._paths if p not in selected]
        for iid in selected:
            self._path_set.discard(iid)
            self._sizes.pop(iid, None)
            self._shown.discard(iid)
            self._table.delete(iid)
        self._update_count()

    def _clear(self):
        if self.busy:
            return
        self._paths.clear()
        self._path_set.clear()
        self._sizes.clear()
        self._shown.clear()
        self._table.delete(*self._table.get_children())
        self._report = None
        for tile in self._tiles:
            tile.set("—")
        self._compare_banner.hide()
        self._extras_banner.hide()
        self._sel_name.set("Nothing selected")
        self._sel_digest.set("")
        self._update_count()
        self._compare()

    # hashing
    def _start(self):
        if self.guard_busy():
            return
        if not self._paths:
            messagebox.showinfo("Nothing to hash", "Add files or a folder first.")
            return
        extras = [k for k, var in self._extra_vars.items() if var.get()]
        paths = list(self._paths)
        pool = self.app.worker_pool  # warm pool (None while it is still starting)
        self.busy = True
        self._hash_btn.configure(state="disabled")
        self._compare_banner.hide()
        self._extras_banner.hide()
        for path in self._shown:  # only rows that exist in the table
            set_row_tags(self._table, path, ("pending",))
            self._table.set(path, "status", "Waiting…")
        task = BackgroundTask(
            self, lambda progress, cancel: hash_paths(paths, extra_algorithms=extras, pool=pool,
                                                      progress=progress, cancel=cancel),
            on_progress=self._progress.update_progress, on_done=self._done,
            on_error=self._error, on_cancel=self._cancelled)
        self._progress.start(task.cancel, "Hashing…")
        self.status("Hashing %d file(s)…" % len(paths))

    def _done(self, report):
        self.busy = False
        self._hash_btn.configure(state="normal")
        self._report = report
        if report.get("worker_pool_failed"):
            self.app.reset_worker_pool()
        self._refresh_columns(report["algorithms"])
        for record in report["files"]:
            if self._table.exists(record["path"]):
                self._table.item(record["path"], values=self._row(record))
                set_row_tags(self._table, record["path"],
                             ("pass",) if record["status"] == "ok" else ("fail",))
        seconds = report["blake3_seconds"]
        errors = report["error_count"]
        self._tiles[0].set("%d / %d" % (report["ok_count"], report["file_count"]),
                           "all files hashed" if not errors else "%d could not be hashed" % errors,
                           "success" if not errors else "danger")
        self._tiles[1].set(format_size(report["total_bytes"]), "hashed")
        self._tiles[2].set(fmt_ms(seconds * 1000.0), "wall-clock time for this job")
        self._tiles[3].set("%.0f MiB/s" % report["blake3_throughput_mib_s"], "Optimized BLAKE3")
        comparison = report.get("standard_comparison")
        if comparison:
            same = comparison["identical_digests"] == comparison["files_compared"]
            if same:
                self._compare_banner.show(
                    "Identical hashes for all %d file(s). Optimized BLAKE3 %s than Standard BLAKE3 "
                    "(%s vs %s). Single-pass comparison; controlled, repeated measurements are available in "
                    "Technique Evaluation." % (
                        comparison["files_compared"],
                        "was " + speed_phrase(comparison["speedup"]),
                        fmt_ms(comparison["optimized_seconds"] * 1000.0),
                        fmt_ms(comparison["standard_seconds"] * 1000.0)),
                    "success")
            else:
                self._compare_banner.show(
                    "%d file(s) gave different Optimized and Standard hashes. Treat these results as "
                    "invalid and run Verification." % (comparison["files_compared"]
                                                       - comparison["identical_digests"]), "danger")
        others = [a for a in report["algorithms"] if a not in ("blake3", "blake3_standard")]
        if others:
            self._extras_banner.show("Extra algorithms: " + " · ".join(
                "%s %s" % (report["algorithm_labels"][a], fmt_ms(report["algorithm_seconds"][a] * 1000.0))
                for a in others), "info")
        self._progress.finish("Done. %s" % ("All files hashed." if not errors else
                                            "%d file(s) need attention (see Status)." % errors))
        children = self._table.get_children()
        if children:
            self._table.selection_set(children[0])
        self._compare()
        self.status("Hashing complete")

    def _cancelled(self):
        self.busy = False
        self._hash_btn.configure(state="normal")
        self._progress.finish("Cancelled.")
        for path in self._shown:
            if self._table.exists(path) and self._table.set(path, "status") == "Waiting…":
                self._table.set(path, "status", "Ready")

    def _error(self, message, trace):
        self.busy = False
        self._hash_btn.configure(state="normal")
        self._progress.finish("Failed: " + message)
        self.report_error(message, trace)

    # selection, copy, compare
    def _record(self, path) -> Optional[Dict[str, Any]]:
        if not self._report:
            return None
        return next((r for r in self._report["files"] if r["path"] == path), None)

    def _on_select(self, _event=None):
        selection = self._table.selection()
        if not selection:
            return
        record = self._record(selection[0])
        self._sel_name.set(os.path.basename(selection[0]))
        self._sel_digest.set(record["blake3"] if record and record["status"] == "ok"
                             else (record["error"] if record else "Not hashed yet"))

    def _popup(self, event):
        row = self._table.identify_row(event.y)
        if row:
            self._table.selection_set(row)
            self._menu.tk_popup(event.x_root, event.y_root)

    def _copy(self, field):
        selection = self._table.selection()
        if not selection:
            return
        if field == "path":
            value = selection[0]
        else:
            record = self._record(selection[0])
            value = record.get(field, "") if record and record["status"] == "ok" else ""
        if not value:
            self.status("Nothing to copy for this file yet")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status("Copied %s to the clipboard" % ("path" if field == "path" else "hash"))

    def _paste_expected(self):
        try:
            self._expected.set(self.clipboard_get().strip())
        except tk.TclError:
            pass

    def _compare(self):
        expected = "".join(self._expected.get().split()).lower()
        for path in self._shown:
            if self._table.exists(path):
                tags = [t for t in self._table.item(path, "tags") if t != "match"]
                self._table.item(path, tags=tags)
        if not expected:
            self._compare_result.hide()
            return
        if not self._report:
            self._compare_result.show("Hash your files first; the expected hash will then be compared.",
                                      "info")
            return
        matches = []
        for record in self._report["files"]:
            for algorithm in self._report["algorithms"]:
                if algorithm == "blake3_standard":
                    continue
                if record.get(algorithm) and record[algorithm] == expected:
                    matches.append((record, algorithm))
        if matches:
            for record, _algorithm in matches:
                if self._table.exists(record["path"]):
                    self._table.item(record["path"],
                                     tags=list(self._table.item(record["path"], "tags")) + ["match"])
                    self._table.see(record["path"])
            names = ", ".join("%s (%s)" % (r["name"], self._report["algorithm_labels"][a])
                              for r, a in matches[:3])
            self._compare_result.show("MATCH: the expected hash belongs to %s." % names, "success")
        else:
            self._compare_result.show("NO MATCH: none of the hashed files has this hash.", "danger")

    # save & verify
    def _save(self):
        if not self._report:
            messagebox.showinfo("Nothing to save", "Hash some files first.")
            return
        folder = filedialog.askdirectory(title="Choose where to save the hash report",
                                         initialdir=str(RESULTS_DIR) if RESULTS_DIR.exists() else None)
        if not folder:
            return
        written = write_hash_report(self._report, folder, "hashes_" + timestamp())
        self._saved_var.set("Saved:  " + "   ·   ".join(written.values()))
        self.status("Hash report saved")

    def _verify_list(self):
        if self.guard_busy():
            return
        path = filedialog.askopenfilename(
            title="Select a saved hash list",
            filetypes=[("Hash lists", "*.b3 *.blake3 *.sha256 *.sha1 *.md5 *.txt"), ("All files", "*.*")])
        if not path:
            return
        self.busy = True
        self._hash_btn.configure(state="disabled")

        def done(result):
            self.busy = False
            self._hash_btn.configure(state="normal")
            counts = result["counts"]
            self._progress.finish("Checked %d file(s) from the list." % len(result["results"]))
            problems = [r for r in result["results"] if r["outcome"] != "match"]
            lines = ["%s list: %s" % (result["algorithm"].upper(), result["list"]), "",
                     "✔ %d match   ✘ %d changed   ? %d missing   ! %d unreadable" % (
                         counts["match"], counts["mismatch"], counts["missing"], counts["error"])]
            if problems:
                lines += ["", "Files that did NOT match:"]
                lines += ["  %s — %s" % (r["outcome"].upper(), r["path"]) for r in problems[:15]]
                if len(problems) > 15:
                    lines.append("  … and %d more" % (len(problems) - 15))
            (messagebox.showinfo if result["passed"] else messagebox.showwarning)(
                "All files match" if result["passed"] else "Some files do not match", "\n".join(lines))

        def error(message, trace):
            self.busy = False
            self._hash_btn.configure(state="normal")
            self._progress.finish("Could not check the list: " + message)
            self.report_error(message, trace)

        pool = self.app.worker_pool
        task = BackgroundTask(self, lambda progress, cancel: verify_hash_list(path, progress=progress,
                                                                              cancel=cancel, pool=pool),
                              on_progress=self._progress.update_progress, on_done=done,
                              on_error=error, on_cancel=self._cancelled)
        self._progress.start(task.cancel, "Re-hashing files from the list…")


# ─────────────────────────────────────────────────────────────────────────────
# Technique Evaluation (thesis Table 8)
# ─────────────────────────────────────────────────────────────────────────────

_CONFIGURATION_HELP = {
    "C0": "Baseline: fixed 1 MiB buffer, one thread, one request per file. Everything is compared with it.",
    "C1": "Only buffer sizing: the buffer follows file size (Table 7: 64 KiB to 16 MiB).",
    "C2": "Only batching: files below 32 MiB are sent up to 32 per request.",
    "C3": "Only multithreading: files of 32 MiB and above use the physical CPU cores.",
    "C4": "All three techniques together (the optimized implementation).",
    "R1": "MD5 with a fixed 1 MiB buffer — reference point only.",
    "R2": "SHA-256 with a fixed 1 MiB buffer — reference point only.",
}


def _comparison_row_values(name, item, comparison, *, reference_speedup=None):
    stats = item["elapsed_ms"]
    if comparison is None:
        verdict = "Baseline" if reference_speedup is None else "Reference point"
        speed = "1.00×" if reference_speedup is None else fmt_speedup(reference_speedup)
        ci = change = p = delta = "—"
    else:
        speed = fmt_speedup(comparison["speedup"])
        ci = fmt_ci(comparison["speedup_ci95"])
        change = fmt_num(comparison["percent_time_reduction"], "%+.1f %%")
        p = "%s (%s)" % (fmt_p(comparison.get("p_holm")),
                         "t" if comparison.get("test") == "paired t-test" else "W")
        delta = ("%.2f (%s)" % (comparison["cohens_d"], comparison["effect_magnitude"])
                 if comparison.get("cohens_d") is not None else "—")
        verdict = verdict_text(comparison["verdict"])
    return (
        name, verdict, fmt_ms(stats["mean"]), fmt_ci(stats["ci95"], "%.2f"),
        fmt_num(stats["cv_percent"], "%.1f %%"), fmt_num(item["throughput_mib_s"]["mean"], "%.0f"),
        fmt_num(item["cpu_percent"]["mean"], "%.1f %%"), fmt_num(item["peak_rss_mib"]["mean"], "%.0f"),
        speed, ci, change, p, delta,
    )


_RESULT_COLUMNS = [
    ("config", "Configuration", 250, "w"), ("verdict", "Result vs C0", 170, "w"),
    ("mean", "Mean time", 90, "e"), ("ci", "95% CI (ms)", 135, "e"), ("cv", "CV", 60, "e"),
    ("thr", "MiB/s", 65, "e"), ("cpu", "CPU", 65, "e"), ("rss", "Peak MiB", 75, "e"),
    ("speed", "Speedup", 90, "e"), ("sci", "Speedup CI", 115, "e"),
    ("change", "Time Δ", 75, "e"), ("p", "p Holm (test)", 100, "e"), ("delta", "Effect d", 120, "w"),
]

_GLOSSARY = (
    "Mean time: all files hashed once (Eq. 2, 7); 95% CI uses the t critical value (Eq. 9); CV (Eq. 10) "
    "above 10 % means the computer was busy — re-run.  Speedup = C0 mean ÷ configuration mean (Eq. 3).  "
    "p Holm (test): Holm-corrected p of the paired t-test (t) when the paired differences are normal "
    "(Shapiro–Wilk), otherwise the Wilcoxon signed-rank test (W).  Effect d: Eq. 18.  "
    "'✔ Faster' means p Holm < 0.05.  MD5 and SHA-256 are reference points and are not tested."
)


def _tone_for(comparison: Optional[Dict[str, Any]]) -> str:
    if not comparison:
        return "neutral"
    return _VERDICT_TONE.get(comparison["verdict"], "neutral")


class TechniqueBenchmarkTab(_Tab):
    PRESETS = (("Quick check", 5), ("Thesis protocol", 30))

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._files: List[str] = []
        _heading(self.body, "Technique Evaluation",
                 "Measures each optimization on its own and all together (thesis Table 8). Every "
                 "configuration hashes the same files through the same engine and data stream as the "
                 "Autopsy module; only the buffer size, batching and threading change. Native SIMD "
                 "(%s) is the same in every configuration." % detected_simd_tier().split(" (")[0],
                 eyebrow="Evaluation")

        # 1. files
        setup = _section(self.body, "Choose the evidence files",
                         "Use a mixed set, like the files of a disk image: many small files (batching "
                         "applies below 32 MiB) and some large ones (threading applies from 32 MiB).", step=1)
        buttons = frame(setup)
        buttons.pack(fill="x", pady=(0, 10))
        FlatButton(buttons, "Add files…", self._add_files, kind="primary").pack(side="left", padx=(0, 6))
        FlatButton(buttons, "Add folder…", self._add_folder).pack(side="left", padx=(0, 6))
        FlatButton(buttons, "Remove selected", self._remove, kind="ghost", size="sm").pack(side="left", padx=6)
        FlatButton(buttons, "Clear", self._clear, kind="ghost", size="sm").pack(side="left")
        self._file_summary = tk.StringVar(value="No files yet.")
        tk.Label(setup, textvariable=self._file_summary, bg=P["surface"], fg=P["text_soft"],
                 font=F["body"], anchor="w").pack(fill="x", pady=(0, 8))
        self._file_table = _table(setup, [
            ("name", "File", 380, "w"), ("size", "Size", 100, "e"),
            ("tier", "Size tier", 220, "w"), ("applies", "Technique that applies", 260, "w"),
        ], height=5)

        # 2. configurations
        configs = _section(self.body, "Choose the configurations",
                           "C0 is always included because every result is compared with it.", step=2)
        self._config_vars: Dict[str, tk.BooleanVar] = {}
        for configuration in TABLE8_CONFIGURATIONS:
            code = configuration["code"]
            var = tk.BooleanVar(value=True)
            self._config_vars[code] = var
            row = frame(configs)
            row.pack(fill="x", pady=2)
            box = check(row, configuration["label"], var)
            box.configure(width=34, anchor="w")
            if code == "C0":
                box.configure(state="disabled")
            box.pack(side="left")
            _cap(row, _CONFIGURATION_HELP[code]).pack(side="left", padx=(4, 0))

        # 3. run
        run = _section(self.body, "Run", step=3)
        chips = frame(run)
        chips.pack(fill="x")
        self._chips: List[FlatButton] = []
        self.trials = tk.IntVar(value=30)
        for index, (name, trials) in enumerate(self.PRESETS):
            chip = FlatButton(chips, "%s · %d trials" % (name, trials), lambda i=index: self._preset(i),
                              kind="chip_off")
            chip.pack(side="left", padx=(0, 8))
            self._chips.append(chip)
        _cap(chips, "Trials").pack(side="left", padx=(12, 0))
        spinbox(chips, self.trials, from_=3, to=200, increment=1, width=5).pack(side="left", padx=6, ipady=3)
        _cap(run, "Each trial runs every chosen configuration once, in a rotated order, after one untimed "
                  "warm-up that loads the files into memory.", wraplength=980,
             justify="left").pack(fill="x", pady=(8, 0))
        self._preset(1)
        action = frame(run)
        action.pack(fill="x", pady=(14, 0))
        self._run_btn = FlatButton(action, "Run evaluation", self._start, kind="primary", size="lg")
        self._run_btn.pack(side="left")
        self._progress = ProgressPanel(action)
        self._progress.pack(side="left", fill="x", expand=True, padx=18)

        # results
        head = frame(self.body, bg="bg")
        head.pack(fill="x", padx=24, pady=(8, 10))
        label(head, "Results", bg="bg", font="h2").pack(side="left")
        FlatButton(head, "Open results folder", lambda: open_folder(RESULTS_DIR), kind="ghost",
                   size="sm").pack(side="right")
        self._banner = Banner(self.body, bg="bg")
        self._banner.pack(fill="x", padx=24, pady=(0, 10))
        self._tiles = tile_row(self.body, ["C1 buffer only", "C2 batching only", "C3 threading only",
                                           "C4 all together"])
        chart = _section(self.body, "Speedup over C0 Baseline BLAKE3",
                         "Above 1.00× = faster than the baseline. Whiskers: range implied by the 95 % "
                         "confidence interval of the paired difference.")
        self._chart = SpeedupChart(chart)
        self._chart.pack(fill="x")
        details = _section(self.body, "Detailed statistics")
        self._table = _table(details, _RESULT_COLUMNS, height=7)
        tk.Label(details, text=_GLOSSARY, bg=P["surface"], fg=P["muted"], font=F["small"], anchor="w",
                 justify="left", wraplength=980).pack(fill="x", pady=(10, 0))
        tiers = _section(self.body, "Speed by file size",
                         "Mean hashing speed (MiB/s) inside the engine for each size tier — how speed "
                         "changes as files get larger.")
        self._tier_frame = frame(tiers)
        self._tier_frame.pack(fill="x")
        self._tier_table: Optional[ttk.Treeview] = None
        self._notes = tk.StringVar(value="")
        tk.Label(tiers, textvariable=self._notes, bg=P["surface"], fg=P["muted"], font=F["small"],
                 anchor="w", justify="left", wraplength=980).pack(fill="x", pady=(10, 0))
        self.finish_page()

    # file list
    def _preset(self, index: int):
        self.trials.set(self.PRESETS[index][1])
        for i, chip in enumerate(self._chips):
            chip.set_kind("chip_on" if i == index else "chip_off")

    def _refresh_files(self):
        self._file_table.delete(*self._file_table.get_children())
        sizes = []
        for path in self._files[:2000]:
            size = os.path.getsize(path)
            sizes.append(size)
            tree_insert(self._file_table, (os.path.basename(path), format_size(size), size_tier(size),
                                           "multithreading" if size >= SMALL_FILE_LIMIT else "batching"),
                        iid=path)
        sizes = [os.path.getsize(p) for p in self._files]
        small = sum(1 for s in sizes if s < SMALL_FILE_LIMIT)
        self._file_summary.set(
            "No files yet." if not sizes else
            "%d files · %s · %d below 32 MiB (batching applies) · %d of 32 MiB or more (threading applies)"
            % (len(sizes), format_size(sum(sizes)), small, len(sizes) - small))

    def _add(self, paths):
        known = set(self._files)
        for path in paths:
            path = str(Path(path).resolve())
            if os.path.isfile(path) and path not in known:
                self._files.append(path)
                known.add(path)
        self._files.sort(key=os.path.getsize)
        self._refresh_files()

    def _add_files(self):
        self._add(filedialog.askopenfilenames(title="Select evidence files"))

    def _add_folder(self):
        folder = filedialog.askdirectory(title="Select a folder (subfolders are included)")
        if folder:
            self._add([str(p) for p in Path(folder).rglob("*") if p.is_file()])

    def _remove(self):
        for iid in self._file_table.selection():
            self._files.remove(iid)
        self._refresh_files()

    def _clear(self):
        self._files.clear()
        self._refresh_files()

    # run
    def _start(self):
        if self.guard_busy():
            return
        if not self._files:
            messagebox.showwarning("No files", "Add evidence files first.")
            return
        try:
            trials = int(self.trials.get())
        except (ValueError, tk.TclError):
            messagebox.showerror("Invalid trials", "Trials must be a whole number.")
            return
        codes = [code for code, var in self._config_vars.items() if var.get() or code == "C0"]
        files = list(self._files)
        planned = planned_read_bytes([os.path.getsize(f) for f in files], trials, 1, len(codes))
        if planned > 200 * 1024 ** 3 and not messagebox.askyesno(
                "Large evaluation", "This evaluation reads about %s in total. At 2 GB/s that takes about "
                "%.1f hours. Continue?" % (format_size(planned), planned / (2 * 1024 ** 3) / 3600)):
            return
        self.busy = True
        self._run_btn.configure(state="disabled")

        def work(progress, cancel):
            report = run_configuration_trials(files, configurations=codes, trials=trials, warmups=1,
                                              progress=progress, cancel=cancel)
            report["exports"] = export_report(report, RESULTS_DIR, "technique_evaluation_" + timestamp())
            return report

        task = BackgroundTask(self, work, on_progress=self._progress.update_progress,
                              on_done=self._done, on_error=self._error, on_cancel=self._cancelled)
        self._progress.start(task.cancel, "Computing reference digests…")
        self.status("Technique evaluation running…")

    def _done(self, report):
        self.busy = False
        self._run_btn.configure(state="normal")
        comparisons = {c["candidate"]: c for c in report["comparisons"]}
        references = {r["reference"]: r["speedup_vs_c0"] for r in report["references"]}
        self._table.delete(*self._table.get_children())
        chart_items = []
        for code, item in report["summary"].items():
            comparison = comparisons.get(code)
            tags = ("base",) if code == "C0" else (("ref",) if code in references else (
                _VERDICT_TAG.get(comparison["verdict"], "neutral"),))
            tree_insert(self._table, _comparison_row_values(item["label"], item, comparison,
                                                            reference_speedup=references.get(code)), tags)
            if comparison:
                chart_items.append((item["label"], comparison["speedup"], comparison["speedup_ci95"],
                                    _tone_for(comparison)))
        workload = report["workload"]
        self._chart.set_data(chart_items, "%d files · %s" % (workload["files"],
                                                            format_size(workload["total_bytes"])))
        for tile, code in zip(self._tiles, ("C1", "C2", "C3", "C4")):
            comparison = comparisons.get(code)
            if comparison:
                tone = _tone_for(comparison)
                tile.set(fmt_speedup(comparison["speedup"]), verdict_text(comparison["verdict"]),
                         tone if tone != "neutral" else None)
            else:
                tile.set("—", "not run")
        best = comparisons.get("C4")
        if best:
            tone = _tone_for(best)
            phrase = {"success": "faster than", "danger": "slower than"}.get(tone, "not clearly different from")
            self._banner.show(
                "With all three techniques (C4) the files were hashed %s the baseline (C0): %s, "
                "Holm-adjusted p %s (%s)." % (phrase, fmt_speedup(best["speedup"]), fmt_p(best.get("p_holm")),
                                              best["test"]),
                {"success": "success", "danger": "danger"}.get(tone, "info"))
        self._show_tiers(report)
        notes = []
        for code, amdahl in report["amdahl"].items():
            if amdahl.get("parallel_fraction") is not None:
                notes.append("Amdahl's Law (Eq. 17): the %s speedup on %d threads implies a parallel portion "
                             "P = %.2f." % (code, amdahl["threads"], amdahl["parallel_fraction"]))
        exports = report["exports"]
        notes.append("Saved: %s · %s · %s" % (exports["json"], exports["summary_csv"], exports["runs_csv"]))
        if report["warnings"]:
            notes.append("Notes: " + " ".join(report["warnings"]))
        self._notes.set("\n".join(notes))
        self._progress.finish("Complete. Every configuration reproduced every file's digest.")
        self.status("Technique evaluation complete")

    def _show_tiers(self, report):
        for child in self._tier_frame.winfo_children():
            child.destroy()
        codes = [c["code"] for c in report["configurations"]]
        self._tier_table = _table(self._tier_frame, [("tier", "Size tier", 230, "w")]
                                  + [(code, code, 90, "e") for code in codes], height=4)
        for row in report["size_tiers"]:
            tree_insert(self._tier_table, [row["size_tier"]] + [fmt_num(row.get(code), "%.0f")
                                                                 for code in codes])

    def _cancelled(self):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._progress.finish("Cancelled; no partial results were saved.")
        self.status("Technique evaluation cancelled")

    def _error(self, message, trace):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._progress.finish("Failed: " + message)
        self.report_error(message, trace)


# ─────────────────────────────────────────────────────────────────────────────
# Verification
# ─────────────────────────────────────────────────────────────────────────────

_CHECK_NAMES = {
    "V1": "Matches the official BLAKE3 test values",
    "V2": "Agrees with an independent BLAKE3 implementation",
    "V3": "Same hash with every setting, configuration and engine profile",
    "H1": "Collision test (Eq. 15)",
    "H2": "Avalanche effect test (Eq. 13)",
    "H3": "Hash distribution test (Eq. 14)",
    "H4": "Deterministic output test (Eq. 16)",
}


class VerificationTab(_Tab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._result: Optional[Dict[str, Any]] = None
        _heading(self.body, "Correctness Verification",
                 "Checks that the optimized engine computes standard BLAKE3 and that the optimizations "
                 "never change a hash. They do not re-prove BLAKE3's security.", eyebrow="Validation")
        setup = _section(self.body, "Input", step=1)
        row = frame(setup)
        row.pack(fill="x")
        self._path = tk.StringVar()
        entry(row, self._path).pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        FlatButton(row, "Browse…", self._browse).pack(side="left", padx=(0, 8))
        FlatButton(row, "Use synthetic input", lambda: self._path.set(""), kind="ghost").pack(side="left")
        _cap(setup, "Leave empty to use a seeded synthetic input that crosses the multithreading threshold. "
                    "A chosen file is used for the consistency check (V3). The hash-behaviour tests H1–H4 "
                    "use seeded random inputs through the optimized engine, as in Section 3.5.",
             wraplength=980, justify="left").pack(fill="x", pady=(8, 0))
        opts = frame(setup)
        opts.pack(fill="x", pady=(12, 0))
        _cap(opts, "Avalanche inputs").pack(side="left")
        self._samples = tk.IntVar(value=1000)
        spinbox(opts, self._samples, from_=100, to=20000, increment=100, width=7).pack(
            side="left", padx=(6, 18), ipady=3)
        _cap(opts, "Collision / distribution digests").pack(side="left")
        self._variants = tk.IntVar(value=10000)
        spinbox(opts, self._variants, from_=100, to=100000, increment=500, width=8).pack(
            side="left", padx=6, ipady=3)
        action = frame(setup)
        action.pack(fill="x", pady=(16, 0))
        self._run_btn = FlatButton(action, "Run all checks", self._start, kind="primary", size="lg")
        self._run_btn.pack(side="left")
        self._progress = ProgressPanel(action)
        self._progress.pack(side="left", fill="x", expand=True, padx=18)

        self._banner = Banner(self.body, bg="bg")
        self._banner.pack(fill="x", padx=24, pady=(0, 10))
        results = _section(self.body, "Results", "Select a row to see the technical details.", step=2)
        self._table = _table(results, [
            ("check", "Check", 380, "w"), ("result", "Result", 100, "w"),
            ("evidence", "Evidence", 380, "w"), ("meaning", "What a pass means", 420, "w"),
        ], height=7)
        self._table.bind("<<TreeviewSelect>>", self._show_detail)
        self._detail = text_box(results, height=9, fg="muted")
        self._detail.insert("1.0", "Run the checks, then select a row above to see its technical details here.")
        self._detail.pack(fill="x", pady=(12, 0))
        limits = frame(results, bg="warning_soft")
        limits.pack(fill="x", pady=(12, 0))
        tk.Label(limits, text="Limitations: " + LIMITATIONS, bg=P["warning_soft"], fg=P["warning"],
                 font=F["small"], wraplength=960, justify="left", anchor="w").pack(fill="x", padx=12, pady=8)
        self._saved = tk.StringVar(value="")
        tk.Label(results, textvariable=self._saved, bg=P["surface"], fg=P["muted"], font=F["small"],
                 anchor="w").pack(fill="x", pady=(8, 0))
        self.finish_page()

    def _browse(self):
        path = filedialog.askopenfilename(title="Select a file to verify against")
        if path:
            self._path.set(path)

    def _start(self):
        if self.guard_busy():
            return
        path = self._path.get().strip() or None
        if path and not os.path.isfile(path):
            messagebox.showwarning("Invalid file", "The selected path is not a file.")
            return
        try:
            samples, variants = int(self._samples.get()), int(self._variants.get())
        except (ValueError, tk.TclError):
            messagebox.showerror("Invalid settings", "Use whole numbers.")
            return
        self.busy = True
        self._run_btn.configure(state="disabled")
        self._banner.hide()

        def work(progress, cancel):
            result = run_validation(path, avalanche_inputs=samples, distribution_digests=variants,
                                    progress=progress)
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            out = RESULTS_DIR / ("verification_%s.json" % timestamp())
            out.write_text(json.dumps(result, indent=2), encoding="utf-8")
            result["saved_to"] = str(out)
            return result

        BackgroundTask(self, work, on_progress=self._progress.update_progress,
                       on_done=self._done, on_error=self._error)
        self._progress.start(None, "Starting…")
        self.status("Verification running…")

    @staticmethod
    def _evidence(p: Dict[str, Any]) -> str:
        name = p["procedure"]
        if name.startswith("V1"):
            return "%d/%d vectors × %d checks (%d-byte outputs)" % (
                p["cases_total"] - p["cases_failed"], p["cases_total"], p["checks_per_case"],
                p["output_bytes_checked"])
        if name.startswith("V2"):
            return "%d inputs, %d disagreements" % (p["inputs_tested"], len(p["failures"]))
        if name.startswith("V3"):
            return "%d variants, %d mismatches (%s)" % (p["variants_tested"], len(p["mismatches"]),
                                                       format_size(p["input_bytes"]))
        if name.startswith("H1"):
            return "%d digests, %d collisions, CR = %.3g" % (
                p["digests_compared"], p["collisions_found"], p["collision_rate"])
        if name.startswith("H2"):
            if not p.get("applicable"):
                return "not applicable"
            return "mean AE %.3f %% over %d inputs (z %.2f vs 50 %%)" % (
                p["mean_avalanche_percent"], p["inputs"], p["z_vs_50_percent"])
        if name.startswith("H3"):
            return "χ² = %.1f, df %d, p = %s" % (p["chi_square"], p["degrees_of_freedom"],
                                                fmt_p(p["p_value"]))
        if name.startswith("H4"):
            return "D = %.1f %% (%d repetitions)" % (p["deterministic_percent"], p["repetitions"])
        return ""

    def _done(self, result):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._result = result
        self._table.delete(*self._table.get_children())
        for index, p in enumerate(result["procedures"]):
            code = p["procedure"].split()[0]
            if p.get("applicable", True) is False:
                text, tags = "N/A", ()
            else:
                text, tags = ("✔ Passed", ("pass",)) if p.get("passed") else ("✘ Failed", ("fail",))
            tree_insert(self._table, ("%s  (%s)" % (_CHECK_NAMES.get(code, p["procedure"]), code), text,
                                      self._evidence(p), p.get("interpretation", "")), tags, iid=str(index))
        passed = sum(1 for p in result["procedures"] if p.get("passed"))
        if result["passed"]:
            self._banner.show("All %d checks passed. The optimized engine produces standard BLAKE3 hashes "
                              "under every setting." % len(result["procedures"]), "success")
        else:
            self._banner.show("%d of %d checks passed. Performance results are valid only when every check "
                              "passes." % (passed, len(result["procedures"])), "danger")
        self._saved.set("Saved: %s  (%.1f s)" % (result["saved_to"], result["duration_seconds"]))
        self._progress.finish("Verification complete")
        self.status("Verification complete")

    def _show_detail(self, _event=None):
        if not self._result or not self._table.selection():
            return
        procedure = dict(self._result["procedures"][int(self._table.selection()[0])])
        for bulky in ("cases", "observations", "lengths", "inputs_with_differences"):
            if bulky in procedure and isinstance(procedure[bulky], list) and len(procedure[bulky]) > 12:
                procedure[bulky] = "%d entries (see the saved JSON report)" % len(procedure[bulky])
        self._detail.configure(fg=P["text"])
        self._detail.delete("1.0", "end")
        self._detail.insert("1.0", json.dumps(procedure, indent=2, ensure_ascii=False))

    def _error(self, message, trace):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._progress.finish("Failed: " + message)
        self.report_error(message, trace)


# ─────────────────────────────────────────────────────────────────────────────
# Overview
# ─────────────────────────────────────────────────────────────────────────────

class OverviewTab(_Tab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        _heading(self.body, THESIS_TITLE,
                 "The study optimizes how files are fed to BLAKE3 — buffer sizing, batching and "
                 "multithreading. The BLAKE3 algorithm is unchanged: every digest is a standard "
                 "BLAKE3-256 value.", eyebrow="Overview")

        label(self.body, "The three techniques", bg="bg", font="h2").pack(anchor="w", padx=24, pady=(0, 10))
        grid = frame(self.body, bg="bg")
        grid.pack(fill="x", padx=24, pady=(0, 16))
        for index, (icon, name, detail) in enumerate((
            ("▤", "Adaptive buffer sizing",
             "Reads each file with a buffer that fits its size (Table 7): 64 KiB for the smallest files up "
             "to 16 MiB for files of 1 GiB and above, instead of a fixed 1 MiB."),
            ("▦", "Batching small files",
             "Files below %d MiB are sent to the hashing engine up to %d per request, so one request "
             "serves many files. Each file still gets its own digest." % (SMALL_FILE_LIMIT // MIB, BATCH_WINDOW)),
            ("⚡", "Multithreading large files",
             "Files of %d MiB and above use BLAKE3's own parallel mode on the %d physical CPU cores. "
             "Smaller files stay single-threaded because starting threads costs more than it saves."
             % (SMALL_FILE_LIMIT // MIB, physical_cpu_count())),
        )):
            grid.columnconfigure(index, weight=1, uniform="tech")
            cell = tk.Frame(grid, bg=P["surface"], highlightbackground=P["border"], highlightthickness=1)
            cell.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 8, 0))
            inner = frame(cell)
            inner.pack(fill="both", expand=True, padx=18, pady=16)
            tk.Label(inner, text=icon, bg=P["accent_soft"], fg=P["accent"], font=F["icon"], width=3,
                     pady=4).pack(anchor="w")
            label(inner, name, font="h3").pack(anchor="w", pady=(10, 4))
            label(inner, detail, fg="muted", font="small", wraplength=290, justify="left",
                  anchor="w").pack(anchor="w", fill="x")

        configs = _section(self.body, "How each technique is measured (Table 8)",
                           "Technique Evaluation runs these configurations on the same files and compares "
                           "each with C0.")
        table = _table(configs, [("code", "Configuration", 250, "w"), ("buffer", "Input buffer", 150, "w"),
                                 ("batch", "Small-file batching", 160, "w"),
                                 ("threads", "Native threads", 230, "w")], height=7)
        for configuration in TABLE8_CONFIGURATIONS:
            blake3_run = configuration["algorithm"] == "BLAKE3"
            threaded = configuration["profile"] in ("blake3_threads_only", "blake3_optimized")
            tree_insert(table, (
                configuration["label"],
                "adaptive (Table 7)" if configuration["adaptive_buffer"] else "fixed 1 MiB",
                "files below 32 MiB" if configuration["batching"] else "no",
                ("physical cores at 32 MiB and above" if threaded else "one") if blake3_run else "n/a"))
        FlatButton(configs, "Open Technique Evaluation →", lambda: app.show("technique"), kind="ghost",
                   size="sm").pack(anchor="w", pady=(10, 0))

        constant = _section(self.body, "Kept the same in every configuration")
        for line in (
            "The BLAKE3 algorithm and its digests (checked on the Correctness Verification page).",
            "Native SIMD (%s): chosen automatically by the BLAKE3 library in every configuration, so it is "
            "not one of the studied techniques." % detected_simd_tier(),
            "The computer, the files and the order rotation: only the configuration changes between runs.",
        ):
            row = frame(constant)
            row.pack(fill="x", pady=3)
            label(row, "✔", fg="success", font="h3").pack(side="left", anchor="n", padx=(0, 10))
            label(row, line, fg="text_soft", wraplength=930, justify="left", anchor="w").pack(side="left", fill="x")

        machine = _section(self.body, "This computer")
        info = system_summary()
        for name, value in (
            ("Processor", info["cpu_model"]),
            ("CPU cores", "%d physical cores (used for large files) · %d logical threads" % (
                info["physical_cores"], info["logical_threads"])),
            ("Memory", "%s GB" % info["memory_gib"] if info["memory_gib"] else "unknown"),
            ("SIMD", info["simd_tier"]),
            ("BLAKE3 library", "blake3 %s (official package)" % info["blake3_package_version"]),
        ):
            row = frame(machine)
            row.pack(fill="x", pady=2)
            label(row, name, fg="muted", font="small", width=18, anchor="w").pack(side="left")
            label(row, value, fg="text_soft", anchor="w", wraplength=820, justify="left").pack(side="left")

        flow = _section(self.body, "How to use this tool")
        for number, (text, page) in enumerate((
            ("Hash evidence files, save a hash list, or check files against one.", "hash"),
            ("Run the correctness checks: the optimized engine must give standard BLAKE3 digests.", "verify"),
            ("Run the technique evaluation on a mixed set of evidence files (30 trials for the thesis).",
             "technique"),
            ("See every formula and the statistical analysis plan, or export them.", "method"),
        ), 1):
            row = frame(flow)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=str(number), bg=P["accent_soft"], fg=P["accent"], font=F["h3"], width=3,
                     pady=3).pack(side="left")
            label(row, text, fg="text_soft", anchor="w").pack(side="left", padx=12)
            FlatButton(row, "Open →", lambda p=page: app.show(p), kind="ghost", size="sm").pack(side="right")
        self.finish_page()


# ─────────────────────────────────────────────────────────────────────────────
# Methodology
# ─────────────────────────────────────────────────────────────────────────────

def methodology_markdown() -> str:
    lines = ["# Methodology: performance indicators and statistical analysis", "",
             "Generated by the %s on %s." % (TOOL_NAME, datetime.now().strftime("%Y-%m-%d")),
             "", "## Formulas", ""]
    for formula in FORMULAS:
        lines += ["### %s. %s" % (formula["id"], formula["name"]), "",
                  "    " + formula["expression"], "", formula["symbols"], "",
                  "*Implemented in:* `%s`" % formula["function"], ""]
    lines += ["## " + STATISTICAL_PLAN.splitlines()[0], ""]
    lines += STATISTICAL_PLAN.splitlines()[2:]
    lines += ["", "## Scope of verification conclusions", "", LIMITATIONS, ""]
    return "\n".join(lines)


class MethodologyTab(_Tab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        _heading(self.body, "Methodology",
                 "Every reported value is computed with one of the following formulas, implemented in "
                 "dev/benchmark_blake3.py, numbered as Equations 1–19 of thesis Chapter 3.", eyebrow="System")
        actions = frame(self.body, bg="bg")
        actions.pack(fill="x", padx=24, pady=(0, 14))
        FlatButton(actions, "Export as Markdown", self._export, kind="primary").pack(side="left")
        self._saved = tk.StringVar(value="")
        tk.Label(actions, textvariable=self._saved, bg=P["bg"], fg=P["muted"], font=F["small"]).pack(
            side="left", padx=12)
        formulas = _section(self.body, "Formulas", "Select a formula to see its symbols and conditions.")
        table = _table(formulas, [
            ("id", "ID", 50, "w"), ("name", "Indicator / procedure", 270, "w"),
            ("expr", "Expression", 520, "w"), ("fn", "Implemented in", 220, "w"),
        ], height=len(FORMULAS))
        for formula in FORMULAS:
            tree_insert(table, (formula["id"], formula["name"], formula["expression"], formula["function"]))
        table.bind("<<TreeviewSelect>>", lambda _e: self._explain(table))
        self._explanation = Banner(formulas)
        self._explanation.pack(fill="x", pady=(10, 0))
        plan = _section(self.body, "Statistical analysis plan")
        text = text_box(plan, height=34)
        text.insert("1.0", STATISTICAL_PLAN)
        text.configure(state="disabled")
        text.pack(fill="x")
        self.finish_page()

    def _explain(self, table):
        selection = table.selection()
        if selection:
            formula_id = table.item(selection[0], "values")[0]
            formula = next(f for f in FORMULAS if f["id"] == formula_id)
            self._explanation.show("%s — %s" % (formula["name"], formula["symbols"]), "info")

    def _export(self):
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        path = RESULTS_DIR / "methodology.md"
        path.write_text(methodology_markdown(), encoding="utf-8")
        self._saved.set("Saved: %s" % path)


# ─────────────────────────────────────────────────────────────────────────────
# Application shell: sidebar + pages + theme
# ─────────────────────────────────────────────────────────────────────────────

# (group heading, pages)
NAVIGATION = (
    ("HASHING", (("hash", "#", "Hash Files", HashFilesTab),)),
    ("EVALUATION", (("technique", "⚡", "Technique Evaluation", TechniqueBenchmarkTab),
                    ("verify", "✓", "Correctness Verification", VerificationTab))),
    ("ABOUT", (("overview", "ⓘ", "Overview", OverviewTab),
               ("method", "ƒ", "Methodology", MethodologyTab))),
)

_REMAP_OPTIONS = (
    "background", "foreground", "activebackground", "activeforeground", "highlightbackground",
    "highlightcolor", "insertbackground", "selectbackground", "selectforeground", "selectcolor",
    "disabledforeground", "readonlybackground", "disabledbackground", "buttonbackground", "troughcolor",
)


def apply_styles(root: tk.Tk, style: ttk.Style) -> None:
    style.theme_use("clam")
    style.configure(".", background=P["bg"], foreground=P["text"], font=F["body"],
                    bordercolor=P["border"], lightcolor=P["surface"], darkcolor=P["surface"],
                    troughcolor=P["surface_alt"], focuscolor=P["accent"])
    style.configure("Treeview", background=P["surface"], fieldbackground=P["surface"],
                    foreground=P["text"], rowheight=30, borderwidth=0, font=F["small"])
    style.configure("Treeview.Heading", background=P["surface_alt"], foreground=P["muted"],
                    font=F["tiny"], relief="flat", padding=(10, 8), borderwidth=0)
    style.map("Treeview.Heading", background=[("active", P["hover"])])
    style.map("Treeview", background=[("selected", P["select_bg"])],
              foreground=[("selected", P["on_select"])])
    for orient in ("Vertical", "Horizontal"):
        style.configure("%s.TScrollbar" % orient, background=P["border"], troughcolor=P["surface"],
                        bordercolor=P["surface"], arrowcolor=P["muted"], lightcolor=P["border"],
                        darkcolor=P["border"], gripcount=0, arrowsize=12)
        style.map("%s.TScrollbar" % orient, background=[("active", P["border_strong"])])
    style.configure("B3.Horizontal.TProgressbar", troughcolor=P["surface_alt"], background=P["accent"],
                    bordercolor=P["surface_alt"], lightcolor=P["accent"], darkcolor=P["accent"], thickness=8)
    style.configure("TCombobox", fieldbackground=P["surface_alt"], background=P["surface_alt"],
                    foreground=P["text"], arrowcolor=P["muted"], bordercolor=P["border"],
                    selectbackground=P["surface_alt"], selectforeground=P["text"], padding=4)
    style.map("TCombobox", fieldbackground=[("readonly", P["surface_alt"])],
              foreground=[("readonly", P["text"])], background=[("readonly", P["surface_alt"])])
    root.option_add("*TCombobox*Listbox.background", P["surface"])
    root.option_add("*TCombobox*Listbox.foreground", P["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", P["select_bg"])
    root.option_add("*TCombobox*Listbox.selectForeground", P["on_select"])
    root.option_add("*Menu.background", P["surface"])
    root.option_add("*Menu.foreground", P["text"])


class Blake3App(tk.Tk):
    SIDEBAR_WIDTH = 236

    def __init__(self) -> None:
        super().__init__()
        self.settings = load_settings()
        self.theme = self.settings.get("theme", "light") if self.settings.get("theme") in THEMES else "light"
        self.worker_pool = None
        self._closing = False
        P.clear()
        P.update(THEMES[self.theme])
        self.title(TOOL_NAME)
        width = min(1360, self.winfo_screenwidth() - 60)
        height = min(920, self.winfo_screenheight() - 90)
        self.geometry("%dx%d" % (width, height))
        self.minsize(1080, 640)
        self.configure(bg=P["bg"])
        self.style = ttk.Style(self)
        apply_styles(self, self.style)
        self.status_var = tk.StringVar(value="Ready")
        self.pages: Dict[str, _Tab] = {}
        self.page_titles: Dict[str, str] = {}
        self._nav_items: Dict[str, Tuple[tk.Frame, tk.Frame, List[tk.Label]]] = {}
        self._current = ""
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self._build_sidebar()
        main = frame(self, bg="bg")
        main.grid(row=0, column=1, sticky="nsew")
        main.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        content = frame(main, bg="bg")
        content.grid(row=0, column=0, sticky="nsew")
        content.rowconfigure(0, weight=1)
        content.columnconfigure(0, weight=1)
        for _group, items in NAVIGATION:
            for key, _icon, title, cls in items:
                page = cls(content, self)
                page.grid(row=0, column=0, sticky="nsew")
                self.pages[key] = page
                self.page_titles[title] = key
        self._build_status(main)
        self.show("hash")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._start_worker_pool_async()

    # warm worker pool for small-file batching
    def _start_worker_pool_async(self):
        threading.Thread(target=self._start_worker_pool, daemon=True).start()

    def _start_worker_pool(self):
        try:
            pool, _startup = make_worker_pool()
        except Exception:
            return  # hashing still works; batching then uses a temporary pool
        if self._closing:
            pool.shutdown(wait=False, cancel_futures=True)
        else:
            self.worker_pool = pool

    def reset_worker_pool(self):
        old, self.worker_pool = self.worker_pool, None
        if old is not None:
            try:
                old.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
        self._start_worker_pool_async()

    def _on_close(self):
        self._closing = True
        if self.worker_pool is not None:
            try:
                self.worker_pool.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
        self.destroy()

    # sidebar
    def _build_sidebar(self):
        bar = tk.Frame(self, bg=P["sidebar"], width=self.SIDEBAR_WIDTH)
        bar.grid(row=0, column=0, sticky="ns")
        bar.grid_propagate(False)
        bar.pack_propagate(False)
        brand = tk.Frame(bar, bg=P["sidebar"])
        brand.pack(fill="x", padx=18, pady=(22, 18))
        tk.Label(brand, text="B3", bg=P["sidebar_accent"], fg=P["sidebar"], font=F["brand"], width=3,
                 pady=6).pack(side="left")
        names = tk.Frame(brand, bg=P["sidebar"])
        names.pack(side="left", padx=10)
        tk.Label(names, text=TOOL_SHORT_NAME, bg=P["sidebar"], fg=P["sidebar_title"],
                 font=F["brand"]).pack(anchor="w")
        tk.Label(names, text=TOOL_SUBTITLE, bg=P["sidebar"], fg=P["sidebar_muted"],
                 font=F["small"]).pack(anchor="w")
        self._nav_frame = tk.Frame(bar, bg=P["sidebar"])
        self._nav_frame.pack(fill="x")
        self._render_nav()
        footer = tk.Frame(bar, bg=P["sidebar"])
        footer.pack(side="bottom", fill="x", padx=14, pady=16)
        self._theme_btn = tk.Label(footer, text="", bg=P["sidebar_hover"], fg=P["sidebar_text"],
                                   font=F["small"], pady=7, cursor="hand2")
        self._theme_btn.pack(fill="x")
        self._theme_btn.bind("<Button-1>", lambda _e: self.toggle_theme())
        self._theme_btn.bind("<Enter>", lambda _e: self._theme_btn.configure(bg=P["sidebar_active"]))
        self._theme_btn.bind("<Leave>", lambda _e: self._theme_btn.configure(bg=P["sidebar_hover"]))
        self._update_theme_label()
        info = system_summary()
        tk.Label(footer, text="%s\n%d cores · %s GB RAM · %s\nblake3 %s" % (
            short_cpu_name(info["cpu_model"]), info["physical_cores"],
            info["memory_gib"] if info["memory_gib"] else "?", info["simd_tier"].split(" capable")[0],
            info["blake3_package_version"]), bg=P["sidebar"], fg=P["sidebar_muted"],
            font=F["small"], justify="left", anchor="w", wraplength=200).pack(fill="x", pady=(10, 0))

    def _render_nav(self):
        for child in self._nav_frame.winfo_children():
            child.destroy()
        self._nav_items = {}
        for group, items in NAVIGATION:
            tk.Label(self._nav_frame, text=group,
                     bg=P["sidebar"], fg=P["sidebar_muted"], font=F["tiny"],
                     anchor="w").pack(fill="x", padx=22, pady=(14, 4))
            for key, icon, title, _cls in items:
                self._nav_item(self._nav_frame, key, icon, title)
        if self._current in self._nav_items:
            self._paint_nav(self._current)

    def _nav_item(self, parent, key, icon, title):
        row = tk.Frame(parent, bg=P["sidebar"], cursor="hand2")
        row.pack(fill="x", padx=10, pady=1)
        indicator = tk.Frame(row, bg=P["sidebar"], width=3)
        indicator.pack(side="left", fill="y")
        icon_label = tk.Label(row, text=icon, bg=P["sidebar"], fg=P["sidebar_text"], font=F["nav_icon"],
                              width=3, pady=7)
        icon_label.pack(side="left", padx=(6, 0))
        text_label = tk.Label(row, text=title, bg=P["sidebar"], fg=P["sidebar_text"], font=F["nav"],
                              anchor="w")
        text_label.pack(side="left", fill="x", expand=True)
        labels = [icon_label, text_label]
        for widget in [row] + labels:
            widget.bind("<Button-1>", lambda _e, k=key: self.show(k))
            widget.bind("<Enter>", lambda _e, k=key: self._nav_hover(k, True))
            widget.bind("<Leave>", lambda _e, k=key: self._nav_hover(k, False))
        self._nav_items[key] = (row, indicator, labels)

    def _paint_nav(self, key):
        row, indicator, labels = self._nav_items[key]
        active = key == self._current
        background = P["sidebar_active"] if active else P["sidebar"]
        row.configure(bg=background)
        indicator.configure(bg=P["sidebar_accent"] if active else background)
        for widget in labels:
            widget.configure(bg=background, fg=P["sidebar_title"] if active else P["sidebar_text"])

    def _nav_hover(self, key, entering):
        if key == self._current:
            return
        row, indicator, labels = self._nav_items[key]
        background = P["sidebar_hover"] if entering else P["sidebar"]
        for widget in [row, indicator] + labels:
            widget.configure(bg=background)

    def show(self, key: str) -> None:
        previous, self._current = self._current, key
        self.pages[key].tkraise()
        for item in {previous, key} - {""}:
            if item in self._nav_items:
                self._paint_nav(item)

    def page(self, title: str) -> _Tab:
        return self.pages[self.page_titles[title]]

    # status bar
    def _build_status(self, parent):
        bar = tk.Frame(parent, bg=P["surface"], highlightbackground=P["border"], highlightthickness=1)
        bar.grid(row=1, column=0, sticky="ew")
        tk.Label(bar, textvariable=self.status_var, bg=P["surface"], fg=P["muted"], font=F["small"],
                 anchor="w").pack(side="left", padx=16, pady=5)
        link = tk.Label(bar, text="Results folder: %s" % RESULTS_DIR, bg=P["surface"], fg=P["accent"],
                        font=F["small"], cursor="hand2")
        link.pack(side="right", padx=16)
        link.bind("<Button-1>", lambda _e: open_folder(RESULTS_DIR))

    # theme
    def _update_theme_label(self):
        self._theme_btn.configure(text="☾   Dark mode" if self.theme == "light" else "☀   Light mode")

    def toggle_theme(self) -> None:
        old, new = self.theme, ("dark" if self.theme == "light" else "light")
        mapping = {THEMES[old][k].lower(): THEMES[new][k] for k in THEMES[old]}
        P.clear()
        P.update(THEMES[new])
        self.theme = new
        self._remap(self, mapping)
        apply_styles(self, self.style)
        for tree in list(_TREES):
            try:
                style_tree(tree)
            except tk.TclError:
                _TREES.remove(tree)
        for chart in list(_CHARTS):
            try:
                chart.redraw()
            except tk.TclError:
                _CHARTS.remove(chart)
        for key in self._nav_items:
            self._paint_nav(key)
        self._update_theme_label()
        self.settings["theme"] = new
        save_settings(self.settings)

    def _remap(self, widget, mapping):
        for option in _REMAP_OPTIONS:
            try:
                value = str(widget.cget(option)).lower()
            except (tk.TclError, ValueError):
                continue
            if value in mapping:
                try:
                    tk.Misc.configure(widget, {option: mapping[value]})
                except tk.TclError:
                    pass
        for child in widget.winfo_children():
            self._remap(child, mapping)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    Blake3App().mainloop()
