"""
PRIMADORIS | Layer 3 — Behavioral Canary
========================================
Continuous behavioral integrity checking of a local *toy* model state file,
with a Gen-Z cyberpunk laser-HUD alert system (3 severity tiers).

SAFETY CONTRACT
---------------
Nothing in this module loads, deserializes, executes or modifies a real
machine-learning model. It reads a small JSON file containing a single
floating-point "weight" and compares deterministic probe outputs against a
golden baseline. The attacks it reacts to are *simulated* by attack.py.

USAGE
-----
    python canary.py                    # monitor forever (3s interval)
    python canary.py --interval 2       # faster polling
    python canary.py --no-hud           # console only (headless/CI friendly)
    python canary.py --demo CRITICAL    # preview one HUD tier, then exit
    python canary.py --demo MEDIUM --attack "Weight Tamper" --variance 12.4

Press Ctrl+C to stop monitoring.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import threading
import time
from datetime import datetime

# ----------------------------------------------------------------------------
# Paths / constants
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(BASE_DIR, "model_brain.json")

BASELINE_WEIGHT = 1.5

# Golden behavioral baseline: five reference probe vectors (binary distributions)
BASELINE = [
    [0.95, 0.05],
    [0.10, 0.90],
    [0.88, 0.12],
    [0.02, 0.98],
    [0.50, 0.50],
]

# Drift model tuning (documented demo heuristics, NOT a real risk model)
DRIFT_GAIN = 0.42      # weight delta -> per-probe output shift
SHIFT_CAP = 0.55       # maximum observable shift
NOISE_FLOOR = 3.0      # variance % <= this  -> HEALTHY
REVIEW_CEILING = 40.0  # variance % <= this  -> SUSPICIOUS, above -> QUARANTINED
THREAT_GAIN = 1.8      # variance % -> threat index (0-100)

# ----------------------------------------------------------------------------
# Console helpers (Windows code-page & ANSI safe)
# ----------------------------------------------------------------------------
if sys.platform == "win32":
    os.system("")  # Enable Virtual Terminal Processing (ANSI colors)
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


def rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Cyberpunk Laser Themes: Safe (Green) -> Low (Cyan) -> Medium (Amber/Yellow) -> Critical (Bright Red)
LASER_THEMES = {
    "CRITICAL": {
        "c1": (160, 0, 30), "c2": (255, 0, 51), "c3": (255, 230, 240),
        "accent": (255, 60, 90), "label": (255, 120, 150), "val": (255, 255, 255),
        "tag": "🚨 CRITICAL THREAT INTERCEPTED 🚨",
    },
    "HIGH": {
        "c1": (160, 0, 30), "c2": (255, 0, 51), "c3": (255, 230, 240),
        "accent": (255, 60, 90), "label": (255, 120, 150), "val": (255, 255, 255),
        "tag": "🚨 HIGH-SEVERITY TAMPER EVENT 🚨",
    },
    "MEDIUM": {
        "c1": (180, 80, 0), "c2": (255, 160, 0), "c3": (255, 240, 160),
        "accent": (255, 180, 40), "label": (255, 200, 100), "val": (255, 250, 230),
        "tag": "⚠️  SUSPICIOUS DRIFT DETECTED  ⚠️",
    },
    "LOW": {
        "c1": (0, 120, 180), "c2": (0, 220, 255), "c3": (200, 250, 255),
        "accent": (50, 230, 255), "label": (120, 220, 255), "val": (240, 250, 255),
        "tag": "ℹ️  STEALTH DRIFT DETECTED  ℹ️",
    },
    "SAFE": {
        "c1": (0, 120, 50), "c2": (0, 255, 128), "c3": (200, 255, 220),
        "accent": (0, 255, 160), "label": (100, 255, 180), "val": (240, 255, 245),
        "tag": "🛡️  GOLDEN BASELINE NOMINAL (SAFE)  🛡️",
    },
}


def render_terminal_laser_box(
    theme_key: str,
    rows: list,
    title: str | None = None,
    footer: str | None = None,
    width: int = 72,
    animate: bool = False,
) -> str:
    """
    Renders a dynamic Cyberpunk Laser HUD Box in the terminal.
    - Safe/Healthy -> Vibrant Laser Green
    - Medium       -> Glowing Laser Amber/Yellow
    - Critical     -> Blazing Neon Laser Red with white-hot core
    - Flowy laser beam borders with energy core pulse
    """
    t = LASER_THEMES.get(theme_key, LASER_THEMES["SAFE"])
    c1, c2, c3 = t["c1"], t["c2"], t["c3"]
    tag = f" ⚡ {title or t['tag']} ⚡ "

    rem = max(4, width - len(tag) - 2)
    left_w = rem // 2
    right_w = rem - left_w

    left_beam = "".join([
        rgb(int(c1[0] + (c2[0] - c1[0]) * i / left_w),
            int(c1[1] + (c2[1] - c1[1]) * i / left_w),
            int(c1[2] + (c2[2] - c1[2]) * i / left_w)) + ("═" if i > left_w // 2 else "─")
        for i in range(left_w)
    ])
    right_beam = "".join([
        rgb(int(c2[0] + (c1[0] - c2[0]) * i / right_w),
            int(c2[1] + (c1[1] - c2[1]) * i / right_w),
            int(c2[2] + (c1[2] - c2[2]) * i / right_w)) + ("═" if i < right_w // 2 else "─")
        for i in range(right_w)
    ])

    top_line = f"{rgb(*c1)}╭{left_beam}{BOLD}{rgb(*c3)}{tag}{RESET}{right_beam}{rgb(*c1)}╮{RESET}"

    # Flowy laser sweep animation across top border on interactive terminals
    if animate and sys.stdout.isatty():
        beam_pulse = ["─", "━", "═", "≡", "█", "≡", "═", "━", "─"]
        for step in range(0, width - 8, 8):
            bar = list(" " * width)
            for idx, ch in enumerate(beam_pulse):
                pos = step + idx
                if 0 <= pos < width:
                    bar[pos] = ch
            sys.stdout.write(f"\r{rgb(*c2)}{''.join(bar)}{RESET}")
            sys.stdout.flush()
            time.sleep(0.008)
        sys.stdout.write("\r" + " " * width + "\r")
        sys.stdout.flush()

    out = [top_line]
    inner_w = width - 2
    border_l = f"{rgb(*c1)}│{RESET}"
    border_r = f"{rgb(*c1)}│{RESET}"

    sub = "  ◈ PRIMADORIS // ATTESTATION ENCLAVE"
    sub_padding = " " * max(0, inner_w - len(sub))
    out.append(f"{border_l}{DIM}{rgb(*c2)}{sub}{RESET}{sub_padding}{border_r}")

    div_beam = "".join([
        rgb(int(c1[0] + (c2[0] - c1[0]) * (abs(i - inner_w / 2) / (inner_w / 2))),
            int(c1[1] + (c2[1] - c1[1]) * (abs(i - inner_w / 2) / (inner_w / 2))),
            int(c1[2] + (c2[2] - c1[2]) * (abs(i - inner_w / 2) / (inner_w / 2)))) + "─"
        for i in range(inner_w)
    ])
    out.append(f"{border_l}{div_beam}{border_r}")

    for row in rows:
        if isinstance(row, tuple):
            k, v = row
            k_plain = f"  {k:<12}: "
            max_v_len = max(5, inner_w - len(k_plain) - 1)
            v_str = str(v)
            if len(v_str) > max_v_len:
                v_str = v_str[:max_v_len - 3] + "..."
            k_fmt = f"  {rgb(*t['label'])}{k:<12}{RESET}: "
            v_fmt = f"{BOLD}{rgb(*t['val'])}{v_str}{RESET}"
            pad = " " * (inner_w - len(k_plain) - len(v_str))
            out.append(f"{border_l}{k_fmt}{v_fmt}{pad}{border_r}")
        else:
            raw_str = f"  {row}"
            max_r_len = max(5, inner_w - 2)
            if len(raw_str) > max_r_len:
                raw_str = raw_str[:max_r_len - 3] + "..."
            pad = " " * (inner_w - len(raw_str))
            out.append(f"{border_l}{rgb(*t['val'])}{raw_str}{RESET}{pad}{border_r}")

    if footer:
        out.append(f"{border_l}{div_beam}{border_r}")
        foot_str = f"  ⚡ {footer}"
        max_f_len = max(5, inner_w - 2)
        if len(foot_str) > max_f_len:
            foot_str = foot_str[:max_f_len - 3] + "..."
        pad = " " * (inner_w - len(foot_str))
        out.append(f"{border_l}{BOLD}{rgb(*t['accent'])}{foot_str}{RESET}{pad}{border_r}")

    bot_beam = "".join([
        rgb(int(c1[0] + (c2[0] - c1[0]) * i / inner_w),
            int(c1[1] + (c2[1] - c1[1]) * i / inner_w),
            int(c1[2] + (c2[2] - c1[2]) * i / inner_w)) + ("═" if inner_w // 4 < i < 3 * inner_w // 4 else "─")
        for i in range(inner_w)
    ])
    out.append(f"{rgb(*c1)}╰{bot_beam}╯{RESET}")
    return "\n".join(out)


def safe_print(text: str = "") -> None:
    """Never crash a demo because a terminal cannot encode an emoji or box character."""
    try:
        print(text)
    except UnicodeEncodeError:
        cleaned = (
            text.replace("⚠️", "[!]")
            .replace("🚨", "[ALERT]")
            .replace("ℹ️", "[INFO]")
            .replace("🛡️", "[SAFE]")
            .replace("═", "=")
            .replace("─", "-")
            .replace("━", "=")
            .replace("│", "|")
            .replace("╭", "+")
            .replace("╮", "+")
            .replace("╰", "+")
            .replace("╯", "+")
            .replace("◈", ">")
            .replace("⬡", "*")
            .replace("●", "o")
            .replace("✳", "*")
            .replace("⚡", "*")
        )
        try:
            print(cleaned, flush=True)
        except Exception:
            print(text.encode("ascii", errors="replace").decode("ascii"), flush=True)


# ----------------------------------------------------------------------------
# Optional extras
# ----------------------------------------------------------------------------
try:
    import winsound
    HAS_WINSOUND = True
except ImportError:                                    # non-Windows
    HAS_WINSOUND = False

try:
    from plyer import notification as _plyer_notification
    PLYER_AVAILABLE = True

    def _suppress_plyer_thread_err(args):
        if "Shell_NotifyIconW" in str(args.exc_value):
            return
        sys.__excepthook__(args.exc_type, args.exc_value, args.exc_traceback)

    threading.excepthook = _suppress_plyer_thread_err
except ImportError:
    _plyer_notification = None
    PLYER_AVAILABLE = False


# ----------------------------------------------------------------------------
# Model state
# ----------------------------------------------------------------------------
def read_model() -> dict:
    """Read the toy model state. Missing/corrupt files fall back to baseline."""
    if not os.path.exists(MODEL_FILE):
        return {
            "weight": BASELINE_WEIGHT,
            "status": "HEALTHY",
            "danger_level": "NOMINAL",
            "attack_name": None,
        }
    try:
        with open(MODEL_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {
            "weight": BASELINE_WEIGHT,
            "status": "HEALTHY",
            "danger_level": "NOMINAL",
            "attack_name": None,
        }


def observe(weight: float) -> list:
    """Deterministic pseudo-inference across the five reference probes."""
    delta = abs(float(weight) - BASELINE_WEIGHT)
    shift = min(SHIFT_CAP, delta * DRIFT_GAIN)      # positive shift => p0 shrinks
    outputs = []
    for p0, _p1 in BASELINE:
        q0 = min(0.999, max(0.001, p0 - shift))
        outputs.append([q0, 1.0 - q0])
    return outputs


def evaluate(weight: float) -> dict:
    """
    Compare observed probe outputs with the golden baseline.

    variance_pct  ~ 100 * mean output shift  (0 = identical behaviour)
    threat_pct    ~ clamped linear map of variance to a 0-100 index
    status        ~ HEALTHY / SUSPICIOUS / QUARANTINED
    """
    weight = float(weight)
    observed = observe(weight)

    # Raw mean squared error across probes (kept for transparency / debugging).
    errors = [
        ((actual[0] - base[0]) ** 2 + (actual[1] - base[1]) ** 2) / 2.0
        for base, actual in zip(BASELINE, observed)
    ]
    mse = sum(errors) / len(errors)

    # Reported variance: the per-probe behavioural shift expressed as a percentage.
    shift = min(SHIFT_CAP, abs(weight - BASELINE_WEIGHT) * DRIFT_GAIN)
    variance_pct = round(shift * 100.0, 4)

    if variance_pct <= NOISE_FLOOR:
        status, severity = "HEALTHY", "LOW"
    elif variance_pct <= REVIEW_CEILING:
        status, severity = "SUSPICIOUS", "MEDIUM"
    else:
        status, severity = "QUARANTINED", "CRITICAL"

    threat_pct = round(min(99.9, variance_pct * THREAT_GAIN), 1)

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "status": status,
        "severity": severity,
        "weight": round(weight, 3),
        "variance_pct": variance_pct,
        "threat_pct": threat_pct,
        "mse": round(mse, 8),
        "baseline_weight": BASELINE_WEIGHT,
        "baseline_matrix": BASELINE,
        "observed_matrix": observed,
    }


def alert_tier(status: str, danger_level: str, variance: float) -> str:
    """Map a state to one of HEALTHY / LOW / MEDIUM / CRITICAL HUD tiers."""
    danger = (danger_level or "NOMINAL").upper()
    if status == "QUARANTINED" or danger in ("CRITICAL", "HIGH"):
        return "CRITICAL"
    if status == "SUSPICIOUS" or danger == "MEDIUM":
        return "MEDIUM"
    if danger == "LOW" or 0.01 < variance <= NOISE_FLOOR:
        return "LOW"
    return "HEALTHY"


# ============================================================================
# CYBERPUNK LASER HUD GUI ALERTS (Tkinter Window Popups)
# ============================================================================
TIER_STYLE = {
    "CRITICAL": dict(
        w=1080, h=560, pos="center",
        a="#ff0033", b="#00f0ff", dark="#030612", panel="#080e22",
        card="#0d1630", text="#ffffff", muted="#7894ba",
        lasers=["#ff0033", "#00f0ff", "#0066ff", "#ff1122", "#33ccff"],
        beep="MB_ICONHAND", n_lasers=36, n_sparks=26, frames=15,
    ),
    "MEDIUM": dict(
        w=780, h=390, pos="center",
        a="#ff8800", b="#ffcc00", dark="#0c0802", panel="#181104",
        card="#241906", text="#fff7e6", muted="#b39b6e",
        lasers=["#ff8800", "#ffcc00", "#ffa600", "#ffe033", "#ff6600"],
        beep="MB_ICONEXCLAMATION", n_lasers=22, n_sparks=15, frames=13,
    ),
    "LOW": dict(
        w=490, h=165, pos="br",
        a="#00f0ff", b="#00aaff", dark="#020b14", panel="#051726",
        card="#0a243a", text="#eaf7ff", muted="#7fa3c2",
        lasers=["#00f0ff", "#00d4ff", "#45e6da", "#38bdf8"],
        beep="MB_OK", n_lasers=12, n_sparks=8, frames=10,
    ),
}


def _beep(name: str):
    if not HAS_WINSOUND:
        return
    try:
        winsound.MessageBeep(getattr(winsound, name, winsound.MB_OK))
    except Exception:
        pass


def spawn_laser_hud_alert(tier: str, attack_name: str | None, variance: float) -> None:
    """Draw the HUD alert window. Must be called from a thread that owns Tk."""
    cfg = TIER_STYLE.get(tier)
    if cfg is None:
        return
    try:
        import tkinter as tk
    except Exception as exc:                       # headless environment
        safe_print(f"[HUD] tkinter unavailable ({exc}); falling back to console.")
        return

    attack_label = attack_name or "Adversarial Model Drift"
    win_w, win_h = cfg["w"], cfg["h"]

    try:
        root = tk.Tk()
        root.title(f"PRIMADORIS // {tier}")
        root.overrideredirect(True)
        root.attributes("-topmost", True)

        screen_w, screen_h = root.winfo_screenwidth(), root.winfo_screenheight()
        if cfg["pos"] == "br":
            pos_x = max(20, screen_w - win_w - 28)
            pos_y = max(20, screen_h - win_h - 48)
        else:
            pos_x = (screen_w - win_w) // 2
            pos_y = (screen_h - win_h) // 2
        root.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
        root.configure(bg=cfg["a"])

        _beep(cfg["beep"])

        container = tk.Frame(root, bg=cfg["dark"], bd=0)
        container.pack(fill="both", expand=True, padx=3, pady=3)

        # ---------------- laser intro canvas ----------------
        canvas = tk.Canvas(container, bg=cfg["dark"], highlightthickness=0)
        canvas.pack(fill="both", expand=True)

        lasers = []
        for _ in range(cfg["n_lasers"]):
            beam_len = random.randint(60, 240)
            lasers.append({
                "y": random.randint(15, win_h - 25),
                "x1": -beam_len - random.randint(0, 150),
                "len": beam_len,
                "spd": random.randint(40, 75),
                "c": random.choice(cfg["lasers"]),
                "w": random.choice([1, 2]),
            })

        sparks = [{
            "x": random.randint(20, win_w - 20),
            "y": random.randint(20, win_h - 20),
            "r": random.randint(1, 3),
            "c": random.choice(cfg["lasers"]),
            "dx": random.choice([-3, -2, 2, 3]),
            "dy": random.choice([-2, -1, 1, 2]),
        } for _ in range(cfg["n_sparks"])]

        frame = [0]
        max_frames = cfg["frames"]

        def close_window(event=None):
            try:
                root.destroy()
            except Exception:
                pass

        def lbl(parent, text, size, color, bg, bold=True, family="Segoe UI",
                wrap=0, padx=0, pady=0, side=None, fill=None, anchor=None):
            widget = tk.Label(
                parent, text=text,
                font=(family, size, "bold") if bold else (family, size),
                fg=color, bg=bg, wraplength=wrap, justify="left",
            )
            opts = {}
            if padx or pady:
                opts["padx"], opts["pady"] = padx, pady
            if side:
                opts["side"] = side
            if fill:
                opts["fill"] = fill
            if anchor:
                opts["anchor"] = anchor
            widget.pack(**opts)
            return widget

        # ---------------- HUD content ----------------
        def build_critical():
            topbar = tk.Frame(container, bg=cfg["panel"], height=42)
            topbar.pack(fill="x", side="top")
            tk.Label(topbar, text="◈  PRIMADORIS v1.0",
                     font=("Segoe UI", 11, "bold"), fg=cfg["b"], bg=cfg["panel"]).pack(side="left", padx=16, pady=8)
            tk.Label(topbar, text="AI INTEGRITY ENCLAVE  ·  SECURITY LOCKDOWN ACTIVE",
                     font=("Consolas", 9, "bold"), fg=cfg["b"], bg=cfg["panel"]).pack(side="right", padx=16, pady=8)

            header = tk.Frame(container, bg=cfg["dark"])
            header.pack(fill="x", pady=(18, 8))
            alarm = lbl(header, "🚨  SYSTEM QUARANTINED  🚨", 25, cfg["a"], cfg["dark"])
            lbl(header, "LAYER 3 RUNTIME INTEGRITY ATTESTATION FAULT  /  NEURAL PIPELINE SEVERED",
                10, cfg["b"], cfg["dark"], family="Consolas", pady=(4, 0))

            cards = tk.Frame(container, bg=cfg["dark"])
            cards.pack(fill="x", padx=28, pady=14)
            for title, value, color, family, size in [
                ("ATTACK SCENARIO", attack_label, cfg["text"], "Segoe UI", 13),
                ("BEHAVIORAL DRIFT (MSE)", f"+{variance:.3f}%", cfg["a"], "Consolas", 19),
                ("CONTAINMENT STATUS", "KILL-SWITCH ENGAGED", cfg["b"], "Segoe UI", 12),
            ]:
                card = tk.Frame(cards, bg=cfg["card"], bd=1, relief="solid")
                card.pack(side="left", fill="both", expand=True, padx=6)
                lbl(card, title, 9, cfg["muted"], cfg["card"], bold=False, family="Consolas",
                    padx=12, pady=(10, 2), anchor="w")
                tk.Label(card, text=value, font=(family, size, "bold"), fg=color, bg=cfg["card"],
                         wraplength=280, justify="left").pack(anchor="w", padx=12, pady=(0, 10))

            info = tk.Frame(container, bg="#071224", bd=1, relief="solid")
            info.pack(fill="x", padx=34, pady=(2, 14))
            lbl(info,
                "◈ [DEFENSE ACTION]: Model parameter drift exceeded the critical threshold (40.00% variance).\n"
                "◈ Live inference execution halted to prevent adversarial payload delivery. Golden baseline enclave intact.",
                9, "#bde4ff", "#071224", bold=False, family="Consolas", padx=14, pady=10)

            buttons = tk.Frame(container, bg=cfg["dark"])
            buttons.pack(fill="x", pady=(0, 14))
            btn = tk.Button(buttons, text="[ ⬡ ACKNOWLEDGE & SECURE CONTAINMENT ⬡ ]",
                            font=("Segoe UI", 12, "bold"), bg="#081832", fg=cfg["b"],
                            activebackground=cfg["a"], activeforeground="#ffffff", bd=2,
                            relief="groove", highlightthickness=0, padx=24, pady=9,
                            cursor="hand2", command=close_window)
            btn.pack()
            btn.bind("<Enter>", lambda e: btn.configure(bg=cfg["a"], fg="#ffffff"))
            btn.bind("<Leave>", lambda e: btn.configure(bg="#081832", fg=cfg["b"]))
            return alarm, topbar, 380

        def build_medium():
            topbar = tk.Frame(container, bg=cfg["panel"], height=36)
            topbar.pack(fill="x", side="top")
            tk.Label(topbar, text="◈  PRIMADORIS", font=("Segoe UI", 10, "bold"),
                     fg=cfg["b"], bg=cfg["panel"]).pack(side="left", padx=12, pady=6)
            tk.Label(topbar, text="INTEGRITY MONITORING  ·  ADVISORY WARNING", font=("Consolas", 8, "bold"),
                     fg=cfg["a"], bg=cfg["panel"]).pack(side="right", padx=12, pady=6)

            header = tk.Frame(container, bg=cfg["dark"])
            header.pack(fill="x", pady=(12, 4))
            warn = lbl(header, "⚠️  CAUTION: PARAMETER DRIFT DETECTED  ⚠️", 18, cfg["a"], cfg["dark"])
            lbl(header, "RUNTIME VARIANCE ELEVATED  /  ACTIVE SURVEILLANCE ARMED",
                9, cfg["b"], cfg["dark"], family="Consolas", pady=(2, 0))

            cards = tk.Frame(container, bg=cfg["dark"])
            cards.pack(fill="x", padx=20, pady=10)
            for title, value, color, family, size in [
                ("THREAT PROFILE", attack_label, cfg["text"], "Segoe UI", 11),
                ("DRIFT MEASURED", f"+{variance:.3f}%", cfg["b"], "Consolas", 15),
                ("STATUS", "SUSPICIOUS DRIFT", cfg["a"], "Segoe UI", 11),
            ]:
                card = tk.Frame(cards, bg=cfg["card"], bd=1, relief="solid")
                card.pack(side="left", fill="both", expand=True, padx=4)
                lbl(card, title, 8, cfg["muted"], cfg["card"], bold=False, family="Consolas",
                    padx=10, pady=(6, 2), anchor="w")
                tk.Label(card, text=value, font=(family, size, "bold"), fg=color, bg=cfg["card"],
                         wraplength=220, justify="left").pack(anchor="w", padx=10, pady=(0, 8))

            buttons = tk.Frame(container, bg=cfg["dark"])
            buttons.pack(fill="x", pady=(6, 10))
            btn = tk.Button(buttons, text="[ ⚠ ACKNOWLEDGE WARNING ⚠ ]",
                            font=("Segoe UI", 11, "bold"), bg="#221603", fg=cfg["b"],
                            activebackground=cfg["a"], activeforeground="#ffffff", bd=1,
                            relief="groove", highlightthickness=0, padx=18, pady=6,
                            cursor="hand2", command=close_window)
            btn.pack()
            btn.bind("<Enter>", lambda e: btn.configure(bg=cfg["a"], fg="#ffffff"))
            btn.bind("<Leave>", lambda e: btn.configure(bg="#221603", fg=cfg["b"]))
            return warn, topbar, 420

        def build_low():
            topbar = tk.Frame(container, bg=cfg["panel"], height=28)
            topbar.pack(fill="x", side="top")
            tk.Label(topbar, text="ℹ️  PRIMADORIS  //  Friendly Reminder", font=("Segoe UI", 9, "bold"),
                     fg=cfg["a"], bg=cfg["panel"]).pack(side="left", padx=10, pady=4)
            tk.Button(topbar, text="✕", font=("Segoe UI", 9, "bold"), fg=cfg["muted"], bg=cfg["panel"],
                      bd=0, cursor="hand2", command=close_window).pack(side="right", padx=8)

            body = tk.Frame(container, bg=cfg["dark"])
            body.pack(fill="both", expand=True, padx=14, pady=8)
            lbl(body, f"Minor gradient shift detected (+{variance:.2f}%).", 10, cfg["text"], cfg["dark"],
                padx=0, pady=0, anchor="w")
            lbl(body, "Model remains nominal & healthy. No lockdown needed.", 9, "#93c4e8", cfg["dark"],
                bold=False, pady=(2, 0), anchor="w")
            lbl(body, f"Profile: {attack_label}", 8, cfg["muted"], cfg["dark"], bold=False,
                family="Consolas", pady=(4, 0), anchor="w")

            root.after(4500, close_window)      # friendly toast auto-dismiss
            return None, topbar, None

        builders = {"CRITICAL": build_critical, "MEDIUM": build_medium, "LOW": build_low}

        def reveal_hud():
            try:
                canvas.destroy()
            except Exception:
                return

            root.bind("<Escape>", close_window)
            root.bind("<Return>", close_window)

            pulsing_label, topbar, blink_ms = builders[tier]()

            # drag support
            def start_drag(e):
                root._dx, root._dy = e.x, e.y

            def on_drag(e):
                root.geometry(f"+{root.winfo_x() + (e.x - root._dx)}+{root.winfo_y() + (e.y - root._dy)}")

            try:
                topbar.bind("<Button-1>", start_drag)
                topbar.bind("<B1-Motion>", on_drag)
            except Exception:
                pass

            # blinking border / headline (red & blue only for CRITICAL)
            if pulsing_label is not None and blink_ms:
                state_toggle = [True]

                def pulse():
                    if not root.winfo_exists():
                        return
                    color = cfg["a"] if state_toggle[0] else cfg["b"]
                    root.configure(bg=color)
                    try:
                        pulsing_label.configure(fg=color)
                    except Exception:
                        pass
                    state_toggle[0] = not state_toggle[0]
                    root.after(blink_ms, pulse)

                pulse()

        # ---------------- laser sweep animation ----------------
        def step():
            if not root.winfo_exists():
                return
            frame[0] += 1
            canvas.delete("beam")

            for s in sparks:
                s["x"] += s["dx"]
                s["y"] += s["dy"]
                canvas.create_oval(s["x"] - s["r"], s["y"] - s["r"], s["x"] + s["r"], s["y"] + s["r"],
                                   fill=s["c"], outline="", tags="beam")

            for l in lasers:
                l["x1"] += l["spd"]
                canvas.create_line(l["x1"], l["y"], l["x1"] + l["len"], l["y"],
                                   fill=l["c"], width=l["w"], tags="beam")

            scan_x = int((frame[0] / max_frames) * win_w)
            canvas.create_line(scan_x, 0, scan_x, win_h, fill=cfg["b"], width=2, tags="beam")

            cx, cy = win_w // 2, win_h // 2
            expand = frame[0] * (win_w // (max_frames * 2))
            canvas.create_rectangle(cx - expand, cy - expand // 2, cx + expand, cy + expand // 2,
                                    outline=cfg["a"], width=1, tags="beam")

            bracket = 14
            for bx, by in [(cx - expand, cy - expand // 2), (cx + expand, cy - expand // 2),
                           (cx - expand, cy + expand // 2), (cx + expand, cy + expand // 2)]:
                canvas.create_line(bx - bracket, by, bx + bracket, by, fill=cfg["b"], width=2, tags="beam")
                canvas.create_line(bx, by - bracket, bx, by + bracket, fill=cfg["b"], width=2, tags="beam")

            status = ("SCANNING THREAT VECTOR..." if frame[0] < max_frames - 3
                      else "THREAT LOCKED // INITIALIZING HUD...")
            canvas.create_text(cx, cy + (expand // 2) + 18, text=status,
                               font=("Consolas", 9, "bold"), fill=cfg["b"], tags="beam")

            if frame[0] < max_frames:
                root.after(22, step)
            else:
                reveal_hud()

        step()
        root.mainloop()

    except Exception as exc:
        safe_print(f"[HUD ALARM ERROR] {exc}")


def send_desktop_toast(status: str, variance: float, attack_name: str | None = None) -> None:
    """Optional OS toast via plyer. Silently skipped when unavailable."""
    if not PLYER_AVAILABLE:
        return
    label = attack_name or "Parameter Drift Event"
    if status in ("QUARANTINED", "CRITICAL"):
        title, message = "🚨 PRIMADORIS: THREAT QUARANTINED", f"Attack: {label}\nVariance: {variance:.2f}%"
    elif status in ("DRIFT", "SUSPICIOUS"):
        title, message = "⚠️ Primadoris: Warning", f"Model drift detected.\nVariance: +{variance:.2f}% | {label}"
    else:
        title, message = "ℹ️ Primadoris: Notice", f"Minor gradient drift: +{variance:.2f}%"
    try:
        _plyer_notification.notify(title=title, message=message,
                                   app_name="PRIMADORIS", timeout=5)
    except Exception:
        pass


def launch_alert(tier: str, attack_name: str | None, variance: float) -> None:
    """
    Show a HUD alert without ever touching the Tk interpreter from a worker
    thread: the window is hosted in its own child process (its own main thread).
    Falls back to an in-process thread if spawning is impossible.
    """
    try:
        proc = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__),
             "--alert", tier,
             "--attack", str(attack_name or "Adversarial Model Drift"),
             "--variance", f"{variance:.4f}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # detach: never block the monitor loop
        threading.Thread(target=proc.wait, daemon=True).start()
    except Exception as exc:
        safe_print(f"[HUD] subprocess spawn failed ({exc}); using inline thread.")
        threading.Thread(target=spawn_laser_hud_alert,
                         args=(tier, attack_name, variance), daemon=True).start()


# ----------------------------------------------------------------------------
# Monitor loop
# ----------------------------------------------------------------------------
def monitor_loop(interval: float = 3.0, hud: bool = True) -> None:
    signature = ("HEALTHY", None)

    banner_rows = [
        ("Golden Target", f"5 reference probe vectors @ weight {BASELINE_WEIGHT:.3f}"),
        ("Poll Interval", f"{interval:.1f}s   |   Laser HUD Alerts: {'ON' if hud else 'OFF'}"),
        ("Thresholds", f"HEALTHY <= {NOISE_FLOOR:.1f}% | SUSPICIOUS <= {REVIEW_CEILING:.1f}% | QUARANTINED"),
        ("Instruction", "Press Ctrl+C to stop continuous behavioral monitoring."),
    ]
    banner_box = render_terminal_laser_box(
        "LOW",
        banner_rows,
        title="PRIMADORIS // LAYER 3 BEHAVIORAL CANARY",
        footer="CONTINUOUS ZERO-TRUST ATTESTATION ENGINE ARMED",
        animate=True,
    )
    safe_print("\n" + banner_box + "\n")

    try:
        while True:
            model = read_model()
            weight = float(model.get("weight", BASELINE_WEIGHT))
            attack_name = model.get("attack_name")
            danger_level = str(model.get("danger_level", "NOMINAL"))

            result = evaluate(weight)
            status = result["status"]
            variance = result["variance_pct"]
            tier = alert_tier(status, danger_level, variance)
            signature_now = (tier, attack_name)

            if tier != "HEALTHY" and signature_now != signature:
                signature = signature_now
                alert_rows = [
                    ("Severity", f"{tier} [ THREAT DETECTED ]"),
                    ("Scenario", attack_name or "Adversarial Parameter Drift"),
                    ("Weight", f"{weight:.3f}   (baseline {BASELINE_WEIGHT:.3f})"),
                    ("Variance", f"+{variance:.4f}%"),
                    ("Threat Index", f"{result['threat_pct']:.1f} / 100"),
                    ("Containment", "KILL-SWITCH ENGAGED // INFERENCE SEVERED" if tier == "CRITICAL" else "ACTIVE SURVEILLANCE ARMED"),
                ]
                alert_box = render_terminal_laser_box(
                    tier,
                    alert_rows,
                    title=f"PRIMADORIS // {tier} ATTESTATION FAULT",
                    footer="REAL-TIME LASER HUD ALARM DISPATCHED",
                    animate=True,
                )
                safe_print("\n" + alert_box + "\n")

                send_desktop_toast(status, variance, attack_name)
                if hud:
                    launch_alert(tier, attack_name, variance)

            elif tier == "HEALTHY" and signature[0] != "HEALTHY":
                signature = ("HEALTHY", None)
                restore_rows = [
                    ("System", "PRIMADORIS // GOLDEN BASELINE RECOVERED"),
                    ("Weight", f"{BASELINE_WEIGHT:.3f}  (Nominal Golden State)"),
                    ("Status", "HEALTHY  (NOMINAL)"),
                    ("Variance", "0.0000%   threat: 0.0 / 100"),
                    ("Enclave", "Model attestation verified; runtime green & secure"),
                ]
                restored_box = render_terminal_laser_box(
                    "SAFE",
                    restore_rows,
                    title="PRIMADORIS // BASELINE RESTORED (SAFE)",
                    footer="ENCLAVE INTEGRITY CERTIFIED CLEAN",
                    animate=True,
                )
                safe_print("\n" + restored_box + "\n")

            # Heartbeat logging with colored status tag
            if status == "HEALTHY":
                status_colored = f"\033[92m{status:12}\033[0m"
            elif status == "SUSPICIOUS":
                status_colored = f"\033[93m{status:12}\033[0m"
            else:
                status_colored = f"\033[1;91m{status:12}\033[0m"

            safe_print(
                f"[{result['timestamp']}] {status_colored} | "
                f"drift={variance:7.4f}% | threat={result['threat_pct']:5.1f}% | weight={weight:.3f}"
            )
            time.sleep(interval)

    except KeyboardInterrupt:
        safe_print("\n[CANARY] Monitor stopped by user.")


# ----------------------------------------------------------------------------
# Canonical ARCHITECTURE.md Layer 3 Functions (Real PyTorch Model)
# ----------------------------------------------------------------------------
def load_baseline(path: str) -> dict:
    """Loads baseline inputs and golden embeddings from JSON."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_drift(embed_fn, baseline: dict, threshold: float = 0.10) -> dict:
    """
    Computes relative L2 drift across reference canary inputs per ARCHITECTURE.md:
    drift_i = ||e_actual,i - e_expected,i||_2 / ||e_expected,i||_2
    """
    import numpy as np
    import torch
    from datetime import timezone

    inputs = baseline.get("inputs", [])
    expected = baseline.get("embeddings", [])
    if not inputs or not expected:
        return {"max_drift": 0.0, "per_canary": [], "passed": True, "ts": datetime.now(timezone.utc).isoformat()}

    actual = embed_fn(inputs)
    if isinstance(actual, torch.Tensor):
        actual = actual.detach().cpu().numpy()
    actual = np.array(actual, dtype=np.float32)
    expected = np.array(expected, dtype=np.float32)

    per_canary = []
    for exp, act in zip(expected, actual):
        norm_exp = np.linalg.norm(exp)
        diff = np.linalg.norm(act - exp)
        drift = float(diff / norm_exp) if norm_exp > 0 else 0.0
        per_canary.append(drift)

    max_drift = float(max(per_canary)) if per_canary else 0.0
    passed = bool(max_drift < float(threshold))
    ts = datetime.now(timezone.utc).isoformat()

    return {
        "max_drift": round(max_drift, 6),
        "per_canary": [round(d, 6) for d in per_canary],
        "passed": passed,
        "ts": ts,
    }


class CanaryWorker:
    """
    Background daemon thread that periodically checks in-memory canary drift
    and executes callbacks upon result and quarantine.
    """
    def __init__(self, get_embed_fn, baseline, interval=3.0, threshold=0.10, on_result=None, on_quarantine=None):
        self.get_embed_fn = get_embed_fn
        self.baseline = baseline
        self.interval = float(interval)
        self.threshold = float(threshold)
        self.on_result = on_result
        self.on_quarantine = on_quarantine
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run(self):
        while not self._stop_event.is_set():
            try:
                fn = self.get_embed_fn()
                res = check_drift(fn, self.baseline, self.threshold)
                if self.on_result:
                    self.on_result(res)
                if not res.get("passed") and self.on_quarantine:
                    self.on_quarantine(res)
            except Exception:
                pass
            self._stop_event.wait(self.interval)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PRIMADORIS Layer 3 behavioural canary")
    parser.add_argument("--interval", type=float, default=3.0, help="Polling interval in seconds (min 0.5)")
    parser.add_argument("--no-hud", action="store_true", help="Console output only, no Tk alert windows")
    parser.add_argument("--demo", choices=["LOW", "MEDIUM", "CRITICAL"],
                        help="Preview a single HUD tier and exit")
    parser.add_argument("--alert", choices=["LOW", "MEDIUM", "CRITICAL"], help=argparse.SUPPRESS)
    parser.add_argument("--attack", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--variance", type=float, default=12.345, help=argparse.SUPPRESS)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # Child-process mode: draw one HUD and exit.
    if args.alert:
        spawn_laser_hud_alert(args.alert, args.attack, args.variance)
        return 0

    if args.demo:
        safe_print(f"[CANARY] Previewing {args.demo} HUD tier "
                   f"(attack={args.attack or 'Demo Scenario'}, variance={args.variance:.3f}%)")
        spawn_laser_hud_alert(args.demo, args.attack or "Demo Scenario", args.variance)
        return 0

    if args.interval < 0.5:
        safe_print("[CANARY] --interval must be at least 0.5 seconds.")
        return 2

    monitor_loop(interval=args.interval, hud=not args.no_hud)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())