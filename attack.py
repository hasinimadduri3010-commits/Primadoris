"""
PRIMADORIS — Attack Simulator
=============================================
Safe, local, *simulated* model-tampering driver with terminal laser HUD boxes.

What it does
------------
Writes one floating-point "weight" into model_brain.json (plus the derived
behavioural metrics). It never imports, deserializes, executes or modifies a
real machine-learning artefact. attack.py + canary.py + the dashboard are a
closed demonstration loop:

    attack.py  ->  model_brain.json  ->  canary.py / dashboard_server.py

USAGE
-----
    python attack.py                      # random severity once
    python attack.py --level HIGH         # specific severity
    python attack.py --reset              # restore golden baseline
    python attack.py --loop --interval 8  # continuous demo
    python attack.py --list               # show available profiles
    python attack.py --json --level LOW   # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime

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
            .replace("⚡", "*")
        )
        try:
            print(cleaned, flush=True)
        except Exception:
            print(text.encode("ascii", errors="replace").decode("ascii"), flush=True)


# ----------------------------------------------------------------------------
# Paths / Profiles
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(BASE_DIR, "model_brain.json")
BASELINE_WEIGHT = 1.5

# Simulated severity profiles: (display name, weight range)
PROFILES = {
    "LOW":      ("Stealth Gradient Drift",                (1.54, 1.61)),
    "MEDIUM":   ("Targeted Parameter Perturbation",       (1.68, 1.85)),
    "HIGH":     ("Simulated Memory Integrity Violation",  (2.20, 2.90)),
    "CRITICAL": ("Catastrophic Model Corruption",         (3.20, 4.80)),
}

# Re-use the canary's evaluation so every file agrees on the numbers.
try:
    from canary import evaluate as _evaluate
except Exception:                       # pragma: no cover - standalone fallback
    _evaluate = None


# ----------------------------------------------------------------------------
# State I/O
# ----------------------------------------------------------------------------
def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def baseline_state() -> dict:
    state = {
        "weight": BASELINE_WEIGHT,
        "status": "HEALTHY",
        "danger_level": "NOMINAL",
        "attack_name": None,
        "variance_pct": 0.0,
        "threat_pct": 0.0,
        "severity": "LOW",
        "last_check": _now(),
        "baseline_weight": BASELINE_WEIGHT,
    }
    if _evaluate is not None:
        metrics = _evaluate(BASELINE_WEIGHT)
        state.update({
            "variance_pct": metrics["variance_pct"],
            "threat_pct": metrics["threat_pct"],
            "severity": metrics["severity"],
            "mse": metrics["mse"],
            "baseline_matrix": metrics["baseline_matrix"],
            "observed_matrix": metrics["observed_matrix"],
            "timestamp": metrics["timestamp"],
        })
    return state


def read_state() -> dict:
    if not os.path.exists(MODEL_FILE):
        reset_baseline(quiet=True)
    try:
        with open(MODEL_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else baseline_state()
    except (OSError, json.JSONDecodeError):
        return baseline_state()


def write_state(state: dict) -> None:
    """Atomic write: never leave a half-written model file behind."""
    tmp = MODEL_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, MODEL_FILE)


# ----------------------------------------------------------------------------
# Actions
# ----------------------------------------------------------------------------
def reset_baseline(quiet: bool = False) -> dict:
    state = baseline_state()
    write_state(state)
    if not quiet:
        reset_rows = [
            ("System", "PRIMADORIS // BASELINE RESTORED"),
            ("Weight", f"{BASELINE_WEIGHT:.3f}  (golden target)"),
            ("Status", f"{state['status']}  ({state['danger_level']})"),
            ("Variance", f"{state['variance_pct']:.4f}%   threat: {state['threat_pct']:.1f}/100"),
            ("Enclave", "Golden baseline enclave restored; canary should reset"),
        ]
        box = render_terminal_laser_box(
            "SAFE",
            reset_rows,
            title="PRIMADORIS // BASELINE RESTORED (SAFE)",
            footer="MODEL INTEGRITY ATTESTATION CLEAN & HEALTHY",
            animate=True,
        )
        safe_print("\n" + box + "\n")
    return state


def launch_attack(level: str | None = None, quiet: bool = False) -> dict:
    level = (level or random.choice(list(PROFILES))).upper()
    if level not in PROFILES:
        raise ValueError(f"Unknown level: {level}")

    name, (low, high) = PROFILES[level]
    weight = round(random.uniform(low, high), 3)

    state = read_state()
    state.update({
        "weight": weight,
        "status": "TAMPERED",
        "danger_level": level,
        "attack_name": name,
        "last_check": _now(),
        "baseline_weight": BASELINE_WEIGHT,
    })

    if _evaluate is not None:
        metrics = _evaluate(weight)
        state.update({
            "variance_pct": metrics["variance_pct"],
            "threat_pct": metrics["threat_pct"],
            "severity": metrics["severity"],
            "mse": metrics["mse"],
            "baseline_matrix": metrics["baseline_matrix"],
            "observed_matrix": metrics["observed_matrix"],
            "timestamp": metrics["timestamp"],
        })

    write_state(state)

    if not quiet:
        # Theme: Critical/High = Bright Red, Medium = Amber/Yellow, Low = Cyan
        theme = "CRITICAL" if level in ("CRITICAL", "HIGH") else level
        attack_rows = [
            ("Severity", f"{level} [ SIMULATION ACTIVE ]"),
            ("Scenario", name),
            ("Weight", f"{weight:.3f}   (baseline {BASELINE_WEIGHT:.3f})"),
        ]
        if _evaluate is not None:
            attack_rows.append(("Variance", f"{state['variance_pct']:.4f}%   threat: {state['threat_pct']:.1f}/100"))
            attack_rows.append(("Detected", state["status"]))
        attack_rows.append(("Target", "Local demonstration model state only"))
        attack_rows.append(("Canary", "State changed; behavioral canary should now fire HUD alert"))

        box = render_terminal_laser_box(
            theme,
            attack_rows,
            title=f"PRIMADORIS // {level} ATTACK SIMULATION",
            footer="ADVERSARIAL WEIGHT DRIFT INJECTED",
            animate=True,
        )
        safe_print("\n" + box + "\n")

    return state


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PRIMADORIS local attack simulator (safe demo only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python attack.py --reset\n"
               "  python attack.py --level CRITICAL\n"
               "  python attack.py --loop --interval 8\n",
    )
    parser.add_argument("--level", choices=list(PROFILES), help="Simulation severity")
    parser.add_argument("--reset", action="store_true", help="Restore the clean baseline")
    parser.add_argument("--loop", "--continuous", dest="loop", action="store_true",
                        help="Repeat simulated attacks until Ctrl+C")
    parser.add_argument("--interval", type=float, default=8.0,
                        help="Seconds between attacks in loop mode (min 1)")
    parser.add_argument("--list", action="store_true", help="List available profiles and exit")
    parser.add_argument("--json", action="store_true", help="Print the resulting state as JSON")
    parser.add_argument("--quiet", action="store_true", help="Suppress the banner text")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list:
        safe_print("Available simulation profiles:")
        for level, (name, (low, high)) in PROFILES.items():
            safe_print(f"  {level:9} {name:38} weight {low:.2f} – {high:.2f}")
        return 0

    if args.reset:
        state = reset_baseline(quiet=args.quiet)
        if args.json:
            print(json.dumps(state, indent=2))
        return 0

    if args.interval < 1:
        print("[ERROR] --interval must be at least 1 second.", file=sys.stderr)
        return 2

    try:
        while True:
            state = launch_attack(args.level, quiet=args.quiet)
            if args.json:
                print(json.dumps(state, indent=2))
            if not args.loop:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[PRIMADORIS] Simulation stopped.")
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())