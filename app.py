"""SentinelEdge AI - Zero-Trust Command Center (Streamlit Dashboard).

Communicates with the Edge and Cloud backends exclusively via ``api_client``.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import pickletools
import tempfile
import zipfile
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
import streamlit as st

import api_client
import config

# ---------------------------------------------------------------------------
# Page Configuration & Styling
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SentinelEdge AI - Zero-Trust Command Center",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .status-banner {
        padding: 18px 24px;
        border-radius: 10px;
        font-size: 1.5rem;
        font-weight: 800;
        text-align: center;
        letter-spacing: 0.04em;
        margin-bottom: 16px;
        border: 2px solid rgba(255, 255, 255, 0.18);
    }
    .banner-green {
        background: linear-gradient(90deg, #0f5132 0%, #198754 100%);
        color: #ffffff;
    }
    .banner-yellow {
        background: linear-gradient(90deg, #664d03 0%, #ffc107 100%);
        color: #111111;
    }
    .banner-red {
        background: linear-gradient(90deg, #58151c 0%, #dc3545 100%);
        color: #ffffff;
    }
    .layer-card {
        padding: 14px 16px;
        border-radius: 8px;
        margin-bottom: 12px;
        border-left: 6px solid;
        background-color: rgba(128, 128, 128, 0.08);
    }
    .card-green {
        border-left-color: #198754;
    }
    .card-yellow {
        border-left-color: #ffc107;
    }
    .card-red {
        border-left-color: #dc3545;
    }
    .card-title {
        font-size: 0.95rem;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .card-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
        margin-left: 6px;
    }
    .badge-green { background-color: #198754; color: #ffffff; }
    .badge-yellow { background-color: #ffc107; color: #111111; }
    .badge-red { background-color: #dc3545; color: #ffffff; }
    .card-detail {
        font-size: 0.85rem;
        opacity: 0.9;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    .verdict-box {
        padding: 16px 20px;
        border-radius: 8px;
        font-size: 1.35rem;
        font-weight: 800;
        text-align: center;
        margin: 10px 0;
    }
    .blocked-box {
        padding: 14px 20px;
        border-radius: 8px;
        background-color: #dc3545;
        color: #ffffff;
        font-size: 1.3rem;
        font-weight: 900;
        text-align: center;
        letter-spacing: 0.06em;
        margin: 10px 0;
        border: 2px solid #ff8787;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------

if "l1_last_verdict" not in st.session_state:
    st.session_state["l1_last_verdict"] = "SAFE"
if "l1_last_filename" not in st.session_state:
    st.session_state["l1_last_filename"] = "edge_extractor.pt (provisioned)"
if "l1_last_scan_result" not in st.session_state:
    st.session_state["l1_last_scan_result"] = None
if "l1_last_scanned_hash" not in st.session_state:
    st.session_state["l1_last_scanned_hash"] = None
if "l4_last_result" not in st.session_state:
    st.session_state["l4_last_result"] = None


# ---------------------------------------------------------------------------
# Demo Samples Loader (for Layer 4: Split Inference)
# ---------------------------------------------------------------------------

DEFAULT_DEMO_SAMPLES: List[Dict[str, Any]] = [
    {
        "sample_index": 0,
        "name": "Sample #0 - Normal Telemetry (Turbine Vibration)",
        "true_label": "NORMAL",
        "features": [0.12, -0.04, 0.31, 0.08, -0.11, 0.25, 0.03, -0.07],
    },
    {
        "sample_index": 1,
        "name": "Sample #1 - Anomaly Probe (Bearing Overheat)",
        "true_label": "ANOMALY",
        "features": [1.85, 2.10, -1.42, 1.77, 2.31, -0.95, 1.64, 2.02],
    },
    {
        "sample_index": 2,
        "name": "Sample #2 - Normal Telemetry (Steady Pressure)",
        "true_label": "NORMAL",
        "features": [0.05, 0.09, -0.02, 0.14, -0.06, 0.11, 0.04, 0.01],
    },
    {
        "sample_index": 3,
        "name": "Sample #3 - Anomaly Probe (Voltage Spike)",
        "true_label": "ANOMALY",
        "features": [-2.04, 1.92, 2.45, -1.68, 1.55, 2.12, -1.89, 1.74],
    },
]


def load_demo_samples() -> List[Dict[str, Any]]:
    """Load demo samples from config.DEMO_SAMPLES_PATH if available, else defaults."""
    try:
        if config.DEMO_SAMPLES_PATH.exists():
            raw = json.loads(config.DEMO_SAMPLES_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, list) and raw:
                samples: List[Dict[str, Any]] = []
                for idx, item in enumerate(raw):
                    if isinstance(item, dict):
                        samples.append(
                            {
                                "sample_index": item.get("sample_index", idx),
                                "name": item.get("name", f"Sample #{idx}"),
                                "true_label": str(item.get("true_label", item.get("label", "NORMAL"))),
                                "features": item.get("features", item.get("input", [0.1, 0.2, 0.3, 0.4])),
                            }
                        )
                if samples:
                    return samples
    except Exception:
        pass
    return DEFAULT_DEMO_SAMPLES


# ---------------------------------------------------------------------------
# Telemetry & Card Derivation Helpers
# ---------------------------------------------------------------------------

def fetch_live_snapshot() -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """Fetch edge status, cloud nodes, and recent events via api_client."""
    edge_status = api_client.get_edge_status()
    nodes_resp = api_client.get_nodes()
    events_resp = api_client.get_events(limit=50)
    return edge_status, nodes_resp, events_resp


def derive_banner_and_cards(
    edge_status: Dict[str, Any],
    nodes_resp: Dict[str, Any],
) -> Tuple[str, str, List[Dict[str, str]]]:
    """Derive the top banner state and the 4 layer status cards."""
    edge_err = edge_status.get("error") if isinstance(edge_status, dict) else "Invalid edge response"
    cloud_err = nodes_resp.get("error") if isinstance(nodes_resp, dict) else "Invalid cloud response"

    edge_state = str(edge_status.get("state", "UNKNOWN")).upper() if not edge_err else "UNREACHABLE"
    hash_match = bool(edge_status.get("hash_match", True)) if not edge_err else False
    file_tampered = bool(edge_status.get("file_tampered", False)) if not edge_err else False

    drift_history = edge_status.get("drift_history", []) if isinstance(edge_status, dict) else []
    current_drift = float(edge_status.get("drift", edge_status.get("current_drift", 0.0)) or 0.0) if not edge_err else 0.0
    max_drift = max([float(x) for x in drift_history] + [current_drift]) if drift_history else current_drift
    threshold = float(edge_status.get("drift_threshold", config.CANARY_DRIFT_THRESHOLD) or config.CANARY_DRIFT_THRESHOLD)

    # Cloud node status lookup
    cloud_node_state = "UNREACHABLE"
    if not cloud_err and isinstance(nodes_resp, dict):
        nodes_list = nodes_resp.get("nodes", [])
        if isinstance(nodes_list, list) and nodes_list:
            matched = next(
                (n for n in nodes_list if isinstance(n, dict) and n.get("device_id") == config.DEVICE_ID),
                nodes_list[0] if isinstance(nodes_list[0], dict) else {},
            )
            cloud_node_state = str(matched.get("state", edge_state)).upper()
        else:
            cloud_node_state = edge_state

    # Layer 1: Bytecode Scanner card
    l1_verdict = str(st.session_state.get("l1_last_verdict", "SAFE")).upper()
    l1_file = str(st.session_state.get("l1_last_filename", "edge_extractor.pt"))
    if l1_verdict == "SAFE":
        l1_color = "green"
    elif l1_verdict in ("WARNING", "SUSPICIOUS", "UNKNOWN", "PLACEHOLDER"):
        l1_color = "yellow"
    else:
        l1_color = "red"
    l1_detail = f"Last scan verdict: {l1_verdict} ({l1_file})"

    # Layer 2: Attestation card
    if edge_err or edge_state in ("QUARANTINED", "LOCKED_DOWN", "COMPROMISED"):
        l2_color = "red"
    elif not hash_match or file_tampered or edge_state != "RUNNING" or cloud_node_state != "RUNNING":
        l2_color = "yellow"
    else:
        l2_color = "green"
    l2_detail = f"Edge: {edge_state} | Cloud Node: {cloud_node_state}"

    # Layer 3: Canary Probing card
    if edge_err or current_drift >= threshold or edge_state == "QUARANTINED":
        l3_color = "red"
    elif current_drift >= threshold * 0.70 or max_drift >= threshold:
        l3_color = "yellow"
    else:
        l3_color = "green"
    l3_detail = f"Max Drift: {max_drift:.3f} (Curr: {current_drift:.3f}) vs Threshold: {threshold:.2f}"

    # Layer 4: Split Inference card
    cloud_reachable = cloud_err is None
    token_valid = bool(edge_status.get("token_valid", edge_state == "RUNNING")) if not edge_err else False
    inference_allowed = cloud_reachable and (edge_state == "RUNNING") and token_valid
    if not cloud_reachable or not inference_allowed:
        l4_color = "red" if (edge_state in ("QUARANTINED", "LOCKED_DOWN") or not cloud_reachable) else "yellow"
    else:
        l4_color = "green"
    l4_detail = (
        f"Cloud: {'Reachable' if cloud_reachable else 'Offline'} | "
        f"Inference: {'ALLOWED' if inference_allowed else f'BLOCKED ({edge_state})'}"
    )

    # Overall Banner derived from Edge state & layer trust
    if edge_state in ("QUARANTINED", "LOCKED_DOWN"):
        banner_color = "red"
        banner_text = f"🚨 NODE QUARANTINED / LOCKED DOWN — Edge State: {edge_state}"
    elif (
        edge_err
        or cloud_err
        or l1_color == "red"
        or file_tampered
        or not hash_match
        or current_drift >= threshold * 0.70
        or edge_state != "RUNNING"
    ):
        banner_color = "yellow"
        banner_text = f"⚠️ DEGRADED — Edge State: {edge_state}"
    else:
        banner_color = "green"
        banner_text = "✅ ALL LAYERS TRUSTED — Edge State: RUNNING"

    cards = [
        {
            "title": "Layer 1: Bytecode Scanner",
            "badge": l1_verdict,
            "color": l1_color,
            "detail": l1_detail,
        },
        {
            "title": "Layer 2: Attestation",
            "badge": edge_state,
            "color": l2_color,
            "detail": l2_detail,
        },
        {
            "title": "Layer 3: Canary Probing",
            "badge": "DRIFT ALERT" if l3_color == "red" else ("ELEVATED" if l3_color == "yellow" else "NOMINAL"),
            "color": l3_color,
            "detail": l3_detail,
        },
        {
            "title": "Layer 4: Split Inference",
            "badge": "ALLOWED" if inference_allowed else "BLOCKED",
            "color": l4_color,
            "detail": l4_detail,
        },
    ]
    return banner_color, banner_text, cards


def render_banner_and_cards(
    banner_color: str,
    banner_text: str,
    cards: List[Dict[str, str]],
) -> None:
    """Render the top status banner and the 4 layer status cards."""
    st.markdown(
        f'<div class="status-banner banner-{banner_color}">{banner_text}</div>',
        unsafe_allow_html=True,
    )
    cols = st.columns(4)
    for col, card in zip(cols, cards):
        color = card["color"]
        with col:
            st.markdown(
                f"""
                <div class="layer-card card-{color}">
                    <div class="card-title">
                        {card["title"]}
                        <span class="card-badge badge-{color}">{card["badge"]}</span>
                    </div>
                    <div class="card-detail" title="{card["detail"]}">{card["detail"]}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_drift_chart_and_events(
    edge_status: Dict[str, Any],
    events_resp: Dict[str, Any],
) -> None:
    """Render the Canary Drift chart with 10% threshold line and colored event log table."""
    left_col, right_col = st.columns([1, 1])

    with left_col:
        st.subheader("📈 Layer 3: Real-Time Canary Drift vs 10% Threshold")
        drift_history = edge_status.get("drift_history", []) if isinstance(edge_status, dict) else []
        if not drift_history:
            drift_history = [0.01]
        threshold = float(
            edge_status.get("drift_threshold", config.CANARY_DRIFT_THRESHOLD)
            if isinstance(edge_status, dict)
            else config.CANARY_DRIFT_THRESHOLD
        )

        df_drift = pd.DataFrame(
            {
                "Probe Tick": list(range(1, len(drift_history) + 1)),
                "Canary Drift": [float(v) for v in drift_history],
                "10% Quarantine Threshold": [threshold] * len(drift_history),
            }
        )

        try:
            import altair as alt

            df_long = df_drift.melt(
                id_vars=["Probe Tick"],
                value_vars=["Canary Drift", "10% Quarantine Threshold"],
                var_name="Series",
                value_name="Relative Drift",
            )
            color_scale = alt.Scale(
                domain=["Canary Drift", "10% Quarantine Threshold"],
                range=["#00b4d8", "#dc3545"],
            )
            chart = (
                alt.Chart(df_long)
                .mark_line(point=True, strokeWidth=2.5)
                .encode(
                    x=alt.X("Probe Tick:Q", title="Canary Probe Window"),
                    y=alt.Y(
                        "Relative Drift:Q",
                        title="Relative Embedding Drift",
                        scale=alt.Scale(domain=[0, max(0.25, float(df_drift["Canary Drift"].max()) * 1.15)]),
                    ),
                    color=alt.Color("Series:N", scale=color_scale, legend=alt.Legend(orient="top")),
                    strokeDash=alt.condition(
                        alt.datum.Series == "10% Quarantine Threshold",
                        alt.value([6, 4]),
                        alt.value([1, 0]),
                    ),
                    tooltip=["Probe Tick", "Series", alt.Tooltip("Relative Drift:Q", format=".4f")],
                )
                .properties(height=340)
            )
            st.altair_chart(chart, use_container_width=True)
        except Exception:
            st.line_chart(
                df_drift.set_index("Probe Tick")[["Canary Drift", "10% Quarantine Threshold"]],
                height=340,
            )

    with right_col:
        st.subheader("🛡️ Zero-Trust Security Event Log")
        events_list = events_resp.get("events", []) if isinstance(events_resp, dict) else []
        if not events_list:
            st.info("No security events recorded yet.")
            return

        df_events = pd.DataFrame(events_list)
        preferred_cols = [c for c in ["timestamp", "level", "layer", "source", "message"] if c in df_events.columns]
        if preferred_cols:
            df_events = df_events[preferred_cols]

        def _style_event_row(row: pd.Series) -> List[str]:
            lvl = str(row.get("level", "INFO")).upper()
            if lvl in ("CRITICAL", "ERROR"):
                bg = "background-color: rgba(220, 53, 69, 0.25); color: #ff8787; font-weight: 600;"
            elif lvl in ("WARNING", "WARN"):
                bg = "background-color: rgba(255, 193, 7, 0.22); color: #ffd43b; font-weight: 600;"
            else:
                bg = "background-color: rgba(25, 135, 84, 0.16); color: #69db7c;"
            return [bg] * len(row)

        styled_events = df_events.style.apply(_style_event_row, axis=1)
        st.dataframe(styled_events, use_container_width=True, height=340, hide_index=True)


# ---------------------------------------------------------------------------
# Layer 1: Bytecode Scanner Helpers & Fallback Inspector
# ---------------------------------------------------------------------------

DANGEROUS_GLOBALS = {
    "os",
    "posix",
    "nt",
    "subprocess",
    "sys",
    "builtins",
    "__builtin__",
    "eval",
    "exec",
    "compile",
    "open",
    "socket",
    "shutil",
    "commands",
    "pty",
    "importlib",
}


def _fallback_inspect_pickle_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Inspect pickle/PyTorch archive streams using stdlib pickletools when scanner.py is absent."""
    streams: List[Tuple[str, bytes]] = []
    if zipfile.is_zipfile(io.BytesIO(raw_bytes)):
        with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
            for name in zf.namelist():
                if name.endswith(".pkl") or "data.pkl" in name:
                    streams.append((name, zf.read(name)))
    else:
        streams.append(("root_stream", raw_bytes))

    opcodes_rows: List[Dict[str, Any]] = []
    findings_rows: List[Dict[str, Any]] = []

    for stream_name, data in streams:
        try:
            for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
                op_name = opcode.name
                arg_str = repr(arg) if arg is not None else ""
                offset_val = int(pos) if pos is not None else 0
                flagged = False
                reason = ""
                severity = "INFO"

                if op_name in ("GLOBAL", "STACK_GLOBAL"):
                    target_lower = arg_str.lower()
                    if any(tok in target_lower for tok in DANGEROUS_GLOBALS):
                        flagged = True
                        severity = "CRITICAL"
                        reason = f"Dangerous global reference in {op_name}: {arg_str}"
                    elif "torch" not in target_lower and "collections" not in target_lower and arg_str:
                        flagged = True
                        severity = "WARNING"
                        reason = f"Non-standard global import in {op_name}: {arg_str}"
                elif op_name in ("REDUCE", "BUILD", "INST", "OBJ", "NEWOBJ_EX"):
                    if opcodes_rows and opcodes_rows[-1].get("flagged"):
                        flagged = True
                        severity = "CRITICAL"
                        reason = f"Callable execution opcode {op_name} immediately following flagged global"

                opcodes_rows.append(
                    {
                        "byte_offset": f"0x{offset_val:04X} ({offset_val})",
                        "stream": stream_name,
                        "opcode": op_name,
                        "argument": arg_str[:100],
                        "flagged": flagged,
                    }
                )
                if flagged:
                    findings_rows.append(
                        {
                            "byte_offset": f"0x{offset_val:04X} ({offset_val})",
                            "opcode": op_name,
                            "severity": severity,
                            "argument": arg_str[:100],
                            "description": reason,
                        }
                    )
        except Exception as exc:
            findings_rows.append(
                {
                    "byte_offset": "0x0000 (0)",
                    "opcode": "PARSE_ERROR",
                    "severity": "WARNING",
                    "argument": stream_name,
                    "description": f"Could not disassemble pickle opcodes: {exc}",
                }
            )

    has_critical = any(f.get("severity") == "CRITICAL" for f in findings_rows)
    has_warning = any(f.get("severity") == "WARNING" for f in findings_rows)
    verdict = "MALICIOUS" if has_critical else ("SUSPICIOUS" if has_warning else "SAFE")
    return {
        "verdict": verdict,
        "findings": findings_rows,
        "opcodes": opcodes_rows,
        "used_placeholder": True,
    }


def run_layer1_scan(temp_path: str, raw_bytes: bytes) -> Dict[str, Any]:
    """Call scanner.scan_file(temp_path) if scanner module exists; otherwise show placeholder & fallback."""
    scanner_mod = None
    try:
        import scanner as scanner_mod  # type: ignore
    except Exception:
        scanner_mod = None

    if scanner_mod is not None and hasattr(scanner_mod, "scan_file"):
        try:
            raw_res = scanner_mod.scan_file(temp_path)
            if isinstance(raw_res, dict):
                verdict = str(
                    raw_res.get("verdict")
                    or raw_res.get("status")
                    or ("SAFE" if raw_res.get("safe", True) else "MALICIOUS")
                ).upper()

                raw_findings = (
                    raw_res.get("findings")
                    or raw_res.get("issues")
                    or raw_res.get("threats")
                    or []
                )
                findings: List[Dict[str, Any]] = []
                for f in raw_findings:
                    if isinstance(f, dict):
                        off = f.get("byte_offset", f.get("offset", f.get("pos", 0)))
                        findings.append(
                            {
                                "byte_offset": f"0x{off:04X} ({off})" if isinstance(off, int) else str(off),
                                "opcode": str(f.get("opcode", f.get("op", "GLOBAL"))),
                                "severity": str(f.get("severity", f.get("level", "CRITICAL"))).upper(),
                                "argument": str(f.get("argument", f.get("arg", f.get("symbol", "")))),
                                "description": str(
                                    f.get("description", f.get("reason", f.get("message", "Flagged instruction")))
                                ),
                            }
                        )

                raw_ops = (
                    raw_res.get("opcodes")
                    or raw_res.get("opcode_preview")
                    or raw_res.get("instructions")
                    or []
                )
                opcodes: List[Dict[str, Any]] = []
                for op in raw_ops:
                    if isinstance(op, dict):
                        off = op.get("byte_offset", op.get("offset", op.get("pos", 0)))
                        opcodes.append(
                            {
                                "byte_offset": f"0x{off:04X} ({off})" if isinstance(off, int) else str(off),
                                "opcode": str(op.get("opcode", op.get("op", op.get("name", "")))),
                                "argument": str(op.get("argument", op.get("arg", ""))),
                                "flagged": bool(
                                    op.get("flagged", op.get("suspicious", op.get("is_dangerous", False)))
                                ),
                            }
                        )

                if not opcodes:
                    fallback = _fallback_inspect_pickle_bytes(raw_bytes)
                    opcodes = fallback["opcodes"]

                return {
                    "verdict": verdict,
                    "findings": findings,
                    "opcodes": opcodes,
                    "used_placeholder": False,
                }
        except Exception as exc:
            fallback = _fallback_inspect_pickle_bytes(raw_bytes)
            fallback["scanner_error"] = str(exc)
            return fallback

    return _fallback_inspect_pickle_bytes(raw_bytes)


# ---------------------------------------------------------------------------
# Header & Sidebar
# ---------------------------------------------------------------------------

st.title("🛡️ SentinelEdge AI - Zero-Trust Command Center")

with st.sidebar:
    st.header("⚙️ Telemetry & Backend Mode")
    mock_mode = st.toggle("Use In-Memory Mock Simulation", value=bool(api_client.USE_MOCK))
    api_client.USE_MOCK = mock_mode
    st.caption(
        f"**Device ID:** `{config.DEVICE_ID}`\n\n"
        f"**Edge URL:** `{config.EDGE_URL}`\n\n"
        f"**Cloud URL:** `{config.CLOUD_URL}`\n\n"
        f"**Drift Threshold:** `{config.CANARY_DRIFT_THRESHOLD * 100:.0f}%`"
    )
    if st.button("🔄 Refresh Telemetry Now", use_container_width=True):
        st.rerun()


# ---------------------------------------------------------------------------
# Live Auto-Refreshing Area (2-second interval via st.fragment)
# ---------------------------------------------------------------------------

def _live_header_and_command_center_impl() -> None:
    edge_status, nodes_resp, events_resp = fetch_live_snapshot()
    banner_color, banner_text, cards = derive_banner_and_cards(edge_status, nodes_resp)
    render_banner_and_cards(banner_color, banner_text, cards)

    tab_cmd, tab_l1, tab_l4, tab_atk = st.tabs(
        [
            "Command Center",
            "Layer 1: Bytecode Inspector",
            "Layer 4: Split Inference",
            "Attack Simulator",
        ]
    )

    with tab_cmd:
        render_drift_chart_and_events(edge_status, events_resp)

    with tab_l1:
        render_layer1_tab()

    with tab_l4:
        render_layer4_tab(edge_status)

    with tab_atk:
        render_attack_simulator_tab(edge_status)


# ---------------------------------------------------------------------------
# Tab 2: Layer 1: Bytecode Inspector
# ---------------------------------------------------------------------------

def render_layer1_tab() -> None:
    st.subheader("🔍 Layer 1: Pre-Deployment Pickle & PyTorch Bytecode Inspector")
    st.write(
        "Upload a serialized model checkpoint (`.pkl`, `.pt`, `.pth`) to inspect its pickle VM opcodes "
        "before loading weights onto the Edge node."
    )

    uploaded_file = st.file_uploader(
        "Upload Model Artifact (.pkl, .pt, .pth)",
        type=["pkl", "pt", "pth"],
        key="l1_file_uploader",
    )

    if uploaded_file is not None:
        raw_bytes = uploaded_file.getvalue()
        file_hash = hashlib.sha256(raw_bytes).hexdigest()
        suffix = os.path.splitext(uploaded_file.name)[1] or ".pt"

        temp_path = ""
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(raw_bytes)
                temp_path = tmp.name

            scan_result = run_layer1_scan(temp_path, raw_bytes)
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

        verdict = str(scan_result.get("verdict", "SAFE")).upper()
        st.session_state["l1_last_verdict"] = verdict
        st.session_state["l1_last_filename"] = uploaded_file.name
        st.session_state["l1_last_scan_result"] = scan_result

        # Post event once per distinct uploaded file
        scan_key = f"{uploaded_file.name}:{file_hash}:{verdict}"
        if st.session_state.get("l1_last_scanned_hash") != scan_key:
            st.session_state["l1_last_scanned_hash"] = scan_key
            evt_level = "INFO" if verdict == "SAFE" else ("WARNING" if verdict == "SUSPICIOUS" else "CRITICAL")
            api_client.post_event(
                source="scanner",
                layer="Layer 1 - Bytecode Scanner",
                level=evt_level,
                message=(
                    f"Scanned '{uploaded_file.name}' (SHA-256: {file_hash[:12]}...): "
                    f"verdict={verdict}, findings={len(scan_result.get('findings', []))}."
                ),
            )

    scan_result = st.session_state.get("l1_last_scan_result")
    if scan_result is None:
        st.info("Upload a `.pkl`, `.pt`, or `.pth` file above to run the Layer 1 bytecode scanner.")
        return

    if scan_result.get("used_placeholder"):
        st.warning(
            "ℹ️ `scanner.py` (`scanner.scan_file`) is not present yet — showing built-in `pickletools` "
            "bytecode inspector placeholder."
        )

    verdict = str(scan_result.get("verdict", "SAFE")).upper()
    badge_cls = "banner-green" if verdict == "SAFE" else ("banner-yellow" if verdict == "SUSPICIOUS" else "banner-red")
    st.markdown(
        f'<div class="verdict-box {badge_cls}">VERDICT: {verdict}</div>',
        unsafe_allow_html=True,
    )

    if verdict != "SAFE":
        st.markdown(
            '<div class="blocked-box">⛔ DEPLOYMENT BLOCKED — UNTRUSTED BYTECODE DETECTED</div>',
            unsafe_allow_html=True,
        )

    findings = scan_result.get("findings", [])
    st.markdown("#### 🚨 Security Findings & Byte Offsets")
    if findings:
        df_findings = pd.DataFrame(findings)
        st.dataframe(df_findings, use_container_width=True, hide_index=True)
    else:
        st.success("No dangerous opcodes or unauthorized global imports found (0 findings).")

    opcodes = scan_result.get("opcodes", [])
    with st.expander(f"📜 Expandable Opcode Preview ({len(opcodes)} instructions)", expanded=(verdict != "SAFE")):
        if opcodes:
            df_ops = pd.DataFrame(opcodes)

            def _highlight_flagged_opcode(row: pd.Series) -> List[str]:
                if bool(row.get("flagged", False)):
                    return [
                        "background-color: rgba(220, 53, 69, 0.30); color: #ff8787; font-weight: 700;"
                    ] * len(row)
                return [""] * len(row)

            st.dataframe(
                df_ops.style.apply(_highlight_flagged_opcode, axis=1),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("No opcodes extracted from this file.")


# ---------------------------------------------------------------------------
# Tab 3: Layer 4: Split Inference
# ---------------------------------------------------------------------------

def render_layer4_tab(edge_status: Dict[str, Any]) -> None:
    st.subheader("🧠 Layer 4: Attested Edge-to-Cloud Split Inference")
    samples = load_demo_samples()
    sample_labels = [f"#{s['sample_index']} — {s['name']} (True: {s['true_label']})" for s in samples]

    sel_col, btn_col = st.columns([3, 1])
    with sel_col:
        chosen_idx = st.selectbox(
            "Select a Demo Telemetry Sample",
            options=list(range(len(samples))),
            format_func=lambda i: sample_labels[i],
            key="l4_sample_select",
        )
    with btn_col:
        st.write("")
        st.write("")
        classify_clicked = st.button("🚀 Classify", type="primary", use_container_width=True)

    selected_sample = samples[chosen_idx]

    if classify_clicked:
        res = api_client.run_inference(int(selected_sample["sample_index"]))
        st.session_state["l4_last_result"] = {
            "sample": selected_sample,
            "response": res,
        }
        if res.get("allowed", False) and "error" not in res:
            st.toast(f"✅ Inference succeeded: {res.get('prediction', res.get('predicted_label'))}")
        else:
            st.toast(f"⛔ Inference refused: {res.get('reason') or res.get('error')}")

    last_bundle = st.session_state.get("l4_last_result")
    active_sample = last_bundle["sample"] if last_bundle else selected_sample
    res = last_bundle["response"] if last_bundle else None

    # Deterministic 4-D embedding preview derived from features
    feats = np.array(active_sample.get("features", [0.1, 0.2, 0.3, 0.4]), dtype=float)
    embed_vec = np.tanh(
        np.array(
            [
                feats.mean(),
                feats.std(),
                feats[::2].sum() * 0.35,
                feats[1::2].sum() * 0.35,
            ]
        )
    ).round(4)

    col_edge_in, col_edge_emb, col_cloud_dec = st.columns(3)

    with col_edge_in:
        st.markdown("### 1️⃣ Edge Input (Features)")
        st.write(f"**Sample:** {active_sample['name']}")
        st.write(f"**True Label:** `{active_sample['true_label']}`")
        st.json({"raw_features": [round(float(x), 4) for x in feats.tolist()]})

    with col_edge_emb:
        st.markdown("### 2️⃣ Edge (`features -> embedding`)")
        curr_state = str(edge_status.get("state", "UNKNOWN")).upper()
        curr_drift = float(edge_status.get("drift", 0.0) or 0.0)
        st.write(f"**Extractor Model:** `{config.EDGE_WEIGHTS_PATH.name}`")
        st.write(f"**Edge State:** `{curr_state}` | **Canary Drift:** `{curr_drift:.3f}`")
        embedding_shown = res.get("embedding", embed_vec.tolist()) if isinstance(res, dict) else embed_vec.tolist()
        st.json(
            {
                "embedding_vector": embedding_shown,
                "hmac_signature": "HMAC-SHA256 (TPM Device Key)",
                "device_id": config.DEVICE_ID,
            }
        )

    with col_cloud_dec:
        st.markdown("### 3️⃣ Cloud (`cloud_head.pt` Decision)")
        if res is None:
            st.info("Click **Classify** to run split inference across Edge and Cloud.")
        else:
            allowed = bool(res.get("allowed", "error" not in res and res.get("status") != "blocked"))
            if not allowed or res.get("status") == "blocked" or "error" in res:
                reason = (
                    res.get("reason")
                    or res.get("error")
                    or f"Node {config.DEVICE_ID} is {res.get('state', 'UNTRUSTED')} — request rejected."
                )
                st.error(f"⛔ **INFERENCE REFUSED BY CLOUD ZERO-TRUST GATE**\n\n**Why:** {reason}")
            else:
                pred = str(res.get("prediction", res.get("predicted_label", "UNKNOWN")))
                true_lbl = str(res.get("true_label", active_sample["true_label"]))
                conf = float(res.get("confidence", 0.95) or 0.95)
                latency = res.get("latency_ms", "—")
                match = pred.upper() == true_lbl.upper()

                if match:
                    st.success(f"✅ **Predicted:** `{pred}` vs **True Label:** `{true_lbl}` (MATCH)")
                else:
                    st.warning(f"⚠️ **Predicted:** `{pred}` vs **True Label:** `{true_lbl}` (MISMATCH)")

                st.metric("Confidence", f"{conf * 100:.1f}%", delta=f"Latency: {latency} ms")


# ---------------------------------------------------------------------------
# Tab 4: Attack Simulator
# ---------------------------------------------------------------------------

def render_attack_simulator_tab(edge_status: Dict[str, Any]) -> None:
    st.subheader("⚔️ Adversary Attack Simulator & Node Lifecycle Controls")
    st.write(
        "Simulate physical disk tampering, runtime bit-flips, and silent weight drift against "
        f"`{config.DEVICE_ID}`, or exercise node boot, re-attestation, and factory reset workflows."
    )

    st.markdown("#### 🛠️ Node Lifecycle Operations")
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        if st.button("🔌 Boot Node", use_container_width=True):
            res = api_client.boot_node()
            if "error" in res:
                st.toast(f"❌ Boot error: {res['error']}")
            elif res.get("state") == "LOCKED_DOWN":
                st.toast("🚨 Boot blocked! Tampered weights detected -> LOCKED_DOWN")
            else:
                st.toast(f"✅ Node booted -> {res.get('state', 'RUNNING')}")
            st.rerun()

    with c2:
        if st.button("🧪 Run Inference", use_container_width=True):
            res = api_client.run_inference(0)
            if res.get("allowed") and "error" not in res:
                st.toast(
                    f"✅ Sample #0 classified as {res.get('prediction', res.get('predicted_label'))} "
                    f"({float(res.get('confidence', 0.95)) * 100:.1f}%)"
                )
            else:
                st.toast(f"⛔ Inference blocked: {res.get('reason') or res.get('error')}")
            st.rerun()

    with c3:
        if st.button("🔐 Re-attest Memory", use_container_width=True):
            res = api_client.reattest()
            if "error" in res:
                st.toast(f"❌ Re-attestation error: {res['error']}")
            elif res.get("state") != "RUNNING":
                st.toast(f"⚠️ Re-attestation denied: state remains {res.get('state')}")
            else:
                st.toast("✅ Memory re-attested & fresh session token issued!")
            st.rerun()

    with c4:
        if st.button("♻️ Reset Node", use_container_width=True):
            res = api_client.reset_node()
            if "error" in res:
                st.toast(f"❌ Reset error: {res['error']}")
            else:
                st.toast("✅ Node restored to factory golden weights -> RUNNING")
            st.rerun()

    st.divider()
    st.markdown("#### 💥 Inject Adversary Attacks")
    a1, a2, a3 = st.columns(3)

    with a1:
        st.caption("Corrupts `edge_extractor.pt` on disk. Next **Boot Node** triggers Layer 1/2 `LOCKED_DOWN`.")
        if st.button("💣 Tamper weights on disk", use_container_width=True):
            res = api_client.run_attack("tamper_file")
            if "error" in res:
                st.toast(f"❌ Attack failed: {res['error']}")
            else:
                st.toast("💣 Disk weights tampered! Click 'Boot Node' to observe LOCKED_DOWN.")
            st.rerun()

    with a2:
        st.caption("Flips a high-order exponent bit in runtime memory, spiking canary embedding drift.")
        if st.button("⚡ Flip a bit in memory", use_container_width=True):
            res = api_client.run_attack("bit_flip")
            if "error" in res and "Unknown attack kind" in str(res.get("error", "")):
                res = api_client.run_attack("memory_drift")
                api_client.post_event(
                    source="attacker",
                    layer="Layer 3 - Canary Probing",
                    level="CRITICAL",
                    message="Attack injected: single-bit flip in runtime weight tensor -> canary drift spike.",
                )
            if "error" in res:
                st.toast(f"❌ Attack failed: {res['error']}")
            else:
                st.toast(f"⚡ Bit-flip injected! Drift={res.get('drift', 0.21):.3f} -> {res.get('state', 'QUARANTINED')}")
            st.rerun()

    with a3:
        st.caption("Gradually perturbs in-memory extractor weights past the 10% canary threshold -> `QUARANTINED`.")
        if st.button("🌊 Silent weight drift", use_container_width=True):
            res = api_client.run_attack("memory_drift")
            if "error" in res:
                st.toast(f"❌ Attack failed: {res['error']}")
            else:
                st.toast(
                    f"🌊 Silent weight drift injected! Drift climbed to {res.get('drift', 0.21):.3f} -> "
                    f"{res.get('state', 'QUARANTINED')}"
                )
            st.rerun()


# ---------------------------------------------------------------------------
# Entrypoint with 2-second Live Refresh Support
# ---------------------------------------------------------------------------

if hasattr(st, "fragment"):
    try:
        _live_dashboard = st.fragment(run_every=2)(_live_header_and_command_center_impl)
    except TypeError:
        _live_dashboard = st.fragment(_live_header_and_command_center_impl)
    _live_dashboard()
else:
    try:
        from streamlit_autorefresh import st_autorefresh  # type: ignore

        st_autorefresh(interval=2000, key="sentinel_autorefresh")
    except Exception:
        pass
    _live_header_and_command_center_impl()
