"""
scanner.py
==========
SentinelEdge AI - Layer 1 Static Bytecode Scanner
Implements scan_file(path: str) -> dict according to ARCHITECTURE.md.

Performs two-pass static bytecode analysis on .pkl files without unpickling
or executing any code:
  Pass 1: Static bytecode traversal, stack simulation, and global import inspection.
  Pass 2: Execution primitives inspection (e.g. REDUCE, BUILD) and threat contextualization.
"""

import os
import pickletools

# High-risk modules that should never be imported by benign model weights
DANGEROUS_MODULES_HIGH = {
    "os", "posix", "nt", "subprocess", "pty", "commands",
    "builtins", "__builtin__", "socket", "sys", "importlib",
    "ctypes", "winreg"
}

# Suspicious modules requiring close scrutiny
DANGEROUS_MODULES_MEDIUM = {
    "urllib", "requests", "http", "shutil", "webbrowser",
    "tempfile", "code", "pdb"
}

# Functions or attributes that execute arbitrary commands or code
DANGEROUS_CALLABLES_HIGH = {
    "eval", "exec", "system", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "fork", "execl", "execle",
    "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "__import__", "getattr", "compile", "run", "Popen", "call", "check_call", "check_output"
}


def scan_file(path: str) -> dict:
    """
    Statically analyzes a pickle file without executing any code.

    Parameters:
        path (str): File path to the .pkl file.

    Returns:
        dict:
            {
                "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
                "findings": [
                    {
                        "pass": 1 | 2,
                        "offset": int,
                        "opcode": str,
                        "detail": str,
                        "severity": "high" | "medium"
                    }
                ],
                "opcodes_scanned": int,
                "bytes_scanned": int,
                "opcode_preview": [
                    {
                        "offset": int,
                        "opcode": str,
                        "arg": str
                    }
                ]   # first 200 opcodes
            }
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: '{path}'")

    with open(path, "rb") as f:
        raw_bytes = f.read()

    res = scan_bytes(raw_bytes)
    return {
        "verdict": res["verdict"],
        "findings": res["findings"],
        "opcodes_scanned": res["opcodes_scanned"],
        "bytes_scanned": res["bytes_scanned"],
        "opcode_preview": res["opcode_preview"]
    }


def scan_bytes(raw_bytes: bytes) -> dict:
    """
    Statically analyzes raw pickle bytes without executing any code.
    Returns rich telemetry including detected protocol, full opcode trace,
    and granular security findings.
    """
    import time
    start_time = time.perf_counter()

    bytes_scanned = len(raw_bytes)
    opcodes_scanned = 0
    findings = []
    opcode_preview = []
    all_opcodes = []
    protocol_version = 0

    # Stack and memo simulation for modern protocols (STACK_GLOBAL)
    stack = []
    memo = {}

    # Track recently loaded global targets for Pass 2 context
    active_globals = []

    try:
        # =================================================================
        # PASS 1: Opcode Traversal & Global Import Inspection
        # =================================================================
        for opcode, arg, pos in pickletools.genops(raw_bytes):
            opcodes_scanned += 1
            op_name = opcode.name
            arg_str = str(arg) if arg is not None else ""
            is_threat = False
            is_suspicious = False

            if op_name == "PROTO":
                protocol_version = arg

            # Populate opcode preview (first 200 opcodes)
            if len(opcode_preview) < 200:
                opcode_preview.append({
                    "offset": pos,
                    "opcode": op_name,
                    "arg": arg_str
                })

            # Track strings pushed to stack
            if op_name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE",
                           "SHORT_BINBYTES", "BINBYTES", "STRING",
                           "SHORT_BINSTRING", "BINSTRING"):
                stack.append(str(arg))

            # Track memo table assignments
            elif op_name in ("PUT", "BINPUT", "LONG_BINPUT"):
                if stack:
                    memo[arg] = stack[-1]
            elif op_name == "MEMOIZE":
                if stack:
                    memo[len(memo)] = stack[-1]

            # Track memo table retrievals
            elif op_name in ("GET", "BINGET", "LONG_BINGET"):
                if arg in memo:
                    stack.append(memo[arg])

            # --- Inspect GLOBAL (Protocols 0, 1, 2, 3) ---
            elif op_name == "GLOBAL":
                parts = arg.split(maxsplit=1) if arg else []
                module_name = parts[0] if len(parts) > 0 else "<unknown>"
                attr_name = parts[1] if len(parts) > 1 else "<unknown>"
                active_globals.append((pos, module_name, attr_name))

                ev = _evaluate_import(
                    findings=findings,
                    pos=pos,
                    opcode=op_name,
                    module=module_name,
                    attr=attr_name,
                    pass_num=1
                )
                if ev == "high":
                    is_threat = True
                elif ev == "medium":
                    is_suspicious = True

            # --- Inspect STACK_GLOBAL (Protocols 4, 5) ---
            elif op_name == "STACK_GLOBAL":
                attr_name = stack.pop() if stack else "<unknown>"
                module_name = stack.pop() if stack else "<unknown>"
                active_globals.append((pos, module_name, attr_name))

                ev = _evaluate_import(
                    findings=findings,
                    pos=pos,
                    opcode=op_name,
                    module=module_name,
                    attr=attr_name,
                    pass_num=1
                )
                if ev == "high":
                    is_threat = True
                elif ev == "medium":
                    is_suspicious = True

            # --- Inspect INST (Protocol 0 Class Instantiation) ---
            elif op_name == "INST":
                parts = arg.split(maxsplit=1) if arg else []
                module_name = parts[0] if len(parts) > 0 else "<unknown>"
                attr_name = parts[1] if len(parts) > 1 else "<unknown>"
                active_globals.append((pos, module_name, attr_name))

                ev = _evaluate_import(
                    findings=findings,
                    pos=pos,
                    opcode=op_name,
                    module=module_name,
                    attr=attr_name,
                    pass_num=1
                )
                if ev == "high":
                    is_threat = True
                elif ev == "medium":
                    is_suspicious = True

            # =============================================================
            # PASS 2: Execution Primitives & Contextual Analysis
            # =============================================================
            elif op_name in ("REDUCE", "BUILD", "OBJ", "NEWOBJ"):
                # Check if a dangerous callable is being executed via REDUCE
                if active_globals:
                    last_pos, last_mod, last_attr = active_globals[-1]
                    if (last_mod in DANGEROUS_MODULES_HIGH or
                            last_attr in DANGEROUS_CALLABLES_HIGH):
                        is_threat = True
                        findings.append({
                            "pass": 2,
                            "offset": pos,
                            "opcode": op_name,
                            "detail": f"Execution of dangerous callable '{last_mod}.{last_attr}' via {op_name}",
                            "severity": "high"
                        })
                    elif last_mod in DANGEROUS_MODULES_MEDIUM:
                        is_suspicious = True
                        findings.append({
                            "pass": 2,
                            "offset": pos,
                            "opcode": op_name,
                            "detail": f"Execution of suspicious callable '{last_mod}.{last_attr}' via {op_name}",
                            "severity": "medium"
                        })

            status = "🚨 THREAT" if is_threat else ("⚠️ SUSPICIOUS" if is_suspicious else "NORMAL")
            all_opcodes.append({
                "Offset": pos,
                "Opcode": op_name,
                "Argument": arg_str,
                "Status": status
            })

    except Exception as e:
        findings.append({
            "pass": 2,
            "offset": 0,
            "opcode": "PARSER_ERROR",
            "detail": f"Bytecode parsing exception: {str(e)}",
            "severity": "medium"
        })

    # =================================================================
    # VERDICT DETERMINATION
    # =================================================================
    has_high = any(f["severity"] == "high" for f in findings)
    has_medium = any(f["severity"] == "medium" for f in findings)

    if has_high:
        verdict = "MALICIOUS"
    elif has_medium:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    scan_duration_ms = (time.perf_counter() - start_time) * 1000.0

    return {
        "verdict": verdict,
        "findings": findings,
        "opcodes_scanned": opcodes_scanned,
        "bytes_scanned": bytes_scanned,
        "opcode_preview": opcode_preview,
        "protocol": protocol_version,
        "all_opcodes": all_opcodes,
        "scan_time_ms": round(scan_duration_ms, 3),
        "high_threats": sum(1 for f in findings if f["severity"] == "high"),
        "medium_threats": sum(1 for f in findings if f["severity"] == "medium")
    }


def _evaluate_import(findings: list, pos: int, opcode: str, module: str, attr: str, pass_num: int):
    """
    Evaluates module and attribute targets against security policies.
    """
    # High severity checks: execution primitives, system modules, built-in evals
    if module in DANGEROUS_MODULES_HIGH or attr in DANGEROUS_CALLABLES_HIGH:
        findings.append({
            "pass": pass_num,
            "offset": pos,
            "opcode": opcode,
            "detail": f"Disallowed dangerous target: {module}.{attr}",
            "severity": "high"
        })
        return "high"
    # Medium severity checks: suspicious network/utility modules
    elif module in DANGEROUS_MODULES_MEDIUM:
        findings.append({
            "pass": pass_num,
            "offset": pos,
            "opcode": opcode,
            "detail": f"Suspicious target: {module}.{attr}",
            "severity": "medium"
        })
        return "medium"
    return None
