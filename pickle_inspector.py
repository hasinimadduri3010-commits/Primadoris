"""
Pickle Static Bytecode Inspector
=================================
A security tool to detect malicious payloads in Python pickle (.pkl) files 
WITHOUT unpickling or executing any code.

Why is pickle dangerous?
------------------------
When Python's `pickle.load()` deserializes an object, it doesn't just read data:
it executes a stream of virtual machine instructions (opcodes). If an object defines 
the `__reduce__` method, it can instruct Python to import any module (like `os` or 
`subprocess`) and invoke any function with custom arguments. This allows arbitrary 
code execution (RCE).

How does this inspector work safely?
------------------------------------
Instead of calling `pickle.load()`, this script uses the standard library module 
`pickletools.genops()` to read raw bytecode bytes as an instruction stream. 
It analyzes instructions such as GLOBAL and STACK_GLOBAL to inspect every requested 
module and function call before any code can run.
"""

import sys
import os
import argparse
import pickletools

# Ensure UTF-8 output on Windows consoles to prevent charmap UnicodeEncodeErrors
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass


# =====================================================================
# SECURITY RULES & BLACKLISTS
# =====================================================================

# Modules commonly abused to execute system commands, spawn processes,
# or establish unauthorized network connections.
DANGEROUS_MODULES = {
    # System execution & process spawning
    "os", "posix", "nt", "subprocess", "pty", "commands",
    
    # Python built-in runtime & execution environments
    "builtins", "__builtin__", "sys", "importlib",
    
    # Networking & sockets
    "socket", "urllib", "requests", "http",
    
    # Low-level memory & foreign functions
    "ctypes", "winreg"
}

# Functions or attributes that directly execute arbitrary code or shell commands
DANGEROUS_CALLABLES = {
    "eval", "exec", "system", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "fork", "execl", "execle",
    "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "__import__", "getattr", "compile", "run", "Popen", "call", "check_call", "check_output"
}


# =====================================================================
# STATIC INSPECTOR CORE ENGINE
# =====================================================================

def inspect_pickle_file(filepath: str, verbose: bool = False) -> dict:
    """
    Statically analyzes a pickle file without executing any of its code.
    
    Parameters:
        filepath (str): Path to the .pkl file to scan.
        verbose (bool): If True, prints every opcode as it is processed.

    Returns:
        dict: Inspection results containing status ('SAFE' or 'COMPROMISED'),
              detected violations, total opcodes scanned, and protocol version.
    """
    if not os.path.exists(filepath):
        return {
            "status": "ERROR",
            "message": f"File '{filepath}' not found.",
            "violations": []
        }

    with open(filepath, "rb") as f:
        raw_bytes = f.read()

    file_size = len(raw_bytes)
    violations = []
    protocol_version = None
    opcode_count = 0

    # We maintain a simulated stack and memo table to track string arguments 
    # pushed before a STACK_GLOBAL opcode (used in modern pickle protocols 4 and 5).
    stack = []
    memo = {}

    try:
        # pickletools.genops parses the raw bytecode stream safely
        # yielding tuples of: (opcode_info, argument, byte_position)
        for opcode, arg, pos in pickletools.genops(raw_bytes):
            opcode_count += 1
            op_name = opcode.name

            if verbose:
                print(f"  [{pos:04d}] {op_name:<18} -> {repr(arg)}")

            # Detect pickle protocol version
            if op_name == "PROTO":
                protocol_version = arg

            # -------------------------------------------------------------
            # Track strings and values pushed onto the stack
            # -------------------------------------------------------------
            if op_name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", 
                           "SHORT_BINBYTES", "BINBYTES", "STRING", 
                           "SHORT_BINSTRING", "BINSTRING"):
                stack.append(str(arg))

            # Store in memo table (memoization / caching opcodes)
            elif op_name in ("PUT", "BINPUT", "LONG_BINPUT"):
                if stack:
                    memo[arg] = stack[-1]
            elif op_name == "MEMOIZE":
                if stack:
                    memo[len(memo)] = stack[-1]

            # Retrieve from memo table
            elif op_name in ("GET", "BINGET", "LONG_BINGET"):
                if arg in memo:
                    stack.append(memo[arg])

            # -------------------------------------------------------------
            # 1. OLDER PROTOCOLS: 'GLOBAL' Opcode (Protocols 0, 1, 2, 3)
            # -------------------------------------------------------------
            # In older protocols, the GLOBAL opcode directly provides 
            # "module_name class_or_function_name" as its argument.
            elif op_name == "GLOBAL":
                parts = arg.split(maxsplit=1) if arg else []
                module_name = parts[0] if len(parts) > 0 else "<unknown>"
                attr_name = parts[1] if len(parts) > 1 else "<unknown>"

                check_and_record_violation(
                    violations=violations,
                    pos=pos,
                    opcode=op_name,
                    module=module_name,
                    attribute=attr_name
                )

            # -------------------------------------------------------------
            # 2. MODERN PROTOCOLS: 'STACK_GLOBAL' Opcode (Protocols 4, 5)
            # -------------------------------------------------------------
            # In protocols 4 and 5, STACK_GLOBAL does not store names in `arg`.
            # Instead, it pops the attribute name from the top of the stack,
            # and the module name from right underneath it.
            elif op_name == "STACK_GLOBAL":
                attr_name = stack.pop() if stack else "<unknown>"
                module_name = stack.pop() if stack else "<unknown>"

                check_and_record_violation(
                    violations=violations,
                    pos=pos,
                    opcode=op_name,
                    module=module_name,
                    attribute=attr_name
                )

            # -------------------------------------------------------------
            # 3. LEGACY INSTANTIATION: 'INST' Opcode (Protocol 0)
            # -------------------------------------------------------------
            elif op_name == "INST":
                parts = arg.split(maxsplit=1) if arg else []
                module_name = parts[0] if len(parts) > 0 else "<unknown>"
                attr_name = parts[1] if len(parts) > 1 else "<unknown>"

                check_and_record_violation(
                    violations=violations,
                    pos=pos,
                    opcode=op_name,
                    module=module_name,
                    attribute=attr_name
                )

            # -------------------------------------------------------------
            # 4. REDUCE Opcode: Callable invocation
            # -------------------------------------------------------------
            # REDUCE takes a callable and a tuple of arguments and executes it.
            # While benign objects like numpy or custom classes use REDUCE,
            # in combination with dangerous imports, it triggers arbitrary RCE.
            elif op_name == "REDUCE":
                if verbose:
                    print(f"  ⚠️ [Byte {pos}] 'REDUCE' opcode encountered (Callable execution)")

    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Error parsing pickle bytecode: {e}",
            "violations": violations,
            "opcodes_scanned": opcode_count,
            "protocol": protocol_version,
            "file_size": file_size
        }

    # Decide verdict: If any dangerous import/callable was flagged, it's COMPROMISED.
    is_compromised = len(violations) > 0

    return {
        "status": "COMPROMISED" if is_compromised else "SAFE",
        "filepath": filepath,
        "file_size": file_size,
        "protocol": protocol_version,
        "opcodes_scanned": opcode_count,
        "violations": violations
    }


def check_and_record_violation(violations: list, pos: int, opcode: str, module: str, attribute: str):
    """
    Checks if a module or attribute matches the list of dangerous targets.
    If so, appends a detailed security violation report to the list.
    """
    reasons = []

    # Check if module is in the dangerous modules list
    if module in DANGEROUS_MODULES:
        reasons.append(f"Suspicious module import: '{module}'")

    # Check if function / attribute is inherently dangerous
    if attribute in DANGEROUS_CALLABLES:
        reasons.append(f"Dangerous callable requested: '{attribute}'")

    # If any reason triggered, record the violation
    if reasons:
        violations.append({
            "byte_position": pos,
            "opcode": opcode,
            "module": module,
            "attribute": attribute,
            "reasons": reasons
        })


# =====================================================================
# CLI REPORTING FORMATTER
# =====================================================================

def display_report(result: dict):
    """
    Renders a formatted security report for the terminal.
    """
    print("=" * 65)
    print(f" 🔍 STATIC BYTECODE SCAN REPORT: {result.get('filepath')}")
    print("=" * 65)

    if result.get("status") == "ERROR":
        print(f"❌ [SCAN ERROR]: {result.get('message')}\n")
        return

    print(f" • File Size:        {result.get('file_size')} bytes")
    print(f" • Pickle Protocol:  {result.get('protocol', 'Unknown')}")
    print(f" • Opcodes Scanned:  {result.get('opcodes_scanned')}")
    print("-" * 65)

    if result["status"] == "COMPROMISED":
        print("🚨 VERDICT: [COMPROMISED] - POTENTIALLY MALICIOUS PAYLOAD DETECTED")
        print("-" * 65)
        print("Details of flagged instructions:")
        for idx, v in enumerate(result["violations"], 1):
            print(f"  [{idx}] Offset: byte {v['byte_position']} | Opcode: {v['opcode']}")
            print(f"      Target: {v['module']}.{v['attribute']}")
            for reason in v["reasons"]:
                print(f"      Alert:  ⚠️ {reason}")
    else:
        print("✅ VERDICT: [SAFE] - NO SUSPICIOUS GLOBAL IMPORTS DETECTED")
        print("-" * 65)
        print("  No restricted modules (os, subprocess, builtins, socket) were found.")
    print("=" * 65 + "\n")


# =====================================================================
# MAIN ENTRY POINT
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Static Bytecode Inspector for Python pickle (.pkl) files."
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="One or more .pkl files to inspect. If omitted, scans 'safe_model.pkl' and 'malicious_model.pkl'."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Display every opcode in the pickle instruction stream."
    )

    args = parser.parse_args()

    # If no files specified, use default test models if they exist
    files_to_scan = args.files
    if not files_to_scan:
        defaults = ["safe_model.pkl", "malicious_model.pkl"]
        files_to_scan = [f for f in defaults if os.path.exists(f)]
        if not files_to_scan:
            print("No pickle files provided and default test models were not found.")
            print("Usage: python pickle_inspector.py <path_to_model.pkl>")
            sys.exit(1)

    has_compromised = False
    for filepath in files_to_scan:
        res = inspect_pickle_file(filepath, verbose=args.verbose)
        display_report(res)
        if res.get("status") == "COMPROMISED":
            has_compromised = True

    # Exit code: 0 if all safe, 2 if compromised files found
    sys.exit(2 if has_compromised else 0)


if __name__ == "__main__":
    main()
