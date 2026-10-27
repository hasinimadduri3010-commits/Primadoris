"""
attacks.py
==========
Primadoris AI - Simulated and real attack drivers per ARCHITECTURE.md:
- tamper_weights_file(path)
- restore_weights_file(path)
- bitflip_in_memory(model)
- drift_in_memory(model, strength=0.25)
"""

import os
import shutil
import torch


def tamper_weights_file(path: str) -> None:
    """
    Corrupts the on-disk weights file so that SHA-256 hash validation
    against golden.json fails on the next boot/attestation.
    Creates a .bak backup before modifying.
    """
    path = str(path)
    bak = path + ".bak"
    if not os.path.exists(bak) and os.path.exists(path):
        shutil.copy2(path, bak)

    if os.path.exists(path):
        # Corrupt a few bytes in the middle of the file
        with open(path, "r+b") as f:
            length = os.path.getsize(path)
            if length > 32:
                f.seek(length // 2)
                f.write(b"TAMPERED_MALICIOUS_BYTES_EXPLOIT")
                f.flush()


def restore_weights_file(path: str) -> None:
    """
    Restores the clean on-disk weights file from .bak backup.
    """
    path = str(path)
    bak = path + ".bak"
    if os.path.exists(bak):
        shutil.copy2(bak, path)
        os.remove(bak)


def bitflip_in_memory(model: torch.nn.Module) -> None:
    """
    Flips/perturbs high-order weight parameters in-place in active runtime memory.
    Spikes canary embedding drift immediately past the 10% threshold.
    """
    with torch.no_grad():
        for param in model.parameters():
            if param.numel() > 0:
                # Add high-magnitude offset to first few weights to spike drift
                flat = param.view(-1)
                flat[:min(8, flat.numel())] += 1.85
                break


def drift_in_memory(model: torch.nn.Module, strength: float = 0.25) -> None:
    """
    Applies stealthy parametric noise in runtime memory.
    Simulates adversarial weight poisoning or environmental corruption.
    """
    with torch.no_grad():
        for param in model.parameters():
            noise = torch.randn_like(param) * float(strength)
            param.add_(noise)
