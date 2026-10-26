"""
split_model.py - Split Deep Learning Architecture.

Defines the EdgeExtractor and CloudHead neural network modules,
along with the utility to load edge weights safely.
"""

from pathlib import Path
from typing import Union
import torch
import torch.nn as nn


class EdgeExtractor(nn.Module):
    """
    Edge-side feature extractor.
    Architecture: Linear(64, 128) -> ReLU -> Linear(128, 32) -> ReLU.
    Outputs a 32-dimensional intermediate embedding tensor.
    """

    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, 32),
            nn.ReLU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class CloudHead(nn.Module):
    """
    Cloud-side decision head.
    Architecture: Linear(32, 64) -> ReLU -> Linear(64, 10).
    Maps 32-dimensional intermediate embeddings to 10 class logits.
    """

    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, 10),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def load_edge_state(path: Union[str, Path]) -> dict:
    """
    Loads edge model state_dict safely from disk.
    Enforces weights_only=True to prevent arbitrary code execution vulnerabilities.
    """
    return torch.load(path, map_location="cpu", weights_only=True)
