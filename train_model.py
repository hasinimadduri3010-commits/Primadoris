"""
train_model.py - End-to-End Training for Split Deep Learning Architecture.

Trains EdgeExtractor and CloudHead on scikit-learn's digits dataset (scaled to 0-1)
on CPU to >95% accuracy using a fixed random seed for reproducibility.

Outputs generated in MODELS_DIR:
- edge_extractor.pt: State dict for EdgeExtractor
- cloud_head.pt: State dict for CloudHead
- golden.json: Trusted SHA-256 hash of the edge extractor weights
- baseline.json: 5 reference test inputs and their baseline embeddings for canary drift detection
- demo_samples.json: 20 test samples with ground-truth labels for edge inference demos
"""

import json
import random
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
from sklearn.datasets import load_digits
from sklearn.model_selection import train_test_split

from config import (
    MODELS_DIR,
    EDGE_WEIGHTS_PATH,
    CLOUD_HEAD_PATH,
    GOLDEN_PATH,
    BASELINE_PATH,
    DEMO_SAMPLES_PATH,
    DEVICE_ID,
)
from split_model import EdgeExtractor, CloudHead, load_edge_state
from attestation import compute_weights_hash


def set_seed(seed: int = 42):
    """Sets fixed random seeds across all libraries for deterministic training."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


class CombinedSplitModel(nn.Module):
    """End-to-end wrapper combining EdgeExtractor and CloudHead for training."""

    def __init__(self, extractor: EdgeExtractor, head: CloudHead):
        super().__init__()
        self.extractor = extractor
        self.head = head

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        embeddings = self.extractor(x)
        logits = self.head(embeddings)
        return logits


def train():
    """Trains the split model and serializes all required artifacts."""
    set_seed(42)

    # 1. Load digits dataset and scale to [0, 1]
    digits = load_digits()
    X = digits.data.astype(np.float32) / 16.0  # Digits pixel values range from 0 to 16
    y = digits.target.astype(np.int64)

    # 80/20 stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    X_train_tensor = torch.tensor(X_train, dtype=torch.float32)
    y_train_tensor = torch.tensor(y_train, dtype=torch.long)
    X_test_tensor = torch.tensor(X_test, dtype=torch.float32)
    y_test_tensor = torch.tensor(y_test, dtype=torch.long)

    # 2. Initialize models
    extractor = EdgeExtractor()
    head = CloudHead()
    model = CombinedSplitModel(extractor, head)

    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.003, weight_decay=1e-4)

    # 3. Train on CPU
    epochs = 60
    batch_size = 32
    num_samples = len(X_train)

    print(f"Training split model on {num_samples} samples across {epochs} epochs...")
    model.train()
    for epoch in range(1, epochs + 1):
        permutation = torch.randperm(num_samples)
        epoch_loss = 0.0

        for i in range(0, num_samples, batch_size):
            indices = permutation[i : i + batch_size]
            batch_x, batch_y = X_train_tensor[indices], y_train_tensor[indices]

            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item() * len(batch_x)

        if epoch % 10 == 0 or epoch == epochs:
            model.eval()
            with torch.no_grad():
                test_outputs = model(X_test_tensor)
                preds = torch.argmax(test_outputs, dim=1)
                acc = (preds == y_test_tensor).float().mean().item()
            print(f"Epoch {epoch:2d}/{epochs} - Train Loss: {epoch_loss/num_samples:.4f} - Test Acc: {acc*100:.2f}%")
            model.train()

    # Final evaluation
    model.eval()
    with torch.no_grad():
        test_outputs = model(X_test_tensor)
        preds = torch.argmax(test_outputs, dim=1)
        final_acc = (preds == y_test_tensor).float().mean().item()

    print(f"\nFinal Test Accuracy: {final_acc * 100:.2f}%")
    if final_acc < 0.95:
        raise RuntimeError(f"Model failed to reach target accuracy > 95% (achieved {final_acc*100:.2f}%)")

    # 4. Ensure models/ directory exists and clean/reset existing artifacts
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # 5. Save model state dicts
    print(f"Saving EdgeExtractor state dict to {EDGE_WEIGHTS_PATH}...")
    torch.save(extractor.state_dict(), EDGE_WEIGHTS_PATH)

    print(f"Saving CloudHead state dict to {CLOUD_HEAD_PATH}...")
    torch.save(head.state_dict(), CLOUD_HEAD_PATH)

    # 6. Verify saved weights and generate golden.json
    loaded_edge_state = load_edge_state(EDGE_WEIGHTS_PATH)
    weights_hash = compute_weights_hash(loaded_edge_state)
    golden_data = {
        "device_id": DEVICE_ID,
        "weights_sha256": weights_hash,
    }
    with open(GOLDEN_PATH, "w", encoding="utf-8") as f:
        json.dump(golden_data, f, indent=2)
    print(f"Wrote golden hash to {GOLDEN_PATH}: {weights_hash}")

    # 7. Generate baseline.json (5 fixed test samples + embeddings from trained extractor)
    with torch.no_grad():
        baseline_inputs = X_test[:5]
        baseline_inputs_tensor = torch.tensor(baseline_inputs, dtype=torch.float32)
        baseline_embeddings = extractor(baseline_inputs_tensor).cpu().numpy().tolist()

    baseline_data = {
        "inputs": [sample.tolist() for sample in baseline_inputs],
        "embeddings": baseline_embeddings,
    }
    with open(BASELINE_PATH, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)
    print(f"Wrote baseline canary data (5 samples) to {BASELINE_PATH}")

    # 8. Generate demo_samples.json (20 test samples with ground-truth labels)
    demo_inputs = X_test[5:25]
    demo_labels = y_test[5:25]
    demo_data = [
        {"features": sample.tolist(), "label": int(label)}
        for sample, label in zip(demo_inputs, demo_labels)
    ]
    with open(DEMO_SAMPLES_PATH, "w", encoding="utf-8") as f:
        json.dump(demo_data, f, indent=2)
    print(f"Wrote demo samples (20 samples) to {DEMO_SAMPLES_PATH}")

    # 9. Remove any stale backup files left by previous runs
    for bak_file in MODELS_DIR.glob("*.bak"):
        bak_file.unlink()
        print(f"Removed stale backup: {bak_file.name}")

    print("\nTraining and artifact generation completed successfully!")


if __name__ == "__main__":
    train()
