from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DATA_ROOT = ROOT / "data" / "raw" / "unsw-nb15"


@dataclass(frozen=True)
class ExperimentConfig:
    seed: int = 20260923
    batch_size: int = 8192
    mlp_epochs: int = 20
    mlp_patience: int = 4
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    threshold_metric: str = "f1"
    endpoint_max_rows: int = 100_000
    tree_n_estimators: int = 50
    tree_max_depth: int = 24
    tree_n_jobs: int = 14
    cpu_threads: int = 14
    experiment_name: str = "unsw-raw-binary"
