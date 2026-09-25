import numpy as np
import pandas as pd

from cyber_training.stage6_training import cap_endpoint_partitions, _rank_by_validation


def test_cap_endpoint_partitions_respects_row_budget_and_keeps_groups_disjoint():
    frame = pd.DataFrame({
        "srcip": ["a"] * 6 + ["b"] * 6 + ["c"] * 6 + ["d"] * 6,
        "dstip": ["x"] * 6 + ["y"] * 6 + ["z"] * 6 + ["w"] * 6,
        "Label": [0, 1] * 12,
    })
    split = {
        "train": np.arange(0, 12),
        "validation": np.arange(12, 18),
        "test": np.arange(18, 24),
    }
    capped, report = cap_endpoint_partitions(frame, split, seed=5, max_rows=10)
    assert {name: len(indices) for name, indices in capped.items()} == {
        "train": 10, "validation": 6, "test": 6,
    }
    assert report["train"]["sampled"] is True
    assert report["validation"]["sampled"] is False


def test_stage6_model_ranking_uses_only_validation_metric():
    records = [
        {"model": "random_forest", "validation_binary_f1": 0.8, "endpoint_holdout_metrics": {"macro_f1": 0.4}},
        {"model": "decision_tree", "validation_binary_f1": 0.9, "endpoint_holdout_metrics": {"macro_f1": 0.3}},
    ]
    assert _rank_by_validation(records) == ["decision_tree", "random_forest"]
