import numpy as np
import pandas as pd
import sys
from pathlib import Path

from cyber_training.data import audit_duplicate_counts, deduplicate_v0_rows, endpoint_group_ids, endpoint_stress_split, make_split, prepare_v0_features, split_audit


def test_duplicate_audit_preserves_source_and_parsed_counts():
    audit = audit_duplicate_counts(parsed_exact=480632, source_audit=266)
    assert audit == {
        "parsed_exact_duplicate_rows": 480632,
        "source_audit_exact_duplicate_rows": 266,
        "source_audit_reconciled": False,
        "source_audit_note": "source manifest uses a different duplicate-audit scope; parsed exact duplicates are retained for this run",
    }


def test_verify_data_cli_coerces_data_root_to_path(monkeypatch, capsys):
    import cyber_training.cli as cli

    seen = {}

    def fake_load_raw(root):
        seen["raw"] = root
        return None, {"files": {}}

    def fake_subset(root):
        seen["subset"] = root
        return {"ok": True}

    monkeypatch.setattr(cli, "load_raw", fake_load_raw)
    monkeypatch.setattr(cli, "load_subset_audit", fake_subset)
    monkeypatch.setattr(sys, "argv", ["cyber-training", "verify-data", "--data-root", "C:/dataset"])
    cli.main()
    assert seen["raw"] == Path("C:/dataset")
    assert seen["subset"] == Path("C:/dataset")
    assert capsys.readouterr().out


def test_split_is_fixed_disjoint_and_stratified():
    labels = pd.Series([0] * 900 + [1] * 100)
    first = make_split(labels, 71)
    second = make_split(labels, 71)
    assert all(np.array_equal(first[k], second[k]) for k in first)
    assert len(set(np.concatenate(list(first.values())))) == len(labels)
    assert [len(first[name]) for name in ("train", "validation", "test")] == [700, 150, 150]


def test_endpoint_groups_are_unordered_pairs():
    frame = pd.DataFrame({"srcip": ["a", "b"], "dstip": ["b", "a"]})
    assert endpoint_group_ids(frame).tolist() == ["a|b", "a|b"]


def test_split_audit_reports_exact_and_entity_overlap():
    frame = pd.DataFrame({"srcip": ["a", "a", "b"], "dstip": ["b", "b", "c"], "x": [1, 2, 3], "Label": [0, 1, 0]})
    report = split_audit(frame, {"train": np.array([0, 1]), "validation": np.array([2]), "test": np.array([], dtype=int)})
    assert report["exact_feature_target_overlap"]["train:validation"] == 0
    assert report["endpoint_group_overlap"]["train:validation"] == 0


def test_split_audit_detects_overlap_after_identifiers_are_excluded():
    frame = pd.DataFrame({"srcip": ["a", "b"], "dstip": ["x", "y"], "Label": [0, 0]})
    model_features = pd.DataFrame({"duration": [1.0, 1.0]})
    report = split_audit(frame, {"train": np.array([0]), "validation": np.array([1]), "test": np.array([], dtype=int)}, model_features)
    assert report["exact_feature_target_overlap"]["train:validation"] == 1


def test_v0_duplicate_rows_are_removed_and_counted_even_with_different_endpoints():
    frame = pd.DataFrame({"srcip": ["a", "b"], "dstip": ["x", "y"], "Label": [1, 1]})
    features = pd.DataFrame({"duration": [1.0, 1.0]})
    kept_frame, kept_features, removed = deduplicate_v0_rows(frame, features)
    assert len(kept_frame) == 1
    assert len(kept_features) == 1
    assert removed == 1


def test_v0_contract_derives_subset_rate_and_excludes_endpoints():
    frame = pd.DataFrame({
        "dur": [0.5, 0.0], "Spkts": [4, 2], "Dpkts": [3, 1],
        "srcip": ["a", "b"], "dstip": ["b", "a"], "sport": [1, 2], "dsport": [3, 4],
        "Stime": [10, 11], "Ltime": [11, 12], "attack_cat": [None, "Normal"], "Label": [1, 0],
        "proto": ["tcp", "udp"], "service": ["-", "dns"], "state": ["FIN", "CON"],
    })
    features = prepare_v0_features(frame)
    assert features["rate"].iloc[0] == 12.0
    assert np.isnan(features["rate"].iloc[1])
    assert {"srcip", "dstip", "sport", "dsport", "Stime", "Ltime", "Label", "attack_cat"}.isdisjoint(features.columns)
    assert "sload" in features.columns
    assert len(features.columns) == 42


def test_endpoint_stress_split_keeps_groups_disjoint():
    frame = pd.DataFrame({
        "srcip": ["a", "b", "c", "d", "e", "f"],
        "dstip": ["b", "a", "d", "c", "f", "e"],
        "Label": [0, 1, 0, 1, 0, 1],
    })
    split, audit = endpoint_stress_split(frame, seed=12)
    groups = endpoint_group_ids(frame)
    assigned = {name: set(groups[indices]) for name, indices in split.items()}
    assert all(not (assigned[left] & assigned[right]) for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")))
    assert sum(len(indices) for indices in split.values()) == len(frame)
    assert audit["total_endpoint_groups"] == 3
