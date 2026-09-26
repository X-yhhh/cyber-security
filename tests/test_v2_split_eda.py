import numpy as np
import pandas as pd
import pytest

from cyber_training.v2 import datasets, eda, split
from cyber_training.v2.guard import PARTITIONS


def synthetic_d1(n_groups=60, rows_per_group=50, seed=0):
    rng = np.random.default_rng(seed)
    frames = []
    for g in range(n_groups):
        attack_group = g % 3 == 0
        label = (rng.random(rows_per_group) < 0.4).astype("int8") if attack_group else np.zeros(rows_per_group, "int8")
        frames.append(pd.DataFrame({
            "srcip": f"10.0.0.{g}", "dstip": "10.0.1.1" if g % 2 else "10.0.1.2",
            "sport": rng.integers(1, 65535, rows_per_group), "dsport": 80,
            "Stime": 1, "Ltime": 2, "proto": "tcp", "service": "-", "state": "FIN",
            "dur": rng.random(rows_per_group), "sbytes": rng.integers(0, 10_000, rows_per_group),
            "stcpb": rng.integers(0, 2**31, rows_per_group), "dtcpb": rng.integers(0, 2**31, rows_per_group),
            "attack_cat": np.where(label == 1, "Exploits", "Normal"), "Label": label,
        }))
    return pd.concat(frames, ignore_index=True)


def test_dedup_key_excludes_ids_targets_and_sequence_numbers():
    key = datasets.d1_dedup_key(synthetic_d1(3, 5))
    assert not set(key) & {"srcip", "dstip", "sport", "dsport", "Stime", "Ltime", "Label", "attack_cat", "stcpb", "dtcpb"}
    assert {"proto", "dur", "sbytes"} <= set(key)


def test_deduplicate_drops_conflicting_groups_and_duplicates():
    frame = pd.DataFrame({"a": [1, 1, 2, 2, 3], "Label": [0, 1, 0, 0, 1]})
    keep, stats = datasets.deduplicate(frame, ["a"], "Label")
    assert keep.tolist() == [False, False, True, False, True]
    assert stats == {"input_rows": 5, "label_conflict_rows_removed": 2, "duplicate_rows_removed": 1, "rows_retained": 2}


def test_endpoint_pair_is_direction_invariant():
    frame = pd.DataFrame({"srcip": ["1.1.1.1", "2.2.2.2"], "dstip": ["2.2.2.2", "1.1.1.1"]})
    pairs = datasets.endpoint_pair(frame)
    assert pairs.iloc[0] == pairs.iloc[1] == "1.1.1.1|2.2.2.2"
    with pytest.raises(datasets.DataIntegrityError):
        datasets.endpoint_pair(pd.DataFrame({"srcip": [None], "dstip": ["1.1.1.1"]}))


def test_assign_groups_is_deterministic_and_balanced():
    sizes = pd.Series(np.full(100, 10), index=[f"g{i}" for i in range(100)])
    first = split.assign_groups(sizes, 1)
    assert first == split.assign_groups(sizes, 1)
    counts = pd.Series(first).value_counts()
    assert counts["train"] == 70 and counts["validation"] == 15 and counts["holdout"] == 15


def test_grouped_split_has_no_group_overlap_and_passes_audit():
    frame = synthetic_d1()
    groups = datasets.endpoint_pair(frame).to_numpy()
    parts = split.grouped_split(pd.Series(groups), frame["Label"], 7)
    audit = split.audit_partitions(parts, frame["Label"].to_numpy(), groups, None)
    assert audit["endpoint_group_overlap"] == 0
    assert sum(len(v) for v in parts.values()) == len(frame)
    assert all(audit["partitions"][n]["attack_rows"] > 0 for n in PARTITIONS)


def test_audit_detects_feature_overlap():
    parts = {"train": np.array([0, 1]), "validation": np.array([2]), "holdout": np.array([3])}
    features = pd.DataFrame({"x": [1, 2, 1, 3]})
    audit = split.audit_partitions(parts, np.array([0, 1, 0, 1]), None, features)
    assert audit["feature_vector_overlap"] == 1 and not audit["checks"]["feature_vector_overlap_zero"]


def test_split_d1_raw_fails_closed_when_no_seed_passes(monkeypatch):
    monkeypatch.setattr(split, "MAX_ATTACK_RATE_DEVIATION", -1.0)
    with pytest.raises(split.SplitAuditError):
        split.split_d1_raw(synthetic_d1(), (1, 2))


def test_split_d1_raw_returns_positions_into_original_frame():
    frame = synthetic_d1()
    frame = pd.concat([frame, frame.iloc[:10]], ignore_index=True)  # 追加完全重复行
    parts, audit = split.split_d1_raw(frame, (1, 2, 3))
    used = np.concatenate([parts[n] for n in PARTITIONS])
    assert audit["dedup"]["duplicate_rows_removed"] >= 10
    assert len(used) == audit["dedup"]["rows_retained"] and used.max() < len(frame)
    assert audit["passed"] and audit["endpoint_group_overlap"] == 0


def test_stratified_three_way_is_disjoint():
    labels = np.array([0] * 900 + [1] * 100)
    parts = split.stratified_three_way(labels, 3)
    assert sum(len(v) for v in parts.values()) == 1000
    assert not np.intersect1d(parts["train"], parts["holdout"]).size


def test_train_sample_stays_inside_train_rows():
    labels = np.array([0, 1] * 500)
    train_rows = np.arange(0, 700)
    picked = eda.train_sample(train_rows, labels, 100, 1)
    assert len(picked) == 100 and np.isin(picked, train_rows).all()


def test_high_correlation_pairs_upper_triangle_only():
    corr = pd.DataFrame([[1, 0.99, 0.1], [0.99, 1, -0.97], [0.1, -0.97, 1]], index=list("abc"), columns=list("abc"))
    pairs = eda.high_correlation_pairs(corr, 0.95)
    assert pairs[["feature_a", "feature_b"]].values.tolist() == [["a", "b"], ["b", "c"]]


def test_common_views_share_columns_and_units():
    d1 = pd.DataFrame({"dur": [2.0], "sbytes": [100], "dbytes": [50], "Spkts": [4], "Dpkts": [1], "sttl": [62], "dttl": [252]})
    d2 = pd.DataFrame({"FLOW_DURATION_MILLISECONDS": [2000], "IN_BYTES": [100], "OUT_BYTES": [50], "IN_PKTS": [4],
                       "OUT_PKTS": [1], "MIN_TTL": [62], "MAX_TTL": [252]})
    a, b = datasets.common_view_d1(d1), datasets.common_view_d2(d2)
    assert list(a.columns) == list(b.columns) == list(datasets.COMMON_FEATURES)
    pd.testing.assert_frame_equal(a, b)


def test_stratified_assignment_balances_each_category():
    rng = np.random.default_rng(0)
    counts = pd.DataFrame({"A": rng.integers(0, 50, 60), "B": rng.integers(0, 50, 60)}, index=[f"g{i}" for i in range(60)])
    counts.iloc[0] = [0, 2000]  # 单个大组集中某一类
    assignment = pd.Series(split.assign_groups_stratified(counts, 1))
    for cat in counts.columns:
        shares = counts[cat].groupby(assignment).sum() / counts[cat].sum()
        assert set(shares.index) == set(PARTITIONS)
    assert split.assign_groups_stratified(counts, 1) == split.assign_groups_stratified(counts, 1)


def test_category_share_deviation_zero_for_perfect_split():
    labels = np.ones(20, dtype=int)
    cats = np.array(["A"] * 20)
    parts = {"train": np.arange(14), "validation": np.arange(14, 17), "holdout": np.arange(17, 20)}
    assert split.category_share_deviation(parts, cats, labels) == pytest.approx(0.0)
