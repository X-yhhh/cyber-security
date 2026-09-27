import json

import numpy as np
import pandas as pd
import pytest

from cyber_training.v2 import feature_compare as fc
from cyber_training.v2 import features
from cyber_training.v2.guard import LeakageError, SplitIndex


def raw_frame(n=600, seed=0):
    rng = np.random.default_rng(seed)
    data = {c: rng.random(n).astype("float32") * 100 for c in features.V1_RAW_COLUMNS}
    data["proto"] = rng.choice(["tcp", "udp", "arp"], n)
    data["service"] = rng.choice(["-", "dns", "http"], n)
    data["state"] = rng.choice(["fin", "con", "int"], n)
    data["dsport"] = pd.array(rng.integers(0, 70000, n), dtype="Int64")
    data["dsport"][:3] = pd.NA
    data["ct_ftp_cmd"] = np.where(np.arange(n) % 7 == 0, np.nan, data["ct_ftp_cmd"])
    frame = pd.DataFrame(data)
    frame["Label"] = (frame["sbytes"] + frame["sttl"] + rng.normal(0, 10, n) > 110).astype("int8")
    return frame


def test_dsport_bucket_boundaries_and_missing():
    ports = pd.Series(pd.array([0, 1023, 1024, 49151, 49152, 65535, 65536, 538989345, None], dtype="Int64"))
    assert list(features.dsport_bucket(ports)) == [
        "well_known", "well_known", "registered", "registered", "dynamic", "dynamic", "missing", "missing", "missing"]


def test_build_v2_columns_order_and_engineered_values():
    raw = raw_frame()
    v2 = features.build_v2(raw)
    assert list(v2.columns) == list(features.V2_FEATURES)
    assert v2.columns[:42].tolist() == list(features.V0_FEATURES) and "dsport" not in v2.columns
    row = raw.iloc[5]
    assert v2["sbytes_per_spkt"].iloc[5] == pytest.approx(row["sbytes"] / (row["Spkts"] + 1), rel=1e-5)
    assert v2["ttl_diff"].iloc[5] == pytest.approx(row["sttl"] - row["dttl"], rel=1e-5)
    assert v2["bytes_rate"].iloc[5] == pytest.approx((row["sbytes"] + row["dbytes"]) / (row["dur"] + 1e-6), rel=1e-4)
    with pytest.raises(features.FeatureContractError):
        features.build_v1(raw.drop(columns=["dsport"]))


def test_redundancy_drops_greedy_by_correlation_and_mutual_information():
    # 链式冗余：dloss–Dpkts（0.98）先处理，删 MI 较低的 dloss；Spkts–Dpkts（0.97）再删 Spkts；dloss–Spkts 已失效。
    pairs = pd.DataFrame({"feature_a": ["dloss", "Spkts", "dloss"], "feature_b": ["Dpkts", "Dpkts", "Spkts"],
                          "spearman": [0.98, 0.97, 0.96]})
    mi = pd.Series({"dloss": 0.03, "Dpkts": 0.07, "Spkts": 0.04})
    assert features.redundancy_drops(pairs, mi, features.V2_FEATURES) == ["dloss", "spkts"]
    with pytest.raises(features.FeatureContractError):
        features.redundancy_drops(pairs, pd.Series({"dloss": 0.1}), features.V2_FEATURES)


def test_cumulative_importance_keeps_minimum_prefix():
    importance = pd.Series({"a": 50.0, "b": 30.0, "c": 19.5, "d": 0.5})
    assert features.cumulative_importance_keep(importance, 0.99) == ["a", "b", "c"]
    assert features.cumulative_importance_keep(importance, 0.5) == ["a"]


def test_run_one_rejects_non_training_rows_and_reports_pr_auc():
    raw = raw_frame()
    frame = features.build_v2(raw)
    labels = raw["Label"].to_numpy()
    split = SplitIndex(np.arange(0, 420), np.arange(420, 510), np.arange(510, 600))
    with pytest.raises(LeakageError):
        fc.run_one("V1", list(features.V1_FEATURES), "LightGBM", 1, frame, labels, np.arange(400, 450), split)
    row = fc.run_one("V1", list(features.V1_FEATURES), "RF", 1, frame, labels, split.train, split)
    assert row["status"] == "ok" and 0 <= row["pr_auc"] <= 1 and row["tp"] + row["fn"] == labels[split.validation].sum()
    assert row["n_features"] == 43


def test_define_views_only_fits_on_training_rows(monkeypatch):
    raw = raw_frame()
    frame = features.build_v2(raw)
    labels = raw["Label"].to_numpy()
    split = SplitIndex(np.arange(0, 420), np.arange(420, 510), np.arange(510, 600))
    monkeypatch.setitem(fc.LGBM_PARAMS, "n_estimators", 20)
    monkeypatch.setitem(fc.LGBM_PARAMS, "min_child_samples", 5)
    pairs = pd.DataFrame({"feature_a": ["swin"], "feature_b": ["dwin"], "spearman": [0.99]})
    mi = pd.Series({"swin": 0.04, "dwin": 0.03})
    views, notes, importance = fc.define_views(frame, labels, split, split.train, pairs, mi, 1)
    assert "dwin" not in views["V3"] and not set(features.RANDOM_ISN) & set(views["V3"])
    assert set(views["V3"]) <= set(views["V2"]) and notes["redundancy_dropped"] == ["dwin"]
    assert list(importance.index) == list(features.V2_FEATURES)
    with pytest.raises(LeakageError):
        fc.define_views(frame, labels, split, np.arange(400, 450), pairs, mi, 1)
    assert fc.diagnostic_view(views, "V2") == [c for c in views["V2"] if c not in features.TTL_FEATURES]


def summary_frame(values, seeds=3):
    rows = []
    for view, per_model in values.items():
        for model, f1 in per_model.items():
            rows.append({"view": view, "model": model, "macro_f1_mean": f1, "seeds": seeds})
    return pd.DataFrame(rows)


def test_select_view_prefers_v3_within_tie_and_rejects_incomplete():
    base = {"V0": {"RF": 0.930, "LightGBM": 0.934}, "V1": {"RF": 0.931, "LightGBM": 0.935},
            "V2": {"RF": 0.933, "LightGBM": 0.937}}
    near = summary_frame({**base, "V3": {"RF": 0.932, "LightGBM": 0.935}})
    assert fc.select_view(near, 3)["selected_view"] == "V3"
    far = summary_frame({**base, "V3": {"RF": 0.925, "LightGBM": 0.930}})
    result = fc.select_view(far, 3)
    assert result["selected_view"] == "V2" and result["top_by_mean_macro_f1"] == "V2"
    with pytest.raises(RuntimeError):
        fc.select_view(summary_frame({**base, "V3": {"RF": 0.93}}), 3)
    with pytest.raises(RuntimeError):
        fc.select_view(summary_frame({**base, "V3": {"RF": 0.93, "LightGBM": 0.93}}, seeds=2), 3)


def test_eda_must_match_split(tmp_path):
    eda = tmp_path / "eda-x"
    eda.mkdir()
    (eda / "run-config.json").write_text(json.dumps({"params": {"split_dir": "E:\\w\\runs\\split-a"}}), encoding="utf-8")
    pd.DataFrame({"feature_a": ["swin"], "feature_b": ["dwin"], "spearman": [0.99]}).to_csv(
        eda / "d1-high-correlation-pairs.csv", index=False)
    pd.Series({"swin": 0.1}, name="mutual_information").to_csv(eda / "d1-mutual-information.csv")
    pairs, mi = fc.load_eda_inputs(eda, tmp_path / "split-a")
    assert len(pairs) == 1 and mi["swin"] == 0.1
    with pytest.raises(LeakageError):
        fc.load_eda_inputs(eda, tmp_path / "split-b")


def test_resume_skips_completed(tmp_path):
    path = tmp_path / "runs.csv"
    fc.append_row(path, {"view": "V0", "model": "RF", "seed": 1, "status": "ok"})
    fc.append_row(path, {"view": "V1", "model": "RF", "seed": 1, "status": "failed", "error": "x"})
    assert fc.completed_keys(path) == {("V0", "RF", 1)}
