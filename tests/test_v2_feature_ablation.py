import json

import numpy as np
import pandas as pd
import pytest

from cyber_training.v2 import feature_ablation as ab
from cyber_training.v2.datasets import DataIntegrityError

# 2026.09.0 交付视图 V3（runs/feature-20260927-1249/feature-views.json）
V3 = ["dur", "proto", "service", "sbytes", "dbytes", "rate", "sttl", "sload", "dload", "sloss", "dinpkt", "sjit",
      "djit", "tcprtt", "ackdat", "smean", "dmean", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
      "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "sbytes_per_spkt",
      "dbytes_per_dpkt", "sbytes_dbytes_ratio", "spkts_dpkts_ratio", "synack_ackdat_diff", "bytes_rate"]


def test_groups_change_one_factor_each():
    g = ab.define_groups(V3)
    assert [len(g[k]) for k in ("F0", "F1", "F2", "F3", "F4", "F5")] == [32, 30, 26, 26, 25, 23]
    assert all(s == "csv" for _, s in g["F0"]) and all(s == "csv" for _, s in g["F2"])
    f5 = dict(g["F5"])
    assert f5["service"] == "v4" and f5["proto"] == "csv"
    assert {c for c, s in f5.items() if s == "v4" and c != "service"} == {
        "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm"}
    removed = {"sttl", "ct_state_ttl", "sloss", "sjit", "djit", "dinpkt", "ct_flw_http_mthd", "ct_dst_sport_ltm",
               "ct_dst_src_ltm"}
    assert not removed & set(f5)


def test_group_view_renames_v4_columns():
    frame = pd.DataFrame({"dur": [1.0, 2.0], "service": ["-", "dns"], "service_v4": ["ssl", "-"],
                          "ct_srv_src": [9.0, 9.0], "ct_srv_src_v4": [1.0, 2.0]})
    view = ab.group_view(frame, [("dur", "csv"), ("service", "v4"), ("ct_srv_src", "v4")], np.array([1]))
    assert list(view.columns) == ["dur", "service", "ct_srv_src"]
    assert view.iloc[0].tolist() == [2.0, "-", 2.0]
    with pytest.raises(DataIntegrityError):
        ab.group_view(frame, [("sload", "v4")], np.array([0]))


def fake_runs():
    rows = []
    for gi, g in enumerate(ab.DESCRIPTIONS):
        for m in ab.MODELS:
            for s in ab.SEEDS[:2]:
                rows.append({"group": g, "model": m, "seed": s, "status": "ok", "macro_f1": 0.93 - gi * 0.001,
                             "pr_auc": 0.95, "fnr": 0.04, "fpr": 0.01 + s % 2 * 0.001, "macro_f1_at_0.5": 0.92,
                             "fnr_at_0.5": 0.1, "fpr_at_0.5": 0.005,
                             "category_recall": json.dumps({"DoS": 0.9, "Generic": 0.99}),
                             "top15_gain": json.dumps({"sbytes": 10.0, "dur": 5.0}), "top1_over_top2": 2.0})
    return pd.DataFrame(rows)


def test_gate_check_and_render():
    runs = fake_runs()
    checks = {c["metric"]: c["passed"] for c in ab.gate_check(ab.summarize(runs))}
    assert checks == {"macro_f1": True, "fnr": True, "fpr": True, "pr_auc": True, "fnr_std": True}
    gen = pd.DataFrame([{"view": "含 TTL（9 项）", "test": "D2 验证", "rows": 10, "macro_f1": 0.5, "roc_auc": 0.6,
                         "fnr": 0.3, "fpr": 0.2}])
    md = ab.render(runs, gen, {"train_rows": 100, "val_rows": 20, "features": {g: 1 for g in ab.DESCRIPTIONS}})
    for heading in ("## 2. XGBoost", "## 3. 各攻击类召回", "## 5. 观测点变化的代价", "## 6. 泛化对照"):
        assert heading in md
    assert "F2→F3" in md and "通过" in md
