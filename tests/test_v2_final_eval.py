"""第 9 步（锁定评估）的单元测试：冻结前置条件、只解锁一次、门槛判定、指标与分类别检出率。"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest

from cyber_training.v2 import final_eval as fe
from cyber_training.v2.guard import HoldoutLockedError


def test_evaluate_requires_unlock_flag():
    with pytest.raises(HoldoutLockedError):
        fe.run_evaluate(unlock_holdout=False)


def test_evaluate_requires_committed_freeze(tmp_path, monkeypatch):
    monkeypatch.setattr(fe, "FREEZE_FILE", tmp_path / "missing.json")
    with pytest.raises(fe.FreezeError):
        fe.run_evaluate(unlock_holdout=True)


def test_freeze_refuses_to_overwrite(tmp_path, monkeypatch):
    existing = tmp_path / "pre-final-freeze.json"
    existing.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(fe, "FREEZE_FILE", existing)
    with pytest.raises(fe.FreezeError):
        fe.freeze()


def test_holdout_unlock_only_once(tmp_path):
    log = tmp_path / "audit.jsonl"
    fe.require_first_unlock("abc", log)  # 无记录：允许
    fe.append_audit({"event": "holdout_unlocked", "split_fingerprint": "abc"}, log)
    with pytest.raises(HoldoutLockedError):
        fe.require_first_unlock("abc", log)
    fe.require_first_unlock("other", log)  # 其他切分不受影响


def test_verify_files_detects_tampering(tmp_path):
    path = tmp_path / "model.txt"
    path.write_text("a", encoding="utf-8")
    digest = fe.sha256_file(path)
    fe.verify_files(tmp_path, {"model.txt": digest})
    path.write_text("b", encoding="utf-8")
    with pytest.raises(fe.FreezeError):
        fe.verify_files(tmp_path, {"model.txt": digest})
    with pytest.raises(fe.FreezeError):
        fe.verify_files(tmp_path, {"absent.pkl": digest})


def test_unsupported_candidate_rejected(tmp_path):
    with pytest.raises(fe.FreezeError):
        fe.T1Model("RF", tmp_path, {})


def test_judge_gates_boundaries():
    metrics = {"macro_f1": 0.92, "fnr": 0.05, "fpr": 0.0151, "pr_auc": 0.95, "roc_auc": 0.999}
    result = {g["metric"]: g["passed"] for g in fe.judge(metrics)}
    assert result == {"macro_f1": True, "fnr": True, "fpr": False, "pr_auc": True, "roc_auc": True}


def test_full_binary_metrics_values():
    y = np.array([0, 0, 0, 0, 1, 1])
    prob = np.array([0.1, 0.2, 0.7, 0.3, 0.8, 0.4])
    m = fe.full_binary_metrics(y, prob, 0.5)
    assert m["confusion"] == {"tn": 3, "fp": 1, "fn": 1, "tp": 1}
    assert m["fpr"] == pytest.approx(0.25) and m["fnr"] == pytest.approx(0.5)
    assert m["specificity"] == pytest.approx(0.75)
    assert -1.0 <= m["mcc"] <= 1.0


def test_category_recall_and_normal_fpr():
    cats = pd.Series(["Normal", "Normal", "DoS", "DoS", "Worms"])
    prob = np.array([0.9, 0.1, 0.9, 0.2, 0.6])
    table = fe.category_recall(cats, prob, 0.5).set_index("attack_cat")
    assert table.loc["DoS", "recall"] == pytest.approx(0.5) and table.loc["DoS", "missed"] == 1
    assert table.loc["Worms", "recall"] == pytest.approx(1.0)
    assert np.isnan(table.loc["Normal", "recall"]) and table.loc["Normal", "normal_flagged_rate"] == pytest.approx(0.5)


def test_threshold_sensitivity_includes_frozen_threshold():
    y = np.array([0, 1, 0, 1])
    prob = np.array([0.2, 0.8, 0.4, 0.6])
    table = fe.threshold_sensitivity(y, prob, 0.3082)
    assert table["threshold"].min() == pytest.approx(0.1) and table["threshold"].max() == pytest.approx(0.9)
    assert table["is_frozen_threshold"].sum() == 1
    assert table["threshold"].is_monotonic_increasing


def test_reproduction_tolerance():
    fe.check_reproduction({"a": 0.5}, {"a": 0.5 + 1e-5})
    with pytest.raises(fe.FreezeError):
        fe.check_reproduction({"a": 0.5}, {"a": 0.51})


def test_common_feature_mapping_units():
    d1 = pd.DataFrame({"dur": [2.0], "sbytes": [100], "dbytes": [50], "Spkts": [4], "Dpkts": [1], "sttl": [254],
                       "dttl": [30]})
    d2 = pd.DataFrame({"FLOW_DURATION_MILLISECONDS": [2000], "IN_BYTES": [100], "OUT_BYTES": [50], "IN_PKTS": [4],
                       "OUT_PKTS": [1], "MIN_TTL": [30], "MAX_TTL": [254]})
    a, b = fe._common(d1, "D1"), fe._common(d2, "D2")
    assert a.shape == (1, len(fe.COMMON_FEATURES))
    np.testing.assert_allclose(a, b)  # 同一条流：秒/字节单位统一后两边一致
    assert [f[0] for f in fe.FEATURE_MAP] == list(fe.COMMON_FEATURES)


def test_t3_params_are_lightgbm_screen_params():
    params = fe.t3_params()
    assert params["num_leaves"] == 127 and "early_stopping_rounds" in params


def test_generalization_rerun_requires_existing_verdict(monkeypatch, tmp_path):
    monkeypatch.setattr(fe, "load_freeze", lambda: ({"t1": {"model": "XGBoost"}}, "sha"))
    monkeypatch.setattr(fe, "load_manifest", lambda: (_raise(fe.FreezeError("stop")), None))
    with pytest.raises(fe.FreezeError):
        fe.run_evaluate(unlock_holdout=True, only_generalization=True, resume=tmp_path)


def _raise(exc):
    raise exc
