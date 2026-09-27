"""第 10 步（导出）的单元测试：契约推导、ONNX 图与 sklearn + XGBoost 的一致性、门槛判定与前置条件。"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest

pytest.importorskip("onnxruntime")
pytest.importorskip("onnxmltools")

from cyber_training.v2 import export as ex
from cyber_training.v2.features import SUBSET_TO_RAW, V1_RAW_COLUMNS, build_v2
from cyber_training.v2.preprocess import SCHEME_BY_KEY, build_preprocessor

COLUMNS = ["dur", "proto", "service", "sbytes", "dbytes", "rate", "sttl", "sload", "ct_flw_http_mthd",
           "sbytes_per_spkt", "sbytes_dbytes_ratio", "synack_ackdat_diff", "bytes_rate"]


def synthetic_raw(n: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    data = {}
    for raw in V1_RAW_COLUMNS:
        if raw in ("proto", "service", "state"):
            continue
        data[raw] = rng.integers(0, 2000, n).astype(np.int64)
    data["dur"] = np.round(rng.exponential(0.5, n), 6)
    data["dur"][rng.random(n) < 0.1] = 0.0  # rate 缺失
    for raw in ("synack", "ackdat", "Sload"):
        data[raw] = rng.exponential(0.01 if raw != "Sload" else 1e6, n)
    http = rng.integers(0, 4, n).astype(np.float64)
    http[rng.random(n) < 0.4] = np.nan
    data["ct_flw_http_mthd"] = http
    data["proto"] = rng.choice(["tcp", "udp", "arp", "ospf"], n)
    data["service"] = rng.choice(["-", "dns", "http", "ftp"], n)
    data["state"] = rng.choice(["FIN", "INT", "CON"], n)
    return pd.DataFrame(data)


@pytest.fixture(scope="module")
def fitted():
    from xgboost import XGBClassifier

    raw = synthetic_raw(3000, 1)
    view = build_v2(raw)[COLUMNS]
    y = ((view["sbytes"] > 1000) ^ (view["proto"] == "udp")).astype(int).to_numpy()
    pre = build_preprocessor(SCHEME_BY_KEY["P1"], 0, COLUMNS).fit(view)
    model = XGBClassifier(n_estimators=40, max_depth=4, tree_method="hist", device="cpu").fit(pre.transform(view), y)
    return pre, model


def test_contract_matches_preprocessor(fitted):
    pre, _ = fitted
    c = ex.contract_from(pre, COLUMNS, 0.3)
    assert c.categorical_fields == ("proto", "service")
    assert set(c.numeric_fields) >= {"spkts", "dpkts", "synack", "ackdat"}  # 派生特征的依赖字段
    assert "rate" not in c.numeric_fields and "bytes_rate" not in c.numeric_fields
    assert c.indicator_columns == ("rate", "ct_flw_http_mthd")
    assert c.feature_names[-2:] == ("proto", "service")


def test_contract_rejects_other_schemes():
    view = build_v2(synthetic_raw(200, 2))[COLUMNS]
    scaled = build_preprocessor(SCHEME_BY_KEY["P3"], 0, COLUMNS).fit(view)
    with pytest.raises(ex.ExportError):
        ex.contract_from(scaled, COLUMNS, 0.5)
    pre = build_preprocessor(SCHEME_BY_KEY["P1"], 0, COLUMNS).fit(view)
    with pytest.raises(ex.ExportError):
        ex.contract_from(pre, list(reversed(COLUMNS)), 0.5)


def test_onnx_matches_sklearn_and_xgboost(fitted):
    pre, model = fitted
    c = ex.contract_from(pre, COLUMNS, 0.5)
    raw = synthetic_raw(2000, 3)
    raw.loc[:5, "proto"] = "unseen-proto"  # 词表外 → -1
    view = build_v2(raw)[COLUMNS]
    ref_features = pre.transform(view).astype(np.float32)
    ref_prob = model.predict_proba(ref_features)[:, 1].astype(np.float64)
    onx = ex.build_model(c, model, debug_features=True)
    result, prob, decision = ex.parity(ex.session(onx.SerializeToString()), ex.raw_inputs(raw, c), ref_prob, ref_features, 0.5)
    assert result["feature_nan_pattern_equal"] and result["feature_max_abs_diff"] == 0.0
    assert result["parity_max_abs_diff"] <= ex.PARITY_TOLERANCE
    assert result["decision_mismatches"] == 0
    assert np.array_equal(decision, prob >= 0.5)


def test_raw_inputs_fail_closed(fitted):
    pre, _ = fitted
    c = ex.contract_from(pre, COLUMNS, 0.5)
    raw = synthetic_raw(10, 4).drop(columns=[SUBSET_TO_RAW["spkts"]])
    with pytest.raises(ex.FeatureContractError):
        ex.raw_inputs(raw, c)


def test_export_gates_boundaries():
    ok = {"parity_max_abs_diff": 1e-4, "parity_decision_agreement": 1.0, "latency_p95_ms": 5.0,
          "batch_throughput_rows_per_s": 20_000.0}
    assert all(g["passed"] for g in ex.judge_export(ok))
    bad = {**ok, "parity_decision_agreement": 0.9999}
    assert [g["metric"] for g in ex.judge_export(bad) if not g["passed"]] == ["parity_decision_agreement"]


def test_verdict_must_pass_and_match_freeze(tmp_path, monkeypatch):
    monkeypatch.setattr(ex, "RUNS_ROOT", tmp_path)
    record = {"t1": {"model": "XGBoost", "threshold": 0.3}}
    with pytest.raises(ex.ExportError):
        ex.load_verdict(record, "abc")
    run = tmp_path / "final-eval-20260101-0000"
    run.mkdir()
    verdict = {"freeze_sha256": "abc", "passed_step9": False, "deliverable": "rejected", "candidate": "XGBoost", "threshold": 0.3}
    (run / "final-verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
    with pytest.raises(ex.ExportError):
        ex.load_verdict(record, "abc")
    verdict.update(passed_step9=True, deliverable="pending_export")
    (run / "final-verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
    with pytest.raises(ex.ExportError):
        ex.load_verdict(record, "other-freeze")
    assert ex.load_verdict(record, "abc")[0] == run


def test_run_rejects_other_candidate(monkeypatch):
    monkeypatch.setattr(ex, "load_freeze", lambda: ({"t1": {"model": "XGBoost"}}, "abc"))
    with pytest.raises(ex.FreezeError):
        ex.run(candidate="LightGBM")
