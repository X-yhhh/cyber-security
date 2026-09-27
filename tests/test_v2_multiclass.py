"""第 8b 步（T2 多分类）的单元测试：类别契约、类权重、SMOTE 只作用于训练行、指标、选型与模型封装。"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest

from cyber_training.v2 import multiclass as mc
from cyber_training.v2.features import V0_CATEGORICAL, V0_FEATURES


def test_encode_classes_fixed_order_and_rejects_unknown():
    assert list(mc.encode_classes(pd.Series(["Normal", "Worms", "DoS"]))) == [0, 9, 3]
    with pytest.raises(mc.ClassContractError):
        mc.encode_classes(pd.Series(["Normal", "Ransomware"]))
    with pytest.raises(mc.ClassContractError):
        mc.encode_classes(pd.Series(["Normal", None]))


def test_balanced_weights_equalize_class_mass():
    y = np.array([0] * 90 + [1] * 9 + [9] * 1)
    w = mc.balanced_weights(y)
    mass = [w[y == c].sum() for c in (0, 1, 9)]
    assert np.allclose(mass, mass[0]) and np.isclose(w.sum(), len(y))


def _toy_frame(n: int, seed: int = 0) -> tuple[pd.DataFrame, np.ndarray]:
    rng = np.random.default_rng(seed)
    y = rng.choice(len(mc.CLASSES), size=n, p=[0.4, 0.02, 0.02, 0.1, 0.15, 0.1, 0.1, 0.07, 0.02, 0.02])
    data = {}
    for col in V0_FEATURES:
        if col in V0_CATEGORICAL:
            data[col] = pd.Series(rng.choice(["tcp", "udp", "-"], n)).astype("string")
        else:
            data[col] = (rng.lognormal(2, 1, n) * (1 + y)).astype("float64")
    frame = pd.DataFrame(data)
    frame["spkts"] = rng.integers(1, 50, n).astype("int64")
    return frame, y.astype(np.int64)


def test_smote_augment_only_small_classes_and_keeps_contract():
    frame, y = _toy_frame(800)
    synth, y_synth = mc.smote_augment(frame, y, seed=1, target=60)
    counts = np.bincount(y, minlength=len(mc.CLASSES))
    after = counts + np.bincount(y_synth, minlength=len(mc.CLASSES))
    for c in range(len(mc.CLASSES)):
        assert after[c] == (60 if counts[c] < 60 else counts[c])
    assert list(synth.columns) == list(frame.columns)
    assert synth["spkts"].dtype == np.int64
    assert set(synth["proto"].unique()) <= {"tcp", "udp", "-"}
    assert (synth.drop(columns=list(V0_CATEGORICAL)) >= 0).all().all()


def test_smote_augment_noop_when_all_classes_large():
    frame, y = _toy_frame(400)
    synth, y_synth = mc.smote_augment(frame, y, seed=1, target=2)
    assert len(synth) == 0 and len(y_synth) == 0


def test_multiclass_metrics_macro_over_present_classes():
    y = np.array([0, 0, 1, 1, 2])
    prob = np.eye(len(mc.CLASSES))[[0, 0, 1, 0, 2]]
    summary, per_class, matrix = mc.multiclass_metrics(y, prob)
    assert matrix.shape == (10, 10) and matrix[1, 0] == 1
    assert summary["min_class_recall"] == pytest.approx(0.5)
    assert summary["balanced_accuracy"] == pytest.approx((1 + 0.5 + 1) / 3)
    assert per_class.set_index("class").loc["Worms", "support"] == 0


def test_select_best_prefers_no_smote_within_tie():
    rows = pd.DataFrame([
        {"model": "LightGBM", "variant": "cw", "status": "ok", "macro_f1": 0.600, "balanced_accuracy": 0.7},
        {"model": "LightGBM", "variant": "cw_smote", "status": "ok", "macro_f1": 0.602, "balanced_accuracy": 0.8},
        {"model": "RF", "variant": "cw", "status": "ok", "macro_f1": 0.550, "balanced_accuracy": 0.9},
        {"model": "MLP", "variant": "cw", "status": "failed", "macro_f1": np.nan, "balanced_accuracy": np.nan},
    ])
    result = mc.select_best(rows)
    assert result["top_by_macro_f1"] == {"model": "LightGBM", "variant": "cw_smote"}
    assert result["selected"] == {"model": "LightGBM", "variant": "cw"}
    assert mc.select_best(rows.assign(status="failed"))["selected"] is None


def test_latest_rows_drops_failures_that_later_succeeded():
    rows = pd.DataFrame([{"model": "RF", "variant": "cw", "status": "failed", "error": "x"},
                         {"model": "RF", "variant": "cw", "status": "ok", "error": ""},
                         {"model": "MLP", "variant": "cw", "status": "failed", "error": "y"}])
    out = mc.latest_rows(rows)
    assert len(out) == 2 and set(out.loc[out["status"] == "failed", "model"]) == {"MLP"}


def test_model_params_reuse_t1(tmp_path):
    studies = {m: {"params": {"k": m}} for m in ("XGBoost", "RF", "MLP")}
    (tmp_path / "tune-selection.json").write_text(json.dumps({"studies": studies}), encoding="utf-8")
    params = mc.model_params(tmp_path)
    assert params["RF"] == {"k": "RF"} and params["LightGBM"] == mc.T1_SCREEN_LIGHTGBM
    (tmp_path / "tune-selection.json").write_text(json.dumps({"studies": {"RF": {}}}), encoding="utf-8")
    with pytest.raises(ValueError):
        mc.model_params(tmp_path)


def _prepared(model: str):
    from cyber_training.v2.preprocess import build_preprocessor

    frame, y = _toy_frame(900)
    pre = build_preprocessor(mc.scheme_for(model), 1, list(V0_FEATURES))
    x = pre.fit_transform(frame.iloc[:700]).astype(np.float32)
    return {"x_train": x, "y_train": y[:700], "w_train": mc.balanced_weights(y[:700]),
            "x_val": pre.transform(frame.iloc[700:]).astype(np.float32), "y_val": y[700:], "synthetic_rows": 0}


@pytest.mark.parametrize("model, params", [
    ("LightGBM", dict(mc.T1_SCREEN_LIGHTGBM, n_estimators=30, early_stopping_rounds=5, num_leaves=7,
                      min_child_samples=5)),
    ("RF", {"n_estimators": 10, "max_depth": 8, "min_samples_leaf": 2, "max_features": "sqrt"}),
])
def test_cpu_models_fit_and_save(model, params, tmp_path):
    row, per_class, matrix, wrapper = mc.fit_and_score(model, params, _prepared(model))
    assert row["status"] == "ok" and 0 <= row["macro_f1"] <= 1 and matrix.sum() == 200
    assert all(p.exists() for p in wrapper.save(tmp_path))


def test_gpu_models_fit_and_save(tmp_path):
    torch = pytest.importorskip("torch")
    if not torch.cuda.is_available():
        pytest.skip("CUDA unavailable")
    xgb = {"n_estimators": 30, "learning_rate": 0.1, "max_depth": 3, "early_stopping_rounds": 5}
    mlp = {"width": 64, "layers": 2, "dropout": 0.1, "lr": 1e-3, "weight_decay": 1e-4, "batch_size": 64,
           "max_epochs": 3, "patience": 2}
    for model, params in (("XGBoost", xgb), ("MLP", mlp)):
        row, _, _, wrapper = mc.fit_and_score(model, params, _prepared(model))
        assert row["status"] == "ok" and row["best_iteration"] is not None
        assert wrapper.predict(_prepared(model)["x_val"]).shape == (200, len(mc.CLASSES))
        assert all(p.exists() for p in wrapper.save(tmp_path))
        mc.release(wrapper)


def test_module_never_references_holdout_loading():
    """官方测试文件是 T2 的锁定 holdout：本模块只能以常量名出现，不能被 load_cached 读取。"""
    import inspect

    source = inspect.getsource(mc)
    assert "load_cached(HOLDOUT_CACHE" not in source and "load_cached(\"d1_subset_test" not in source
