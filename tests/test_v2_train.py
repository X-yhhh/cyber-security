"""第 8 步（多模型训练与调优）的单元测试：阈值选择、候选筛选、选型规则、只在训练分区拟合与模型封装。"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from cyber_training.v2 import train
from cyber_training.v2.guard import HoldoutLockedError, SplitIndex


def test_threshold_meets_fnr_target_with_min_fpr():
    y = np.array([0] * 90 + [1] * 10)
    prob = np.concatenate([np.linspace(0.0, 0.5, 90), np.linspace(0.4, 1.0, 10)])
    threshold, met = train.select_threshold(y, prob, target_fnr=0.0)
    pred = prob >= threshold
    assert met and pred[y == 1].all()
    # 召回全部正类所需的最高阈值：再高一点就会漏报
    assert threshold == pytest.approx(prob[y == 1].min())


def test_threshold_falls_back_to_f1_when_target_unreachable():
    y = np.array([0, 0, 1, 1])
    prob = np.array([0.1, 0.9, 0.2, 0.8])
    threshold, met = train.select_threshold(y, prob, target_fnr=-1.0)
    assert not met and 0.0 < threshold <= 0.9


def test_threshold_requires_both_classes():
    with pytest.raises(ValueError):
        train.select_threshold(np.zeros(5), np.linspace(0, 1, 5))


def test_tune_candidates_top3_plus_mlp_and_skip_untunable():
    assert train.tune_candidates(["LightGBM", "XGBoost", "RF", "ET", "MLP"]) == ["LightGBM", "XGBoost", "RF", "MLP"]
    assert train.tune_candidates(["DT", "LightGBM", "MLP", "XGBoost", "LR"]) == ["LightGBM", "MLP", "XGBoost"]
    assert len(train.tune_candidates(list(train.MODELS))) <= train.TUNE_MAX


def _summary(**models):
    rows = []
    for name, (f1, fnr, fnr_std, fpr, lat, size) in models.items():
        rows.append({"model": name, "macro_f1_mean": f1, "fnr_mean": fnr, "fnr_std": fnr_std, "fpr_mean": fpr,
                     "latency_p95_ms_mean": lat, "model_bytes_mean": size})
    return pd.DataFrame(rows)


def test_select_final_prefers_faster_within_tie():
    summary = _summary(A=(0.940, 0.04, 0.005, 0.01, 2.0, 9e6), B=(0.938, 0.04, 0.005, 0.01, 0.5, 1e6),
                       C=(0.950, 0.08, 0.005, 0.01, 0.1, 1e5))
    result = train.select_final(summary)
    assert result["top_by_macro_f1"] == "A"  # C 的 FNR 超限被排除
    assert result["selected"] == "B"


def test_select_final_rejects_unstable_or_high_rate_models():
    summary = _summary(A=(0.95, 0.04, 0.03, 0.01, 1, 1), B=(0.95, 0.04, 0.01, 0.02, 1, 1))
    assert train.select_final(summary)["selected"] is None


def test_summarize_mean_std_and_constraint_flag():
    base = {c: 0.5 for c in train.SUMMARY_METRICS}
    rows = pd.DataFrame([
        {**base, "model": "A", "status": "ok", "fnr": 0.02, "constraint_met": True},
        {**base, "model": "A", "status": "ok", "fnr": 0.04, "constraint_met": False},
        {**base, "model": "A", "status": "failed", "fnr": 0.9, "constraint_met": True},
    ])
    s = train.summarize(rows).set_index("model").loc["A"]
    assert s["n"] == 2 and s["fnr_mean"] == pytest.approx(0.03) and s["fnr_std"] == pytest.approx(0.01)
    assert not s["constraint_met_all"]


def _toy(n: int = 600, seed: int = 0):
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.2).astype(np.int8)
    frame = pd.DataFrame({
        "sbytes": rng.lognormal(3, 1, n) * (1 + 3 * y), "dur": rng.random(n) + y, "sttl": rng.integers(0, 255, n),
        "proto": rng.choice(["tcp", "udp"], n), "service": rng.choice(["-", "http"], n),
    })
    order = rng.permutation(n)
    split = SplitIndex(order[:360], order[360:480], order[480:])
    return frame, y, split


def test_matrices_fit_only_on_train_and_holdout_locked():
    frame, y, split = _toy()
    m = train.Matrices(frame, y, split, list(frame.columns))
    data = m.get("P1", 1)
    assert data["x_train"].shape[0] == len(split.train) and data["x_val"].shape[0] == len(split.validation)
    assert np.array_equal(data["train_rows"], np.sort(split.train))
    x_sub, y_sub = m.subsample(data, 0.5, 1)
    assert len(y_sub) == len(split.train) // 2
    with pytest.raises(HoldoutLockedError):
        _ = split.holdout


@pytest.mark.parametrize("model", ["LR", "SVM", "GNB", "DT", "RF", "ET", "LightGBM"])
def test_cpu_models_fit_and_score(model):
    frame, y, split = _toy()
    m = train.Matrices(frame, y, split, list(frame.columns))
    params = dict(train.SCREEN_PARAMS[model])
    if model in ("RF", "ET"):
        params["n_estimators"] = 10
    if model == "LightGBM":
        params.update(n_estimators=50, early_stopping_rounds=10, num_leaves=7, min_child_samples=5)
    row, wrapper = train.fit_and_score(model, params, 1, m.get(train.scheme_for(model).key, 1))
    assert row["status"] == "ok" and 0.0 <= row["fnr"] <= 1.0 and row["latency_p95_ms"] > 0
    assert row["model_bytes"] > 0
    train.release(wrapper)


def test_gpu_models_fit_and_score(tmp_path):
    torch = pytest.importorskip("torch")
    if not torch.cuda.is_available():
        pytest.skip("CUDA unavailable")
    frame, y, split = _toy()
    m = train.Matrices(frame, y, split, list(frame.columns))
    xgb = dict(train.SCREEN_PARAMS["XGBoost"], n_estimators=50, early_stopping_rounds=10, max_depth=3)
    mlp = dict(train.SCREEN_PARAMS["MLP"], max_epochs=3, batch_size=64)
    for model, params in (("XGBoost", xgb), ("MLP", mlp)):
        row, wrapper = train.fit_and_score(model, params, 1, m.get(train.scheme_for(model).key, 1))
        assert row["status"] == "ok" and row["best_iteration"]
        assert all(p.exists() for p in wrapper.save(tmp_path))
        train.release(wrapper)


def test_search_spaces_cover_tunable_models():
    import optuna

    for model in train.TUNE_BUDGET:
        trial = optuna.trial.FixedTrial({
            "max_depth": 8 if model == "XGBoost" else 32, "learning_rate": 0.05, "min_child_weight": 2.0,
            "gamma": 0.0, "subsample": 0.8, "colsample_bytree": 0.8, "num_leaves": 63, "min_child_samples": 50,
            "reg_lambda": 1.0, "n_estimators": 150, "min_samples_leaf": 2, "max_features": "sqrt", "width": 256,
            "layers": 2, "dropout": 0.2, "lr": 1e-3})
        params = train.suggest(model, trial)
        assert set(train.SCREEN_PARAMS[model]) <= set(params)


def test_model_bytes_counts_large_sklearn_models():
    """树模型的 numpy 数组经协议 5 以 PickleBuffer 写出，体积统计不能依赖 len()。"""
    from sklearn.tree import DecisionTreeClassifier

    rng = np.random.default_rng(0)
    x, y = rng.normal(size=(2000, 5)), rng.integers(0, 2, 2000)
    wrapper = train.SklearnModel(DecisionTreeClassifier(random_state=0).fit(x, y))
    import pickle

    assert train.model_bytes(wrapper) == len(pickle.dumps(wrapper.estimator, protocol=pickle.HIGHEST_PROTOCOL))


def _rows(model: str, seeds: list[int], fnr: float) -> list[dict]:
    base = {k: 0.5 for k in train.SUMMARY_METRICS}
    return [{**base, "model": model, "seed": s, "status": "ok", "fnr": fnr, "fpr": 0.01, "macro_f1": 0.93,
             "constraint_met": True} for s in seeds]


def test_summarize_and_paper_table_render_all_models():
    rows = pd.DataFrame(_rows("XGBoost", [1, 2], 0.04) + _rows("MLP", [1, 2], 0.05)
                        + [{"model": "RF", "status": "failed", "seed": 1}])
    summary = train.summarize(rows).set_index("model")
    assert list(summary.index) == ["XGBoost", "MLP"] and (summary["n"] == 2).all()
    assert summary.loc["XGBoost", "fnr_std"] == 0.0
    table = train.paper_table(summary, ["XGBoost", "MLP"], 6, "初筛", "Screening", "_mean")
    assert "表 6" in table and "| FNR | **0.040** | 0.050 |" in table


def test_journal_storage_resumes_study(tmp_path):
    import optuna

    study = optuna.create_study(study_name="m", storage=train.journal_storage(tmp_path, "m"), direction="maximize")
    study.optimize(lambda t: t.suggest_float("x", 0, 1), n_trials=2)
    again = optuna.load_study(study_name="m", storage=train.journal_storage(tmp_path, "m"))
    assert len(again.trials) == 2
