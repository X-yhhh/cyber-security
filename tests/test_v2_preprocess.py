import numpy as np
import pandas as pd
import pytest

from cyber_training.v2 import features, preprocess
from cyber_training.v2.guard import LeakageError, SplitIndex


def raw_frame(n=600, seed=0):
    rng = np.random.default_rng(seed)
    data = {c: rng.random(n).astype("float32") * 100 for c in features.V0_RAW_COLUMNS}
    data["proto"] = rng.choice(["tcp", "udp", "arp"], n)
    data["service"] = rng.choice(["-", "dns", "http"], n)
    data["state"] = rng.choice(["fin", "con", "int"], n)
    data["dur"] = np.where(np.arange(n) % 50 == 0, 0.0, data["dur"])
    data["ct_ftp_cmd"] = np.where(np.arange(n) % 7 == 0, np.nan, data["ct_ftp_cmd"])
    frame = pd.DataFrame(data)
    frame["Label"] = (frame["sbytes"] + rng.normal(0, 10, n) > 70).astype("int8")
    return frame


def test_build_v0_order_rate_and_missing_contract():
    raw = raw_frame()
    view = features.build_v0(raw)
    assert list(view.columns) == list(features.V0_FEATURES) and len(view.columns) == 42
    assert view["rate"].isna().sum() == (raw["dur"] == 0).sum()
    with pytest.raises(features.FeatureContractError):
        features.build_v0(raw.drop(columns=["Sload"]))


@pytest.mark.parametrize("key", [s.key for s in preprocess.SCHEMES])
def test_every_scheme_fits_and_transforms(key):
    raw = raw_frame()
    view = features.build_v0(raw)
    pipe = preprocess.build_preprocessor(preprocess.SCHEME_BY_KEY[key], 1)
    out = pipe.fit_transform(view.iloc[:400])
    assert out.shape[0] == 400 and np.isfinite(out).all()
    assert pipe.transform(view.iloc[400:]).shape[1] == out.shape[1]


def test_resample_changes_only_training_matrix_ratio():
    x = np.random.default_rng(0).random((400, 5))
    y = np.array([1] * 40 + [0] * 360)
    xu, yu = preprocess.resample(x, y, preprocess.SCHEME_BY_KEY["P10"], 1)
    assert yu.sum() == 40 and (yu == 0).sum() == 120
    xs, ys = preprocess.resample(x, y, preprocess.SCHEME_BY_KEY["P11"], 1)
    assert (ys == 0).sum() == 360 and ys.sum() == 180


def test_run_one_rejects_non_training_rows_and_scores_validation():
    raw = raw_frame()
    view = features.build_v0(raw)
    labels = raw["Label"].to_numpy()
    split = SplitIndex(np.arange(0, 420), np.arange(420, 510), np.arange(510, 600))
    with pytest.raises(LeakageError):
        preprocess.run_one(preprocess.SCHEME_BY_KEY["P3"], "LR", 1, view, labels, np.arange(400, 450), split)
    row = preprocess.run_one(preprocess.SCHEME_BY_KEY["P3"], "LR", 1, view, labels, split.train, split)
    assert row["status"] == "ok" and 0 <= row["f1"] <= 1 and row["tp"] + row["fn"] == labels[split.validation].sum()


def test_binary_metrics_counts():
    y = np.array([0, 0, 1, 1])
    m = preprocess.binary_metrics(y, np.array([0.1, 0.6, 0.4, 0.9]))
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (1, 1, 1, 1)
    assert m["fpr"] == 0.5 and m["fnr"] == 0.5


def summary_frame(values):
    rows = []
    for scheme, per_model in values.items():
        for model, f1 in per_model.items():
            rows.append({"scheme": scheme, "model": model, "macro_f1_mean": f1, "f1_mean": f1,
                         **{f"{k}_mean": f1 for k in ("precision", "recall", "accuracy", "auc")}})
    return pd.DataFrame(rows)


def test_select_scheme_prefers_simpler_when_tied():
    summary = summary_frame({"P1": {"LR": 0.900, "RF": 0.950, "MLP": 0.920},
                             "P6": {"LR": 0.901, "RF": 0.950, "MLP": 0.921},
                             "P3": {"LR": 0.850, "RF": 0.950, "MLP": 0.900}})
    selection = preprocess.select_scheme(summary)
    assert selection["top_by_mean_macro_f1"] == "P6" and selection["selected_scheme"] == "P1"


def test_select_scheme_ignores_incomplete_schemes():
    summary = summary_frame({"P1": {"LR": 0.9, "RF": 0.9, "MLP": 0.9}, "P2": {"LR": 0.99, "RF": 0.99}})
    assert preprocess.select_scheme(summary)["selected_scheme"] == "P1"


def test_markdown_table_follows_reference_layout():
    summary = summary_frame({"P0": {"LR": 0.8}, "P1": {"LR": 0.9}})
    table = preprocess.markdown_table(summary, "LR", 1)
    lines = table.splitlines()
    assert lines[0].startswith("表 1") and lines[1].startswith("Table 1")
    assert lines[3] == "| 指标 | P0 | P1 |" and "**0.900**" in lines[5]
    assert [l.split("|")[1].strip() for l in lines[5:]] == ["Precision", "Recall", "F1-score", "Accuracy", "AUC"]


def test_resume_skips_completed(tmp_path):
    path = tmp_path / "runs.csv"
    preprocess.append_row(path, {"scheme": "P0", "model": "LR", "seed": 1, "status": "ok"})
    preprocess.append_row(path, {"scheme": "P1", "model": "LR", "seed": 1, "status": "failed", "error": "x"})
    assert preprocess.completed_keys(path) == {("P0", "LR", 1)}
