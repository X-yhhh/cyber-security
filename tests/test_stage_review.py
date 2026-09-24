import copy
import json

import numpy as np
import pandas as pd
import pytest

from cyber_training.metrics import binary_metrics
from cyber_training.pipeline import _preprocessing_manifest
from cyber_training.preprocessing import build_preprocessor, normalize_for_pipeline
from cyber_training.stage_review import MODELS, artifact_path, summarize_stability, validate_rows
from cyber_training.validation_latency import transform_saved


def fixture():
    labels = np.array([0, 0, 1, 1])
    rows = []
    for model in MODELS:
        for phase in ("validation", "locked_test"):
            rows.append({"model": model, "phase": phase, "seed": 7, "training_seconds": 1, "rows": "4.0",
                         **binary_metrics(labels, np.array([0.1, 0.2, 0.8, 0.9]), 0.5)})
    for model in MODELS[:3]:
        for seed in (7, 8, 9):
            rows.append({"model": model, "phase": "three_seed_validation", "seed": seed, "training_seconds": seed - 6,
                         **binary_metrics(labels, np.array([0.1, 0.2, 0.8, 0.9]), 0.5)})
    audit = {"partitions": {key: {"rows": 4, "label_counts": {"0": 2, "1": 2}} for key in ("validation", "test")}}
    selection = {"test_used_for_selection": False, "selected_for_three_seed_runs": list(MODELS[:3]), "validation_f1_ranking": list(MODELS)}
    return rows, {"seed": 7}, selection, audit


def test_complete_grid_produces_sample_std():
    rows, selected = validate_rows(*fixture())
    summary = summarize_stability(rows, selected)
    assert summary[0]["training_seconds_mean"] == 2
    assert summary[0]["training_seconds_std"] == 1
    assert summary[0]["binary_f1_mean"] == 1


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "metric", "selection", "seed", "test_selection"])
def test_review_rejects_invalid_experiment_evidence(mutation):
    rows, config, selection, audit = fixture()
    if mutation == "missing":
        rows.pop()
    elif mutation == "duplicate":
        rows.append(copy.deepcopy(rows[-1]))
    elif mutation == "metric":
        rows[-1]["accuracy"] = 0.5
    elif mutation == "selection":
        selection["selected_for_three_seed_runs"] = list(MODELS[1:4])
    elif mutation == "seed":
        rows[-1]["seed"] = 999
    else:
        selection["test_used_for_selection"] = True
    with pytest.raises(ValueError):
        validate_rows(rows, config, selection, audit)


def test_manifest_transform_matches_train_fitted_transformer_on_unseen_values():
    train = pd.DataFrame({"amount": [1.0, np.nan, 4.0, 8.0], "proto": ["tcp", "udp", "tcp", "tcp"]})
    valid = pd.DataFrame({"amount": [np.nan, 10.0], "proto": ["unknown", "tcp"]})
    columns = list(train.columns)
    transformer = build_preprocessor(train, columns, "standard")
    transformer.fit(normalize_for_pipeline(train, columns))
    manifest = json.loads(json.dumps(_preprocessing_manifest(transformer, columns)))
    expected = transformer.transform(normalize_for_pipeline(valid, columns))
    if hasattr(expected, "toarray"):
        expected = expected.toarray()
    np.testing.assert_allclose(transform_saved(valid, manifest), expected, rtol=1e-6, atol=1e-6)
    with pytest.raises(ValueError):
        transform_saved(valid[list(reversed(columns))], manifest)
    invalid = valid.copy()
    invalid.loc[0, "proto"] = None
    with pytest.raises(ValueError, match="categorical missing"):
        transform_saved(invalid, manifest)


def test_manifest_artifact_cannot_escape_run(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("x")
    run = tmp_path / "run"
    run.mkdir()
    with pytest.raises(ValueError):
        artifact_path(run, "../outside")
