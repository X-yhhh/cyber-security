"""真实转换回归：覆盖五类曾失败的导出与冻结阈值下的连续分数一致性。"""
import numpy as np
import onnxruntime as ort
import pytest
from sklearn.datasets import make_classification

from cyber_training.config import ExperimentConfig
from cyber_training.export import _export_sklearn, onnx_attack_scores
from cyber_training.models import model_specs, predict_scores
from cyber_training.stage5 import check_parity
from cyber_training.validation_latency import transform_saved
from cyber_training.preprocessing import build_preprocessor, normalize_for_pipeline
from cyber_training.pipeline import _preprocessing_manifest


@pytest.mark.parametrize("name", ["svm_linear", "ada_boost", "decision_tree", "random_forest", "extra_trees"])
def test_export_scores_match_native_on_unseen_data(tmp_path, name):
    x, y = make_classification(n_samples=240, n_features=12, random_state=19)
    x = x.astype(np.float32)
    model = model_specs(7, ExperimentConfig(tree_n_estimators=5, tree_max_depth=4, tree_n_jobs=1))[name]
    model.fit(x[:160], y[:160])
    path, error = _export_sklearn(name, model, tmp_path, 12)
    assert error is None, error
    session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    actual = onnx_attack_scores(name, session.run(None, {"features": x[160:]}))
    expected = predict_scores(name, model, x[160:])
    assert check_parity(expected, actual, 0 if name == "svm_linear" else 0.5)["status"] == "passed"


def test_parity_rejects_threshold_crossing_within_numeric_tolerance():
    with pytest.raises(ValueError, match="decision_differences=1"):
        check_parity(np.array([0.500001]), np.array([0.499999]), 0.5)


def test_saved_preprocessor_preserves_training_float64():
    import pandas as pd
    train = pd.DataFrame({"value": [1.123456789, np.nan, 3.456789012, 8.7], "proto": ["a", "b", "a", "c"]})
    features = list(train.columns)
    transformer = build_preprocessor(train, features)
    expected = transformer.fit_transform(normalize_for_pipeline(train, features))
    if hasattr(expected, "toarray"):
        expected = expected.toarray()
    restored = transform_saved(train, _preprocessing_manifest(transformer, features), dtype=np.float64)
    np.testing.assert_array_equal(restored, expected)
