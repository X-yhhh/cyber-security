import numpy as np
from scipy.sparse import csr_matrix

from cyber_training.metrics import choose_threshold, binary_metrics
from cyber_training.metrics import timed_scores


def test_threshold_is_selected_using_validation_scores():
    threshold, record = choose_threshold(np.array([0, 0, 1, 1]), np.array([0.1, 0.3, 0.6, 0.8]))
    assert threshold == 0.6
    assert record["selected_on"] == "validation"


def test_threshold_ties_choose_value_nearest_default_cutoff():
    threshold, _ = choose_threshold(np.array([0, 0, 1, 1]), np.array([0.1, 0.3, 0.6, 0.8]))
    assert threshold == 0.6


def test_threshold_search_does_not_recompute_sklearn_metric_per_score(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("threshold search must use a vectorized sweep")

    monkeypatch.setattr("cyber_training.metrics.f1_score", fail)
    labels = np.tile(np.array([0, 1], dtype=np.int8), 5000)
    scores = np.linspace(0.0, 1.0, labels.size, dtype=np.float64)
    threshold, record = choose_threshold(labels, scores)
    assert 0.0 <= threshold <= 1.0
    assert record["selected_on"] == "validation"


def test_binary_metrics_has_required_operational_metrics():
    metrics = binary_metrics([0, 0, 1, 1], [0.1, 0.8, 0.6, 0.9], 0.5)
    assert {"accuracy", "precision", "recall", "macro_f1", "weighted_f1", "roc_auc", "pr_auc", "specificity", "fpr", "fnr", "mcc"} <= metrics.keys()
    assert metrics["confusion_matrix"] == [[1, 1], [0, 2]]


def test_timed_scores_supports_sparse_matrices():
    features = csr_matrix([[1.0, 0.0], [0.0, 1.0]])
    scores, timing = timed_scores(lambda matrix: np.asarray(matrix.sum(axis=1)).ravel(), features)
    assert scores.shape == (2,)
    assert timing["rows"] == 2
