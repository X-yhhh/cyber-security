from __future__ import annotations

import time

import numpy as np
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, matthews_corrcoef, precision_score, recall_score,
                             roc_auc_score)


def choose_threshold(y_true, scores, metric: str = "f1") -> tuple[float, dict]:
    y_true = np.asarray(y_true, dtype=np.int8)
    scores = np.asarray(scores, dtype=np.float64)
    if metric not in {"f1", "balanced_accuracy"}:
        raise ValueError(f"unsupported threshold metric: {metric}")
    if y_true.ndim != 1 or scores.ndim != 1 or len(y_true) != len(scores) or not len(scores):
        raise ValueError("labels and scores must be non-empty one-dimensional arrays of equal length")
    if not np.isfinite(scores).all() or not set(np.unique(y_true)).issubset({0, 1}):
        raise ValueError("threshold selection requires finite scores and binary labels")

    order = np.argsort(scores, kind="stable")[::-1]
    sorted_scores = scores[order]
    sorted_labels = y_true[order]
    group_ends = np.r_[np.flatnonzero(sorted_scores[:-1] != sorted_scores[1:]), len(scores) - 1]
    tp = np.cumsum(sorted_labels, dtype=np.int64)[group_ends]
    predicted_positive = group_ends + 1
    positives = int(y_true.sum())
    negatives = len(y_true) - positives
    fp = predicted_positive - tp
    fn = positives - tp
    tn = negatives - fp

    thresholds = sorted_scores[group_ends]
    thresholds = np.r_[thresholds, np.nextafter(sorted_scores[0], np.inf)]
    tp = np.r_[tp, 0]
    fp = np.r_[fp, 0]
    fn = np.r_[fn, positives]
    tn = np.r_[tn, negatives]
    if metric == "f1":
        values = np.divide(2 * tp, 2 * tp + fp + fn, out=np.zeros(len(tp), dtype=float), where=(2 * tp + fp + fn) > 0)
    else:
        tpr = np.divide(tp, positives, out=np.zeros(len(tp), dtype=float), where=positives > 0)
        tnr = np.divide(tn, negatives, out=np.zeros(len(tp), dtype=float), where=negatives > 0)
        values = (tpr + tnr) / 2
    best_value = float(values.max())
    tied = np.flatnonzero(np.isclose(values, best_value, rtol=0.0, atol=1e-15))
    chosen = max(tied, key=lambda index: float(thresholds[index]))
    threshold = float(thresholds[chosen])
    return threshold, {"metric": metric, "validation_metric": best_value, "threshold": threshold, "selected_on": "validation"}


def binary_metrics(y_true, scores, threshold: float) -> dict:
    y_true = np.asarray(y_true, dtype=int)
    scores = np.asarray(scores, dtype=float)
    predicted = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y_true, predicted)),
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "macro_f1": float(f1_score(y_true, predicted, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, predicted, average="weighted", zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, scores)) if len(np.unique(y_true)) == 2 else None,
        "pr_auc": float(average_precision_score(y_true, scores)) if len(np.unique(y_true)) == 2 else None,
        "specificity": float(tn / (tn + fp)) if tn + fp else 0.0,
        "fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
        "fnr": float(fn / (fn + tp)) if fn + tp else 0.0,
        "mcc": float(matthews_corrcoef(y_true, predicted)),
        "threshold": float(threshold),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def timed_scores(predict_fn, features):
    started = time.perf_counter()
    scores = predict_fn(features)
    elapsed = time.perf_counter() - started
    rows = int(features.shape[0]) if hasattr(features, "shape") else len(features)
    per_row_ms = elapsed * 1000 / max(1, rows)
    return scores, {"batch_seconds": elapsed, "per_row_ms": per_row_ms, "rows": rows}
