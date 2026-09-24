from __future__ import annotations

import json
import gc
import os
import platform
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
import torch
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.metrics import ConfusionMatrixDisplay, PrecisionRecallDisplay, RocCurveDisplay, classification_report, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from threadpoolctl import threadpool_limits

from .config import DATA_ROOT, ExperimentConfig, ROOT
from .data import (IDENTIFIERS, TARGET, V0_FEATURES, endpoint_group_ids, endpoint_stress_split,
                   deduplicate_v0_rows, hash_frame, load_raw, load_subset_audit, make_split,
                   prepare_v0_features, split_audit, write_json)
from .metrics import binary_metrics, choose_threshold, timed_scores
from .models import fit_mlp, fit_sklearn_model, model_specs, predict_mlp, predict_scores

_THREADPOOL_LIMITER = None


def _categorical_columns(frame: pd.DataFrame, feature_columns: list[str]) -> list[str]:
    return [
        column for column in feature_columns
        if frame[column].dtype == "object"
        or str(frame[column].dtype).startswith(("string", "category"))
    ]


def _normalize_for_pipeline(frame: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    normalized = frame.loc[:, feature_columns].copy()
    for column in _categorical_columns(frame, feature_columns):
        normalized[column] = normalized[column].astype("string")
    return normalized


def _cap_endpoint_split(frame: pd.DataFrame, split: dict[str, np.ndarray], seed: int, max_rows: int) -> tuple[dict[str, np.ndarray], dict]:
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    capped = {}
    report = {}
    for offset, (name, ids) in enumerate(split.items()):
        ids = np.asarray(ids, dtype=int)
        if len(ids) <= max_rows:
            selected = ids
            sampled = False
        else:
            labels = frame.iloc[ids][TARGET]
            stratify = labels if labels.nunique() == 2 else None
            selected, _ = train_test_split(ids, train_size=max_rows, random_state=seed + offset, stratify=stratify)
            selected = np.sort(selected)
            sampled = True
        capped[name] = selected
        report[name] = {"original_rows": int(len(ids)), "evaluation_rows": int(len(selected)), "sampled": sampled}
    return capped, report


def _feature_pipeline(frame: pd.DataFrame, feature_columns: list[str]) -> ColumnTransformer:
    categorical = _categorical_columns(frame, feature_columns)
    numeric = [c for c in feature_columns if c not in categorical]
    numeric_pipe = Pipeline([("impute", SimpleImputer(strategy="median", add_indicator=True)), ("scale", StandardScaler())])
    category_pipe = Pipeline([("impute", SimpleImputer(strategy="most_frequent")), ("encode", OneHotEncoder(handle_unknown="ignore", sparse_output=True, dtype=np.float32))])
    return ColumnTransformer([("numeric", numeric_pipe, numeric), ("categorical", category_pipe, categorical)], remainder="drop", verbose_feature_names_out=True)


def _environment(device: torch.device) -> dict:
    info = {"python": platform.python_version(), "platform": platform.platform(), "numpy": np.__version__, "pandas": pd.__version__, "scikit_learn": sklearn.__version__, "torch": torch.__version__, "torch_cuda_build": torch.version.cuda, "cuda_available": torch.cuda.is_available(), "device": str(device), "cpu_thread_limit": torch.get_num_threads()}
    if torch.cuda.is_available():
        info["gpu"] = torch.cuda.get_device_name(0)
        info["gpu_capability"] = torch.cuda.get_device_capability(0)
        info["gpu_memory_bytes"] = torch.cuda.get_device_properties(0).total_memory
    return info


def _plot_curves(y, scores, prefix: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 6))
    RocCurveDisplay.from_predictions(y, scores, ax=ax)
    fig.tight_layout()
    fig.savefig(prefix.with_name(prefix.name + "-roc.png"), dpi=180)
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(7, 6))
    PrecisionRecallDisplay.from_predictions(y, scores, ax=ax)
    fig.tight_layout()
    fig.savefig(prefix.with_name(prefix.name + "-pr.png"), dpi=180)
    plt.close(fig)


def _plot_confusion(y, scores, threshold, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay.from_predictions(y, (scores >= threshold).astype(int), labels=[0, 1], display_labels=["Normal", "Attack"], ax=ax, colorbar=False)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _preprocessing_manifest(preprocess, feature_columns: list[str]) -> dict:
    numeric = preprocess.named_transformers_["numeric"]
    categorical = preprocess.named_transformers_["categorical"]
    numeric_imputer = numeric.named_steps["impute"]
    scaler = numeric.named_steps.get("scale")
    category_imputer = categorical.named_steps["impute"]
    encoder = categorical.named_steps["encode"]
    return {
        "format_version": "1.0",
        "fit_partition": "train",
        "input_feature_order": feature_columns,
        "numeric": {
            "feature_order": list(preprocess.transformers_[0][2]),
            "imputation": "median",
            "imputer_statistics": numeric_imputer.statistics_.tolist(),
            "missing_indicator_features": numeric_imputer.indicator_.features_.tolist(),
            "scaler": type(scaler).__name__ if scaler is not None else "none",
            "scaler_mean": scaler.mean_.tolist() if hasattr(scaler, "mean_") else None,
            "scaler_scale": scaler.scale_.tolist() if hasattr(scaler, "scale_") else None,
        },
        "categorical": {
            "feature_order": list(preprocess.transformers_[1][2]),
            "imputation": "most_frequent",
            "imputer_statistics": [str(value) for value in category_imputer.statistics_],
            "one_hot_categories": [[str(value) for value in categories] for categories in encoder.categories_],
            "unknown_category": "all_zero",
        },
        "encoded_feature_order": preprocess.get_feature_names_out().tolist(),
        "output_dtype": "float32",
    }


def _endpoint_stress_evaluation(frame: pd.DataFrame, features: pd.DataFrame, split: dict[str, np.ndarray], report: dict, feature_columns: list[str], cfg: ExperimentConfig, device: torch.device) -> dict:
    if not report["evaluable"]:
        return {"status": "not_evaluable", "reason": "an endpoint-isolated partition lacks one or more classes", **report}
    groups = endpoint_group_ids(frame)
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        if set(groups[split[left]]) & set(groups[split[right]]):
            raise RuntimeError(f"endpoint isolation failed for {left}/{right}")
    labels = frame[TARGET].to_numpy(dtype=np.int8)
    transformer = _feature_pipeline(features, feature_columns)
    evaluation_split, sampling_report = _cap_endpoint_split(frame, split, cfg.seed, cfg.endpoint_max_rows)
    matrices = {}
    for name in ("train", "validation", "test"):
        partition = _normalize_for_pipeline(features.iloc[evaluation_split[name]], feature_columns)
        matrices[name] = transformer.fit_transform(partition) if name == "train" else transformer.transform(partition)
    results = []
    for name, model in model_specs(cfg.seed, cfg).items():
        fit_sklearn_model(name, model, matrices["train"], labels[evaluation_split["train"]])
        validation_scores = predict_scores(name, model, matrices["validation"])
        threshold, policy = choose_threshold(labels[evaluation_split["validation"]], validation_scores, cfg.threshold_metric)
        test_scores = predict_scores(name, model, matrices["test"])
        results.append({"model": name, "device": "cpu", "threshold_policy": policy, "validation_metrics": binary_metrics(labels[evaluation_split["validation"]], validation_scores, threshold), "test_metrics": binary_metrics(labels[evaluation_split["test"]], test_scores, threshold)})
    mlp, fit_info = fit_mlp(matrices["train"], labels[evaluation_split["train"]], matrices["validation"], labels[evaluation_split["validation"]], cfg, cfg.seed, device)
    validation_scores = predict_mlp(mlp, matrices["validation"])
    threshold, policy = choose_threshold(labels[evaluation_split["validation"]], validation_scores, cfg.threshold_metric)
    test_scores = predict_mlp(mlp, matrices["test"])
    results.append({"model": "torch_mlp_cuda", "device": str(device), "fit": fit_info, "threshold_policy": policy, "validation_metrics": binary_metrics(labels[evaluation_split["validation"]], validation_scores, threshold), "test_metrics": binary_metrics(labels[evaluation_split["test"]], test_scores, threshold)})
    return {"status": "completed_sampled" if any(item["sampled"] for item in sampling_report.values()) else "completed", "protocol": "whole unordered endpoint-pair group isolation; diagnostic only", "used_for_primary_model_selection": False, "split": report, "evaluation_sampling": sampling_report, "results": results}


def run_experiment(config: ExperimentConfig | None = None, data_root: Path = DATA_ROOT, output_root: Path | None = None) -> Path:
    cfg = config or ExperimentConfig()
    global _THREADPOOL_LIMITER
    _THREADPOOL_LIMITER = threadpool_limits(limits=cfg.cpu_threads)
    torch.set_num_threads(cfg.cpu_threads)

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for the first-run MLP training; refusing CPU fallback")
    device = torch.device("cuda:0")
    run_id = f"{cfg.experiment_name}-{time.strftime('%Y%m%d-%H%M%S')}"
    out = output_root or ROOT / "runs" / run_id
    out.mkdir(parents=True, exist_ok=False)
    data, data_manifest = load_raw(data_root)
    data_manifest["subset_audit"] = load_subset_audit(data_root)
    raw_features = prepare_v0_features(data)
    data, raw_features, feature_duplicates = deduplicate_v0_rows(data, raw_features)
    data_manifest["duplicate_v0_feature_target_rows_removed"] = feature_duplicates
    data_manifest["rows_after_v0_deduplication"] = int(len(data))
    data_manifest["label_counts_after_v0_deduplication"] = {str(k): int(v) for k, v in data[TARGET].value_counts().sort_index().items()}
    data_manifest["model_input_data_fingerprint"] = hash_frame(raw_features.assign(_target=data[TARGET].to_numpy()))
    split = make_split(data[TARGET], cfg.seed)
    audit = split_audit(data, split, raw_features)
    grouped_split, grouped_report = endpoint_stress_split(data, cfg.seed)
    audit["endpoint_stress"] = grouped_report
    if any(audit["exact_feature_target_overlap"].values()):
        raise RuntimeError("V0 feature/target rows overlap across primary partitions")
    feature_columns = list(V0_FEATURES)
    if len(feature_columns) != 42 or TARGET in feature_columns or IDENTIFIERS.intersection(feature_columns):
        raise RuntimeError("V0 feature contract must contain exactly 42 non-identifier, non-target fields")
    write_json(out / "dataset-manifest.json", data_manifest)
    write_json(out / "split-audit.json", audit)
    write_json(out / "endpoint-stress-evaluation.json", _endpoint_stress_evaluation(data, raw_features, grouped_split, grouped_report, feature_columns, cfg, device))
    write_json(out / "feature-contract.json", {"contract_version": "unsw-flow-v0-raw-1", "feature_order": feature_columns, "excluded_fields": sorted(IDENTIFIERS | {TARGET, "attack_cat"}), "raw_to_subset": data_manifest.get("raw_to_subset_mapping", {})})
    y = data[TARGET].to_numpy(dtype=np.int8)
    train_idx, valid_idx, test_idx = split["train"], split["validation"], split["test"]
    x_train_raw, x_valid_raw, x_test_raw = (_normalize_for_pipeline(raw_features.iloc[idx], feature_columns) for idx in (train_idx, valid_idx, test_idx))
    y_train, y_valid, y_test = (y[idx] for idx in (train_idx, valid_idx, test_idx))
    preprocess = _feature_pipeline(raw_features, feature_columns)
    x_train = preprocess.fit_transform(x_train_raw)
    x_valid = preprocess.transform(x_valid_raw)
    x_test = preprocess.transform(x_test_raw)
    for partition_name, matrix in (("train", x_train), ("validation", x_valid), ("test", x_test)):
        values = matrix.data if hasattr(matrix, "tocsr") else matrix
        if not np.isfinite(values).all():
            raise RuntimeError(f"preprocessing yielded non-finite values in {partition_name}")

    metrics_rows = []
    validation_scores = {}
    model_records = {}
    run_metadata = {"run_id": run_id, "seed": cfg.seed, "config": cfg.__dict__, "environment": _environment(device), "split_fingerprint": {name: value["fingerprint"] for name, value in audit["partitions"].items()}, "feature_count_raw": len(feature_columns), "feature_count_encoded": int(x_train.shape[1]), "preprocessing_fit_partition": "train", "locked_test_evaluations": 0}
    write_json(out / "environment.json", run_metadata["environment"])
    write_json(out / "run-config.json", run_metadata)

    from .export import export_candidates
    preprocessing_manifest = _preprocessing_manifest(preprocess, feature_columns)
    parity_features = x_valid[:128].toarray() if hasattr(x_valid, "toarray") else x_valid[:128]

    for name, model in model_specs(cfg.seed, cfg).items():
        started = time.perf_counter()
        fit_sklearn_model(name, model, x_train, y_train)
        train_seconds = time.perf_counter() - started
        valid_scores, valid_latency = timed_scores(lambda matrix: predict_scores(name, model, matrix), x_valid)
        threshold, threshold_info = choose_threshold(y_valid, valid_scores, cfg.threshold_metric)
        test_scores, test_latency = timed_scores(lambda matrix: predict_scores(name, model, matrix), x_test)
        entry = {"model": model, "threshold": threshold, "threshold_info": threshold_info, "train_seconds": train_seconds, "latency": valid_latency, "runtime": "cpu"}
        validation_scores[name] = valid_scores
        model_records[name] = {key: value for key, value in entry.items() if key != "model"}
        metrics_rows.append({"model": name, "phase": "validation", "seed": cfg.seed, "training_seconds": train_seconds, "device": "cpu", **binary_metrics(y_valid, valid_scores, threshold), **valid_latency})
        metrics_rows.append({"model": name, "phase": "locked_test", "seed": cfg.seed, "training_seconds": train_seconds, "device": "cpu", **binary_metrics(y_test, test_scores, threshold), **test_latency})
        run_metadata["locked_test_evaluations"] += 1
        _plot_curves(y_test, test_scores, out / name)
        _plot_confusion(y_test, test_scores, threshold, out / f"{name}-confusion.png")
        pd.DataFrame(classification_report(y_test, test_scores >= threshold, labels=[0, 1], target_names=["Normal", "Attack"], output_dict=True, zero_division=0)).T.to_csv(out / f"{name}-classification-report.csv")
        export_candidates(out, {name: entry}, feature_columns, preprocess, data_manifest, audit, pd.DataFrame(metrics_rows), preprocessing_manifest, parity_features)
        del model
        gc.collect()

    mlp, mlp_fit = fit_mlp(x_train, y_train, x_valid, y_valid, cfg, cfg.seed, device)
    mlp_scores, mlp_latency = timed_scores(lambda x: predict_mlp(mlp, x), x_valid)
    mlp_threshold, mlp_threshold_info = choose_threshold(y_valid, mlp_scores, cfg.threshold_metric)
    mlp_test_scores, mlp_test_latency = timed_scores(lambda x: predict_mlp(mlp, x), x_test)
    validation_scores["torch_mlp_cuda"] = mlp_scores
    mlp_entry = {"model": mlp, "threshold": mlp_threshold, "threshold_info": mlp_threshold_info, "train_seconds": mlp_fit["training_seconds"], "latency": mlp_latency, "runtime": "cuda", "fit": mlp_fit}
    model_records["torch_mlp_cuda"] = {key: value for key, value in mlp_entry.items() if key != "model"}
    metrics_rows.append({"model": "torch_mlp_cuda", "phase": "validation", "seed": cfg.seed, "device": str(device), **mlp_fit, **binary_metrics(y_valid, mlp_scores, mlp_threshold), **mlp_latency})
    metrics_rows.append({"model": "torch_mlp_cuda", "phase": "locked_test", "seed": cfg.seed, "training_seconds": mlp_fit["training_seconds"], "device": str(device), **binary_metrics(y_test, mlp_test_scores, mlp_threshold), **mlp_test_latency})
    run_metadata["locked_test_evaluations"] += 1
    _plot_curves(y_test, mlp_test_scores, out / "torch_mlp_cuda")
    _plot_confusion(y_test, mlp_test_scores, mlp_threshold, out / "torch_mlp_cuda-confusion.png")
    pd.DataFrame(classification_report(y_test, mlp_test_scores >= mlp_threshold, labels=[0, 1], target_names=["Normal", "Attack"], output_dict=True, zero_division=0)).T.to_csv(out / "torch_mlp_cuda-classification-report.csv")
    export_candidates(out, {"torch_mlp_cuda": mlp_entry}, feature_columns, preprocess, data_manifest, audit, pd.DataFrame(metrics_rows), preprocessing_manifest, parity_features)
    del mlp
    gc.collect()
    torch.cuda.empty_cache()

    ranked = sorted(model_records, key=lambda name: f1_score(y_valid, validation_scores[name] >= model_records[name]["threshold"], zero_division=0), reverse=True)
    selected = ranked[:3]
    write_json(out / "model-selection.json", {"selected_for_three_seed_runs": selected, "validation_f1_ranking": ranked, "test_used_for_selection": False})

    seed_results = []
    for model_name in selected:
        primary = model_records[model_name]
        seed_results.append({"model": model_name, "seed": cfg.seed, "phase": "three_seed_validation", "training_seconds": primary["train_seconds"], "device": primary["runtime"], **binary_metrics(y_valid, validation_scores[model_name], primary["threshold"])})
        for seed in (cfg.seed + 1, cfg.seed + 2):
            if model_name == "torch_mlp_cuda":
                candidate, fit_info = fit_mlp(x_train, y_train, x_valid, y_valid, cfg, seed, device)
                valid_scores = predict_mlp(candidate, x_valid)
                threshold, _ = choose_threshold(y_valid, valid_scores, cfg.threshold_metric)
                duration = fit_info["training_seconds"]
                actual_device = str(device)
            else:
                candidate = model_specs(seed, cfg)[model_name]
                started = time.perf_counter(); fit_sklearn_model(model_name, candidate, x_train, y_train); duration = time.perf_counter() - started
                valid_scores = predict_scores(model_name, candidate, x_valid)
                threshold, _ = choose_threshold(y_valid, valid_scores, cfg.threshold_metric)
                actual_device = "cpu"
            seed_results.append({"model": model_name, "seed": seed, "phase": "three_seed_validation", "training_seconds": duration, "device": actual_device, **binary_metrics(y_valid, valid_scores, threshold)})
            del candidate
            gc.collect()
            torch.cuda.empty_cache()
    metrics_frame = pd.DataFrame(metrics_rows + seed_results)
    metrics_frame.to_csv(out / "metrics.csv", index=False)
    write_json(out / "metrics.json", {"records": metrics_frame.to_dict(orient="records"), "three_seed_validation_summary": _seed_summary(seed_results), "locked_test_evaluations": run_metadata["locked_test_evaluations"]})

    write_json(out / "run-config.json", run_metadata)
    write_json(out / "run-summary.json", {"run_id": run_id, "selected_models": selected, "model_ranking": ranked, "environment": run_metadata["environment"], "locked_test_evaluations": run_metadata["locked_test_evaluations"], "candidate_only": True, "production_activated": False, "notes": ["Primary split is stratified random and is not endpoint-isolated.", "Endpoint-pair split is a separate stress test due to the small endpoint universe.", "This run uses raw binary labels; official subset multiclass is not included."]})
    return out


def _seed_summary(records: list[dict]) -> dict:
    frame = pd.DataFrame(records)
    summary = {}
    for model, group in frame.groupby("model"):
        summary[model] = {}
        for column in ("accuracy", "precision", "recall", "macro_f1", "weighted_f1", "roc_auc", "pr_auc", "specificity", "fpr", "fnr", "mcc"):
            summary[model][column] = {"mean": float(group[column].mean()), "std": float(group[column].std(ddof=1))}
    return summary
