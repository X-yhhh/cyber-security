from __future__ import annotations

import gc
import platform
import time
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
import torch
from sklearn.metrics import f1_score
from threadpoolctl import threadpool_limits

from .config import DATA_ROOT, ExperimentConfig, ROOT
from .data import (
    IDENTIFIERS,
    TARGET,
    endpoint_stress_split,
    deduplicate_v0_rows,
    hash_frame,
    load_raw,
    load_subset_audit,
    make_split,
    prepare_v0_features,
    split_audit,
    write_json,
)
from .eda import write_eda_artifacts
from .export import export_candidates
from .features import engineer_features, feature_view_manifest
from .metrics import binary_metrics, choose_threshold, timed_scores
from .models import fit_mlp, fit_sklearn_model, model_specs, predict_mlp, predict_scores
from .pipeline import _preprocessing_manifest
from .preprocessing import build_preprocessor, compare_preprocessing, normalize_for_pipeline


def _environment(device: torch.device, cfg: ExperimentConfig) -> dict:
    result = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scikit_learn": sklearn.__version__,
        "torch": torch.__version__,
        "torch_cuda_build": torch.version.cuda,
        "cuda_available": torch.cuda.is_available(),
        "device": str(device),
        "cpu_thread_limit": cfg.cpu_threads,
    }
    if torch.cuda.is_available():
        result.update({
            "gpu": torch.cuda.get_device_name(0),
            "gpu_memory_bytes": torch.cuda.get_device_properties(0).total_memory,
        })
    return result


def _model_comparison(metrics: pd.DataFrame, output: Path) -> None:
    metric_columns = ["precision", "recall", "macro_f1", "accuracy", "roc_auc"]
    table = metrics.loc[metrics["phase"] == "locked_test", ["model", *metric_columns]].drop_duplicates("model").set_index("model")
    table = table.rename(columns={"macro_f1": "f1"})
    table.to_csv(output / "model-comparison.csv")
    if table.empty:
        return
    fig, ax = plt.subplots(figsize=(max(11, len(table) * 0.85), 6))
    image = ax.imshow(table.to_numpy(dtype=float), cmap="YlGnBu", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(np.arange(len(table.columns)), labels=[column.upper() for column in table.columns])
    ax.set_yticks(np.arange(len(table.index)), labels=table.index)
    for row in range(table.shape[0]):
        for column in range(table.shape[1]):
            value = table.iloc[row, column]
            if pd.notna(value):
                ax.text(column, row, f"{value:.3f}", ha="center", va="center", fontsize=8)
    ax.set_title("Model comparison on locked test")
    fig.colorbar(image, ax=ax, label="score")
    fig.tight_layout()
    fig.savefig(output / "model-comparison.png", dpi=180)
    plt.close(fig)


def run_training_workflow(config: ExperimentConfig | None = None, data_root: Path = DATA_ROOT, output_root: Path | None = None) -> Path:
    """Run the auditable EDA -> preprocessing comparison -> feature/model workflow."""
    cfg = config or ExperimentConfig()
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for the MLP candidate; refusing CPU fallback")
    torch.set_num_threads(cfg.cpu_threads)
    limiter = threadpool_limits(limits=cfg.cpu_threads)
    try:
        device = torch.device("cuda:0")
        run_id = f"{cfg.experiment_name}-{time.strftime('%Y%m%d-%H%M%S')}"
        output = output_root or ROOT / "runs" / run_id
        output.mkdir(parents=True, exist_ok=False)

        raw, manifest = load_raw(data_root)
        manifest["subset_audit"] = load_subset_audit(data_root)
        manifest["eda"] = write_eda_artifacts(raw, output / "eda", cfg.seed)
        raw_v0 = prepare_v0_features(raw)
        raw, raw_v0, feature_duplicates = deduplicate_v0_rows(raw, raw_v0)
        engineered = engineer_features(raw_v0)
        manifest["duplicate_v0_feature_target_rows_removed"] = feature_duplicates
        manifest["rows_after_v0_deduplication"] = int(len(raw))
        manifest["label_counts_after_v0_deduplication"] = {str(k): int(v) for k, v in raw[TARGET].value_counts().sort_index().items()}
        manifest["model_input_data_fingerprint"] = hash_frame(engineered.assign(_target=raw[TARGET].to_numpy()))
        write_json(output / "dataset-manifest.json", manifest)
        write_json(output / "feature-view-manifest.json", feature_view_manifest(raw_v0, engineered))

        split = make_split(raw[TARGET], cfg.seed)
        audit = split_audit(raw, split, engineered)
        grouped, grouped_report = endpoint_stress_split(raw, cfg.seed)
        audit["endpoint_stress"] = grouped_report
        write_json(output / "split-audit.json", audit)
        feature_columns = list(engineered.columns)
        if TARGET in feature_columns or IDENTIFIERS.intersection(feature_columns) or len(feature_columns) <= 42:
            raise RuntimeError("engineered feature view must extend V0 without labels or identifiers")
        write_json(output / "feature-contract.json", {
            "contract_version": "unsw-flow-v2-engineered-1",
            "feature_order": feature_columns,
            "excluded_fields": sorted(IDENTIFIERS | {TARGET, "attack_cat"}),
            "raw_to_subset": manifest.get("raw_to_subset_mapping", {}),
        })

        y = raw[TARGET].to_numpy(dtype=np.int8)
        train_idx, valid_idx, test_idx = split["train"], split["validation"], split["test"]
        train_frame = engineered.iloc[train_idx].reset_index(drop=True)
        valid_frame = engineered.iloc[valid_idx].reset_index(drop=True)
        preprocessing_rows, selected_strategy = compare_preprocessing(
            train_frame, valid_frame, y[train_idx], y[valid_idx], feature_columns, cfg.seed,
        )
        write_json(output / "preprocessing-comparison.json", {
            "selected_strategy": selected_strategy,
            "test_used": False,
            "rows": preprocessing_rows,
        })
        pd.DataFrame(preprocessing_rows).to_csv(output / "preprocessing-comparison.csv", index=False)

        preprocessor = build_preprocessor(engineered, feature_columns, selected_strategy)
        x_train = preprocessor.fit_transform(normalize_for_pipeline(engineered.iloc[train_idx], feature_columns))
        x_valid = preprocessor.transform(normalize_for_pipeline(engineered.iloc[valid_idx], feature_columns))
        x_test = preprocessor.transform(normalize_for_pipeline(engineered.iloc[test_idx], feature_columns))
        for name, matrix in (("train", x_train), ("validation", x_valid), ("test", x_test)):
            values = matrix.data if hasattr(matrix, "tocsr") else matrix
            if not np.isfinite(values).all():
                raise RuntimeError(f"preprocessing yielded non-finite values in {name}")

        metrics_rows: list[dict] = []
        validation_scores: dict[str, np.ndarray] = {}
        records: dict[str, dict] = {}
        model_count = len(model_specs(cfg.seed, cfg)) + 1
        preprocessing_manifest = _preprocessing_manifest(preprocessor, feature_columns)
        parity_features = x_valid[:128].toarray() if hasattr(x_valid, "toarray") else x_valid[:128]
        for name, model in model_specs(cfg.seed, cfg).items():
            started = time.perf_counter()
            fit_sklearn_model(name, model, x_train, y[train_idx])
            duration = time.perf_counter() - started
            valid_scores, valid_latency = timed_scores(lambda matrix: predict_scores(name, model, matrix), x_valid)
            threshold, threshold_policy = choose_threshold(y[valid_idx], valid_scores, cfg.threshold_metric)
            test_scores, test_latency = timed_scores(lambda matrix: predict_scores(name, model, matrix), x_test)
            validation_scores[name] = valid_scores
            records[name] = {
                "threshold": threshold,
                "threshold_policy": threshold_policy,
                "threshold_info": threshold_policy,
                "training_seconds": duration,
                "runtime": "cpu",
            }
            metrics_rows.extend([
                {"model": name, "phase": "validation", "seed": cfg.seed, "device": "cpu", "training_seconds": duration, **binary_metrics(y[valid_idx], valid_scores, threshold), **valid_latency},
                {"model": name, "phase": "locked_test", "seed": cfg.seed, "device": "cpu", "training_seconds": duration, **binary_metrics(y[test_idx], test_scores, threshold), **test_latency},
            ])
            export_candidates(
                output,
                {name: {"model": model, "threshold_info": threshold_policy, "runtime": "cpu"}},
                feature_columns,
                preprocessor,
                manifest,
                audit,
                pd.DataFrame(metrics_rows),
                preprocessing_manifest,
                parity_features,
                input_contract_version="unsw-flow-v2-engineered-1",
            )
            del model
            gc.collect()

        mlp, mlp_info = fit_mlp(x_train, y[train_idx], x_valid, y[valid_idx], cfg, cfg.seed, device)
        valid_scores = predict_mlp(mlp, x_valid)
        test_scores = predict_mlp(mlp, x_test)
        threshold, threshold_policy = choose_threshold(y[valid_idx], valid_scores, cfg.threshold_metric)
        validation_scores["torch_mlp_cuda"] = valid_scores
        records["torch_mlp_cuda"] = {
            "threshold": threshold,
            "threshold_policy": threshold_policy,
            "threshold_info": threshold_policy,
            "training_seconds": mlp_info["training_seconds"],
            "runtime": "cuda",
        }
        metrics_rows.extend([
            {"model": "torch_mlp_cuda", "phase": "validation", "seed": cfg.seed, "device": "cuda:0", **mlp_info, **binary_metrics(y[valid_idx], valid_scores, threshold)},
            {"model": "torch_mlp_cuda", "phase": "locked_test", "seed": cfg.seed, "device": "cuda:0", **mlp_info, **binary_metrics(y[test_idx], test_scores, threshold)},
        ])
        export_candidates(
            output,
            {"torch_mlp_cuda": {"model": mlp, "threshold_info": threshold_policy, "runtime": "cuda"}},
            feature_columns,
            preprocessor,
            manifest,
            audit,
            pd.DataFrame(metrics_rows),
            preprocessing_manifest,
            parity_features,
            input_contract_version="unsw-flow-v2-engineered-1",
        )
        del mlp
        gc.collect()
        torch.cuda.empty_cache()

        ranked = sorted(records, key=lambda name: f1_score(y[valid_idx], validation_scores[name] >= records[name]["threshold"], zero_division=0), reverse=True)
        selected = ranked[:3]
        seed_rows = []
        for model_name in selected:
            for seed in (cfg.seed, cfg.seed + 1, cfg.seed + 2):
                if model_name == "torch_mlp_cuda":
                    started = time.perf_counter()
                    candidate, fit_info = fit_mlp(x_train, y[train_idx], x_valid, y[valid_idx], cfg, seed, device)
                    scores = predict_mlp(candidate, x_valid)
                    threshold, policy = choose_threshold(y[valid_idx], scores, cfg.threshold_metric)
                    seed_rows.append({"model": model_name, "phase": "three_seed_validation", "seed": seed, "device": "cuda:0", "training_seconds": time.perf_counter() - started, **binary_metrics(y[valid_idx], scores, threshold)})
                    del candidate
                    torch.cuda.empty_cache()
                    continue
                candidate = model_specs(seed, cfg).get(model_name)
                if candidate is None:
                    continue
                started = time.perf_counter()
                fit_sklearn_model(model_name, candidate, x_train, y[train_idx])
                scores = predict_scores(model_name, candidate, x_valid)
                threshold, policy = choose_threshold(y[valid_idx], scores, cfg.threshold_metric)
                seed_rows.append({"model": model_name, "phase": "three_seed_validation", "seed": seed, "device": "cpu", "training_seconds": time.perf_counter() - started, **binary_metrics(y[valid_idx], scores, threshold)})
                del candidate
                gc.collect()
        metrics = pd.DataFrame(metrics_rows + seed_rows)
        metrics.to_csv(output / "metrics.csv", index=False)
        _model_comparison(metrics, output)
        write_json(output / "model-selection.json", {"selected_for_three_seed_runs": selected, "validation_f1_ranking": ranked, "test_used_for_selection": False, "model_count": model_count})
        write_json(output / "run-config.json", {"run_id": run_id, "seed": cfg.seed, "config": cfg.__dict__, "environment": _environment(device, cfg), "feature_view": "v2_engineered", "preprocessing_strategy": selected_strategy, "model_count": model_count, "locked_test_evaluations": model_count})
        write_json(output / "run-summary.json", {"run_id": run_id, "candidate_only": True, "production_activated": False, "model_count": model_count, "selected_models": selected, "preprocessing_comparison": True, "eda": True, "feature_engineering": True, "candidate_export": True, "candidate_export_format": "ONNX plus train-fitted preprocessing manifest", "notes": ["The locked test is evaluated once per first-pass model.", "PCA and third-party gradient-boosting backends are follow-up experiments unless explicitly enabled."]})
        return output
    finally:
        limiter.unregister()
