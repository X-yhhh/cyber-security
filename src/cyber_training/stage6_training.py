"""Train and evaluate stage-six candidates on endpoint-group-isolated data."""

from __future__ import annotations

import gc
import hashlib
import json
import platform
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import onnxruntime as ort
import pandas as pd
import sklearn
import torch
from sklearn.metrics import ConfusionMatrixDisplay, PrecisionRecallDisplay, RocCurveDisplay, f1_score
from threadpoolctl import threadpool_limits

from .config import DATA_ROOT, ExperimentConfig, ROOT
from .data import (
    TARGET,
    deduplicate_v0_rows,
    endpoint_group_ids,
    endpoint_stress_split,
    hash_frame,
    load_raw,
    load_subset_audit,
    prepare_v0_features,
    split_audit,
    write_json,
)
from .export import _export_sklearn, onnx_attack_scores
from .features import engineer_features
from .metrics import binary_metrics, choose_threshold
from .models import fit_sklearn_model, model_specs, predict_scores
from .pipeline import _cap_endpoint_split, _feature_pipeline, _normalize_for_pipeline, _preprocessing_manifest
from .stage5 import check_parity
from .stage_review import sha256


STAGE6_MODEL_ORDER = ("random_forest", "decision_tree", "extra_trees")


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _environment(cfg: ExperimentConfig) -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scikit_learn": sklearn.__version__,
        "torch": torch.__version__,
        "cpu_threads": cfg.cpu_threads,
        "device": "cpu",
        "cuda_used": False,
    }


def _verify_source_run(source: Path) -> dict[str, Any]:
    status_path = source / "stage5-status.json"
    checksum_path = source / "checksums.json"
    source_hash_path = source / "source-hashes.json"
    required = (status_path, checksum_path, source_hash_path, source / "candidates/index.json")
    if any(not path.is_file() for path in required):
        raise FileNotFoundError("stage-five delivery is missing required status, checksum, or index files")
    status = _read_json(status_path)
    if not (status.get("status") == "completed" and status.get("stage") == 5
            and status.get("delivery_ready") is True and status.get("candidate_only") is True
            and status.get("production_approved") is False):
        raise ValueError("source run is not a completed candidate-only stage-five delivery")

    checksums = _read_json(checksum_path)
    mismatches = [relative for relative, expected in checksums.items()
                  if not (source / relative).is_file() or sha256(source / relative) != expected]
    if mismatches:
        raise ValueError(f"stage-five checksum mismatch: {mismatches[:5]}")

    original_run = source.parent / status["source_run"]
    source_hashes = _read_json(source_hash_path)
    original_mismatches = [relative for relative, expected in source_hashes.items()
                           if not (original_run / relative).is_file() or sha256(original_run / relative) != expected]
    if original_mismatches:
        raise ValueError(f"stage-five source artifact mismatch: {original_mismatches[:5]}")

    index = _read_json(source / "candidates/index.json")
    model_map = index.get("models", {})
    if index.get("candidate_only") is not True or not set(STAGE6_MODEL_ORDER).issubset(model_map):
        raise ValueError("stage-five candidate index does not contain the selected stage-four models")
    for name in STAGE6_MODEL_ORDER:
        manifest = model_map[name]
        if manifest.get("candidate_only") is not True or manifest.get("production_approved") is not False:
            raise ValueError(f"source candidate escaped candidate-only boundary: {name}")

    selection = _read_json(source / "model-selection.json")
    selected = selection.get("selected_for_three_seed_runs", [])
    if tuple(selected) != STAGE6_MODEL_ORDER or selection.get("test_used_for_selection") is not False:
        raise ValueError(f"stage-six model set does not match reviewed validation ranking: {selected}")
    review_path = source / "source-review/stage34-review.json"
    historical_review = _read_json(review_path) if review_path.is_file() else {}
    return {
        "status": status,
        "checksums_verified": len(checksums),
        "source_hashes_verified": len(source_hashes),
        "source_run": status["source_run"],
        "selected_models": list(selected),
        "historical_same_test_exposure": historical_review.get("previous_same_test_exposure", []),
        "source_stage3_locked_test_models": historical_review.get("phase_counts", {}).get("locked_test", 0),
    }


def cap_endpoint_partitions(
    frame: pd.DataFrame,
    split: dict[str, np.ndarray],
    seed: int,
    max_rows: int,
) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    capped, sampling = _cap_endpoint_split(frame, split, seed, max_rows)
    groups = endpoint_group_ids(frame)
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        if set(groups[capped[left]]) & set(groups[capped[right]]):
            raise ValueError(f"sampled endpoint partitions overlap for {left}/{right}")
    for name, indices in capped.items():
        labels = set(map(int, frame.iloc[indices][TARGET].unique()))
        if labels != {0, 1}:
            raise ValueError(f"sampled endpoint partition {name} does not contain both labels")
    return capped, sampling


def _rank_by_validation(records: list[dict[str, Any]]) -> list[str]:
    return [item["model"] for item in sorted(
        records, key=lambda item: (-item["validation_binary_f1"], item["model"])
    )]


def _save_curves(y: np.ndarray, scores: np.ndarray, threshold: float, folder: Path) -> None:
    figure, axis = plt.subplots(figsize=(7, 6))
    RocCurveDisplay.from_predictions(y, scores, ax=axis)
    figure.tight_layout()
    figure.savefig(folder / "endpoint-holdout-roc.png", dpi=160)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(7, 6))
    PrecisionRecallDisplay.from_predictions(y, scores, ax=axis)
    figure.tight_layout()
    figure.savefig(folder / "endpoint-holdout-pr.png", dpi=160)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay.from_predictions(
        y, scores >= threshold, labels=[0, 1], display_labels=["Normal", "Attack"],
        ax=axis, colorbar=False,
    )
    figure.tight_layout()
    figure.savefig(folder / "endpoint-holdout-confusion.png", dpi=160)
    plt.close(figure)


def _write_comparison(records: list[dict[str, Any]], output: Path) -> None:
    rows = []
    for record in records:
        row = {
            "model": record["model"],
            "validation_binary_f1": record["validation_binary_f1"],
            "validation_macro_f1": record["validation_metrics"]["macro_f1"],
        }
        row.update({f"endpoint_holdout_{key}": value for key, value in record["endpoint_holdout_metrics"].items()
                    if key != "confusion_matrix"})
        row["endpoint_holdout_confusion_matrix"] = json.dumps(
            record["endpoint_holdout_metrics"]["confusion_matrix"], separators=(",", ":")
        )
        rows.append(row)
    table = pd.DataFrame(rows).sort_values("validation_binary_f1", ascending=False)
    table.to_csv(output / "model-comparison.csv", index=False)
    columns = ["validation_binary_f1", "endpoint_holdout_macro_f1", "endpoint_holdout_fpr", "endpoint_holdout_fnr"]
    matrix = table.set_index("model")[columns]
    figure, axis = plt.subplots(figsize=(9, 4.5))
    image = axis.imshow(matrix.to_numpy(dtype=float), cmap="YlGnBu", aspect="auto")
    axis.set_xticks(np.arange(len(columns)), labels=[column.replace("endpoint_holdout_", "holdout ").replace("validation_", "val ") for column in columns])
    axis.set_yticks(np.arange(len(matrix.index)), labels=matrix.index)
    for row in range(matrix.shape[0]):
        for column in range(matrix.shape[1]):
            axis.text(column, row, f"{matrix.iloc[row, column]:.4f}", ha="center", va="center", fontsize=8)
    figure.colorbar(image, ax=axis, label="score / rate")
    figure.tight_layout()
    figure.savefig(output / "model-comparison.png", dpi=160)
    plt.close(figure)


def _sha_sample(features: pd.DataFrame, labels: np.ndarray, indices: np.ndarray) -> str:
    frame = features.iloc[indices].reset_index(drop=True).copy()
    frame["_target"] = labels[indices]
    return hash_frame(frame)


def run_stage6_training(
    source_run: Path,
    output: Path,
    data_root: Path = DATA_ROOT,
    config: ExperimentConfig | None = None,
) -> dict[str, Any]:
    source_run, output, data_root = source_run.resolve(), output.resolve(), data_root.resolve()
    if output.exists() or output.is_relative_to(source_run):
        raise ValueError("stage-six output must be new and outside the source run")
    cfg = config or ExperimentConfig()
    source = _verify_source_run(source_run)
    output.mkdir(parents=True)
    status: dict[str, Any] = {
        "stage": 6,
        "status": "running",
        "candidate_only": True,
        "production_approved": False,
        "release_ready": False,
        "source_run": source_run.name,
        "selected_models": source["selected_models"],
        "completed_models": [],
        "original_locked_test_evaluations": 0,
        "endpoint_holdout_evaluations": 0,
        "preprocessing_refit": "endpoint-group-train only",
        "started_at": datetime.now().astimezone().isoformat(),
    }

    def progress(message: str) -> None:
        status["progress"] = message
        status["updated_at"] = datetime.now().astimezone().isoformat()
        write_json(output / "stage6-status.json", status)
        print(message, flush=True)

    try:
        progress("Verifying raw data, historical fingerprint, and deterministic endpoint partitions")
        data, dataset_manifest = load_raw(data_root)
        source_dataset = _read_json(source_run / "dataset-manifest.json")
        if dataset_manifest["data_fingerprint"] != source_dataset["data_fingerprint"]:
            raise ValueError("raw dataset fingerprint differs from stage five")
        dataset_manifest["subset_audit"] = load_subset_audit(data_root)
        v0 = prepare_v0_features(data)
        data, v0, feature_duplicates = deduplicate_v0_rows(data, v0)
        if feature_duplicates != source_dataset.get("duplicate_v0_feature_target_rows_removed"):
            raise ValueError("V0 feature/target deduplication count differs from stage five")
        if len(data) != source_dataset.get("rows_after_v0_deduplication"):
            raise ValueError("deduplicated row count differs from stage five")
        engineered = engineer_features(v0)
        feature_columns = list(engineered.columns)
        source_contract = _read_json(source_run / "feature-contract.json")
        if feature_columns != source_contract.get("feature_order"):
            raise ValueError("engineered input feature order differs from the reviewed candidate contract")

        seed = cfg.seed
        group_split, group_report = endpoint_stress_split(data, seed)
        if not group_report["evaluable"]:
            raise ValueError("endpoint-isolated split does not contain both classes in every partition")
        source_audit = _read_json(source_run / "split-audit.json")
        if group_report != source_audit.get("endpoint_stress"):
            raise ValueError("endpoint-group split differs from the audited deterministic split")
        group_ids = endpoint_group_ids(data)
        for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
            if set(group_ids[group_split[left]]) & set(group_ids[group_split[right]]):
                raise ValueError(f"endpoint group overlap detected for {left}/{right}")

        audit = split_audit(data, group_split, engineered)
        sampled_split, sampling = cap_endpoint_partitions(
            data, group_split, seed, cfg.endpoint_max_rows,
        )
        audit["endpoint_stress"] = group_report
        audit["endpoint_stress_sampling"] = sampling
        audit["random_split_exposure_reference"] = {
            key: source_audit.get(key, {}) for key in (
                "partitions", "exact_feature_target_overlap", "feature_vector_overlap", "endpoint_group_overlap"
            )
        }
        audit["historical_test_exposure"] = {
            "same_test_prior_runs": source["historical_same_test_exposure"],
            "source_stage3_locked_test_models": source["source_stage3_locked_test_models"],
            "stage5_locked_test_evaluations": source["status"].get("new_locked_test_evaluations", 0),
            "stage6_locked_test_evaluations": 0,
        }
        split_fingerprints = {
            name: hash_frame(data.iloc[ids].reset_index(drop=True))
            for name, ids in sampled_split.items()
        }
        sample_fingerprints = {
            name: _sha_sample(engineered, data[TARGET].to_numpy(dtype=np.int8), ids)
            for name, ids in sampled_split.items()
        }

        labels = data[TARGET].to_numpy(dtype=np.int8)
        progress("Fitting preprocessing on the capped endpoint-group training partition")
        transformer = _feature_pipeline(engineered, feature_columns)
        x_train = transformer.fit_transform(
            _normalize_for_pipeline(engineered.iloc[sampled_split["train"]], feature_columns)
        )
        x_valid = transformer.transform(
            _normalize_for_pipeline(engineered.iloc[sampled_split["validation"]], feature_columns)
        )
        x_test = transformer.transform(
            _normalize_for_pipeline(engineered.iloc[sampled_split["test"]], feature_columns)
        )
        for partition, matrix in (("train", x_train), ("validation", x_valid), ("endpoint test", x_test)):
            values = matrix.data if hasattr(matrix, "tocsr") else matrix
            if not np.isfinite(values).all():
                raise ValueError(f"non-finite transformed feature values in {partition}")
        preprocessing_manifest = _preprocessing_manifest(transformer, feature_columns)
        preprocessing_manifest["fit_scope"] = "endpoint_group_train_capped"
        preprocessing_manifest["training_rows"] = int(len(sampled_split["train"]))
        preprocessing_path = output / "preprocessing.json"
        write_json(preprocessing_path, preprocessing_manifest)
        preprocessing_sha = sha256(preprocessing_path)

        records: list[dict[str, Any]] = []
        candidate_map: dict[str, Any] = {}
        model_registry = model_specs(seed, cfg)
        training_limiter = threadpool_limits(limits=cfg.cpu_threads)
        try:
            for name in source["selected_models"]:
                progress(f"Training {name} on endpoint-group train rows; validation chooses threshold")
                model = model_registry.pop(name)
                started = time.perf_counter()
                fit_sklearn_model(name, model, x_train, labels[sampled_split["train"]])
                training_seconds = time.perf_counter() - started

                valid_scores = predict_scores(name, model, x_valid)
                threshold, threshold_policy = choose_threshold(
                    labels[sampled_split["validation"]], valid_scores, cfg.threshold_metric,
                )
                validation_metrics = binary_metrics(
                    labels[sampled_split["validation"]], valid_scores, threshold,
                )
                validation_binary_f1 = float(f1_score(
                    labels[sampled_split["validation"]], valid_scores >= threshold, zero_division=0,
                ))

                # The endpoint holdout is evaluated once per fitted candidate. It never selects a model or threshold.
                progress(f"Evaluating {name} once on the endpoint-group holdout")
                test_scores = predict_scores(name, model, x_test)
                endpoint_metrics = binary_metrics(
                    labels[sampled_split["test"]], test_scores, threshold,
                )
                endpoint_metrics["rows"] = int(len(sampled_split["test"]))
                plot_dir = output / name
                plot_dir.mkdir(exist_ok=True)
                _save_curves(labels[sampled_split["test"]], test_scores, threshold, plot_dir)

                candidate_dir = output / "candidates" / name
                candidate_dir.mkdir(parents=True)
                artifact, error = _export_sklearn(name, model, output, x_train.shape[1])
                if error or artifact is None:
                    raise RuntimeError(error or f"ONNX export missing for {name}")
                options = ort.SessionOptions()
                options.intra_op_num_threads = 1
                options.inter_op_num_threads = 1
                session = ort.InferenceSession(
                    str(artifact), sess_options=options, providers=["CPUExecutionProvider"],
                )
                valid_parity = x_valid[: min(8192, x_valid.shape[0])]
                dense_parity = valid_parity.toarray() if hasattr(valid_parity, "toarray") else np.asarray(valid_parity)
                expected = predict_scores(name, model, valid_parity)
                outputs = session.run(None, {session.get_inputs()[0].name: np.asarray(dense_parity, dtype=np.float32)})
                actual = onnx_attack_scores(name, outputs)
                parity = check_parity(expected, actual, threshold)
                parity.update({
                    "partition": "endpoint_validation",
                    "sample_sha256": hashlib.sha256(np.asarray(dense_parity, dtype=np.float32).tobytes()).hexdigest(),
                })
                write_json(candidate_dir / "parity.json", parity)
                write_json(candidate_dir / "preprocessing.json", preprocessing_manifest)
                artifact_sha = sha256(artifact)
                preprocessing_rel = "preprocessing.json"
                candidate_preprocessing_sha = sha256(candidate_dir / preprocessing_rel)
                if candidate_preprocessing_sha != preprocessing_sha:
                    raise ValueError("candidate preprocessing artifact differs from shared manifest")

                source_candidate = source_run / "candidates" / name / "model_manifest.json"
                source_candidate_manifest = _read_json(source_candidate)
                source_manifest_sha = sha256(source_candidate)
                manifest = {
                    "manifest_version": "1.0",
                    "model_key": "unsw-nb15-flow-binary",
                    "model_version": f"0.2.0-stage6-endpoint-{name}",
                    "algorithm": name,
                    "task_type": "binary-classification",
                    "candidate_only": True,
                    "production_approved": False,
                    "input_contract_version": source_contract["contract_version"],
                    "feature_order": transformer.get_feature_names_out().tolist(),
                    "source_feature_order": feature_columns,
                    "preprocessing": {
                        "description": "see preprocessing.json for exact endpoint-train-fitted parameters",
                        "fit_partition": "train",
                        "fit_scope": "endpoint_group_train_capped",
                        "artifact": preprocessing_rel,
                        "sha256": candidate_preprocessing_sha,
                    },
                    "label_mapping": {"0": "Normal", "1": "Attack"},
                    "threshold_policy": threshold_policy,
                    "dataset_fingerprint": dataset_manifest["data_fingerprint"],
                    "split_fingerprint": split_fingerprints,
                    "locked_test_metrics": None,
                    "endpoint_holdout_metrics": endpoint_metrics,
                    "training": {
                        "fit_partition": "endpoint_group_train_capped",
                        "training_rows": int(len(sampled_split["train"])),
                        "training_seconds": training_seconds,
                        "seed": seed,
                        "parameters": model.get_params(deep=False),
                    },
                    "training_runtime": {"python": platform.python_version(), "device": "cpu"},
                    "inference_runtime": {
                        "format": "ONNX",
                        "provider": "CPUExecutionProvider",
                        "required_package": "onnxruntime",
                        "version": ort.__version__,
                    },
                    "source_stage5_candidate": {
                        "model_version": source_candidate_manifest.get("model_version"),
                        "manifest_sha256": source_manifest_sha,
                        "historical_locked_test_binding": "not used for stage-six selection or evaluation",
                    },
                    "artifact": {
                        "status": "exported",
                        "format": "onnx",
                        "artifact": f"candidates/{name}/model.onnx",
                        "sha256": artifact_sha,
                        "bytes": artifact.stat().st_size,
                        "preprocessing_artifact": preprocessing_rel,
                        "preprocessing_sha256": candidate_preprocessing_sha,
                        "smoke_test": "passed",
                        "prediction_parity": parity,
                        "onnx_input": session.get_inputs()[0].name,
                        "onnx_outputs": [item.name for item in session.get_outputs()],
                    },
                }
                write_json(candidate_dir / "model_manifest.json", manifest)
                candidate_map[name] = manifest

                records.append({
                    "model": name,
                    "device": "cpu",
                    "seed": seed,
                    "training_rows": int(len(sampled_split["train"])),
                    "training_seconds": training_seconds,
                    "threshold_policy": threshold_policy,
                    "validation_binary_f1": validation_binary_f1,
                    "validation_metrics": validation_metrics,
                    "endpoint_holdout_metrics": endpoint_metrics,
                    "onnx_parity": parity,
                })
                status["completed_models"].append(name)
                status["endpoint_holdout_evaluations"] += 1
                write_json(candidate_dir / "validation-summary.json", {
                    "validation_binary_f1": validation_binary_f1,
                    "validation_metrics": validation_metrics,
                    "threshold_policy": threshold_policy,
                    "validation_rows": int(len(sampled_split["validation"])),
                })
                del model, valid_scores, test_scores, expected, actual, outputs, session
                gc.collect()
        finally:
            training_limiter.unregister()

        ranked = _rank_by_validation(records)
        write_json(output / "candidates/index.json", {"candidate_only": True, "models": candidate_map})
        write_json(output / "dataset-manifest.json", {
            **dataset_manifest,
            "duplicate_v0_feature_target_rows_removed": feature_duplicates,
            "rows_after_v0_deduplication": int(len(data)),
            "label_counts_after_v0_deduplication": {
                str(key): int(value) for key, value in data[TARGET].value_counts().sort_index().items()
            },
            "model_input_data_fingerprint": hash_frame(
                engineered.assign(_target=labels)
            ),
        })
        write_json(output / "feature-contract.json", source_contract)
        write_json(output / "split-audit.json", audit)
        write_json(output / "run-config.json", {
            "stage": 6,
            "source_run": source_run.name,
            "config": cfg.__dict__,
            "environment": _environment(cfg),
            "feature_view": "v2_engineered",
            "preprocessing_fit_partition": "endpoint_group_train_capped",
            "original_locked_test_evaluations": 0,
            "endpoint_holdout_evaluations": len(records),
            "split_fingerprints": split_fingerprints,
            "sample_fingerprints": sample_fingerprints,
            "selected_candidate_by_validation_binary_f1": ranked[0],
            "model_ranking_uses_endpoint_holdout": False,
        })
        write_json(output / "model-selection.json", {
            "validation_binary_f1_ranking": ranked,
            "selection_partition": "endpoint_group_validation",
            "selection_metric": "binary_f1",
            "endpoint_holdout_used_for_selection": False,
        })
        pd.DataFrame([{
            "model": record["model"],
            "phase": "endpoint_group_validation",
            "seed": seed,
            "device": "cpu",
            "training_seconds": record["training_seconds"],
            "validation_binary_f1": record["validation_binary_f1"],
            **record["validation_metrics"],
        } for record in records]).to_csv(output / "validation-metrics.csv", index=False)
        pd.DataFrame([{
            "model": record["model"],
            "phase": "endpoint_group_holdout_test",
            "seed": seed,
            "device": "cpu",
            "training_seconds": record["training_seconds"],
            **record["endpoint_holdout_metrics"],
        } for record in records]).to_csv(output / "endpoint-holdout-metrics.csv", index=False)
        _write_comparison(records, output)
        write_json(output / "stage6-results.json", {
            "stage": 6,
            "status": "completed",
            "candidate_only": True,
            "production_approved": False,
            "original_locked_test_evaluations": 0,
            "endpoint_holdout_evaluations": len(records),
            "records": records,
            "validation_binary_f1_ranking": ranked,
            "selected_candidate_by_validation_only": ranked[0],
        })

        source_code = {
            "stage6_training.py": sha256(Path(__file__)),
            "cli.py": sha256(Path(__file__).with_name("cli.py")),
            "pipeline.py": sha256(Path(__file__).with_name("pipeline.py")),
            "models.py": sha256(Path(__file__).with_name("models.py")),
            "export.py": sha256(Path(__file__).with_name("export.py")),
            "data.py": sha256(Path(__file__).with_name("data.py")),
            "features.py": sha256(Path(__file__).with_name("features.py")),
            "metrics.py": sha256(Path(__file__).with_name("metrics.py")),
        }
        write_json(output / "source-code-hashes.json", source_code)
        report_lines = [
            "# 第六阶段端点隔离训练与评估",
            "",
            f"源阶段五运行：`{source_run.name}`。",
            "本阶段只用第四阶段验证集排名前三的候选，在无序端点组互斥的 train/validation/holdout 上重新训练。",
            "每个分区最多分层抽取 100,000 行；预处理只在 endpoint train 拟合；阈值和模型排序只使用 endpoint validation 的二分类 F1。",
            "endpoint holdout test 每个候选只推理一次，未参与模型或阈值选择。阶段 1/3 的随机锁定测试没有重评。",
            "新候选、预处理配置和 ONNX parity 已生成；所有制品仍 candidate-only。Mac 联调、影子验证和人工审批不在本阶段训练产物范围内。",
            f"压力切分 feature-target 精确重叠为 0；纯特征向量重叠 train/test、train/validation、validation/test 分别为 {audit['feature_vector_overlap']['train:test']}、{audit['feature_vector_overlap']['train:validation']}、{audit['feature_vector_overlap']['validation:test']}，保留为泄漏审查注意项。",
            "",
            "| 模型 | 验证集二分类 F1 | Holdout Macro-F1 | Holdout FPR | Holdout FNR |",
            "|---|---:|---:|---:|---:|",
        ]
        for record in sorted(records, key=lambda item: item["validation_binary_f1"], reverse=True):
            holdout = record["endpoint_holdout_metrics"]
            report_lines.append(
                f"| {record['model']} | {record['validation_binary_f1']:.4f} | {holdout['macro_f1']:.4f} | {holdout['fpr']:.4%} | {holdout['fnr']:.4%} |"
            )
        report_lines.extend([
            "",
            f"按验证集二分类 F1 选出的候选：`{ranked[0]}`。holdout 指标用于报告，不参与选择。",
            "端点组只有 171 个，需把此压力集结果解释为有限端点集合上的压力诊断，不等同于大规模真实网络泛化保证。",
        ])
        (output / "stage6-report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

        hashes = {
            path.relative_to(output).as_posix(): sha256(path)
            for path in output.rglob("*") if path.is_file() and path.name not in {"checksums.json", "stage6-status.json"}
        }
        write_json(output / "checksums.json", hashes)
        _verify_source_run(source_run)
        status.update(
            status="completed",
            candidate_only=True,
            production_approved=False,
            release_ready=False,
            endpoint_holdout_evaluations=len(records),
            original_locked_test_evaluations=0,
            selected_candidate_by_validation_only=ranked[0],
            source_artifacts_unchanged=True,
        )
        progress("Stage-six endpoint training completed; candidates remain inactive")
        return status
    except Exception as exc:
        status.update(status="failed", error=f"{type(exc).__name__}: {str(exc)[:1800]}")
        progress("Stage-six training failed closed; partial artifacts are not a completed run")
        raise


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, default=DATA_ROOT)
    parser.add_argument("--seed", type=int, default=20260923)
    args = parser.parse_args()
    result = run_stage6_training(
        args.source_run, args.output, args.data_root,
        ExperimentConfig(seed=args.seed, experiment_name="stage6-endpoint-stress"),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
