"""第五阶段候选交付：复用历史产物，按原配置重建缺失权重；禁止测试集重评和发布。"""
from __future__ import annotations

import argparse
import csv
import gc
import importlib.metadata
import json
import shutil
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort
from scipy import sparse
from threadpoolctl import threadpool_limits

from .config import DATA_ROOT, ExperimentConfig
from .data import TARGET, deduplicate_v0_rows, hash_frame, load_raw, make_split, prepare_v0_features, write_json
from .export import _export_sklearn, onnx_attack_scores
from .features import engineer_features
from .metrics import binary_metrics
from .models import fit_sklearn_model, model_specs, predict_scores
from .stage_review import MODELS, artifact_path, read_json, review_run, sha256
from .validation_latency import transform_saved

REBUILD = {"svm_linear", "ada_boost", "decision_tree", "random_forest", "extra_trees"}


def check_parity(expected, actual, threshold: float) -> dict:
    """分数误差与冻结阈值下的决策均须一致；禁止放宽阈值来掩盖转换误差。"""
    expected, actual = np.asarray(expected), np.asarray(actual)
    if expected.shape != actual.shape or not np.isfinite(actual).all():
        raise ValueError("invalid parity shape or non-finite scores")
    difference = int(np.count_nonzero((expected >= threshold) != (actual >= threshold)))
    error = float(np.max(np.abs(expected - actual)))
    if not np.allclose(expected, actual, rtol=1e-4, atol=1e-5) or difference:
        raise ValueError(f"ONNX parity failed: max_abs_error={error}, decision_differences={difference}")
    return {"status": "passed", "rows": len(expected), "max_abs_error": error,
            "decision_differences": difference, "rtol": 1e-4, "atol": 1e-5}


def restored_matrix(v0, indices, preprocessing):
    """分块恢复原 train-fitted float64 稀疏输入，避免全量稠密矩阵占满 16 GiB 主机。"""
    chunks = []
    for start in range(0, len(indices), 8192):
        frame = engineer_features(v0.iloc[indices[start:start + 8192]].reset_index(drop=True))
        chunks.append(sparse.csr_matrix(transform_saved(frame, preprocessing, dtype=np.float64)))
    return sparse.vstack(chunks, format="csr")


def _scores(session, name, matrix):
    """ONNX 验证推理限定有界批次，调用方只能传入验证分区。"""
    result = []
    for start in range(0, matrix.shape[0], 8192):
        batch = matrix[start:start + 8192].toarray().astype(np.float32)
        result.append(onnx_attack_scores(name, session.run(None, {session.get_inputs()[0].name: batch})))
    return np.concatenate(result)


def run_stage5(source: Path, output: Path, previous_runs: list[Path], data_root: Path = DATA_ROOT):
    """创建全新候选目录；保留原始记录，重建制品的历史测试指标仅作未绑定参考。"""
    source, output = source.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(source):
        raise ValueError("output must be new and outside source run")
    source_hashes = {str(p.relative_to(source)): sha256(p) for p in source.rglob("*") if p.is_file()}
    output.mkdir(parents=True)
    status = {"status": "running", "stage": 5, "source_run": source.name,
              "started_at": datetime.now().astimezone().isoformat(), "candidate_only": True,
              "production_approved": False, "new_locked_test_evaluations": 0, "completed_models": []}
    def progress(message):
        status["progress"] = message
        status["updated_at"] = datetime.now().astimezone().isoformat()
        write_json(output / "stage5-status.json", status)
        print(message, flush=True)
    try:
        progress("Auditing source experiment and SHA-256 before any fitting")
        review = review_run(source, output / "source-review", previous_runs)
        config = read_json(source / "run-config.json")
        cfg = ExperimentConfig(**config["config"])
        for package, field in (("numpy", "numpy"), ("pandas", "pandas"), ("scikit-learn", "scikit_learn")):
            if importlib.metadata.version(package) != config["environment"][field]:
                raise ValueError(f"source training runtime mismatch: {package}")
        dataset, audit = read_json(source / "dataset-manifest.json"), read_json(source / "split-audit.json")
        with (source / "metrics.csv").open(encoding="utf-8-sig", newline="") as stream:
            metrics = list(csv.DictReader(stream))
        source_manifests = {name: read_json(source / "candidates" / name / "model_manifest.json") for name in MODELS}
        blocked = {name for name, m in source_manifests.items() if m["artifact"]["status"] == "blocked"}
        if blocked != REBUILD:
            raise ValueError(f"unexpected reconstruction scope: {sorted(blocked)}")
        saved = source_manifests["torch_mlp_cuda"]["artifact"]
        pre_path = artifact_path(source, saved["preprocessing_artifact"])
        if sha256(pre_path) != saved["preprocessing_sha256"]:
            raise ValueError("preprocessing checksum mismatch")
        preprocessing = read_json(pre_path)
        for name, manifest in source_manifests.items():
            if manifest["artifact"]["status"] == "exported" and manifest["artifact"]["preprocessing_sha256"] != saved["preprocessing_sha256"]:
                raise ValueError(f"nonshared preprocessing: {name}")
        for name in MODELS:
            if source_manifests[name]["feature_order"] != preprocessing["encoded_feature_order"]:
                raise ValueError(f"feature contract mismatch: {name}")
        for name in ("metrics.csv", "model-comparison.csv", "model-comparison.png", "dataset-manifest.json",
                     "split-audit.json", "feature-contract.json", "feature-view-manifest.json",
                     "preprocessing-comparison.csv", "preprocessing-comparison.json", "model-selection.json", "run-config.json"):
            shutil.copy2(source / name, output / name)
        shutil.copytree(source / "eda", output / "eda")
        progress("Verifying raw hashes, deduplication and fixed partitions; no test inference")
        raw, observed = load_raw(data_root)
        if observed["data_fingerprint"] != dataset["data_fingerprint"]:
            raise ValueError("dataset fingerprint mismatch")
        raw, v0, removed = deduplicate_v0_rows(raw, prepare_v0_features(raw))
        if removed != dataset["duplicate_v0_feature_target_rows_removed"] or len(raw) != dataset["rows_after_v0_deduplication"]:
            raise ValueError("deduplication mismatch")
        split = make_split(raw[TARGET], cfg.seed)
        for partition, ids in split.items():
            if hash_frame(raw.iloc[ids].reset_index(drop=True)) != audit["partitions"][partition]["fingerprint"]:
                raise ValueError(f"split fingerprint mismatch: {partition}")
        train_y = raw[TARGET].to_numpy()[split["train"]].copy()
        valid_y = raw[TARGET].to_numpy()[split["validation"]].copy()
        del raw
        gc.collect()
        progress("Restoring train/validation matrices from saved parameters without preprocessing fit")
        train_x = restored_matrix(v0, split["train"], preprocessing)
        valid_x = restored_matrix(v0, split["validation"], preprocessing)
        del v0, split
        gc.collect()
        parity_x = valid_x[:8192]
        sample_hash = __import__("hashlib").sha256(parity_x.toarray().astype(np.float32).tobytes()).hexdigest()
        candidates = {}
        parity_records = {}
        with threadpool_limits(limits=cfg.cpu_threads):
            for name in MODELS:
                started = time.perf_counter()
                original = source_manifests.pop(name)
                directory = output / "candidates" / name
                directory.mkdir(parents=True)
                threshold = float(original["threshold_policy"]["threshold"])
                if name in REBUILD:
                    progress(f"Reconstructing {name}: original seed/config, train partition only")
                    model = model_specs(cfg.seed, cfg)[name]
                    fit_sklearn_model(name, model, train_x, train_y)
                    fit_seconds = time.perf_counter() - started
                    valid_scores = predict_scores(name, model, valid_x)
                    native_metrics = binary_metrics(valid_y, valid_scores, threshold)
                    historical = next(row for row in metrics if row["model"] == name and row["phase"] == "validation")
                    validation_check = {
                        "confusion_matrix_matches": native_metrics["confusion_matrix"] == json.loads(historical["confusion_matrix"]),
                        "original_threshold": threshold,
                        "metric_deltas": {key: float(native_metrics[key]) - float(historical[key])
                                          for key in ("accuracy", "macro_f1", "roc_auc", "pr_auc")},
                    }
                    artifact, error = _export_sklearn(name, model, output, train_x.shape[1])
                    if error:
                        raise RuntimeError(error)
                else:
                    progress(f"Reusing hash-verified {name} ONNX and recorded native parity")
                    artifact = directory / "model.onnx"
                    shutil.copy2(artifact_path(source, original["artifact"]["artifact"]), artifact)
                    if sha256(artifact) != original["artifact"]["sha256"]:
                        raise ValueError(f"copied artifact checksum mismatch: {name}")
                shutil.copy2(pre_path, directory / "preprocessing.json")
                onnx.checker.check_model(str(artifact))
                options = ort.SessionOptions()
                options.intra_op_num_threads = cfg.cpu_threads
                options.inter_op_num_threads = 1
                session = ort.InferenceSession(str(artifact), sess_options=options, providers=["CPUExecutionProvider"])
                scores = _scores(session, name, parity_x)
                if name in REBUILD:
                    expected = predict_scores(name, model, parity_x.toarray().astype(np.float32))
                    parity = check_parity(expected, scores, threshold)
                    np.savez_compressed(directory / "parity-fixture.npz", features=parity_x.toarray().astype(np.float32),
                                        native_scores=expected, threshold=np.array(threshold))
                    parity.update(partition="validation", sample_sha256=sample_hash, validation_reproduction=validation_check,
                                  fixture="parity-fixture.npz", fixture_sha256=sha256(directory / "parity-fixture.npz"))
                    del model, valid_scores
                    original["historical_locked_test_metrics"] = original.pop("locked_test_metrics")
                    original["locked_test_metrics"] = None
                    original["historical_metrics_binding"] = "reference_only_not_verified_for_reconstructed_weights"
                    original["reconstruction"] = {"seed": cfg.seed, "parameters": "unchanged source run-config and model registry",
                                                  "training_seconds": fit_seconds, "preprocessing_refit": False,
                                                  "validation_metrics": native_metrics, "original_checkpoint_available": False}
                    original["model_version"] += "-stage5-reconstructed"
                else:
                    parity = {"status": "historical_native_parity_reused", "recorded_parity": original["artifact"]["prediction_parity"],
                              "fresh_runtime_smoke": "passed", "fresh_rows": len(scores), "partition": "validation",
                              "sample_sha256": sample_hash, "native_checkpoint_available": False}
                # 同一 ONNX 的单条和批次结果仍必须一致；不是 native parity 的替代品。
                single = _scores(session, name, parity_x[:1])
                if not np.allclose(single, scores[:1], rtol=1e-4, atol=1e-5):
                    raise ValueError("single/batch mismatch")
                original["artifact"] = {"status": "exported", "format": "onnx", "artifact": artifact.relative_to(output).as_posix(),
                    "sha256": sha256(artifact), "bytes": artifact.stat().st_size,
                    "preprocessing_artifact": (directory / "preprocessing.json").relative_to(output).as_posix(),
                    "preprocessing_sha256": sha256(directory / "preprocessing.json"), "smoke_test": "passed",
                    "prediction_parity": parity, "onnx_input": session.get_inputs()[0].name,
                    "onnx_outputs": [item.name for item in session.get_outputs()]}
                original.update(candidate_only=True, production_approved=False, source_run=source.name,
                                source_manifest_sha256=source_hashes[str(Path("candidates") / name / "model_manifest.json")])
                original["inference_runtime"]["version"] = ort.__version__
                original["stage5_provenance"] = {"source_code_sha256": {
                    filename: sha256(Path(__file__).parent / filename)
                    for filename in ("stage5.py", "export.py", "models.py", "validation_latency.py")},
                    "packages": {package: importlib.metadata.version(package)
                                 for package in ("numpy", "scipy", "scikit-learn", "onnx", "onnxruntime", "skl2onnx", "protobuf")}}
                write_json(directory / "model_manifest.json", original)
                write_json(directory / "parity.json", parity)
                candidates[name], parity_records[name] = original, parity
                status["completed_models"].append(name)
                progress(f"Completed {name}; {len(candidates)}/10 candidates")
                del session, scores
                gc.collect()
        for relative, digest in source_hashes.items():
            if sha256(source / relative) != digest:
                raise ValueError(f"source changed: {relative}")
        write_json(output / "candidates/index.json", {"candidate_only": True, "models": candidates})
        write_json(output / "parity-results.json", parity_records)
        write_json(output / "source-hashes.json", source_hashes)
        (output / "delivery-report.md").write_text(
            "# 第五阶段候选交付\n\n复用源运行 " + source.name + " 的 EDA、预处理比较、十模型历史结果和稳定性报告。\n\n"
            "5 个成功 ONNX 保持原始哈希，复用当时的 native parity，新增验证样本推理检查。"
            "另 5 个因未保存权重，在原训练分区按原配置/种子重建；没有重新拟合预处理或选择阈值。"
            "其历史测试指标仅作参考，未验证与新权重的绑定，manifest 的 locked_test_metrics 为 null。\n\n"
            "本次没有重新评价锁定测试集。历史模型对比图中 F1 指 Macro-F1。所有制品 candidate_only=true、production_approved=false。"
            "端点压力测试、重复测试暴露审查、特征向量跨分区重叠、macOS parity、影子验证与发布审批仍属于第六阶段。\n",
            encoding="utf-8")
        hashes = {p.relative_to(output).as_posix(): sha256(p) for p in output.rglob("*")
                  if p.is_file() and p.name != "stage5-status.json"}
        write_json(output / "checksums.json", hashes)
        status.update(status="completed", rebuilt_models=sorted(REBUILD), reused_models=sorted(set(MODELS) - REBUILD),
                      source_artifacts_unchanged=True, preprocessing_refit=False, delivery_ready=True,
                      release_ready=False, historical_test_binding_for_rebuilt_models="unverified")
        progress("Stage 5 completed; candidate-only, release gates remain closed")
    except Exception as exc:
        status.update(status="failed", error=f"{type(exc).__name__}: {str(exc)[:1800]}")
        progress("Stage 5 failed closed; partial artifacts are not a complete delivery")
        raise
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous-run", type=Path, action="append", default=[])
    args = parser.parse_args()
    print(json.dumps(run_stage5(args.source_run, args.output, args.previous_run), ensure_ascii=True))


if __name__ == "__main__":
    main()
