"""从已保存的预处理参数复现验证样本，补测 ONNX CPU 延迟；不拟合任何对象。"""
from __future__ import annotations

import argparse
import gc
import json
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pandas as pd

from .data import DATA_ROOT, TARGET, deduplicate_v0_rows, hash_frame, load_raw, make_split, prepare_v0_features
from .features import engineer_features
from .stage_review import artifact_path, read_json, sha256


def transform_saved(frame: pd.DataFrame, manifest: dict) -> np.ndarray:
    """严格使用保存的 train-fitted 参数；未知类别全零，禁止拟合或静默更换特征顺序。"""
    if manifest["fit_partition"] != "train" or list(frame.columns) != manifest["input_feature_order"]:
        raise ValueError("preprocessing partition or feature order mismatch")
    numeric = manifest["numeric"]
    if numeric["scaler"] != "StandardScaler" or numeric["imputation"] != "median":
        raise ValueError("latency replay currently requires audited StandardScaler preprocessing")
    values = frame[numeric["feature_order"]].to_numpy(dtype=float)
    missing = np.isnan(values)
    statistics = np.asarray(numeric["imputer_statistics"], dtype=float)
    if not np.isfinite(statistics).all():
        raise ValueError("unsupported all-missing numeric feature")
    values = np.where(missing, statistics, values)
    indicators = numeric["missing_indicator_features"]
    if indicators:
        values = np.column_stack([values, missing[:, indicators].astype(float)])
    values = (values - np.asarray(numeric["scaler_mean"])) / np.asarray(numeric["scaler_scale"])
    categories = manifest["categorical"]
    if categories["unknown_category"] != "all_zero" or categories["imputation"] != "most_frequent":
        raise ValueError("unsupported categorical preprocessing")
    chunks = [values]
    for column, fill, vocabulary in zip(categories["feature_order"], categories["imputer_statistics"], categories["one_hot_categories"], strict=True):
        # 历史 pandas StringDtype + sklearn 路径不接受 pd.NA；拒绝超出已验证范围的输入。
        if frame[column].isna().any():
            raise ValueError("categorical missing values are unsupported by the historical pipeline")
        column_values = frame[column].astype("string").fillna(fill).to_numpy(dtype=str)
        chunks.append((column_values[:, None] == np.asarray(vocabulary, dtype=str)[None, :]).astype(np.float32))
    result = np.column_stack(chunks).astype(np.float32)
    if result.shape[1] != len(manifest["encoded_feature_order"]) or not np.isfinite(result).all():
        raise ValueError("invalid encoded matrix")
    return result


def benchmark(run: Path, output: Path, data_root: Path = DATA_ROOT) -> dict:
    """仅对验证分区测延迟；保留历史 CUDA 计时缺项，不冒充原训练运行时。"""
    if output.exists():
        raise FileExistsError(output)
    model_manifest = read_json(run / "candidates/torch_mlp_cuda/model_manifest.json")
    item = model_manifest["artifact"]
    if item["status"] != "exported" or item.get("smoke_test") != "passed":
        raise ValueError("MLP export/parity not passed")
    model_path = artifact_path(run, item["artifact"])
    preprocessing_path = artifact_path(run, item["preprocessing_artifact"])
    if sha256(model_path) != item["sha256"] or sha256(preprocessing_path) != item["preprocessing_sha256"]:
        raise ValueError("artifact checksum mismatch")
    preprocessing = read_json(preprocessing_path)
    dataset = read_json(run / "dataset-manifest.json")
    config = read_json(run / "run-config.json")
    audit = read_json(run / "split-audit.json")
    print("Loading verified raw files for validation-only latency replay", flush=True)
    raw, observed = load_raw(data_root)
    if observed["data_fingerprint"] != dataset["data_fingerprint"]:
        raise ValueError("dataset fingerprint changed")
    raw, v0, removed = deduplicate_v0_rows(raw, prepare_v0_features(raw))
    if removed != dataset["duplicate_v0_feature_target_rows_removed"] or len(raw) != dataset["rows_after_v0_deduplication"]:
        raise ValueError("deduplication mismatch")
    split = make_split(raw[TARGET], config["seed"])
    valid_ids = split["validation"]
    if hash_frame(raw.iloc[valid_ids].reset_index(drop=True)) != audit["partitions"]["validation"]["fingerprint"]:
        raise ValueError("validation split fingerprint mismatch")
    selected_ids = valid_ids[:8192]
    frame = engineer_features(v0.iloc[selected_ids].reset_index(drop=True))
    samples = transform_saved(frame, preprocessing)
    sample_fingerprint = hash_frame(frame)
    del raw, v0, split, frame
    gc.collect()
    options = ort.SessionOptions()
    options.intra_op_num_threads = config["config"]["cpu_threads"]
    options.inter_op_num_threads = 1
    session = ort.InferenceSession(str(model_path), sess_options=options, providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    scores = np.asarray(session.run(None, {input_name: samples})[0]).reshape(-1)
    if len(scores) != len(samples) or not np.isfinite(scores).all() or not ((scores >= 0) & (scores <= 1)).all():
        raise ValueError("invalid MLP inference output")
    results = []
    for size, repeats in ((1, 100), (8192, 20)):
        batch = samples[:size]
        for _ in range(10):
            session.run(None, {input_name: batch})
        elapsed = []
        for _ in range(repeats):
            start = time.perf_counter()
            session.run(None, {input_name: batch})
            elapsed.append((time.perf_counter() - start) * 1000)
        results.append({"batch_rows": len(batch), "repeats": repeats, "warmup_calls": 10,
                        "median_batch_ms": float(np.median(elapsed)), "p95_batch_ms": float(np.percentile(elapsed, 95)),
                        "mean_batch_ms": float(np.mean(elapsed)), "mean_amortized_per_row_ms": float(np.mean(elapsed) / len(batch))})
    report = {"model": "torch_mlp_cuda", "runtime": "ONNX Runtime CPUExecutionProvider",
              "onnxruntime_version": ort.__version__, "intra_op_threads": options.intra_op_num_threads,
              "partition": "validation", "sample_rows": len(samples), "sample_fingerprint": sample_fingerprint,
              "validation_split_fingerprint": audit["partitions"]["validation"]["fingerprint"],
              "model_sha256": item["sha256"], "preprocessing_sha256": item["preprocessing_sha256"],
              "preprocessing_refit": False, "new_training_runs": 0, "new_locked_test_evaluations": 0,
              "includes_preprocessing": False, "includes_model_loading": False,
              "historical_cuda_latency_recovered": False, "measurements": results}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="验证样本上的补充 ONNX CPU 延迟测试；不训练")
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--data-root", type=Path, default=DATA_ROOT)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.run, args.output, args.data_root), ensure_ascii=True))


if __name__ == "__main__":
    main()
