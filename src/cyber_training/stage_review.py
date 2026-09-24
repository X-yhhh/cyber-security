"""第三、四阶段的只读验收：复用既有指标，不拟合模型、不重评测试集。"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path

MODELS = (
    "svm_linear", "gaussian_nb", "logistic_regression_c01", "passive_aggressive",
    "ada_boost", "decision_tree", "random_forest", "extra_trees", "sgd_log_loss",
    "torch_mlp_cuda",
)
METRICS = (
    "binary_f1", "accuracy", "precision", "recall", "macro_f1", "weighted_f1",
    "roc_auc", "pr_auc", "specificity", "fpr", "fnr", "mcc", "training_seconds",
)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_path(run: Path, relative: str) -> Path:
    """仅允许运行目录内的制品，拒绝 manifest 越界引用。"""
    result = (run / relative).resolve()
    if not result.is_relative_to(run.resolve()) or not result.is_file():
        raise ValueError(f"invalid artifact path: {relative}")
    return result


def _number(row: dict, field: str) -> float:
    value = float(row[field])
    if not math.isfinite(value):
        raise ValueError(f"non-finite {field}")
    return value


def _close(actual: float, expected: float, name: str) -> None:
    if not math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-10):
        raise ValueError(f"inconsistent metric: {name}")


def validate_rows(rows: list[dict], config: dict, selection: dict, audit: dict) -> tuple[list[dict], list[str]]:
    """核对完整性、混淆矩阵与指标及验证集排名；失败时禁止生成完成报告。"""
    base_seed = int(config["seed"])
    expected_seeds = {base_seed, base_seed + 1, base_seed + 2}
    if selection.get("test_used_for_selection") is not False:
        raise ValueError("model selection must use validation only")
    normalized = []
    seen = set()
    for original in rows:
        row = dict(original)
        model, phase, seed = row["model"], row["phase"], int(row["seed"])
        key = (model, phase, seed)
        if key in seen:
            raise ValueError(f"duplicate model/phase/seed: {key}")
        seen.add(key)
        if model not in MODELS or phase not in {"validation", "locked_test", "three_seed_validation"}:
            raise ValueError(f"unknown model or phase: {key}")
        if (phase == "three_seed_validation" and seed not in expected_seeds) or (phase != "three_seed_validation" and seed != base_seed):
            raise ValueError(f"unexpected seed: {key}")
        matrix = json.loads(row["confusion_matrix"]) if isinstance(row["confusion_matrix"], str) else row["confusion_matrix"]
        if len(matrix) != 2 or any(len(part) != 2 for part in matrix):
            raise ValueError("confusion matrix must be 2 by 2")
        tn, fp, fn, tp = matrix[0] + matrix[1]
        if any(type(value) is not int or value < 0 for value in (tn, fp, fn, tp)):
            raise ValueError("confusion matrix must contain nonnegative integers")
        partition = "test" if phase == "locked_test" else "validation"
        counts = audit["partitions"][partition]["label_counts"]
        if tn + fp != int(counts["0"]) or fn + tp != int(counts["1"]):
            raise ValueError(f"partition count mismatch: {key}")
        total = tn + fp + fn + tp
        if total != audit["partitions"][partition]["rows"]:
            raise ValueError(f"partition row mismatch: {key}")
        # pandas 含空值的计数列以 302597.0 写入 CSV；比较数值而非截断小数。
        if row.get("rows") not in (None, "") and _number(row, "rows") != total:
            raise ValueError(f"metric row count mismatch: {key}")
        def ratio(a, b):
            return a / b if b else 0.0
        f1 = ratio(2 * tp, 2 * tp + fp + fn)
        normal_f1 = ratio(2 * tn, 2 * tn + fp + fn)
        expected = {
            "accuracy": (tn + tp) / total, "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn), "specificity": ratio(tn, tn + fp),
            "fpr": ratio(fp, tn + fp), "fnr": ratio(fn, tp + fn),
            "macro_f1": (f1 + normal_f1) / 2,
            "weighted_f1": (normal_f1 * (tn + fp) + f1 * (tp + fn)) / total,
            "mcc": ratio(tp * tn - fp * fn, math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))),
        }
        for field, value in expected.items():
            _close(_number(row, field), value, field)
        for field in ("roc_auc", "pr_auc"):
            if not 0 <= _number(row, field) <= 1:
                raise ValueError(f"out-of-range {field}")
        if _number(row, "training_seconds") < 0:
            raise ValueError("negative training duration")
        _number(row, "threshold")
        row.update(seed=seed, binary_f1=f1, confusion_matrix=matrix)
        normalized.append(row)
    for phase in ("validation", "locked_test"):
        if {row["model"] for row in normalized if row["phase"] == phase} != set(MODELS):
            raise ValueError(f"incomplete ten-model {phase}")
    validation = {row["model"]: row for row in normalized if row["phase"] == "validation"}
    ranked = sorted(MODELS, key=lambda model: validation[model]["binary_f1"], reverse=True)
    selected = ranked[:3]
    if selection["selected_for_three_seed_runs"] != selected or selection["validation_f1_ranking"] != ranked:
        raise ValueError("selection disagrees with validation binary F1 ranking")
    expected = {(model, seed) for model in selected for seed in expected_seeds}
    actual = {(row["model"], row["seed"]) for row in normalized if row["phase"] == "three_seed_validation"}
    if actual != expected:
        raise ValueError("incomplete or unexpected three-model three-seed grid")
    return normalized, selected


def summarize_stability(rows: list[dict], selected: list[str]) -> list[dict]:
    """同一切分上量化模型随机种子的变动，标准差采用样本标准差 ddof=1。"""
    result = []
    for model in selected:
        group = [row for row in rows if row["model"] == model and row["phase"] == "three_seed_validation"]
        item = {"model": model, "seed_count": len(group), "seeds": ",".join(str(row["seed"]) for row in group)}
        for field in METRICS:
            values = [_number(row, field) for row in group]
            item[field + "_mean"] = statistics.mean(values)
            item[field + "_std"] = statistics.stdev(values)
        result.append(item)
    return result


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def review_run(run: Path, output: Path, previous_runs: list[Path] | None = None) -> dict:
    """只读取已有实验并创建独立验收目录；不覆盖原指标、权重或训练摘要。"""
    run, output = run.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(output)
    paths = [run / name for name in ("metrics.csv", "run-config.json", "model-selection.json", "split-audit.json", "dataset-manifest.json", "run-summary.json")]
    source_hashes = {path.name: sha256(path) for path in paths}
    config, selection, audit, dataset, summary = [read_json(path) for path in paths[1:]]
    if not summary.get("candidate_only") or summary.get("production_activated") is not False:
        raise ValueError("candidate-only boundary not satisfied")
    if any(audit["exact_feature_target_overlap"].values()):
        raise ValueError("exact feature-target leakage reported")
    with paths[0].open(encoding="utf-8-sig", newline="") as stream:
        rows, selected = validate_rows(list(csv.DictReader(stream)), config, selection, audit)
    stability = summarize_stability(rows, selected)
    candidates = []
    for model in MODELS:
        path = run / "candidates" / model / "model_manifest.json"
        source_hashes[str(path.relative_to(run))] = sha256(path)
        manifest = read_json(path)
        if manifest.get("candidate_only") is not True or manifest.get("production_approved") is not False:
            raise ValueError(f"invalid candidate boundary: {model}")
        if manifest["dataset_fingerprint"] != dataset["data_fingerprint"] or manifest["split_fingerprint"] != {key: part["fingerprint"] for key, part in audit["partitions"].items()}:
            raise ValueError(f"candidate provenance mismatch: {model}")
        if manifest["preprocessing"]["fit_partition"] != "train" or manifest["threshold_policy"]["selected_on"] != "validation":
            raise ValueError(f"fit/threshold partition mismatch: {model}")
        test = next(row for row in rows if row["model"] == model and row["phase"] == "locked_test")
        for field in METRICS[1:]:
            _close(_number(test, field), _number(manifest["locked_test_metrics"], field), field)
        _close(_number(test, "threshold"), float(manifest["threshold_policy"]["threshold"]), "threshold")
        item = manifest["artifact"]
        record = {"model": model, "export_status": item["status"], "recorded_parity": item.get("smoke_test"), "files_hash_verified": False}
        if item["status"] == "exported":
            for key, digest_key in (("artifact", "sha256"), ("preprocessing_artifact", "preprocessing_sha256")):
                artifact = artifact_path(run, item[key])
                actual = sha256(artifact)
                if actual != item[digest_key]:
                    raise ValueError(f"artifact SHA-256 mismatch: {model}/{key}")
                source_hashes[str(artifact.relative_to(run))] = actual
            record["files_hash_verified"] = True
        record["delivery_ready"] = item["status"] == "exported" and item.get("smoke_test") == "passed"
        candidates.append(record)
    previous_exposure = []
    for previous in previous_runs or []:
        previous_audit = read_json(previous / "split-audit.json")
        if previous_audit["partitions"]["test"]["fingerprint"] == audit["partitions"]["test"]["fingerprint"]:
            with (previous / "metrics.csv").open(encoding="utf-8-sig") as stream:
                count = sum(row["phase"] == "locked_test" for row in csv.DictReader(stream))
            previous_exposure.append({"run": previous.name, "locked_test_records": count})
    for relative, digest in source_hashes.items():
        if sha256(run / relative) != digest:
            raise ValueError("source artifacts changed while reviewing")
    missing_latency = [row["model"] for row in rows if row["phase"] == "locked_test" and not row.get("batch_seconds")]
    report = {
        "review_version": "1.0", "created_at": datetime.now().astimezone().isoformat(),
        "source_run": run.name, "source_hashes": source_hashes,
        "phase_counts": dict(Counter(row["phase"] for row in rows)),
        "stage3": {"training_and_classification_metrics": "verified", "historical_latency_missing": missing_latency},
        "stage4": {"training_complete": True, "selected_models": selected,
                   "selection_metric": "validation binary F1", "sample_std_ddof": 1,
                   "split_varied": False, "seed_scope": "model randomness only; fixed data split",
                   "locked_test_used_by_stability": False, "summary": stability},
        "candidate_export_audit": candidates, "previous_same_test_exposure": previous_exposure,
        "new_training_runs": 0, "new_locked_test_evaluations": 0,
        "candidate_only": True, "production_approved": False,
        "limitations": [
            "AUC values are range-checked, not recomputed because prediction vectors were not retained.",
            "Confusion-matrix metrics are independently recomputed; no new model inference on test data.",
            "Three seeds measure model randomness on one fixed split, not independent split robustness.",
            "Historical GPU MLP latency is unavailable; any ONNX CPU timing is a separate supplemental measurement.",
            "Existing test exposure remains recorded; repeated runs are not a fresh untouched final test.",
        ],
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "stage34-review.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_csv(output / "stage4-stability-summary.csv", stability)
    _write_csv(output / "stage4-seed-metrics.csv", [{key: row[key] for key in ("model", "seed", *METRICS)} for row in rows if row["phase"] == "three_seed_validation"])
    _write_csv(output / "stage3-locked-results.csv", [{key: row[key] for key in ("model", "seed", *METRICS)} for row in rows if row["phase"] == "locked_test"])
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="验收现有第三、四阶段结果；不训练、不重新评估测试集")
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous-run", type=Path, action="append", default=[])
    args = parser.parse_args()
    report = review_run(args.run, args.output, args.previous_run)
    print(json.dumps({"output": str(args.output), "phase_counts": report["phase_counts"], "stage4_complete": True, "new_training_runs": 0, "new_locked_test_evaluations": 0}))


if __name__ == "__main__":
    main()
