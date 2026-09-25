"""Read-only preflight checks for the stage-six release gate."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path
from typing import Any

from .config import DATA_ROOT
from .data import load_raw, load_subset_audit


MODELS = (
    "svm_linear",
    "gaussian_nb",
    "logistic_regression_c01",
    "passive_aggressive",
    "ada_boost",
    "decision_tree",
    "random_forest",
    "extra_trees",
    "sgd_log_loss",
    "torch_mlp_cuda",
)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_stage5_status(status: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "status_completed": status.get("status") == "completed",
        "stage_is_5": status.get("stage") == 5,
        "delivery_ready": status.get("delivery_ready") is True,
        "candidate_only": status.get("candidate_only") is True,
        "production_not_approved": status.get("production_approved") is False,
        "release_not_ready": status.get("release_ready") is False,
        "no_new_locked_test_evaluation": status.get("new_locked_test_evaluations") == 0,
        "preprocessing_not_refit": status.get("preprocessing_refit") is False,
    }
    return {"passed": all(checks.values()), "checks": checks}


def check_model_manifest(name: str, manifest: dict[str, Any], feature_order: list[str]) -> dict[str, Any]:
    preprocessing = manifest.get("preprocessing", {})
    threshold = manifest.get("threshold_policy", {})
    runtime = manifest.get("inference_runtime", {})
    artifact = manifest.get("artifact", {})
    parity = artifact.get("prediction_parity", {})
    checks = {
        "candidate_only": manifest.get("candidate_only") is True,
        "production_not_approved": manifest.get("production_approved") is False,
        "onnx_exported": artifact.get("status") == "exported" and artifact.get("format") == "onnx",
        "preprocessing_fit_on_train": preprocessing.get("fit_partition") == "train",
        "feature_order_matches": manifest.get("source_feature_order") == feature_order,
        "label_mapping_present": manifest.get("label_mapping") == {"0": "Normal", "1": "Attack"},
        "threshold_selected_on_validation": threshold.get("selected_on") == "validation",
        "cpu_onnx_runtime_declared": runtime.get("format") == "ONNX" and runtime.get("provider") == "CPUExecutionProvider",
        "parity_recorded": parity.get("status") in {"passed", "historical_native_parity_reused"},
    }
    return {"model": name, "passed": all(checks.values()), "checks": checks}


def _overlap_summary(split_audit: dict[str, Any]) -> dict[str, Any]:
    exact = split_audit.get("exact_feature_target_overlap", {})
    feature = split_audit.get("feature_vector_overlap", {})
    endpoint = split_audit.get("endpoint_group_overlap", {})
    stress = split_audit.get("endpoint_stress", {})
    exact_clear = all(value == 0 for value in exact.values())
    stress_clear = stress.get("evaluable") is True and all(value == 0 for value in stress.get("group_overlap", {}).values())
    return {
        "exact_feature_target_overlap_clear": exact_clear,
        "exact_feature_target_overlap": exact,
        "feature_vector_overlap": feature,
        "endpoint_group_overlap": endpoint,
        "endpoint_stress_evaluable_and_group_disjoint": stress_clear,
        "endpoint_stress": stress,
        "review_required": bool(any(feature.values()) or any(endpoint.values()) or not exact_clear or not stress_clear),
    }


def run_preflight(run: Path, output: Path | None = None) -> dict[str, Any]:
    run = run.resolve()
    required = [
        "stage5-status.json",
        "checksums.json",
        "source-hashes.json",
        "dataset-manifest.json",
        "split-audit.json",
        "feature-contract.json",
        "preprocessing-comparison.json",
        "parity-results.json",
        "candidates/index.json",
    ]
    missing = [relative for relative in required if not (run / relative).is_file()]
    status = _read_json(run / "stage5-status.json") if not missing or (run / "stage5-status.json").is_file() else {}
    status_check = check_stage5_status(status) if status else {"passed": False, "checks": {"status_file_present": False}}

    checksums: dict[str, str] = _read_json(run / "checksums.json") if (run / "checksums.json").is_file() else {}
    checksum_missing: list[str] = []
    checksum_mismatch: list[str] = []
    for relative, expected in checksums.items():
        path = run / relative
        if not path.is_file():
            checksum_missing.append(relative)
        elif _sha256(path) != expected:
            checksum_mismatch.append(relative)
    checksum_check = {
        "passed": not checksum_missing and not checksum_mismatch,
        "missing": checksum_missing,
        "mismatch": checksum_mismatch,
        "entries": len(checksums),
    }

    source_hashes = _read_json(run / "source-hashes.json") if (run / "source-hashes.json").is_file() else {}
    source_run_name = status.get("source_run")
    source_run = run.parent / source_run_name if source_run_name else None
    source_missing: list[str] = []
    source_mismatch: list[str] = []
    for relative, expected in source_hashes.items():
        path = source_run / relative if source_run is not None else None
        if path is None or not path.is_file():
            source_missing.append(relative)
        elif _sha256(path) != expected:
            source_mismatch.append(relative)
    source_check = {
        "passed": bool(source_hashes) and not source_missing and not source_mismatch,
        "source_run": source_run_name,
        "entries": len(source_hashes),
        "missing": source_missing,
        "mismatch": source_mismatch,
    }

    contract = _read_json(run / "feature-contract.json") if (run / "feature-contract.json").is_file() else {}
    feature_order = contract.get("feature_order", [])
    model_checks: list[dict[str, Any]] = []
    artifact_missing: list[str] = []
    candidate_index_path = run / "candidates" / "index.json"
    candidate_index = _read_json(candidate_index_path) if candidate_index_path.is_file() else {}
    candidate_map = candidate_index.get("models", {})
    for name in MODELS:
        directory = run / "candidates" / name
        for filename in ("model.onnx", "model_manifest.json", "preprocessing.json", "parity.json"):
            if not (directory / filename).is_file():
                artifact_missing.append(f"candidates/{name}/{filename}")
        manifest_path = directory / "model_manifest.json"
        parity_path = directory / "parity.json"
        if manifest_path.is_file():
            manifest = _read_json(manifest_path)
            parity = _read_json(parity_path) if parity_path.is_file() else {}
            checks = check_model_manifest(name, manifest, feature_order)["checks"]
            checks["parity_file_passed"] = parity.get("status") in {"passed", "historical_native_parity_reused"}
            checks["index_matches_manifest"] = candidate_map.get(name) == manifest
            model_checks.append({"model": name, "passed": all(checks.values()), "checks": checks})
        else:
            model_checks.append({"model": name, "passed": False, "checks": {"manifest_present": False}})
    model_check = {
        "passed": not artifact_missing and candidate_index.get("candidate_only") is True
        and set(candidate_map) == set(MODELS) and all(item["passed"] for item in model_checks),
        "missing": artifact_missing,
        "index_models": sorted(candidate_map),
        "models": model_checks,
    }

    split_audit = _read_json(run / "split-audit.json") if (run / "split-audit.json").is_file() else {}
    split_check = _overlap_summary(split_audit)

    historical_binding = status.get("historical_test_binding_for_rebuilt_models")
    unresolved_gates = [
        "endpoint pressure evaluation is not present; split audit alone is insufficient",
        "macOS/local-application ONNX parity is not present",
        "shadow validation and manual approval are not present",
    ]
    if historical_binding != "verified":
        unresolved_gates.append("reconstructed candidate weights are not verified against locked-test metrics")
    if split_check["review_required"]:
        unresolved_gates.append("split/leakage review is required because overlap or exposure evidence is recorded")

    dataset_manifest = _read_json(run / "dataset-manifest.json") if (run / "dataset-manifest.json").is_file() else {}
    data_check: dict[str, Any]
    try:
        raw, current_data = load_raw(DATA_ROOT)
        current_data["subset_audit"] = load_subset_audit(DATA_ROOT)
        data_check = {
            "passed": current_data.get("data_fingerprint") == dataset_manifest.get("data_fingerprint"),
            "data_fingerprint_matches": current_data.get("data_fingerprint") == dataset_manifest.get("data_fingerprint"),
            "raw_rows": current_data.get("raw_rows"),
            "raw_columns": current_data.get("raw_columns"),
            "exact_duplicate_rows_removed": current_data.get("exact_duplicate_rows_removed"),
            "dataset_fingerprint": current_data.get("data_fingerprint"),
            "stage5_fingerprint": dataset_manifest.get("data_fingerprint"),
            "subset_audit_matches": current_data.get("subset_audit") == dataset_manifest.get("subset_audit"),
        }
        data_check["passed"] = data_check["passed"] and data_check["subset_audit_matches"]
        del raw
    except Exception as exc:  # pragma: no cover - depends on local dataset
        data_check = {"passed": False, "error": f"{type(exc).__name__}: {exc}"}

    runtime: dict[str, Any]
    try:
        ort_version = importlib.metadata.version("onnxruntime")
        import onnxruntime as ort

        loaded: list[str] = []
        for name in MODELS:
            path = run / "candidates" / name / "model.onnx"
            if path.is_file():
                ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
                loaded.append(name)
        runtime = {"passed": len(loaded) == len(MODELS), "onnxruntime": ort_version, "loaded_models": loaded}
    except Exception as exc:  # pragma: no cover - depends on local runtime
        runtime = {"passed": False, "error": f"{type(exc).__name__}: {exc}"}

    result = {
        "stage": 6,
        "source_run": run.name,
        "candidate_only": True,
        "stage6_start_ready": bool(
            not missing and status_check["passed"] and checksum_check["passed"]
            and source_check["passed"] and model_check["passed"] and data_check["passed"] and runtime["passed"]
        ),
        "release_ready": False,
        "status": {
            "stage5": status_check,
            "checksums": checksum_check,
            "source_artifacts": source_check,
            "artifacts": model_check,
            "dataset": data_check,
            "split_and_leakage": split_check,
            "onnx_runtime_load": runtime,
        },
        "missing_required_files": missing,
        "unresolved_gates": unresolved_gates,
        "notes": [
            "Read-only preflight: no preprocessing fit, threshold selection, locked-test inference, or model activation was performed.",
            "A passing stage6_start_ready result means the release-gate checks can begin; it does not approve production release.",
        ],
    }
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run_preflight(args.run, args.output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
