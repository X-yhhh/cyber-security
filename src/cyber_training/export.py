from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path

import numpy as np
import onnxruntime as ort
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from skl2onnx.common._registration import get_converter
from skl2onnx._supported_operators import sklearn_operator_name_map
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from .data import write_json
from .models import BinaryMLP, predict_mlp, predict_scores


def merge_candidate_index(existing: dict, candidates: dict) -> dict:
    models = dict(existing.get("models", {}))
    models.update(candidates)
    return {"candidate_only": True, "models": models}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _tree_compatible_converter(model):
    """仅在当前转换容器内将树的缺失分支标志转为 ONNX INTS，兼容严格 Protobuf。"""
    converter = get_converter(sklearn_operator_name_map[type(model)])

    def convert(scope, operator, container):
        original = container.add_node

        def add_node(op_type, inputs, outputs, **kwargs):
            if op_type in {"TreeEnsembleClassifier", "TreeEnsembleRegressor"}:
                key = "nodes_missing_value_tracks_true"
                if key in kwargs:
                    kwargs[key] = [int(value) for value in kwargs[key]]
            return original(op_type, inputs, outputs, **kwargs)

        container.add_node = add_node
        try:
            return converter(scope, operator, container)
        finally:
            container.add_node = original

    return convert


def onnx_attack_scores(name: str, outputs: list) -> np.ndarray:
    """提取连续攻击分数；二分类 LinearSVC 输出单列 margin，不能当概率或取标签。"""
    if name == "torch_mlp_cuda":
        values = np.asarray(outputs[0]).reshape(-1)
    else:
        values = np.asarray(outputs[-1])
        if values.ndim != 2 or values.shape[1] not in (1, 2):
            raise ValueError(f"unsupported ONNX score shape: {values.shape}")
        values = values[:, 0 if values.shape[1] == 1 else 1]
    if not np.isfinite(values).all():
        raise ValueError("non-finite ONNX scores")
    return values


def _export_sklearn(name, model, out: Path, n_features: int) -> tuple[Path | None, str | None]:
    """转换候选；按模型类型配置选项，失败信息有界且不产生可用制品声明。"""
    path = out / "candidates" / name / "model.onnx"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        options = {"raw_scores": True} if isinstance(model, LinearSVC) else {"zipmap": False}
        custom = {type(model): _tree_compatible_converter(model),
                  DecisionTreeClassifier: _tree_compatible_converter(DecisionTreeClassifier())} if name in {
            "ada_boost", "decision_tree", "random_forest", "extra_trees"
        } else None
        proto = convert_sklearn(
            model, initial_types=[("features", FloatTensorType([None, n_features]))],
            target_opset={"": 17, "ai.onnx.ml": 3}, options={id(model): options},
            custom_conversion_functions=custom,
        )
        __import__("onnx").checker.check_model(proto)
        path.write_bytes(proto.SerializeToString())
        return path, None
    except Exception as exc:
        path.unlink(missing_ok=True)
        cause = exc
        while cause.__cause__ is not None:
            cause = cause.__cause__
        return None, f"ONNX export blocked: {type(cause).__name__}: {str(cause)[:1500]}"


def _export_mlp(model: BinaryMLP, out: Path, n_features: int) -> tuple[Path | None, str | None]:
    path = out / "candidates" / "torch_mlp_cuda" / "model.onnx"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        torch = __import__("torch")
        class ProbabilityModel(torch.nn.Module):
            def __init__(self, inner):
                super().__init__()
                self.inner = inner

            def forward(self, value):
                return torch.sigmoid(self.inner(value))

        cpu_model = ProbabilityModel(model.to("cpu").eval()).eval()
        sample = np.zeros((2, n_features), dtype=np.float32)
        torch.onnx.export(cpu_model, torch.from_numpy(sample), path, input_names=["features"], output_names=["attack_score"], dynamic_axes={"features": {0: "batch"}, "attack_score": {0: "batch"}}, opset_version=17, dynamo=False)
        return path, None
    except Exception as exc:
        path.unlink(missing_ok=True)
        cause = exc
        while cause.__cause__ is not None:
            cause = cause.__cause__
        return None, f"ONNX export blocked: {type(cause).__name__}: {str(cause)[:1500]}"
    finally:
        model.to("cuda:0")


def export_candidates(
    out: Path,
    model_objects: dict,
    feature_columns: list[str],
    preprocess,
    dataset_manifest: dict,
    split_audit: dict,
    metrics_frame,
    preprocessing_manifest: dict,
    parity_features: np.ndarray,
    input_contract_version: str = "unsw-flow-v0-raw-1",
) -> None:
    candidate_index = {}
    for name, entry in model_objects.items():
        model = entry["model"]
        transformed_count = len(preprocess.get_feature_names_out())
        if name == "torch_mlp_cuda":
            artifact, blocked = _export_mlp(model, out, transformed_count)
            expected = predict_mlp(model, parity_features)
        else:
            artifact, blocked = _export_sklearn(name, model, out, transformed_count)
            expected = predict_scores(name, model, parity_features)
        item = {"status": "blocked" if blocked else "exported", "format": "onnx", "export_error": blocked}
        if artifact:
            item["artifact"] = str(artifact.relative_to(out)).replace("\\", "/")
            item["sha256"] = _sha256(artifact)
            preprocessing_path = artifact.parent / "preprocessing.json"
            write_json(preprocessing_path, preprocessing_manifest)
            item["preprocessing_artifact"] = str(preprocessing_path.relative_to(out)).replace("\\", "/")
            item["preprocessing_sha256"] = _sha256(preprocessing_path)
            try:
                session = ort.InferenceSession(str(artifact), providers=["CPUExecutionProvider"])
                item["onnx_input"] = session.get_inputs()[0].name
                item["onnx_outputs"] = [o.name for o in session.get_outputs()]
                outputs = session.run(None, {item["onnx_input"]: np.asarray(parity_features, dtype=np.float32)})
                actual = onnx_attack_scores(name, outputs)
                max_error = float(np.max(np.abs(expected - actual)))
                if not np.allclose(expected, actual, rtol=1e-4, atol=1e-5):
                    raise ValueError(f"ONNX prediction parity failed; max_abs_error={max_error}")
                item["smoke_test"] = "passed"
                item["prediction_parity"] = {"rows": int(len(expected)), "max_abs_error": max_error, "tolerance": {"rtol": 1e-4, "atol": 1e-5}}
            except Exception as exc:
                item["smoke_test"] = f"failed: {type(exc).__name__}: {exc}"
        test_metric = metrics_frame[(metrics_frame["model"] == name) & (metrics_frame["phase"] == "locked_test")].iloc[0].to_dict()
        manifest = {
            "manifest_version": "1.0",
            "model_key": "unsw-nb15-flow-binary",
            "model_version": f"0.1.0-{name}",
            "algorithm": name,
            "task_type": "binary-classification",
            "candidate_only": True,
            "production_approved": False,
            "input_contract_version": input_contract_version,
            "feature_order": list(preprocess.get_feature_names_out()),
            "source_feature_order": feature_columns,
            "preprocessing": {"description": "see preprocessing_artifact for exact train-fitted parameters and category vocabularies", "fit_partition": "train", "artifact": item.get("preprocessing_artifact"), "sha256": item.get("preprocessing_sha256")},
            "label_mapping": {"0": "Normal", "1": "Attack"},
            "threshold_policy": entry["threshold_info"],
            "dataset_fingerprint": dataset_manifest["data_fingerprint"],
            "split_fingerprint": {name: part["fingerprint"] for name, part in split_audit["partitions"].items()},
            "locked_test_metrics": test_metric,
            "training_runtime": {"python": platform.python_version(), "device": entry["runtime"]},
            "inference_runtime": {"format": "ONNX", "provider": "CPUExecutionProvider", "required_package": "onnxruntime"},
            "artifact": item,
        }
        model_dir = out / "candidates" / name
        model_dir.mkdir(parents=True, exist_ok=True)
        write_json(model_dir / "model_manifest.json", manifest)
        candidate_index[name] = manifest
    index_path = out / "candidates" / "index.json"
    existing = {}
    if index_path.is_file():
        try:
            existing = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}
    write_json(index_path, merge_candidate_index(existing, candidate_index))
