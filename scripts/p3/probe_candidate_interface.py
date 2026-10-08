#!/usr/bin/env python3
"""T1.7 候选接口探针：零拟合，只读 train/validation，不访问封存 test/L3。

给已登记的研究制品补齐后端输入契约（categorical_codes 为 int64、默认 opset 17），
在完整 train/validation 上与原图对拍，并证明主机上下文字段不影响输出；随后生成
仅供后端加载的 rc.3 探针 manifest 和抽样观察。探针不是候选：不登记评估计划、
不进入 P6、不生成策略或发布包。任一核验失败都不落盘。
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import numpy as np
import onnx
import onnxruntime as ort

sys.path.insert(0, str(Path(__file__).resolve().parent))
from freeze_multiclass_candidate import (CLASSES, DATA_HASHES, ROOT, batches, converted_model,  # noqa: E402
                                         read, sha, write)

HOST_FIELDS = ("hostFlowStarts", "hostDistinctPeers")
INPUTS = {"numeric_values": (onnx.TensorProto.FLOAT, 43), "numeric_missing": (onnx.TensorProto.FLOAT, 43),
          "categorical_codes": (onnx.TensorProto.INT64, 3)}
OUTPUTS = {"attack_score": 1, "family_scores": 4}
TOLERANCE = 1e-6


def host_indices(numeric: list[str]) -> list[int]:
    """43 维中 3 个窗口 × 2 个主机侧字段的位置；数量不为 6 说明特征档案已变。"""
    indices = [i for i, name in enumerate(numeric) if name.split(".")[-1] in HOST_FIELDS]
    if len(indices) != 6:
        raise ValueError("特征档案中的主机上下文字段不是 6 个")
    return indices


def patch_categorical(model: onnx.ModelProto) -> bool:
    """类别输入为 float 时改为 int64 并在入口补 Cast；不改树、预处理参数或输出。"""
    categorical = next(i for i in model.graph.input if i.name == "categorical_codes")
    kind = categorical.type.tensor_type.elem_type
    if kind == onnx.TensorProto.INT64:
        return False
    if kind != onnx.TensorProto.FLOAT:
        raise ValueError("类别输入既不是 float 也不是 int64")
    categorical.type.tensor_type.elem_type = onnx.TensorProto.INT64
    for node in model.graph.node:
        node.input[:] = ["probe_categorical_float" if name == "categorical_codes" else name for name in node.input]
    model.graph.node.insert(0, onnx.helper.make_node("Cast", ["categorical_codes"], ["probe_categorical_float"],
                                                     to=onnx.TensorProto.FLOAT))
    onnx.checker.check_model(model)
    return True


def check_contract(model: onnx.ModelProto) -> dict:
    """与后端 GuardModelRuntime.shape 相同的输入输出约束，另核默认 opset 唯一为 17。"""
    def shape(value):
        return [d.dim_value if d.HasField("dim_value") else None for d in value.type.tensor_type.shape.dim]
    inputs = {i.name: i for i in model.graph.input}
    outputs = {o.name: o for o in model.graph.output}
    if set(inputs) != set(INPUTS) or set(outputs) != set(OUTPUTS):
        raise ValueError("输入输出名称不符合契约")
    for name, (kind, width) in INPUTS.items():
        if inputs[name].type.tensor_type.elem_type != kind or shape(inputs[name])[1:] != [width] \
                or len(shape(inputs[name])) != 2 or shape(inputs[name])[0] not in (None, 1):
            raise ValueError(f"输入 {name} 类型或形状不符")
    for name, width in OUTPUTS.items():
        if outputs[name].type.tensor_type.elem_type != onnx.TensorProto.FLOAT or shape(outputs[name])[1:] != [width] \
                or len(shape(outputs[name])) != 2 or shape(outputs[name])[0] not in (None, 1):
            raise ValueError(f"输出 {name} 类型或形状不符")
    defaults = [item.version for item in model.opset_import if not item.domain]
    if defaults != [17]:
        raise ValueError("默认 opset 未唯一固定为 17")
    onnx.checker.check_model(model)
    return {"inputs": {name: [onnx.TensorProto.DataType.Name(kind), width] for name, (kind, width) in INPUTS.items()},
            "outputs": OUTPUTS, "opsetImports": [[item.domain, item.version] for item in model.opset_import]}


def check_feature_selection(model: onnx.ModelProto, preprocessing: dict, hosts: list[int]) -> dict:
    """预处理与图内选列一致，且两者都不含主机上下文；只是结构证据，输出不变另行实测。"""
    indices = [int(i) for i in preprocessing["numericIndices"]]
    if preprocessing["featureSet"] != "no_host_context" or set(indices) & set(hosts):
        raise ValueError("预处理仍选用主机上下文字段")
    graph = {item.name: onnx.numpy_helper.to_array(item).tolist() for item in model.graph.initializer}
    if graph.get("feature_indices") != indices:
        raise ValueError("图内 feature_indices 与 preprocessing.json 不一致")
    return {"numericIndices": indices, "excludedHostIndices": hosts, "graphFeatureIndicesMatch": True}


def session(path: Path):
    options = ort.SessionOptions()
    options.intra_op_num_threads = 8
    options.inter_op_num_threads = 1
    return ort.InferenceSession(str(path), sess_options=options, providers=["CPUExecutionProvider"])


def run(runtime, feed) -> np.ndarray:
    return np.column_stack(runtime.run(["attack_score", "family_scores"], feed))


def labels(output: np.ndarray, threshold: float) -> np.ndarray:
    return np.where(output[:, 0] >= threshold, np.argmax(output[:, 1:], axis=1) + 1, 0)


def perturbed(feed: dict, hosts: list[int], variant: str) -> dict:
    """单对端（值 1、缺失 0）与极端值/全缺失两种改写；只动 6 个主机上下文列。"""
    values, missing = feed["numeric_values"].copy(), feed["numeric_missing"].copy()
    if variant == "single_peer":
        values[:, hosts], missing[:, hosts] = 1.0, 0.0
    else:
        values[:, hosts], missing[:, hosts] = 1e9, 1.0
    return {"numeric_values": values, "numeric_missing": missing, "categorical_codes": feed["categorical_codes"]}


def compare_role(role: str, frozen: Path, original: Path, probe: Path, numeric: list[str],
                 vocab: list[list[str]], hosts: list[int], threshold: float, float_categories: bool) -> dict:
    """完整角色对拍：原图（按原类型喂入）对探针图，及探针图对主机上下文改写后的自身。"""
    dataset = frozen / role / "dataset.jsonl"
    if sha(dataset) != DATA_HASHES[role]:
        raise ValueError(f"{role} 冻结数据哈希不符")
    old, new = session(original), session(probe)
    rows, max_error, flips, identical = 0, 0.0, 0, True
    host = {"single_peer": {"maxAbsError": 0.0, "bitIdentical": True},
            "extreme_missing": {"maxAbsError": 0.0, "bitIdentical": True}}
    for feed in batches(dataset, numeric, vocab):
        source_feed = dict(feed)
        if float_categories:
            source_feed["categorical_codes"] = feed["categorical_codes"].astype(np.float32)
        baseline, actual = run(old, source_feed), run(new, feed)
        if not (np.isfinite(baseline).all() and np.isfinite(actual).all()) or actual.shape[1] != 5:
            raise ValueError(f"{role} 输出维度或数值非法")
        max_error = max(max_error, float(np.max(np.abs(actual.astype(np.float64) - baseline))))
        identical &= bool(np.array_equal(actual, baseline))
        flips += int(np.count_nonzero(labels(actual, threshold) != labels(baseline, threshold)))
        for variant, record in host.items():
            changed = run(new, perturbed(feed, hosts, variant))
            record["maxAbsError"] = max(record["maxAbsError"], float(np.max(np.abs(changed.astype(np.float64) - actual))))
            record["bitIdentical"] &= bool(np.array_equal(changed, actual))
        rows += len(actual)
    if not rows or max_error > TOLERANCE or flips or not all(r["bitIdentical"] for r in host.values()):
        raise ValueError(f"{role} 对拍或主机上下文不变性未通过")
    return {"rows": rows, "maxOriginalAbsError": max_error, "bitIdenticalToOriginal": identical,
            "classFlips": flips, "hostContextInvariance": host}


def backend_samples(frozen: Path, probe: Path, numeric: list[str], vocab: list[list[str]], per_class: int) -> list:
    """validation 每类取文件序前 N 条，附探针图输出，供后端 infer() 对照；不含标签以外的标识。"""
    chosen = {name: [] for name in CLASSES}
    with (frozen / "validation" / "dataset.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if len(chosen[row["label"]]) < per_class:
                # 冻结数据为 CIC-IDS2017 IPv4 TCP 入站（P3-A 提取范围），observation 需显式给出地址族。
                chosen[row["label"]].append(row["input"] | {"profile": row["profile"], "addressFamily": "ipv4"}
                                            | {"_label": row["label"]})
            if all(len(items) == per_class for items in chosen.values()):
                break
    observations = [item for name in CLASSES for item in chosen[name]]
    path = probe.parent / "samples-input.jsonl"
    with path.open("x", encoding="utf-8") as stream:
        for item in observations:
            fields = {k: v for k, v in item.items() if k not in ("_label", "profile", "addressFamily")}
            stream.write(json.dumps({"input": fields}, ensure_ascii=False) + "\n")
    feed = next(batches(path, numeric, vocab, size=len(observations)))
    path.unlink()
    output = run(session(probe), feed)
    return [{"label": item.pop("_label"), "observation": item, "attackScore": float(score[0]),
             "familyScores": [float(v) for v in score[1:]]} for item, score in zip(observations, output)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="含 model.onnx、preprocessing.json 的研究制品目录")
    parser.add_argument("--run-events", type=Path, required=True, help="登记该制品哈希的 run-events.jsonl")
    parser.add_argument("--name", required=True, help="run-events 中 fit-completed 记录的模型名")
    parser.add_argument("--frozen", type=Path, default=ROOT / ".cache/p3-a-20261007/frozen")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples-per-class", type=int, default=20)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or ROOT / ".cache" not in output.parents:
        raise ValueError("目标必须是本仓库 .cache 下不存在的新目录")
    records = [json.loads(line)["record"] for line in args.run_events.read_text(encoding="utf-8").splitlines()
               if line.strip() and json.loads(line).get("event") == "fit-completed"]
    record = [item for item in records if item.get("name") == args.name]
    model_path, preprocessing_path = args.source / "model.onnx", args.source / "preprocessing.json"
    if len(record) != 1 or record[0]["artifactSha256"] != sha(model_path):
        raise ValueError("制品哈希与 run 记录不符")
    record = record[0]
    split = read(args.frozen / "manifest.json")
    preprocessing = read(preprocessing_path)
    metrics = read(args.source / "validation-metrics.json")
    threshold = float(metrics["alertThreshold"])
    if (split["finalTestRead"] or split["classOrder"] != list(CLASSES)
            or {role: split["datasetSha256"][role] for role in DATA_HASHES} != DATA_HASHES
            or preprocessing["fitRole"] != "train" or preprocessing["featureSet"] != record["featureSet"]
            or not np.isfinite(threshold) or not 0 <= threshold <= 1):
        raise ValueError("切分、预处理或阈值与登记不一致")
    feature = read(ROOT / "docs/contracts/feature-profile.json")
    numeric, hosts = feature["numericFeatures"], host_indices(feature["numericFeatures"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="t17-", dir=output.parent) as temporary:
        target = Path(temporary)
        source = onnx.load(model_path)
        float_categories = patch_categorical(source)
        onnx.save(source, target / "int64-opset15.onnx")
        original_imports = converted_model(target / "int64-opset15.onnx", target / "model.onnx")
        (target / "int64-opset15.onnx").unlink()
        probe = onnx.load(target / "model.onnx")
        contract = check_contract(probe)
        selection = check_feature_selection(probe, preprocessing, hosts)
        parity = {role: compare_role(role, args.frozen, model_path, target / "model.onnx", numeric,
                                     preprocessing["vocabularies"], hosts, threshold, float_categories)
                  for role in DATA_HASHES}
        write(target / "preprocessing.json", preprocessing)
        write(target / "calibration.json", {"version": "p3-calibration/none", "method": "none",
                                             "fitRole": None, "modelOutput": "raw_lightgbm_softmax"})
        write(target / "probe-plan.json", {"purpose": "T1.7 interface probe", "candidate": False,
                                           "notForEvaluation": True, "testRead": False, "newFits": 0,
                                           "sourceModelSha256": record["artifactSha256"]})
        model_hash = sha(target / "model.onnx")
        manifest = {
            "contractVersion": "host-guard/5.0.0-rc.3", "modelId": str(uuid.uuid5(uuid.NAMESPACE_URL, model_hash)),
            "modelVersion": f"interface-probe-{args.name}", "candidateOnly": True, "artifactSha256": model_hash,
            "featureProfileSha256": sha(ROOT / "docs/contracts/feature-profile.json"),
            "extractorSha256": sha(ROOT / ".cache/p3-a-20261007/bin/guardextract"),
            "preprocessingSha256": sha(target / "preprocessing.json"),
            "calibrationSha256": sha(target / "calibration.json"),
            "datasetManifestSha256": sha(args.frozen / "manifest.json"),
            "splitManifestSha256": sha(args.frozen / "manifest.json"),
            "evaluationPlanSha256": sha(target / "probe-plan.json"),
            "validationReportSha256": sha(args.source / "validation-metrics.json"),
            "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "algorithm": record["algorithm"], "profiles": feature["profiles"], "numericFeatures": numeric,
            "categoricalFeatures": feature["categoricalFeatures"],
            "supportedScope": [{"addressFamily": "ipv4", "transport": "tcp", "direction": "inbound",
                                "family": family, "minimumCoverageMs": 0, "coverageWindowSeconds": 1}
                               for family in CLASSES[1:]],
            "scoreCalibration": "none",
            # 后端只接受其内置 ORT 版本；Python 对拍所用版本另记于报告。
            "runtime": {"format": "onnx", "opset": 17, "maxProbabilityAbsError": 0.0001, "runtimeVersion": "1.23.2"},
            "finalEvaluationReportSha256": None,
            "trainingRunId": str(uuid.uuid5(uuid.NAMESPACE_URL, record["artifactSha256"] + ":" + args.name)),
            "algorithmVersion": f"{record['algorithm']} (version not recorded in source run)",
            # 源 run 未保存代码清单；探针以实验计划哈希占位，正式冻结须用 T2 的代码清单。
            "trainingCodeSha256": sha(args.run_events.parent / "experiment-plan.json"),
            "outputContract": {"attackScoreName": "attack_score", "binaryLabels": {"benign": 0, "attack": 1},
                               "familyScoreOrder": list(CLASSES[1:])}}
        schema = read(ROOT / "docs/contracts/model-manifest.schema.json")
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(manifest)
        write(target / "manifest.json", manifest)
        samples = backend_samples(args.frozen, target / "model.onnx", numeric, preprocessing["vocabularies"],
                                  args.samples_per_class)
        with (target / "backend-samples.jsonl").open("x", encoding="utf-8") as stream:
            for item in samples:
                stream.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
        write(target / "probe-report.json", {
            "stage": "T1.7", "candidate": False, "newFits": 0, "testRead": False, "l3Read": False,
            "source": {"name": args.name, "modelSha256": record["artifactSha256"],
                       "preprocessingSha256": sha(preprocessing_path), "originalOpsetImports": original_imports,
                       "categoricalWasFloat": float_categories},
            "probeModelSha256": model_hash, "contract": contract, "featureSelection": selection,
            "alertThreshold": threshold, "parity": parity, "backendSamples": len(samples),
            "manifestPlaceholders": {"trainingCodeSha256": "experiment-plan.json of source run",
                                     "evaluationPlanSha256": "probe-plan.json",
                                     "validationReportSha256": "source validation-metrics.json"},
            "runtime": {"onnx": onnx.__version__, "onnxruntime": ort.__version__,
                        "provider": "CPUExecutionProvider"},
            "probeCodeSha256": sha(Path(__file__))})
        files = {path.name: {"sha256": sha(path), "bytes": path.stat().st_size}
                 for path in sorted(target.iterdir()) if path.is_file()}
        write(target / "checksums.json", {"version": "t17-probe-checksums/1", "files": files,
                                          "selfExcluded": "checksums.json"})
        target.chmod(0o755)
        target.rename(output)
    print(json.dumps({"output": str(output), "probeModelSha256": model_hash, "parity": parity}, ensure_ascii=False))


if __name__ == "__main__":
    main()
