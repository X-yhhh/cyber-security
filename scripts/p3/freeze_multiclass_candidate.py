#!/usr/bin/env python3
"""冻结 P3-C 候选；只读取 P3-A/B 开发制品，不访问封存 test/L3。

输入为已收口的 B5 复现和 Mac validation 审计。转换后在完整 train、
validation 上对照保存的框架概率；任何哈希、契约或概率核验失败都不落盘候选。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import numpy as np
import onnx
import onnxruntime as ort
from onnx import version_converter
from candidate_plan import check_plan


ROOT = Path(__file__).resolve().parents[2]
CLASSES = ("normal", "port_scan", "brute_force", "dos_flood", "dos_slow")
# 仅供已收口 T1.7 探针兼容；新冻结入口使用 split manifest 的数据绑定。
DATA_HASHES = {"train": "9f2a19313725b373b774e796a6523cbec37d46727ceecb55bb925596ad873572",
               "validation": "2e168dfac592207e0448529ff93d8a6ccbcbeec265253dd0354bfc463940d568"}


def sha(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def checked_copy(source: Path, target: Path, expected: str):
    if sha(source) != expected:
        raise ValueError(f"输入哈希不符: {source.name}")
    shutil.copyfile(source, target)
    if sha(target) != expected:
        raise ValueError(f"复制后哈希不符: {target.name}")


def converted_model(source: Path, target: Path):
    model = onnx.load(source)
    original = [(item.domain, item.version) for item in model.opset_import]
    # 导出器可能重复声明相同域/版本；先去重，冲突版本必须拒绝，不能任取其一。
    versions = {}
    for domain, version in original:
        if domain in versions and versions[domain] != version:
            raise ValueError("源图同一域存在冲突 opset")
        versions[domain] = version
    defaults = [version for domain, version in versions.items() if not domain]
    if len(defaults) != 1 or defaults[0] not in (15, 16, 17):
        raise ValueError("源图默认 opset 不在已验证转换范围")
    del model.opset_import[:]
    for domain, version in versions.items():
        model.opset_import.add(domain=domain, version=version)
    model = version_converter.convert_version(model, 17)
    # 当前转换器会保留 15 并追加 17；单一默认域声明避免运行时歧义。
    imports = [(item.domain, item.version) for item in model.opset_import if item.domain]
    del model.opset_import[:]
    model.opset_import.add(domain="", version=17)
    for domain, version in imports:
        model.opset_import.add(domain=domain, version=version)
    onnx.checker.check_model(model)
    if [(item.domain, item.version) for item in model.opset_import if not item.domain] != [("", 17)]:
        raise ValueError("默认 opset 未唯一固定为 17")
    onnx.save(model, target)
    return original


def batches(path: Path, numeric: list[str], vocab: list[list[str]], size=4096):
    maps = [{value: index + 1 for index, value in enumerate(items)} for items in vocab]
    values, missing, categories = [], [], []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)["input"]
            contexts = {item["windowSeconds"]: item for item in row["contexts"]}
            fields = []
            masks = []
            for name in numeric:
                parts = name.split(".")
                value = row["features"][parts[1]] if parts[0] == "features" else contexts[int(parts[1])][parts[2]]
                fields.append(0.0 if value is None else float(value))
                masks.append(float(value is None))
            values.append(fields)
            missing.append(masks)
            categories.append([maps[index].get(row.get(name), 0)
                               for index, name in enumerate(("transport", "direction", "serviceClass"))])
            if len(values) == size:
                yield {"numeric_values": np.asarray(values, dtype=np.float32),
                       "numeric_missing": np.asarray(missing, dtype=np.float32),
                       "categorical_codes": np.asarray(categories, dtype=np.int64)}
                values, missing, categories = [], [], []
    if values:
        yield {"numeric_values": np.asarray(values, dtype=np.float32),
               "numeric_missing": np.asarray(missing, dtype=np.float32),
               "categorical_codes": np.asarray(categories, dtype=np.int64)}


def verify_role(role: str, frozen: Path, source: Path, converted: Path,
                numeric: list[str], vocab: list[list[str]], expected_hashes: dict,
                threshold: float, data_hashes: dict):
    dataset = frozen / role / "dataset.jsonl"
    if sha(dataset) != data_hashes[role]:
        raise ValueError(f"{role} 冻结数据哈希不符")
    expected_path = source / f"framework-{role}.npy"
    if sha(expected_path) != expected_hashes[expected_path.name]:
        raise ValueError(f"{role} 框架输出哈希不符")
    expected = np.load(expected_path, mmap_mode="r")
    options = ort.SessionOptions()
    options.intra_op_num_threads = 8
    options.inter_op_num_threads = 1
    old = ort.InferenceSession(str(source / "model.onnx"), sess_options=options,
                               providers=["CPUExecutionProvider"])
    new = ort.InferenceSession(str(converted), sess_options=options,
                               providers=["CPUExecutionProvider"])
    count, max_framework, max_original, flips = 0, 0.0, 0.0, 0
    for feed in batches(dataset, numeric, vocab):
        baseline = np.column_stack(old.run(["attack_score", "family_scores"], feed))
        actual = np.column_stack(new.run(["attack_score", "family_scores"], feed))
        end = count + len(actual)
        reference = expected[count:end]
        if (end > len(expected) or actual.shape[1] != 5 or reference.shape != actual.shape
                or not np.isfinite(actual).all() or not np.isfinite(baseline).all()
                or not np.isfinite(reference).all()):
            raise ValueError(f"{role} 输出维度或数值非法")
        probabilities = np.column_stack((1.0 - actual[:, 0], actual[:, 1:]))
        max_framework = max(max_framework, float(np.max(np.abs(probabilities - reference))))
        max_original = max(max_original, float(np.max(np.abs(actual - baseline))))
        old_labels = np.where(baseline[:, 0] >= threshold, np.argmax(baseline[:, 1:], axis=1) + 1, 0)
        new_labels = np.where(actual[:, 0] >= threshold, np.argmax(actual[:, 1:], axis=1) + 1, 0)
        flips += int(np.count_nonzero(old_labels != new_labels))
        count = end
    if not count or count != len(expected) or max_framework > 1e-4 or max_original > 1e-4 or flips:
        raise ValueError(f"{role} 全量对拍未通过")
    return {"rows": count, "maxFrameworkProbabilityAbsError": max_framework,
            "maxOriginalOnnxAbsError": max_original, "classFlips": flips}


def new_output(output):
    output = output.resolve()
    if output.exists() or not any(part in (".cache", "artifacts") for part in output.parts):
        raise ValueError("目标必须为受控的新目录")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def checksums(target):
    """manifest 不进入文件清单；其摘要由 provenance 单向绑定，不形成循环。"""
    return {"version": "p3-candidate-checksums/2",
            "files": {p.name: {"sha256": sha(p), "bytes": p.stat().st_size}
                      for p in sorted(target.iterdir()) if p.is_file()
                      and p.name not in ("checksums.json", "model-manifest.json")},
            "selfExcluded": "checksums.json", "excluded": ["checksums.json", "model-manifest.json"]}


def checked_selection(path, source, summary):
    """R4 冻结记录必须绑定本 run/validation，且不能借说明文件启用自动化。"""
    if path is None:
        return None
    value = read(path)
    selected = value["selected"]
    if (value.get("version") != "host-guard-dos-slow-selection/1"
            or value.get("modelSha256") != sha(source / "model.onnx")
            or value.get("preprocessingSha256") != sha(source / "preprocessing.json")
            or value.get("runSummarySha256") != sha(source / "reproduction-summary.json")
            or value.get("datasetSha256") != summary["datasetSha256"]["validation"]
            or value.get("metadataSha256") != summary["metadataSha256"]["validation"]
            or value.get("datasetRole") != "validation" or value.get("testRead") is not False
            or value.get("l3Read") is not False or value.get("newFits") != 0
            or value.get("automaticExecutionEnabled") is not False
            or value.get("candidateOnly") is not True or value.get("mode") != "alert_only"
            or type(selected["minDistinctFlows"]) is not int or selected["minDistinctFlows"] < 5
            or selected not in value["alternatives"] or selected["autoThreshold"] != summary["alertThreshold"]
            or not 0 <= selected["falsePositiveRate"] <= .01
            or not 0 <= selected["maxObservedNormalSourceFpr"] <= .01
            or selected["coveredAttackOpportunities"] <= 0
            or value["outsideCoverage"]["claimAllowed"] is not False
            or value["outsideCoverage"]["excludedFromEvaluation"] is not False):
        raise ValueError("dos_slow 选值记录不满足冻结绑定")
    return value


def prepare(args):
    """零拟合准备 rc.3 制品与计划；没有外部策略的准备包不能进入 P6。"""
    output = new_output(args.output)
    source, frozen, audit = args.source.resolve(), args.frozen.resolve(), args.audit.resolve()
    summary, split = read(source / "reproduction-summary.json"), read(frozen / "manifest.json")
    plan = read(args.plan)
    check_plan(plan)
    feature = read(ROOT / "docs/contracts/feature-profile.json")
    pre = read(source / "preprocessing.json")
    threshold = float(summary["alertThreshold"])
    report, verification = read(audit / "validation-report.json"), read(audit / "verification.json")
    if (summary["finalTestRead"] or split["finalTestRead"] or not summary["candidateOnly"]
            or summary["fitCountAfter"] < 1 or summary["fitCountAfter"] > summary["budget"]
            or not summary["frameworkParityPassed"] or not summary["validationExitPassed"]
            or split["classOrder"] != list(CLASSES)
            or any(summary["datasetSha256"][r] != split["datasetSha256"][r] for r in ("train", "validation"))
            or summary["artifacts"]["model.onnx"] != args.source_sha256
            or sha(source / "model.onnx") != args.source_sha256
            or report["modelSha256"] != args.source_sha256 or report["newFits"] != 0
            or report["finalTestRead"] or not verification["platformParityPassed"]
            or verification["modelSha256"] != args.source_sha256 or verification["finalTestRead"]
            or verification["newFits"] != 0 or not verification["candidateOnly"]
            or verification["alertThreshold"] != threshold
            or not verification["validationExitPassed"] or not verification["alertMatchesWindows"]
            or pre["fitRole"] != "train" or not pre["includeServiceClass"]
            or summary["featureSet"] != pre["featureSet"]
            or not np.isfinite(threshold) or not 0 <= threshold <= 1
            or report["alertThreshold"] != threshold):
        raise ValueError("登记 run、开发数据或审计不符")
    import sys
    sys.path.insert(0, str(ROOT / "scripts/p6"))
    from evaluate import numeric_indices
    if pre["numericIndices"] != numeric_indices(pre["featureSet"], feature):
        raise ValueError("预处理选列不符")
    selection_path = getattr(args, "dos_slow_selection", None)
    selection = checked_selection(selection_path, source, summary)
    scope = read(args.scope)
    if not scope or any(item["transport"] != "tcp" or item["direction"] != "inbound" for item in scope):
        raise ValueError("适用范围超出开发数据的实测方向/协议")
    uuid.UUID(args.training_run_id)
    with tempfile.TemporaryDirectory(prefix="p3c-", dir=output.parent) as temporary:
        target = Path(temporary)
        checked_copy(source / "model.onnx", target / "source-model.onnx", args.source_sha256)
        original_imports = converted_model(source / "model.onnx", target / "model.onnx")
        parity = {role: verify_role(role, frozen, source, target / "model.onnx",
                                   feature["numericFeatures"], pre["vocabularies"],
                                   summary["artifacts"], threshold, split["datasetSha256"])
                  for role in ("train", "validation")}
        for name in ("preprocessing.json", "native-model.txt"):
            checked_copy(source / name, target / name, summary["artifacts"][name])
        checked_copy(source / "code-manifest.json", target / "training-code-manifest.json",
                     summary["codeManifestSha256"])
        for name in ("validation-report.json", "verification.json", "policy-preview.json", "rules-comparison.json"):
            checked_copy(audit / name, target / name, sha(audit / name))
        for name, digest in (("manifest.json", sha(frozen / "manifest.json")),
                             ("split-ledger.jsonl", split["splitLedgerSha256"])):
            checked_copy(frozen / name, target / ("split-manifest.json" if name == "manifest.json" else name), digest)
        write(target / "calibration.json", {"version": "p3-calibration/none", "method": "none",
                                           "fitRole": None, "modelOutput": "raw_lightgbm_softmax"})
        write(target / "class-map.json", {"version": split["classMappingVersion"], "classOrder": CLASSES,
                                         "labelRuleVersion": split["labelRuleVersion"]})
        model_hash, extractor_hash = sha(target / "model.onnx"), sha(args.extractor)
        bindings = {"candidateSha256": model_hash, "splitManifestSha256": sha(target / "split-manifest.json"),
                    "testDatasetSha256": split["datasetSha256"]["test"],
                    "featureProfileSha256": sha(ROOT / "docs/contracts/feature-profile.json"),
                    "extractorSha256": extractor_hash, "freezeCodeSha256": sha(Path(__file__))}
        bindings.update({key: sha(target / name) for key, name in {
            "classMapSha256": "class-map.json", "preprocessingSha256": "preprocessing.json",
            "calibrationSha256": "calibration.json", "trainingCodeManifestSha256": "training-code-manifest.json"}.items()})
        if any(key in plan and plan[key] != value for key, value in bindings.items()):
            raise ValueError("计划预置的制品绑定与实际字节冲突")
        plan.update(bindings)
        write(target / "evaluation-plan.json", plan)
        code = read(target / "training-code-manifest.json")
        manifest = {
            "contractVersion": "host-guard/5.0.0-rc.3", "modelId": str(uuid.uuid5(uuid.NAMESPACE_URL, model_hash)),
            "modelVersion": args.model_version, "candidateOnly": True,
            "artifactSha256": model_hash, "featureProfileSha256": bindings["featureProfileSha256"],
            "extractorSha256": extractor_hash, "preprocessingSha256": bindings["preprocessingSha256"],
            "calibrationSha256": bindings["calibrationSha256"],
            "datasetManifestSha256": bindings["splitManifestSha256"],
            "splitManifestSha256": bindings["splitManifestSha256"],
            "evaluationPlanSha256": sha(target / "evaluation-plan.json"),
            "validationReportSha256": sha(target / "validation-report.json"),
            "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "algorithm": "lightgbm", "profiles": feature["profiles"],
            "numericFeatures": feature["numericFeatures"], "categoricalFeatures": feature["categoricalFeatures"],
            "supportedScope": scope, "scoreCalibration": "none",
            "runtime": {"format": "onnx", "opset": 17, "maxProbabilityAbsError": .0001,
                        "runtimeVersion": ort.__version__},
            "finalEvaluationReportSha256": None, "trainingRunId": args.training_run_id,
            "algorithmVersion": code["packages"]["lightgbm"], "trainingCodeSha256": summary["codeManifestSha256"],
            "outputContract": {"attackScoreName": "attack_score", "binaryLabels": {"benign": 0, "attack": 1},
                               "familyScoreOrder": list(CLASSES[1:])}}
        schema = read(ROOT / "docs/contracts/model-manifest.schema.json")
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(manifest)
        write(target / "model-manifest.json", manifest)
        hosts = [name for name in feature["numericFeatures"]
                 if name.rsplit(".", 1)[-1] in ("hostFlowStarts", "hostDistinctPeers")]
        used = [feature["numericFeatures"][i] for i in pre["numericIndices"]]
        record = {"version": "p3-candidate-freeze-record/1", "modelManifestSha256": sha(target / "model-manifest.json"),
            "modelSha256": args.source_sha256, "artifactSha256": model_hash,
            "sourceRun": summary.get("run"), "featureSet": pre["featureSet"],
            "hostContextFields": [name for name in hosts if name in used],
            "excludedHostContextFields": [name for name in hosts if name not in used],
            "interfaceNumericFeatureCount": len(feature["numericFeatures"]), "usedNumericFeatureCount": len(used),
            "preprocessingSha256": bindings["preprocessingSha256"], "trainingCodeSha256": summary["codeManifestSha256"],
            "fitCount": summary["fitCountAfter"], "budget": summary["budget"], "roundId": summary["roundId"],
            "candidateOnly": True, "automaticExecutionEnabled": False, "newFits": 0, "testRead": False,
            "familyModes": {family: "alert_only" for family in CLASSES[1:]},
            "evaluationPlanStatus": plan.get("registrationStatus", "provided_by_caller"),
            "packageStatus": "prepared_not_sealed", "p6Ready": False,
            "schemaFieldMapping": {"modelSha256": "source-model.onnx; rc.3 artifactSha256 binds converted model.onnx",
                "featureSet_hostContextFields_fitCount": "freeze-record.json; current rc.3 forbids additional properties"}}
        if selection is not None:
            checked_copy(selection_path, target / "dos-slow-selection.json", sha(selection_path))
            record["dosSlowSelectionSha256"] = sha(target / "dos-slow-selection.json")
            record["dosSlow"] = {"capability": selection["capability"], "scope": selection["scope"],
                                 "parameters": selection["selected"], "outsideCoverage": selection["outsideCoverage"]}
        write(target / "freeze-record.json", record)
        write(target / "provenance.json", {"stage": "P3-C-prepared", "sourceModelSha256": args.source_sha256,
              "convertedModelSha256": model_hash, "originalOpsetImports": original_imports, "parity": parity,
              "fitCount": summary["fitCountAfter"], "budget": summary["budget"], "roundId": summary["roundId"],
              "runSummarySha256": sha(source / "reproduction-summary.json"),
              "freezeCodeSha256": sha(Path(__file__)), "modelManifestSha256": sha(target / "model-manifest.json"),
              "freezeRecordSha256": sha(target / "freeze-record.json"), "newFits": 0, "testRead": False,
              "automaticExecutionEnabled": False})
        write(target / "checksums.json", checksums(target))
        target.rename(output)
    print(json.dumps({"prepared": True, "frozen": False, "modelSha256": model_hash,
                      "evaluationPlanSha256": sha(output / "evaluation-plan.json")}, ensure_ascii=False))


def seal(args):
    """外部策略与单对端开发证据通过后，才生成不可覆盖的完整候选。"""
    import sys
    sys.path.insert(0, str(ROOT / "scripts/p6"))
    from evaluate import checked_candidate
    output = new_output(args.output)
    prepared = args.prepared.resolve()
    if read(prepared / "evaluation-plan.json").get("registrationStatus") == "t34_preparation_only":
        raise ValueError("T3.4 计划仅为 manifest 依赖，须经 T3.6 正式登记并重新准备后封口")
    listing = read(prepared / "checksums.json")
    if (prepared / "decision-policy.json").exists():
        raise ValueError("只能封口尚未绑定策略的准备包")
    for name, item in listing["files"].items():
        if Path(name).name != name or sha(prepared / name) != item["sha256"] or (prepared / name).stat().st_size != item["bytes"]:
            raise ValueError("准备包内容变动")
    exclusions = {"checksums.json"}
    if listing.get("version") == "p3-candidate-checksums/2":
        exclusions.add("model-manifest.json")
        if read(prepared / "provenance.json")["modelManifestSha256"] != sha(prepared / "model-manifest.json"):
            raise ValueError("准备包 manifest 哈希不符")
    if set(listing["files"]) != {p.name for p in prepared.iterdir() if p.is_file() and p.name not in exclusions}:
        raise ValueError("准备包校验清单不完整")
    proof = read(args.single_peer_report)
    policy = read(args.policy)
    provenance, split = read(prepared / "provenance.json"), read(prepared / "split-manifest.json")
    if (provenance["stage"] != "P3-C-prepared" or not proof["passed"] or proof["testRead"] or proof["newFits"] != 0
            or proof["candidateSha256"] != provenance["sourceModelSha256"]
            or proof["preprocessingSha256"] != sha(prepared / "preprocessing.json")
            or proof["datasetSha256"] != split["datasetSha256"]["validation"]
            or proof["threshold"] != read(prepared / "validation-report.json")["alertThreshold"]
            or any(item["alertThreshold"] != proof["threshold"] for item in policy["familyPolicies"])
            or proof["datasetRole"] != "validation" or not proof["candidateOnly"]
            or proof["codeSha256"] != {name: sha(ROOT / name) for name in
                ("scripts/p3/single_peer_check.py", "scripts/p6/evaluate.py", "scripts/p6/runtime.py")}
            or proof["hostRewrite"] != {"hostDistinctPeers": 1, "hostFlowStarts": "peerFlowStarts"}
            or set(proof["dropByClass"]) != set(CLASSES[1:])
            or any(not np.isfinite(v) or v > .20 + 1e-12 for v in proof["dropByClass"].values())):
        raise ValueError("缺少同一 run 的单对端通过证据")
    if (prepared / "dos-slow-selection.json").exists():
        selected = read(prepared / "dos-slow-selection.json")["selected"]
        slow = [item for item in policy["familyPolicies"] if item["family"] == "dos_slow"]
        if len(slow) != 1 or any(slow[0][key] != selected[key] for key in ("minDistinctFlows", "autoThreshold")):
            raise ValueError("策略未保留 T3.3 的 dos_slow 冻结参数")
    with tempfile.TemporaryDirectory(prefix="p3c-seal-", dir=output.parent) as temporary:
        target = Path(temporary)
        for name, item in listing["files"].items():
            checked_copy(prepared / name, target / name, item["sha256"])
        if "model-manifest.json" in exclusions:
            checked_copy(prepared / "model-manifest.json", target / "model-manifest.json",
                         provenance["modelManifestSha256"])
        checked_copy(args.policy, target / "decision-policy.json", sha(args.policy))
        checked_copy(args.single_peer_report, target / "single-peer-report.json", sha(args.single_peer_report))
        write(target / "checksums.json", checksums(target))
        checked_candidate(target)
        target.rename(output)
    print(json.dumps({"frozen": True, "candidateOnly": True, "testRead": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    ready = sub.add_parser("prepare")
    ready.add_argument("--dos-slow-selection", type=Path,
                       help="T3.3 validation 选值记录，绑定本 run 并写入冻结说明")
    for name in ("source", "frozen", "audit", "extractor", "plan", "scope", "output"):
        ready.add_argument("--" + name, type=Path, required=True)
    for name in ("source-sha256", "model-version", "training-run-id"):
        ready.add_argument("--" + name, required=True)
    sealing = sub.add_parser("seal")
    for name in ("prepared", "policy", "single-peer-report", "output"):
        sealing.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    {"prepare": prepare, "seal": seal}[args.command](args)


if __name__ == "__main__":
    main()
