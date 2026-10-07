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


ROOT = Path(__file__).resolve().parents[2]
CLASSES = ("normal", "port_scan", "brute_force", "dos_flood", "dos_slow")
SOURCE_HASH = "5a5f8ab34366ce2e70c3e6ad32bdc9b4e3aeb3937d32efea387b6d1310c2d613"
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
    if ("", 15) not in original:
        raise ValueError("B5 原图默认 opset 已改变")
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
                threshold: float):
    dataset = frozen / role / "dataset.jsonl"
    if sha(dataset) != DATA_HASHES[role]:
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or ROOT / ".cache" not in output.parents:
        raise ValueError("目标必须是本仓库 .cache 下不存在的新目录")
    frozen = ROOT / ".cache/p3-a-20261007/frozen"
    source = ROOT / ".cache/p3b-20261007/windows-evidence/run-reproduce-v1"
    audit = ROOT / ".cache/p3b-20261007/verification-reproduce-mac-v1"
    summary = read(source / "reproduction-summary.json")
    split = read(frozen / "manifest.json")
    policy_preview = read(audit / "policy-preview.json")
    if (summary["artifacts"]["model.onnx"] != SOURCE_HASH or sha(source / "model.onnx") != SOURCE_HASH
            or split["finalTestRead"] or summary["finalTestRead"] or summary["fitCountAfter"] != 33
            or not summary["frameworkParityPassed"] or not summary["validationExitPassed"]
            or split["classOrder"] != list(CLASSES) or split["datasetSha256"] != DATA_HASHES | {"test": split["datasetSha256"]["test"]}
            or policy_preview["automaticExecutionEnabled"]):
        raise ValueError("P3-A/B 收口证据不匹配")
    schema = read(ROOT / "docs/contracts/model-manifest.schema.json")
    feature = read(ROOT / "docs/contracts/feature-profile.json")
    preprocessing = read(source / "preprocessing.json")
    threshold = float(summary["alertThreshold"])
    if (not np.isfinite(threshold) or not 0 <= threshold <= 1
            or threshold != policy_preview["alertThreshold"] or preprocessing["fitRole"] != "train"
            or set(policy_preview["classes"]) != set(CLASSES[1:])):
        raise ValueError("预处理或阈值版本不一致")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="p3c-", dir=output.parent) as temporary:
        target = Path(temporary)
        checked_copy(source / "model.onnx", target / "source-model.onnx", SOURCE_HASH)
        original_imports = converted_model(source / "model.onnx", target / "model.onnx")
        parity = {role: verify_role(role, frozen, source, target / "model.onnx",
                                    feature["numericFeatures"], preprocessing["vocabularies"],
                                    summary["artifacts"], threshold)
                  for role in DATA_HASHES}
        checked_copy(source / "preprocessing.json", target / "preprocessing.json",
                     summary["artifacts"]["preprocessing.json"])
        checked_copy(source / "native-model.txt", target / "native-model.txt",
                     summary["artifacts"]["native-model.txt"])
        checked_copy(source / "code-manifest.json", target / "training-code-manifest.json",
                     summary["codeManifestSha256"])
        checked_copy(frozen / "manifest.json", target / "split-manifest.json", sha(frozen / "manifest.json"))
        checked_copy(frozen / "split-ledger.jsonl", target / "split-ledger.jsonl",
                     split["splitLedgerSha256"])
        checked_copy(audit / "validation-report.json", target / "validation-report.json",
                     sha(audit / "validation-report.json"))
        checked_copy(audit / "rules-comparison.json", target / "rules-comparison.json",
                     sha(audit / "rules-comparison.json"))
        write(target / "calibration.json", {"version": "p3-calibration/none", "method": "none",
                                             "fitRole": None, "modelOutput": "raw_lightgbm_softmax"})
        write(target / "class-map.json", {"version": split["classMappingVersion"], "classOrder": CLASSES,
                                           "labelRuleVersion": split["labelRuleVersion"]})
        rules = read(target / "rules-comparison.json")
        write(target / "decision-policy.json", {
            "policyVersion": "host-guard-decision/2026-10-06.1", "ruleVersion": "host-guard-rules/1",
            "ruleSourceVersion": rules["version"], "rules": rules["rules"],
            "alertThreshold": threshold, "maxEvidenceAgeMs": policy_preview["maxEvidenceAgeMs"],
            "automaticExecutionEnabled": False,
            "classes": {name: {"mode": "alert_only", "autoThreshold": item["parameters"]["autoThreshold"],
                               "minDistinctFlows": item["parameters"]["minDistinctFlows"]}
                        for name, item in policy_preview["classes"].items()}})
        model_hash = sha(target / "model.onnx")
        plan = {"plan": split["plan"], "stage": "P6", "candidateSha256": model_hash,
                "splitManifestSha256": sha(frozen / "manifest.json"),
                "testDatasetSha256": split["datasetSha256"]["test"],
                "classMapSha256": sha(target / "class-map.json"),
                "decisionPolicySha256": sha(target / "decision-policy.json"),
                "preprocessingSha256": sha(target / "preprocessing.json"),
                "calibrationSha256": sha(target / "calibration.json"),
                "trainingCodeManifestSha256": sha(target / "training-code-manifest.json"),
                "freezeCodeSha256": sha(Path(__file__)),
                "featureProfileSha256": sha(ROOT / "docs/contracts/feature-profile.json"),
                "extractorSha256": sha(ROOT / ".cache/p3-a-20261007/bin/guardextract"),
                "evaluationVersion": "host-guard-evaluation/2026-10-07.1",
                "metricDefinitionSha256": sha(ROOT / "docs/验证与验收.md"),
                "statisticalUnit": "parentConnection",
                "connectionDecision": "first_snapshot_at_alert_threshold_then_argmax_family",
                "attackDetectionAggregation": "equal_weight_four_attack_classes",
                "falsePositiveAggregation": "equal_weight_internal_and_website_normal",
                "automaticEligibility": {"recallMin": 0.80, "precisionMin": 0.90,
                                         "requiresG3": True},
                "evaluationIds": ["p6-l1-01", "p6-l1-02", "p6-l1-03"], "maxTestEvaluations": 3,
                "repeatPolicy": "第 2/3 次须先登记改动及原因，不得逐条或逐时段针对 test 调参",
                "gates": {"G1": {"attackDetectionMin": 0.90, "falsePositiveRateMax": 0.02},
                          "G2": {"macroF1Min": 0.80}},
                "otherDatasets": {"L2": "report_only_optional_A7", "L3": "test_only_report"},
                "noTestReadBeforeP6": True}
        write(target / "evaluation-plan.json", plan)
        code = read(target / "training-code-manifest.json")
        created = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        manifest = {
            "contractVersion": "host-guard/5.0.0-rc.2", "modelId": str(uuid.uuid5(uuid.NAMESPACE_URL, model_hash)),
            "modelVersion": "p3-multiclass-20261007-candidate-2", "candidateOnly": True,
            "artifactSha256": model_hash, "featureProfileSha256": sha(ROOT / "docs/contracts/feature-profile.json"),
            "extractorSha256": sha(ROOT / ".cache/p3-a-20261007/bin/guardextract"),
            "preprocessingSha256": sha(target / "preprocessing.json"),
            "calibrationSha256": sha(target / "calibration.json"),
            "datasetManifestSha256": sha(frozen / "manifest.json"),
            "splitManifestSha256": sha(target / "split-manifest.json"),
            "evaluationPlanSha256": sha(target / "evaluation-plan.json"),
            "validationReportSha256": sha(target / "validation-report.json"),
            "createdAt": created, "algorithm": "lightgbm",
            "profiles": feature["profiles"], "numericFeatures": feature["numericFeatures"],
            "categoricalFeatures": feature["categoricalFeatures"],
            "supportedScope": [{"addressFamily": "ipv4", "transport": "tcp", "direction": "inbound",
                                "family": family, "minimumCoverageMs": 0, "coverageWindowSeconds": 1}
                               for family in CLASSES[1:]],
            "scoreCalibration": "none", "runtime": {"format": "onnx", "opset": 17,
                                                      "maxProbabilityAbsError": 0.0001,
                                                      "runtimeVersion": ort.__version__},
            "finalEvaluationReportSha256": None,
            "trainingRunId": str(uuid.uuid5(uuid.NAMESPACE_URL, SOURCE_HASH + ":run-reproduce-v1")),
            "algorithmVersion": code["packages"]["lightgbm"],
            "trainingCodeSha256": summary["codeManifestSha256"],
            "outputContract": {"attackScoreName": "attack_score",
                               "binaryLabels": {"benign": 0, "attack": 1},
                               "familyScoreOrder": list(CLASSES[1:])}}
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(manifest)
        write(target / "model-manifest.json", manifest)
        write(target / "provenance.json", {"stage": "P3-C", "sourceModelSha256": SOURCE_HASH,
                                           "originalOpsetImports": original_imports,
                                           "convertedModelSha256": model_hash,
                                           "converterVersion": onnx.__version__,
                                           "runtimeVersion": ort.__version__, "parity": parity,
                                           "freezeCodeSha256": sha(Path(__file__)),
                                           "fitCount": 33, "newFits": 0, "testRead": False,
                                           "automaticExecutionEnabled": False})
        files = {path.name: {"sha256": sha(path), "bytes": path.stat().st_size}
                 for path in sorted(target.iterdir()) if path.is_file()}
        write(target / "checksums.json", {"version": "p3-candidate-checksums/1", "files": files,
                                          "selfExcluded": "checksums.json"})
        target.rename(output)
    print(json.dumps({"output": str(output), "modelSha256": model_hash, "parity": parity}, ensure_ascii=False))


if __name__ == "__main__":
    main()
