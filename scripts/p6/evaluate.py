#!/usr/bin/env python3
"""P6 冻结离线评价入口；prepare 不打开测试数据，run 只读取登记的冻结组合。

产物仅写入忽略的受控新目录，不修改模型、阈值、后端、数据库或真实防火墙。
失败读取也计入 L1 三次预算；重复评价须预先登记非逐条/逐时段改动与原因。
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

import numpy as np
import onnxruntime as ort
import jsonschema

from metrics import CLASSES, first_decisions, gates_and_eligibility, report, source_eligibility
from runtime import compare, framework_predict, predict, read, session, sha, write

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/p3"))
from access_multiclass_test import evaluation_lock
from multiclass_common import model_input, micros
from candidate_plan import check_plan

CODE = ("scripts/p6/evaluate.py", "scripts/p6/metrics.py", "scripts/p6/runtime.py",
        "scripts/p6/closeout.py", "scripts/p6/test_evaluation.py",
        "scripts/p3/access_multiclass_test.py", "scripts/p3/multiclass_common.py", "scripts/p3/candidate_plan.py")
SCHEMA_REVISION = "efcbd12"
SCHEMA_SHA256 = "b24176be2841a5fb3bc4bec65bbc14646a897e54ff302bbe510cbba5e128c2df"
LEGACY_CHECKSUMS = "29c2ebf328c07cdc9cc6fb11ae382a714e340e5d48e2b35b930607155bafb3ee"


def candidate_schema(legacy=False):
    """新候选使用现行 Schema；历史 Schema 仅供固定 candidate-v2 只读复核。"""
    if not legacy:
        return read(ROOT / "docs/contracts/model-manifest.schema.json")
    result = subprocess.run(["git", "show", SCHEMA_REVISION + ":docs/contracts/model-manifest.schema.json"],
                            cwd=ROOT, capture_output=True, check=True)
    if hashlib.sha256(result.stdout).hexdigest() != SCHEMA_SHA256:
        raise ValueError("历史候选 Schema 哈希不符")
    return json.loads(result.stdout)


def append(path, value):
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def events(root):
    path = root / "test-access.jsonl"
    return [json.loads(value) for value in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def checked_candidate(candidate, *, legacy=False):
    """核验完整包与计划的实际字节绑定；不以可修改的路径名代替哈希。"""
    checksums = read(candidate / "checksums.json")
    if legacy and sha(candidate / "checksums.json") != LEGACY_CHECKSUMS:
        raise ValueError("历史复核只允许原始 candidate-v2")
    required = {"model.onnx", "model-manifest.json", "evaluation-plan.json", "decision-policy.json",
                "preprocessing.json", "calibration.json", "class-map.json", "split-manifest.json",
                "training-code-manifest.json", "validation-report.json", "native-model.txt"}
    if not legacy and checksums.get("version") == "p3-candidate-checksums/2":
        # T3.4 的 manifest 不列入 checksums；改由被清单绑定的 provenance 单向核验。
        required.remove("model-manifest.json")
        required.update(("provenance.json", "freeze-record.json"))
        if ("model-manifest.json" in checksums["files"]
                or checksums.get("excluded") != ["checksums.json", "model-manifest.json"]
                or read(candidate / "provenance.json")["modelManifestSha256"] != sha(candidate / "model-manifest.json")
                or read(candidate / "provenance.json")["freezeRecordSha256"] != sha(candidate / "freeze-record.json")):
            raise ValueError("manifest 或冻结说明绑定不符")
    if not legacy:
        # 单对端检查是冻结准入条件（验收第 6 节）；手工组包也不能绕过，P6 入口独立复核。
        required.add("single-peer-report.json")
    if not required <= set(checksums["files"]):
        raise ValueError("候选校验清单缺少必需文件")
    for name, item in checksums["files"].items():
        if Path(name).name != name or (candidate / name).stat().st_size != item["bytes"] \
                or sha(candidate / name) != item["sha256"]:
            raise ValueError("候选文件哈希不符")
    manifest, plan = read(candidate / "model-manifest.json"), read(candidate / "evaluation-plan.json")
    if not legacy:
        if plan.get("registrationStatus") == "t34_preparation_only":
            raise ValueError("T3.4 准备计划尚未完成 T3.6 登记")
        check_plan(plan)
    elif plan["evaluationVersion"] != "host-guard-evaluation/2026-10-07.1":
        raise ValueError("历史评价版本不符")
    jsonschema.Draft202012Validator(candidate_schema(legacy),
                                   format_checker=jsonschema.FormatChecker()).validate(manifest)
    bindings = {"candidateSha256": "model.onnx", "splitManifestSha256": "split-manifest.json",
                "classMapSha256": "class-map.json",
                "preprocessingSha256": "preprocessing.json", "calibrationSha256": "calibration.json",
                "trainingCodeManifestSha256": "training-code-manifest.json"}
    for key, name in bindings.items():
        if plan[key] != sha(candidate / name):
            raise ValueError("P6 计划绑定不符")
    if legacy and plan["decisionPolicySha256"] != sha(candidate / "decision-policy.json"):
        raise ValueError("历史策略绑定不符")
    if not legacy and "decisionPolicySha256" in plan:
        raise ValueError("计划不能反向绑定策略造成循环哈希；策略由候选清单和登记绑定")
    references = {"artifactSha256": "model.onnx", "preprocessingSha256": "preprocessing.json",
                  "calibrationSha256": "calibration.json", "splitManifestSha256": "split-manifest.json",
                  "datasetManifestSha256": "split-manifest.json", "trainingCodeSha256": "training-code-manifest.json",
                  "evaluationPlanSha256": "evaluation-plan.json", "validationReportSha256": "validation-report.json"}
    for key, name in references.items():
        if manifest[key] != sha(candidate / name):
            raise ValueError("manifest 引用不符")
    feature = read(ROOT / "docs/contracts/feature-profile.json")
    class_map, policy = read(candidate / "class-map.json"), read(candidate / "decision-policy.json")
    pre = read(candidate / "preprocessing.json")
    if (not manifest["candidateOnly"] or plan["stage"] != "P6" or not plan["evaluationVersion"]
            or (not legacy and plan["metricDefinitionSha256"] != sha(ROOT / "docs/验证与验收.md"))
            or plan["featureProfileSha256"] != sha(ROOT / "docs/contracts/feature-profile.json")
            or manifest["numericFeatures"] != feature["numericFeatures"]
            or manifest["categoricalFeatures"] != feature["categoricalFeatures"]
            or manifest["outputContract"]["familyScoreOrder"] != list(CLASSES[1:])
            or class_map["classOrder"] != list(CLASSES)
            or pre["fitRole"] != "train" or pre["numericIndices"] != numeric_indices(pre["featureSet"], feature)
            or not pre["includeServiceClass"] or read(candidate / "calibration.json")["method"] != "none"
            or plan["maxTestEvaluations"] != 3
            or read(candidate / "split-manifest.json")["datasetSha256"]["test"] != plan["testDatasetSha256"]):
        raise ValueError("冻结评价语义不符")
    if len(plan["evaluationIds"]) != 3 or len(set(plan["evaluationIds"])) != 3:
        raise ValueError("评价 ID 必须为三个不同的登记值")
    if manifest["featureProfileSha256"] != plan["featureProfileSha256"] or manifest["extractorSha256"] != plan["extractorSha256"]:
        raise ValueError("manifest 与计划版本绑定不符")
    checked_policy(policy, manifest, plan, candidate, feature, legacy=legacy)
    if not legacy:
        checked_single_peer(candidate)
    return manifest, plan, feature, policy, pre


def checked_single_peer(candidate):
    """单对端证据须针对同一源模型、预处理与 validation，四类降幅都不超过 20 个百分点。

    不比对当前工具源码哈希：冻结后 P6 工具的修正不应使已冻结证据失效，源码哈希仍随报告保存。
    """
    proof = read(candidate / "single-peer-report.json")
    split = read(candidate / "split-manifest.json")
    drops = proof.get("dropByClass")
    if (proof.get("version") != "host-guard-single-peer-check/1" or proof.get("passed") is not True
            or proof.get("testRead") is not False or proof.get("newFits") != 0
            or proof.get("candidateOnly") is not True or proof.get("datasetRole") != "validation"
            # 单对端在源模型上运行；转换图与源图的逐行对拍已在 prepare 完成并记录在 provenance。
            or proof.get("candidateSha256") != read(candidate / "provenance.json")["sourceModelSha256"]
            or proof.get("candidateSha256") != sha(candidate / "source-model.onnx")
            or proof.get("preprocessingSha256") != sha(candidate / "preprocessing.json")
            or proof.get("datasetSha256") != split["datasetSha256"]["validation"]
            or proof.get("threshold") != read(candidate / "validation-report.json")["alertThreshold"]
            or proof.get("hostRewrite") != {"hostDistinctPeers": 1, "hostFlowStarts": "peerFlowStarts"}
            or not isinstance(drops, dict) or set(drops) != set(CLASSES[1:])
            or any(isinstance(value, bool) or not isinstance(value, (int, float)) or not np.isfinite(value)
                   or value > .20 + 1e-12 for value in drops.values())):
        raise ValueError("缺少同一候选的单对端通过证据")


def numeric_indices(feature_set, feature):
    """外部张量始终为 43 维；原生模型按冻结的消融选列还原。"""
    if feature_set not in ("full", "no_host_context"):
        raise ValueError("未知特征集")
    return [i for i, name in enumerate(feature["numericFeatures"])
            if feature_set == "full" or name.split(".")[-1] not in ("hostFlowStarts", "hostDistinctPeers")]


def checked_policy(policy, manifest, plan, candidate, feature, *, legacy=False):
    """校验冻结策略；新策略必须合规且只告警，不从离线成绩授予动作资格。"""
    if legacy:
        if (policy["automaticExecutionEnabled"] or set(policy["classes"]) != set(CLASSES[1:])
                or any(item["mode"] != "alert_only" for item in policy["classes"].values())
                or any(item["automatic"] for item in policy["rules"])):
            raise ValueError("历史研究策略非法")
        return
    jsonschema.Draft202012Validator(read(ROOT / "docs/contracts/decision-policy.schema.json"),
                                   format_checker=jsonschema.FormatChecker()).validate(policy)
    families, rules = policy["familyPolicies"], policy.get("rulePolicies", [])
    if (policy["modelId"] != manifest["modelId"] or policy["evaluationPlanSha256"] != sha(candidate / "evaluation-plan.json")
            or policy["mode"] != "alert_only" or len(families) != 4
            or {item["family"] for item in families} != set(CLASSES[1:])
            or any(item["autoEligible"] or item["modelAutoEligible"] for item in families)
            or any(item["autoEligible"] for item in rules)
            or len({item["ruleId"] for item in rules}) != len(rules)
            or any(item["field"] not in feature["numericFeatures"] for item in rules)
            or plan["automaticEligibility"].get("sourceMode") != "model_and_each_rule"):
        raise ValueError("冻结策略、来源口径或计划绑定非法")
    if plan["evaluationVersion"] == "host-guard-evaluation/2026-10-07.1":
        raise ValueError("新来源口径必须另行登记评价版本")


def model_decisions(scores, policy):
    """按 argmax 家族对应的冻结告警阈值判定；旧研究格式保留统一阈值。"""
    families = np.argmax(scores[:, 1:], axis=1)
    thresholds = {item["family"]: item["alertThreshold"] for item in policy.get("familyPolicies", [])}
    cutoffs = np.asarray([thresholds.get(CLASSES[i + 1], policy["alertThreshold"]) for i in families])
    return np.where(scores[:, 0] >= cutoffs, families + 1, 0)


def alert_thresholds(policy):
    return ({item["family"]: item["alertThreshold"] for item in policy["familyPolicies"]}
            if "familyPolicies" in policy else policy["alertThreshold"])


def prepare(args):
    candidate, frozen, extract, output = [value.resolve() for value in
                                          (args.candidate, args.frozen, args.extract, args.output)]
    if output.exists() or not any(part in (".cache", "artifacts") for part in output.parts):
        raise ValueError("输出须为受控新目录")
    manifest, plan, feature, policy, pre = checked_candidate(candidate)
    dataset_manifest = read(frozen / "manifest.json")
    prior = events(frozen)
    used = {value["evaluationId"] for value in prior if value["event"] == "access_started"}
    if args.layer == "L1":
        if (sha(frozen / "manifest.json") != plan["splitManifestSha256"]
                or dataset_manifest["datasetSha256"]["test"] != plan["testDatasetSha256"]
                or args.evaluation_id not in plan["evaluationIds"] or args.evaluation_id in used
                or len(used) >= 3):
            raise ValueError("L1 切分、登记 ID 或读取预算不符")
        if used and not (args.change_description and args.change_reason):
            raise ValueError("重复评价须先登记改动与原因")
        dataset_hash = plan["testDatasetSha256"]
    else:
        if dataset_manifest.get("datasetRole") != "L3_test_only" or args.layer != "L3" \
                or dataset_manifest.get("trainingAllowed") is not False:
            raise ValueError("当前只支持登记的 L3 测试组合；L2 须先完成 A7")
        dataset_hash = dataset_manifest["datasetSha256"]
    development_parity = None
    if args.layer == "L1":
        development = frozen / "validation/dataset.jsonl"
        if sha(development) != dataset_manifest["datasetSha256"]["validation"]:
            raise ValueError("validation 冻结哈希不符")
        with development.open("rb") as stream:
            development_rows = [json.loads(value) for value in stream]
        feed = inputs(development_rows, feature, pre)
        development_parity = compare(predict(session(candidate / "model.onnx"), feed),
                                     framework_predict(feed, pre, candidate / "native-model.txt"),
                                     alert_thresholds(policy))
        if not development_parity["passed"]:
            raise ValueError("开发集自检未通过，不准入 test")
        del development_rows, feed
    sources = {}
    for path in sorted(extract.glob("*/observations.jsonl")):
        proof_path = path.with_name("extraction.json")
        proof = read(proof_path)
        if proof["binarySha256"] != dataset_manifest.get("binarySha256", plan["extractorSha256"]):
            raise ValueError("提取器版本不一致")
        sources[str(path.relative_to(extract))] = {"observationsSha256": proof["observationsSha256"],
                                                   "proofSha256": sha(proof_path)}
    if not sources:
        raise ValueError("缺少事件时间和规则端口的原始观察")
    # 这里只读取准备阶段清单，不打开封存数据或观察内容。
    runtime = session(candidate / "model.onnx")
    del runtime
    import lightgbm
    output.mkdir(parents=True, mode=0o700)
    registration = {"version": "p6-registration/1", "stage": "P6", "layer": args.layer,
                    "evaluationId": args.evaluation_id, "evaluationOrdinal": len(used) + 1,
                    "candidate": str(candidate), "frozen": str(frozen), "extract": str(extract),
                    "candidateChecksumsSha256": sha(candidate / "checksums.json"),
                    "modelManifestSha256": sha(candidate / "model-manifest.json"),
                    "evaluationPlanSha256": sha(candidate / "evaluation-plan.json"),
                    "datasetManifestSha256": sha(frozen / "manifest.json"), "datasetSha256": dataset_hash,
                    "datasetRelativePath": "test/dataset.jsonl" if args.layer == "L1" else "sealed-test/dataset.jsonl",
                    "priorAccessLogSha256": sha(frozen / "test-access.jsonl"),
                    "codeSha256": {name: sha(ROOT / name) for name in CODE}, "observationSources": sources,
                    "candidateSchemaSha256": sha(ROOT / "docs/contracts/model-manifest.schema.json"),
                    "policySchemaSha256": sha(ROOT / "docs/contracts/decision-policy.schema.json"),
                    "decisionPolicySha256": sha(candidate / "decision-policy.json"),
                    "evaluationVersion": plan["evaluationVersion"], "candidateSchemaRevision": "current",
                    "changeRecord": {"evaluationId": args.evaluation_id,
                                     "description": args.change_description, "reason": args.change_reason},
                    "packages": {"numpy": np.__version__, "onnxruntime": ort.__version__,
                                 "lightgbm": lightgbm.__version__},
                    "developmentPreflight": development_parity,
                    "registeredAt": datetime.now(timezone.utc).isoformat(),
                    "testRead": False, "automaticExecutionEnabled": False}
    write(output / "registration.json", registration)
    write(output / "registration-receipt.json", {"sha256": sha(output / "registration.json")})
    print(json.dumps({"prepared": True, "layer": args.layer, "evaluationId": args.evaluation_id, "testRead": False}))


def decode(stream, expected):
    """单遍收取入口输出并核验哈希；只保存到本次内存，不导出原始 test。"""
    digest = hashlib.sha256()
    rows = []
    for value in stream:
        digest.update(value)
        rows.append(json.loads(value))
    if digest.hexdigest() != expected or not rows:
        raise ValueError("测试流哈希不符或为空")
    return rows


def load_registered(registration, output):
    frozen = Path(registration["frozen"])
    if registration["layer"] == "L1":
        command = [sys.executable, "-B", str(ROOT / "scripts/p3/access_multiclass_test.py"),
                   "--frozen", str(frozen), "--evaluation-plan",
                   str(Path(registration["candidate"]) / "evaluation-plan.json"),
                   "--candidate", str(Path(registration["candidate"]) / "model.onnx"),
                   "--evaluation-id", registration["evaluationId"]]
        if registration["evaluationOrdinal"] > 1:
            write(output / "change-record.json", registration["changeRecord"])
            command.extend(["--change-record", str(output / "change-record.json")])
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                result = decode(process.stdout, registration["datasetSha256"])
            except BaseException:
                # 继续排空入口，让其 finally 重封存；SIGTERM 会跳过 Python 清理。
                process.communicate()
                raise
            _, errors = process.communicate()
            if process.returncode:
                raise ValueError("受控测试入口失败；详情保留在访问日志")
        return result
    with evaluation_lock(frozen):
        append(frozen / "test-access.jsonl", {"event": "access_started", "stage": "P6",
                                              "evaluationId": registration["evaluationId"],
                                              "registrationSha256": sha(output / "registration.json")})
        with (frozen / registration["datasetRelativePath"]).open("rb") as stream:
            result = decode(stream, registration["datasetSha256"])
        append(frozen / "test-access.jsonl", {"event": "access_completed", "stage": "P6",
                                              "evaluationId": registration["evaluationId"]})
    return result


def metadata(rows, registration):
    """仅解码已准入观察 ID；事件时间、服务端口与标签均是评估旁路。

    原始文件在同一评价中扫描并核对准备时记录的哈希。快照特征必须逐字段
    等于冻结输入，不允许借原始观察重新提取特征或修正困难样本。
    """
    wanted = {row["observationId"].encode(): row for row in rows}
    if len(wanted) != len(rows):
        raise ValueError("重复观察 ID")
    pattern = re.compile(rb'"observationId"\s*:\s*"([0-9a-f-]+)"')
    matched = {}
    extract = Path(registration["extract"])
    for name, proof in registration["observationSources"].items():
        path = extract / name
        if sha(path.with_name("extraction.json")) != proof["proofSha256"]:
            raise ValueError("观察清单变动")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for value in stream:
                digest.update(value)
                found = pattern.search(value)
                if not found or found[1] not in wanted:
                    continue
                row, observation = wanted[found[1]], json.loads(value)
                if (found[1] in matched or observation["parentConnectionId"] != row["parentConnectionId"]
                        or model_input(observation) != row["input"] or observation["profile"] != row["profile"]):
                    raise ValueError("观察旁路与冻结输入不一致")
                matched[found[1]] = {"time": micros(observation["asOf"]),
                                     "sequence": observation["snapshotIndex"],
                                     "servicePort": observation["servicePort"]}
        if digest.hexdigest() != proof["observationsSha256"]:
            raise ValueError("观察内容哈希不符")
    if len(matched) != len(rows):
        raise ValueError("缺少评价时间或服务端口；拒绝按文件顺序猜测")
    return [matched[row["observationId"].encode()] for row in rows]


def inputs(rows, feature, pre):
    """固定 43+43+3 张量；不加入身份、时间、标签或 servicePort。"""
    numeric, missing, categories = [], [], []
    nullable = set(feature["nullableNumericFeatures"])
    maps = [{value: i + 1 for i, value in enumerate(vocab)} for vocab in pre["vocabularies"]]
    for row in rows:
        value = row["input"]
        if value["transport"] != "tcp" or value["direction"] != "inbound" or row["label"] not in CLASSES:
            raise ValueError("输入不满足冻结适用范围")
        contexts = {item["windowSeconds"]: item for item in value["contexts"]}
        if set(contexts) != {1, 5, 30} or len(value["contexts"]) != 3:
            raise ValueError("上下文窗口不符")
        numbers, masks = [], []
        for name in feature["numericFeatures"]:
            parts = name.split(".")
            item = value["features"][parts[1]] if parts[0] == "features" else contexts[int(parts[1])][parts[2]]
            if item is None and name not in nullable:
                raise ValueError("不可空特征缺失")
            if item is not None and (not isinstance(item, (int, float)) or not np.isfinite(item) or item < 0):
                raise ValueError("非法特征数值")
            numbers.append(0.0 if item is None else float(item))
            masks.append(float(item is None))
        numeric.append(numbers)
        missing.append(masks)
        categories.append([maps[i].get(value[name], 0) for i, name in enumerate(feature["categoricalFeatures"])])
    feed = {"numeric_values": np.asarray(numeric, dtype=np.float32),
            "numeric_missing": np.asarray(missing, dtype=np.float32),
            "categorical_codes": np.asarray(categories, dtype=np.int64)}
    if not np.isfinite(feed["numeric_values"]).all():
        raise ValueError("float32 转换溢出")
    return feed


def frozen_rules(feed, metadata_rows, feature, policy):
    """新策略逐条执行契约操作符；历史研究策略仅用于固定包的复核。"""
    ports = np.asarray([row["servicePort"] for row in metadata_rows])
    if "familyPolicies" in policy:
        return rule_hits(feed, feature, policy)
    hits = np.zeros((len(ports), 4), dtype=bool)
    for i, rule in enumerate(policy["rules"]):
        index = feature["numericFeatures"].index(rule["field"])
        gate = np.ones(len(ports), dtype=bool) if rule["servicePorts"] is None else np.isin(ports, rule["servicePorts"])
        hits[:, i] = gate & (feed["numeric_missing"][:, index] == 0) \
            & (feed["numeric_values"][:, index].astype(np.float64) >= rule["threshold"]) \
            & (feed["numeric_values"][:, 0] >= rule["minElapsedMs"])
    return hits


def rule_hits(feed, feature, policy):
    """返回每条规则的独立命中，避免同一家族多规则互相借用成绩。"""
    operators = {"gte": np.greater_equal, "gt": np.greater, "lte": np.less_equal,
                 "lt": np.less, "eq": np.equal}
    result = np.zeros((len(feed["numeric_values"]), len(policy.get("rulePolicies", []))), dtype=bool)
    for i, rule in enumerate(policy.get("rulePolicies", [])):
        index = feature["numericFeatures"].index(rule["field"])
        result[:, i] = (feed["numeric_missing"][:, index] == 0) & operators[rule["operator"]](
            feed["numeric_values"][:, index].astype(np.float64), rule["threshold"])
    return result


def family_hits(hits, policy):
    if "familyPolicies" not in policy:
        return hits
    result = np.zeros((len(hits), 4), dtype=bool)
    for i, rule in enumerate(policy.get("rulePolicies", [])):
        result[:, CLASSES.index(rule["family"]) - 1] |= hits[:, i]
    return result


def run(args):
    output = args.registration.resolve().parent
    registration = read(args.registration)
    if sha(args.registration) != read(output / "registration-receipt.json")["sha256"]:
        raise ValueError("登记哈希改变")
    lock = output / ".evaluation-lock"
    lock.mkdir(mode=0o700)
    started = time.monotonic()
    try:
        if (output / "report.json").exists() or (output / "failure.json").exists():
            raise ValueError("已运行登记不能重用")
        for name, expected in registration["codeSha256"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("评估代码在登记后改变")
        candidate, frozen = Path(registration["candidate"]), Path(registration["frozen"])
        _, plan, feature, policy, pre = checked_candidate(candidate)
        import lightgbm
        if registration["packages"] != {"numpy": np.__version__, "onnxruntime": ort.__version__,
                                        "lightgbm": lightgbm.__version__}:
            raise ValueError("准入后运行时依赖改变")
        if (sha(candidate / "checksums.json") != registration["candidateChecksumsSha256"]
                or sha(candidate / "evaluation-plan.json") != registration["evaluationPlanSha256"]
                or sha(frozen / "manifest.json") != registration["datasetManifestSha256"]
                or sha(frozen / "test-access.jsonl") != registration["priorAccessLogSha256"]):
            raise ValueError("准入后清单或访问状态改变")
        if (
                registration["evaluationVersion"] != plan["evaluationVersion"]
                or registration["decisionPolicySha256"] != sha(candidate / "decision-policy.json")
                or registration["modelManifestSha256"] != sha(candidate / "model-manifest.json")
                or registration["candidateSchemaSha256"] != sha(ROOT / "docs/contracts/model-manifest.schema.json")
                or registration["policySchemaSha256"] != sha(ROOT / "docs/contracts/decision-policy.schema.json")):
            raise ValueError("准入后策略、manifest 或 Schema 改变")
        data = load_registered(registration, output)
        meta = metadata(data, registration)
        feed = inputs(data, feature, pre)
        runtime = session(candidate / "model.onnx")
        inference_start = time.perf_counter()
        scores = predict(runtime, feed)
        inference_seconds = time.perf_counter() - inference_start
        parity = compare(scores, framework_predict(feed, pre, candidate / "native-model.txt"), alert_thresholds(policy))
        labels = np.asarray([CLASSES.index(row["label"]) for row in data])
        sources = np.asarray(["website" if row.get("websiteSupplement") else "internal" for row in data])
        scenarios = np.asarray([row["activityId"] for row in data])
        parents = [row["parentConnectionId"] for row in data]
        identities = {}
        for i, parent in enumerate(parents):
            identity = (int(labels[i]), str(sources[i]), str(scenarios[i]))
            if identities.setdefault(parent, identity) != identity:
                raise ValueError("同一 parent 标签、来源或活动冲突")
        hits = frozen_rules(feed, meta, feature, policy)
        first, decisions = first_decisions(parents, [row["time"] for row in meta],
                                            [row["sequence"] for row in meta],
                                            [row["observationId"] for row in data], scores, family_hits(hits, policy),
                                            policy["alertThreshold"], model_decisions(scores, policy))
        reports = [report(labels[first], decision, sources[first], scenarios[first], l1=registration["layer"] == "L1")
                   for decision in decisions]
        per_rule = {}
        for i, rule in enumerate(policy.get("rulePolicies", [])):
            detected = {parent for parent, hit in zip(parents, hits[:, i]) if hit}
            selected = [CLASSES.index(rule["family"]) if parents[index] in detected else 0 for index in first]
            per_rule[rule["ruleId"]] = report(labels[first], selected, sources[first], scenarios[first],
                                              l1=registration["layer"] == "L1")
        dataset_manifest = read(frozen / "manifest.json")
        if registration["layer"] == "L1":
            if (dict(Counter(row["label"] for row in data)) != dataset_manifest["snapshotCounts"]["test"]
                    or dict(Counter(CLASSES[index] for index in labels[first])) != dataset_manifest["connectionCounts"]["test"]):
                raise ValueError("测试样本量与冻结清单不符")
            gates, eligibility = gates_and_eligibility(reports[0], plan)
            if "familyPolicies" in policy:
                eligibility = source_eligibility(reports[0], per_rule, policy, plan)
        else:
            gates, eligibility = {"G1": "report_only", "G2": "report_only", "G3": "not_evaluated"}, {}
        bundle = output / "runtime-bundle"
        bundle.mkdir(mode=0o700)
        shutil.copyfile(candidate / "model.onnx", bundle / "model.onnx")
        np.savez_compressed(bundle / "feed.npz", **feed)
        np.save(bundle / "mac-output.npy", scores, allow_pickle=False)
        write(bundle / "runtime-bundle.json", {"version": "p6-runtime-bundle/1",
                                               "evaluationId": registration["evaluationId"],
                                               "referencePlatform": platform.system(),
                                               "alertThreshold": alert_thresholds(policy),
                                               "runtimeCodeSha256": registration["codeSha256"]["scripts/p6/runtime.py"],
                                               "files": {name: sha(bundle / name) for name in
                                                         ("model.onnx", "feed.npz", "mac-output.npy")},
                                               "containsLabelsOrIdentifiers": False})
        result = {"version": plan["evaluationVersion"], "stage": "P6", "layer": registration["layer"],
                  "evaluationId": registration["evaluationId"], "snapshots": len(data),
                  "registrationSha256": sha(args.registration),
                  "modelSha256": plan["candidateSha256"], "datasetSha256": registration["datasetSha256"],
                  "evaluationPlanSha256": registration["evaluationPlanSha256"],
                  "decisionPolicySha256": registration.get("decisionPolicySha256"),
                  "modelManifestSha256": registration.get("modelManifestSha256"),
                  "modelOnly": reports[0], "ruleOnly": reports[1], "ruleOnlyById": per_rule, "combinedOr": reports[2],
                  "modelAdditionalAttacks": int(((labels[first] > 0) & (decisions[0] > 0) & (decisions[1] == 0)).sum()),
                  "ruleFalseAlarmsNotRaisedByModel": int(((labels[first] == 0) & (decisions[1] > 0) & (decisions[0] == 0)).sum()),
                  "orCorrectedRuleFalseAlarms": 0, "gates": gates, "classEligibility": eligibility,
                  "sourceEligibility": {family: {"model": values["modelOnly"], "rules": values["ruleOnly"]}
                                        for family, values in eligibility.items()} if "familyPolicies" in policy else {},
                  "frameworkParity": parity, "crossPlatformParity": "pending_runtime_bundle",
                  "candidateOnly": True, "automaticExecutionEnabled": False,
                  "testEvaluationsUsed": len({item["evaluationId"] for item in events(frozen)
                                               if item["event"] == "access_started"}),
                  "qualityCoverage": dataset_manifest.get("qualityCoverage", dataset_manifest.get("activities")),
                  "exclusions": dataset_manifest["exclusions"],
                  "limitations": dataset_manifest["limitations"],
                  "l2Status": "not_prepared_optional_A7", "g3Status": "not_evaluated",
                  "inferenceSeconds": inference_seconds,
                  "snapshotsPerSecond": len(data) / inference_seconds if inference_seconds > 0 else None,
                  "elapsedSeconds": time.monotonic() - started,
                  "platform": platform.system(), "runtimeVersion": ort.__version__}
        write(output / "report.json", result)
        print(json.dumps({"evaluationId": registration["evaluationId"], "gates": gates,
                          "frameworkParity": parity, "connections": len(first), "snapshots": len(data)}))
        if not parity["passed"]:
            raise SystemExit(2)
    except BaseException:
        if not (output / "failure.json").exists():
            write(output / "failure.json", {"evaluationId": registration["evaluationId"],
                                            "failed": True, "testBudgetNotReset": True})
        raise
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    ready = commands.add_parser("prepare")
    for name in ("candidate", "frozen", "extract", "output"):
        ready.add_argument("--" + name, type=Path, required=True)
    ready.add_argument("--layer", choices=("L1", "L3"), required=True)
    ready.add_argument("--evaluation-id", required=True)
    ready.add_argument("--change-description")
    ready.add_argument("--change-reason")
    evaluate = commands.add_parser("run")
    evaluate.add_argument("--registration", type=Path, required=True)
    review = commands.add_parser("check")
    review.add_argument("--candidate", type=Path, required=True)
    review.add_argument("--legacy-candidate-v2", action="store_true")
    args = parser.parse_args()
    if args.command == "check":
        manifest, plan, _, _, _ = checked_candidate(args.candidate.resolve(), legacy=args.legacy_candidate_v2)
        print(json.dumps({"checked": True, "modelVersion": manifest["modelVersion"],
                          "evaluationVersion": plan["evaluationVersion"], "testRead": False}))
    else:
        prepare(args) if args.command == "prepare" else run(args)


if __name__ == "__main__":
    main()
