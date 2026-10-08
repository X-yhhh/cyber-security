#!/usr/bin/env python3
"""B2：以冻结审计与显式 P4 绑定生成 rc.4 策略；不登记、不审批、不激活动作。"""
import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
FAMILIES = ("port_scan", "brute_force", "dos_flood", "dos_slow")
LAYER_FIELDS = ("policyId", "policyVersion", "modelId", "family", "profile", "alertThreshold",
                "autoThreshold", "minDistinctFlows", "minEvidenceSpanMs", "episodeSeconds",
                "contextWindowSeconds", "minPeerFlowStarts", "maxEvidenceAgeMs", "evaluationPlanSha256")
DEPLOYMENT_FIELDS = ("maxTtlSeconds", "maxContinuousBlockSeconds", "maxActiveRulesPerAsset",
                     "maxNewActionsPerMinute", "supportedCapabilityIds", "protectionSetSha256")
FAMILY_FIELDS = ("family", "alertThreshold", "autoThreshold", "minDistinctFlows", "scope")
RULE_FIELDS = ("ruleId", "family", "field", "operator", "threshold")


class PolicyError(ValueError):
    """输入不完整、不一致或转换会丢失语义时拒绝，错误不回显输入值。"""


def require(condition, message):
    if not condition:
        raise PolicyError(message)


def required(value, key):
    require(isinstance(value, dict) and key in value and value[key] is not None,
            f"缺少必填字段: {key}")
    return value[key]


def fields(value, keys, name):
    require(isinstance(value, dict) and set(value) == set(keys), f"字段缺失或未知: {name}")


def boolean(value, name):
    require(isinstance(value, bool), f"必须为布尔值: {name}")
    return value


def canonical(value):
    try:
        return rfc8785.dumps(value)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise PolicyError("非法 JSON 数值或 Unicode") from exc


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "重复 JSON 字段")
        result[key] = value
    return result


def decode(raw):
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: require(False, "非法 JSON 数值"))
        canonical(value)
        return value
    except (ValueError, UnicodeError) as exc:
        raise PolicyError("无效 JSON：重复字段、数值或编码错误") from exc


def load(path):
    return decode(Path(path).read_bytes())


def exact_families(rows, name):
    require(isinstance(rows, list), f"必须为数组: {name}")
    names = [required(row, "family") for row in rows]
    require(all(isinstance(name, str) for name in names), f"非法类别: {name}")
    require(len(names) == 4 and set(names) == set(FAMILIES), f"类别必须完整且唯一: {name}")
    return dict(zip(names, rows))


def finite(value):
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def equal_number(left, right, name):
    require(finite(left) and finite(right) and left == right, f"冻结值不一致: {name}")


def check_preview(layer, preview):
    """告警阈值由冻结层显式提供；审计存在同名阈值时必须相等，不能由自动阈值猜出。"""
    equal_number(layer["alertThreshold"], required(preview, "alertThreshold"), "alertThreshold")
    equal_number(layer["maxEvidenceAgeMs"], required(preview, "maxEvidenceAgeMs"), "maxEvidenceAgeMs")
    classes = required(preview, "classes")
    require(isinstance(classes, dict) and set(classes) == set(FAMILIES), "preview 类别不完整")
    rows = exact_families(layer["familyPolicies"], "candidate.familyPolicies")
    for family, row in rows.items():
        fields(row, FAMILY_FIELDS + ("modelAutoRequested",), "candidate.familyPolicies")
        boolean(row["modelAutoRequested"], "modelAutoRequested")
        parameters = required(classes[family], "parameters")
        for key in ("autoThreshold", "minDistinctFlows"):
            equal_number(row[key], required(parameters, key), f"{family}.{key}")
        # 审计未给逐类告警阈值时沿用 validation 全局阈值，与冻结 seal 的约束一致，不允许另选。
        equal_number(row["alertThreshold"], parameters.get("alertThreshold", preview["alertThreshold"]),
                     f"{family}.alertThreshold")
    return rows


def compare_rules(layer_rules, comparison):
    """只接受已按 rc.4 表达并在 validation 比较过的规则；旧端口/时间条件不做有损映射。"""
    audited = required(comparison, "rules")
    require(isinstance(layer_rules, list) and isinstance(audited, list), "规则必须为数组")
    by_id = {}
    for rule in audited:
        fields(rule, RULE_FIELDS + ("automatic",), "rules-comparison.rules（旧规则须重新审计）")
        require(rule["automatic"] is False, "规则比较不得声明自动执行")
        rule_id = rule["ruleId"]
        require(isinstance(rule_id, str) and rule_id not in by_id, "规则 ID 无效或重复")
        by_id[rule_id] = rule
    ids = set()
    for rule in layer_rules:
        fields(rule, RULE_FIELDS + ("autoRequested",), "candidate.rulePolicies")
        rule_id = rule["ruleId"]
        require(isinstance(rule_id, str) and rule_id not in ids, "规则 ID 无效或重复")
        ids.add(rule_id)
        boolean(rule["autoRequested"], "autoRequested")
        require(isinstance(rule["family"], str) and rule["family"] in FAMILIES, "未知规则类别")
        require(rule_id in by_id and all(rule[key] == by_id[rule_id][key] for key in RULE_FIELDS),
                "规则与 validation 比较不一致")
    require(ids == set(by_id), "规则与 validation 比较不完整一致")
    return layer_rules


def derive_sources(rows, rules, report):
    """P6 来源成绩只能授权对应来源；总类别成绩不可代替模型或单条规则成绩。"""
    source_flags = {}
    if report is not None:
        classes = required(report, "classEligibility")
        require(isinstance(classes, dict) and set(classes) == set(FAMILIES), "报告类别不完整")
        for family in FAMILIES:
            entry = required(classes, family)
            model = boolean(required(required(entry, "modelOnly"), "offlineEligible"), "modelOnly.offlineEligible")
            by_rule = required(entry, "ruleOnly")
            expected = {rule["ruleId"] for rule in rules if rule["family"] == family}
            require(isinstance(by_rule, dict) and set(by_rule) == expected, "报告规则来源不完整或多余")
            flags = {key: boolean(required(value, "offlineEligible"), "ruleOnly.offlineEligible")
                     for key, value in by_rule.items()}
            overall = boolean(required(entry, "offlineEligible"), "class.offlineEligible")
            require(overall == (model or any(flags.values())), "类别与来源开关矛盾")
            source_flags[family] = (model, flags)
        if "sourceEligibility" in report:
            expected = {family: {"model": classes[family]["modelOnly"], "rules": classes[family]["ruleOnly"]}
                        for family in FAMILIES}
            require(report["sourceEligibility"] == expected, "分来源报告别名矛盾")
    family_policies, rule_policies = [], []
    for family in FAMILIES:
        row = rows[family]
        model_requested = row["modelAutoRequested"]
        family_rules = [rule for rule in rules if rule["family"] == family]
        requested = model_requested or any(rule["autoRequested"] for rule in family_rules)
        require(not requested or report is not None, "无报告却请求可自动")
        model_eligible, rule_eligible = source_flags.get(family, (False, {}))
        require(not model_requested or model_eligible, "模型请求与来源资格矛盾")
        for rule in family_rules:
            require(not rule["autoRequested"] or rule_eligible[rule["ruleId"]], "规则请求与来源资格矛盾")
            rule_policies.append({key: rule[key] for key in RULE_FIELDS} | {"autoEligible": rule["autoRequested"]})
        family_policies.append({key: row[key] for key in FAMILY_FIELDS} | {
            "autoEligible": requested, "modelAutoEligible": model_requested})
    return family_policies, rule_policies


def schema_errors(policy, schema_path=None):
    validator = Draft202012Validator(load(schema_path or ROOT / "docs/contracts/decision-policy.schema.json"),
                                     format_checker=FormatChecker())
    return sorted(validator.iter_errors(policy), key=lambda error: tuple(map(str, error.absolute_path)))


def validate_policy(policy):
    """与 GuardContracts.policy 一致的结构/数值/作用域/特征检查，另约束来源开关一致性。"""
    canonical(policy)
    errors = schema_errors(policy)
    require(not errors, "rc.4 Schema 校验失败: " + ", ".join(
        ("/" + "/".join(map(str, error.absolute_path))) + ":" + error.validator for error in errors))
    rows = exact_families(policy["familyPolicies"], "policy.familyPolicies")
    for family, row in rows.items():
        require(row["scope"] == ("peer_inbound" if family == "port_scan" else "peer_service"), "非法类别作用域")
        require(row["autoThreshold"] >= row["alertThreshold"], "类别阈值越界")
        require(not row["modelAutoEligible"] or row["autoEligible"], "模型与类别来源开关矛盾")
    numeric = set(load(ROOT / "docs/contracts/feature-profile.json")["numericFeatures"])
    ids = set()
    for rule in policy.get("rulePolicies", []):
        require(rule["ruleId"] not in ids, "重复 ruleId")
        ids.add(rule["ruleId"])
        require(rule["field"] in numeric, "规则字段不在特征档案")
        require(not rule["autoEligible"] or rows[rule["family"]]["autoEligible"], "规则与类别来源开关矛盾")
    require(policy["autoThreshold"] >= policy["alertThreshold"], "全局阈值越界")
    require(policy["minEvidenceSpanMs"] <= policy["maxEvidenceAgeMs"], "证据时长越界")


def compose(layer, preview, comparison, deployment, report=None):
    """纯合成入口；文件真实性与哈希由 compose_files 检查，不能用此函数代替完整 CLI。"""
    for value in (layer, preview, comparison, deployment, report):
        canonical(value)
    fields(layer, LAYER_FIELDS + ("familyPolicies", "rulePolicies", "sourceSha256"), "candidate-layer")
    fields(deployment, DEPLOYMENT_FIELDS, "deployment-binding")
    rows = check_preview(layer, preview)
    rules = compare_rules(layer["rulePolicies"], comparison)
    families, rules = derive_sources(rows, rules, report)
    policy = {"contractVersion": "host-guard/5.0.0-rc.4"}
    policy.update({key: required(layer, key) for key in LAYER_FIELDS})
    policy.update({key: required(deployment, key) for key in DEPLOYMENT_FIELDS})
    policy.update(familyPolicies=families, rulePolicies=rules,
                  mode="auto" if any(row["autoEligible"] for row in families) else "alert_only")
    validate_policy(policy)
    return policy


def frozen_semantics(policy):
    """部署绑定、策略登记 ID 与资格可形成新发布组合；冻结的模型/阈值/规则语义不可改变。"""
    return {key: policy[key] for key in LAYER_FIELDS if key not in ("policyId", "policyVersion")} | {
        "familyPolicies": sorted(({key: row[key] for key in FAMILY_FIELDS} for row in policy["familyPolicies"]),
                                 key=lambda row: row["family"]),
        "rulePolicies": sorted(({key: row[key] for key in RULE_FIELDS} for row in policy.get("rulePolicies", [])),
                               key=lambda row: row["ruleId"])}


def checked_protection(protection):
    """保护集须是 P4 可加载的结构：两个字段、整数端口 1—65535，并入 22/53/3389 后不超过 128 个。"""
    fields(protection, ("protectedBudgetTargetIds", "protectedServicePorts"), "protection-set")
    ports = protection["protectedServicePorts"]
    require(isinstance(protection["protectedBudgetTargetIds"], list) and isinstance(ports, list)
            and all(isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 for port in ports)
            and len(set(ports) | {22, 53, 3389}) <= 128, "保护集结构不符合 P4 契约")
    return protection


def checked_closeout(closeout, report, report_raw):
    """P6 收口记录须引用同一份 L1 报告原字节并已完成：框架对拍、Mac/Windows 对拍与 L3 均通过才算。"""
    require(required(closeout, "stage") == "P6" and required(closeout, "completed") is True, "P6 收口未完成")
    require(required(required(closeout, "evidenceSha256"), "l1Report") == digest(report_raw), "收口记录未绑定该 L1 报告")
    for key, expected in (("evaluationId", "evaluationId"), ("evaluationVersion", "version"),
                          ("modelSha256", "modelSha256"), ("evaluationPlanSha256", "evaluationPlanSha256"),
                          ("gates", "gates"), ("classEligibility", "classEligibility")):
        require(required(closeout, key) == required(report, expected), f"收口记录与报告不一致: {key}")


def compose_files(candidate_layer, policy_preview, rules_comparison, deployment_binding,
                  evaluation_plan, protection_set, source_eligibility=None, evaluated_policy=None,
                  closeout=None):
    """每个源文件只读取一次；原字节 SHA 绑定审计/计划/报告，保护集单独按后端 RFC8785 计算。"""
    require((source_eligibility is None) == (evaluated_policy is None), "报告与被评价策略须同时提供")
    require(closeout is None or source_eligibility is not None, "收口记录须与 L1 报告同时提供")
    layer, deployment = load(candidate_layer), load(deployment_binding)
    paths = {"policyPreview": policy_preview, "rulesComparison": rules_comparison,
             "featureProfile": ROOT / "docs/contracts/feature-profile.json", "evaluationPlan": evaluation_plan}
    if source_eligibility is not None:
        paths.update(sourceEligibility=source_eligibility, evaluatedPolicy=evaluated_policy)
    expected = required(layer, "sourceSha256")
    fields(expected, paths, "sourceSha256")
    raw = {key: Path(path).read_bytes() for key, path in paths.items()}
    for key in paths:
        require(expected[key] == digest(raw[key]), f"源文件哈希不符: {key}")
    values = {key: decode(value) for key, value in raw.items()}
    plan = values["evaluationPlan"]
    plan_hash = digest(raw["evaluationPlan"])
    require(required(layer, "evaluationPlanSha256") == plan_hash, "评价计划哈希不符")
    require(required(plan, "featureProfileSha256") == expected["featureProfile"], "计划特征档案哈希不符")
    require(required(deployment, "protectionSetSha256") == digest(canonical(checked_protection(load(protection_set)))),
            "保护集哈希不符")
    report = values.get("sourceEligibility")
    policy = compose(layer, values["policyPreview"], values["rulesComparison"], deployment, report)
    if report is not None:
        require(required(report, "stage") == "P6" and required(report, "layer") == "L1", "须使用 P6 L1 分来源报告")
        require(required(report, "evaluationPlanSha256") == plan_hash, "报告评价计划哈希不符")
        require(required(report, "decisionPolicySha256") == expected["evaluatedPolicy"], "报告策略哈希不符")
        require(required(report, "modelSha256") == required(plan, "candidateSha256"), "报告模型哈希不符")
        evaluation_ids = required(plan, "evaluationIds")
        require(isinstance(evaluation_ids, list) and all(isinstance(value, str) for value in evaluation_ids)
                and len(set(evaluation_ids)) == len(evaluation_ids), "评价 ID 清单无效")
        require(required(report, "version") == required(plan, "evaluationVersion")
                and required(report, "evaluationId") in evaluation_ids, "报告评价登记不符")
        require(required(required(plan, "automaticEligibility"), "sourceMode") == "model_and_each_rule", "缺少分来源评价口径")
        evaluated = values["evaluatedPolicy"]
        validate_policy(evaluated)
        require(frozen_semantics(evaluated) == frozen_semantics(policy), "报告绑定的冻结策略语义不一致")
        if policy["mode"] == "auto":
            require(required(required(report, "gates"), "G1") is True
                    and required(report["gates"], "G2") is True, "G1/G2 未通过")
            # 报告只证明 L1 指标；对拍或 L3 未收口时任何来源都不能开启自动。
            require(closeout is not None, "自动资格须提供已完成的 P6 收口记录")
        if closeout is not None:
            checked_closeout(load(closeout), report, raw["sourceEligibility"])
    return policy


def inspect(policy_path, schema_path=None):
    raw = Path(policy_path).read_bytes()
    errors = schema_errors(decode(raw), schema_path)
    return {"policySha256": digest(raw), "schemaSha256": digest(Path(schema_path or ROOT / "docs/contracts/decision-policy.schema.json").read_bytes()),
            "count": len(errors), "schemaErrors": [
                {"path": "/" + "/".join(map(str, error.absolute_path)), "message": error.message}
                for error in errors]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compose_parser = commands.add_parser("compose")
    for name in ("candidate-layer", "policy-preview", "rules-comparison", "deployment-binding",
                 "evaluation-plan", "protection-set", "output"):
        compose_parser.add_argument("--" + name, type=Path, required=True)
    compose_parser.add_argument("--source-eligibility", type=Path)
    compose_parser.add_argument("--evaluated-policy", type=Path)
    compose_parser.add_argument("--closeout", type=Path)
    inspect_parser = commands.add_parser("inspect")
    inspect_parser.add_argument("--policy", type=Path, required=True)
    inspect_parser.add_argument("--schema", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            print(json.dumps(inspect(args.policy, args.schema), ensure_ascii=False, indent=2))
            return
        inputs = vars(args).copy()
        inputs.pop("command")
        output = inputs.pop("output")
        policy = compose_files(**inputs)
        # 排他创建，既有文件/软链接一律不覆盖；失败验证不会创建输出目录。
        with output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(policy, ensure_ascii=False, allow_nan=False, indent=2) + "\n")
    except (PolicyError, OSError) as exc:
        message = str(exc) if isinstance(exc, PolicyError) else "文件无法读取或输出已存在/不可写"
        print("拒绝生成: " + message, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
