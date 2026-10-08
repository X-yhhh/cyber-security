"""P6 连接级指标：不选阈值，不拟合，不把离线资格写成自动能力。"""
from __future__ import annotations

import numpy as np

CLASSES = ("normal", "port_scan", "brute_force", "dos_flood", "dos_slow")


def first_decisions(parents, times, sequence, identifiers, scores, rule_hits, threshold, model_labels=None):
    """按事件时间选择首个命中；同观察模型优先，规则平局按冻结类别顺序。

    时间和身份只用来排序及去重，绝不输入模型；续段不能重置 parent。
    """
    ordered = sorted(range(len(parents)), key=lambda i: (times[i], sequence[i], identifiers[i]))
    first = {}
    predictions = [{}, {}, {}]
    for i in ordered:
        parent = parents[i]
        first.setdefault(parent, i)
        model = (int(model_labels[i]) if model_labels is not None else
                 int(np.argmax(scores[i, 1:])) + 1 if float(scores[i, 0]) >= threshold else 0)
        rule = int(np.argmax(rule_hits[i])) + 1 if rule_hits[i].any() else 0
        for selected, value in zip(predictions, (model, rule, model or rule)):
            if value:
                selected.setdefault(parent, value)
    keys = list(first)
    indices = np.asarray([first[key] for key in keys], dtype=np.int64)
    return indices, [np.asarray([item.get(key, 0) for key in keys], dtype=np.int64)
                     for item in predictions]


def report(labels, predicted, sources, scenarios, *, l1=False):
    """攻击错分仍计检出；L1 四攻击类与两正常来源分别等权。

    缺失分母返回 null，L1 不完整时拒绝判定门槛；不通过删除类别改善均值。
    """
    labels, predicted = np.asarray(labels), np.asarray(predicted)
    sources, scenarios = np.asarray(sources), np.asarray(scenarios)
    if not len(labels) or labels.shape != predicted.shape:
        raise ValueError("空数据或判定维度不符")
    if not np.isin(labels, range(5)).all() or not np.isin(predicted, range(5)).all():
        raise ValueError("未知类别")
    matrix = np.zeros((5, 5), dtype=np.int64)
    np.add.at(matrix, (labels, predicted), 1)
    support, positives = matrix.sum(axis=1), matrix.sum(axis=0)
    per_class, detection = {}, {}
    for i, name in enumerate(CLASSES):
        tp = int(matrix[i, i])
        recall = tp / int(support[i]) if support[i] else None
        precision = tp / int(positives[i]) if positives[i] else 0.0
        f1 = 2 * tp / int(support[i] + positives[i]) if support[i] + positives[i] else 0.0
        per_class[name] = {"support": int(support[i]), "predicted": int(positives[i]),
                           "recall": recall, "precision": precision, "f1": f1}
        if i:
            detection[name] = float(np.mean(predicted[labels == i] > 0)) if support[i] else None
    fprs = {}
    for source in sorted(set(sources[labels == 0])):
        mask = (labels == 0) & (sources == source)
        fprs[str(source)] = {"connections": int(mask.sum()),
                             "falseAlarms": int((predicted[mask] > 0).sum()),
                             "rate": float(np.mean(predicted[mask] > 0))}
    complete = all(support) and set(fprs) == {"internal", "website"}
    attack_values = [value for value in detection.values() if value is not None]
    fpr = (sum(fprs[key]["rate"] for key in ("internal", "website")) / 2
           if l1 and complete else
           float(np.mean(predicted[labels == 0] > 0)) if np.any(labels == 0) and not l1 else None)
    scenario_metrics = {}
    for scenario in sorted(set(scenarios)):
        mask = scenarios == scenario
        cm = np.zeros((5, 5), dtype=np.int64)
        np.add.at(cm, (labels[mask], predicted[mask]), 1)
        scenario_metrics[str(scenario)] = {"connections": int(mask.sum()), "confusionMatrix": cm.tolist()}
    return {"connections": len(labels), "classOrder": list(CLASSES), "confusionMatrix": matrix.tolist(),
            "perClass": per_class, "attackDetectionByClass": detection,
            "attackDetection": sum(attack_values) / len(attack_values)
            if attack_values and (not l1 or complete) else None,
            "falsePositiveRate": fpr, "normalSourceFpr": fprs,
            "macroF1": sum(value["f1"] for value in per_class.values()) / 5,
            "l1DenominatorsComplete": complete, "scenarioMetrics": scenario_metrics}


def gates_and_eligibility(metrics, plan):
    """P6 只登记离线数值资格；G3 与真实授权均保持待验。"""
    complete = metrics["l1DenominatorsComplete"]
    criteria = plan["gates"]
    g1 = complete and metrics["attackDetection"] >= criteria["G1"]["attackDetectionMin"] \
        and metrics["falsePositiveRate"] <= criteria["G1"]["falsePositiveRateMax"]
    g2 = complete and metrics["macroF1"] >= criteria["G2"]["macroF1Min"]
    eligibility = {}
    for name in CLASSES[1:]:
        item = metrics["perClass"][name]
        eligible = bool(item["support"] and item["recall"] >= plan["automaticEligibility"]["recallMin"]
                        and item["precision"] >= plan["automaticEligibility"]["precisionMin"])
        eligibility[name] = {"offlineEligible": eligible, "requiresG3": True,
                             "automaticExecutionEnabled": False, "mode": "alert_only",
                             "reason": "G3_PENDING" if eligible else "OFFLINE_CLASS_METRICS_INSUFFICIENT"}
    return {"G1": bool(g1), "G2": bool(g2), "G3": "not_evaluated"}, eligibility


def source_eligibility(model, rules, policy, plan):
    """每条规则独立计分，不用规则 OR 或其他来源的成绩代替其资格。"""
    _, model_eligible = gates_and_eligibility(model, plan)
    result = {}
    for family in CLASSES[1:]:
        by_rule = {}
        for rule in policy.get("rulePolicies", []):
            if rule["family"] == family:
                _, values = gates_and_eligibility(rules[rule["ruleId"]], plan)
                by_rule[rule["ruleId"]] = values[family] | {
                    "recall": rules[rule["ruleId"]]["perClass"][family]["recall"],
                    "precision": rules[rule["ruleId"]]["perClass"][family]["precision"]}
        result[family] = {"modelOnly": model_eligible[family] | {
            "recall": model["perClass"][family]["recall"], "precision": model["perClass"][family]["precision"]},
            "ruleOnly": by_rule,
            "offlineEligible": model_eligible[family]["offlineEligible"] or any(v["offlineEligible"] for v in by_rule.values()),
            "requiresG3": True, "automaticExecutionEnabled": False, "mode": "alert_only"}
    return result
