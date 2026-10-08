"""P3 准备与 P6 准入共用的评价计划语义，不依赖 ONNX 转换器。"""
import hashlib
from pathlib import Path

from multiclass_common import PLAN

ROOT = Path(__file__).resolve().parents[2]


def check_plan(plan):
    """计划须显式登记来源口径与预算；实际制品哈希由准备阶段补齐。"""
    required = {"plan", "stage", "evaluationVersion", "metricDefinitionSha256", "statisticalUnit",
                "connectionDecision", "attackDetectionAggregation", "falsePositiveAggregation",
                "automaticEligibility", "evaluationIds", "maxTestEvaluations", "repeatPolicy",
                "gates", "otherDatasets", "noTestReadBeforeP6"}
    if not required <= plan.keys() or "decisionPolicySha256" in plan:
        raise ValueError("计划缺项或存在循环策略绑定")
    metric_hash = hashlib.sha256((ROOT / "docs/验证与验收.md").read_bytes()).hexdigest()
    # test 访问入口与全局 3 次额度按同一计划名记账；换名会在 access_requested 时被拒，这里提前拒绝。
    if (plan["plan"] != PLAN or plan["stage"] != "P6" or plan["noTestReadBeforeP6"] is not True
            or plan["metricDefinitionSha256"] != metric_hash
            or plan["evaluationVersion"] == "host-guard-evaluation/2026-10-07.1"
            or not isinstance(plan["evaluationVersion"], str) or not plan["evaluationVersion"].strip()
            or plan["statisticalUnit"] != "parentConnection"
            or plan["connectionDecision"] != "first_snapshot_at_alert_threshold_then_argmax_family"
            or plan["attackDetectionAggregation"] != "equal_weight_four_attack_classes"
            or plan["falsePositiveAggregation"] != "equal_weight_internal_and_website_normal"
            or plan["automaticEligibility"] != {"recallMin": .8, "precisionMin": .9,
                                               "requiresG3": True, "sourceMode": "model_and_each_rule"}
            or plan["gates"] != {"G1": {"attackDetectionMin": .9, "falsePositiveRateMax": .02},
                                 "G2": {"macroF1Min": .8}}
            or plan["maxTestEvaluations"] != 3 or not isinstance(plan["evaluationIds"], list)
            or len(plan["evaluationIds"]) != 3
            or any(not isinstance(v, str) or not v.strip() for v in plan["evaluationIds"])
            or len(set(plan["evaluationIds"])) != 3 or not plan["repeatPolicy"]):
        raise ValueError("评价计划语义不符")
