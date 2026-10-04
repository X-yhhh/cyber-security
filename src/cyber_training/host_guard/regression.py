"""冻结组合的开发回归与统一裁决；不拟合、不搜索参数、不访问最终测试。

先在完整资产预算域按原时间生成候选，再按角色、来源、活动、场景投影机会。
逐观察/机会材料仅写入受控运行目录；公开摘要不得包含这些明细。
"""
from collections import Counter
from pathlib import Path
import argparse
import json

import numpy as np

from .data import Batch, Dataset, Preprocessor, ROLES, read, sha, write
from .evaluation import Replay
from .export import session, score_session


SCENARIOS = {("cic2017-wednesday", "train"): "cic2017_slowloris",
             ("cic2017-wednesday", "validation_selection"): "cic2017_slowhttptest",
             ("cic2018-thursday", "validation_calibration"): "cic2018_slowloris"}
EXPOSURE = {"train": "model_and_preprocessing_fit_diagnostic_only",
            "validation_selection": "model_and_raw_threshold_selection_exposed",
            "validation_calibration": "calibration_and_policy_selection_exposed"}


def combine(batches):
    """完整拼接开发角色；保留原时间、资产和捕获域，不重置来源的动作预算。"""
    if any(b.role not in ROLES for b in batches):
        raise ValueError("仅允许已冻结的开发角色")
    return Batch([dict(r, split=b.role) for b in batches for r in b.rows],
                 [o for b in batches for o in b.observations],
                 np.concatenate([b.values for b in batches]), np.concatenate([b.missing for b in batches]),
                 np.concatenate([b.categories for b in batches]), "all_development")


def summarize(batch, details, ids):
    """投影同一次回放；混合标签机会保留全局保守分类，绝不拆组重新生成动作。"""
    ids = set(ids)
    opportunities = [o for o in details["opportunities"] if ids.intersection(o["observationIndices"])]
    actions = [a for a in details["actions"] if a["triggerIndex"] in ids]
    positive = [o for o in opportunities if o["positive"]]
    negative = [o for o in opportunities if not o["positive"]]
    affected = lambda o: o["status"] in ("covered", "late_covered")
    traces = [r for r in details["observations"] if r["index"] in ids]
    return {"attackOpportunities": len(positive), "benignOpportunities": len(negative),
            "coveredAttackOpportunities": sum(affected(o) for o in positive),
            "falseBenignOpportunities": sum(affected(o) for o in negative),
            "opportunityRecallDiagnostic": sum(affected(o) for o in positive) / len(positive) if positive else None,
            "ambiguousOpportunitiesCountedAsBenign": sum(o["mixedCountedAsBenign"] for o in opportunities),
            "candidateActions": len(actions), "incorrectCandidateActions": sum(not a["correct"] for a in actions),
            "opportunityStates": dict(Counter(o["status"] for o in opportunities)),
            "firstRejections": dict(Counter(r["firstRejection"] for r in traces if r["firstRejection"])),
            "ttlCoveredObservations": sum(r["coveredByExistingTtl"] for r in traces),
            "attackActivities": len({batch.rows[i]["activityId"] for i in ids if batch.rows[i]["label"] == 1}),
            "benignIndexedGroups": len({batch.rows[i]["activityId"] for i in ids if batch.rows[i]["label"] == 0}),
            "independentEvaluation": False, "onsetTimingEvaluated": False}


def regression(batches, raw_scores, calibrated_scores, raw_threshold, parameters, details_dir=None):
    """保持原始、校准后工作点与完整策略三种口径，阈值来自冻结记录。"""
    batch = combine(batches)
    raw_scores, calibrated_scores = map(lambda xs: np.concatenate(xs), (raw_scores, calibrated_scores))
    report = {"version": "p3-frozen-development-regression-v1", "budgetReplay": "global_before_grouping",
              "unit": "observed_final_target_30s_opportunity", "selectionChanged": False,
              "calibrationRefit": False, "finalTestRead": False, "workingPoints": {}}
    for name, scores, params in [
        ("raw_model", raw_scores, {"threshold": raw_threshold}),
        ("calibrated_model", calibrated_scores, {"threshold": parameters["threshold"]}),
        ("frozen_policy", calibrated_scores, parameters)]:
        details = {}
        full = Replay(batch).run(scores, **params, diagnostics=details, raw_scores=raw_scores, policy_version="legacy-final-diagnostic-v1")
        result = {"parameters": params, "global": full, "byRole": {}, "bySource": {}, "byActivity": {}, "byScenario": {}}
        for field, dimension in [("split", "byRole"), ("sourceId", "bySource"), ("activityId", "byActivity")]:
            for value in sorted({r[field] for r in batch.rows}):
                ids = [i for i, r in enumerate(batch.rows) if r[field] == value]
                result[dimension][value] = summarize(batch, details, ids)
                if dimension == "byRole":
                    result[dimension][value]["exposure"] = EXPOSURE[value]
        for (source, role), scene in SCENARIOS.items():
            ids = [i for i, r in enumerate(batch.rows) if r["sourceId"] == source and r["split"] == role and r["label"] == 1]
            if ids:
                result["byScenario"][scene] = dict(summarize(batch, details, ids), role=role, sourceId=source,
                                                   exposure=EXPOSURE[role])
        report["workingPoints"][name] = result
        if details_dir is not None:
            for kind, records in details.items():
                path = Path(details_dir) / name / (kind + ".jsonl")
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("x", encoding="utf-8") as f:
                    for record in records:
                        f.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
    return report


def stage_decision(report, *, export_passed=True):
    """P3 final研究的共享出口：实测失败、证据不足和实现缺口分列；不授予P6。"""
    regress = report["developmentRegression"]["workingPoints"]
    failures, missing, gaps = [], [], []
    selection = regress["raw_model"]["byRole"]["validation_selection"]
    if (selection["opportunityRecallDiagnostic"] or 0) < 0.8:
        failures.append({"code": "SELECTION_COVERAGE_BELOW_TARGET", "role": "validation_selection",
                         "actual": selection["opportunityRecallDiagnostic"], "target": 0.8})
    frozen = regress["frozen_policy"]
    for scenario, metrics in frozen["byScenario"].items():
        if metrics["role"] != "train" and (metrics["opportunityRecallDiagnostic"] or 0) < 0.8:
            failures.append({"code": "FROZEN_POLICY_SCENARIO_COVERAGE_BELOW_TARGET", "scenario": scenario,
                             "role": metrics["role"], "actual": metrics["opportunityRecallDiagnostic"], "target": 0.8})
    for role, metrics in frozen["byRole"].items():
        if metrics["falseBenignOpportunities"] or metrics["incorrectCandidateActions"]:
            failures.append({"code": "FROZEN_POLICY_FALSE_POSITIVE_BUDGET_EXCEEDED", "role": role})
    if report.get("e5", {}).get("positiveCoverageGain", 0) <= 0:
        failures.append({"code": "NO_POSITIVE_MODEL_POLICY_COVERAGE_GAIN"})
    if not export_passed:
        failures.append({"code": "WINNER_SEED_EXPORT_FAILURE"})
    missing.extend([{"code": "MISSING_QUALIFIED_ONSET_AND_PREFIX", "gate": "prefix_entry"},
                    {"code": "INSUFFICIENT_INDEPENDENT_ATTACK_ACTIVITIES", "gate": "P3_independent_development",
                     "independentDevelopmentGroups": 0, "minimumPlanned": 5},
                    {"code": "MISSING_INDEPENDENT_BENIGN_ACTIVITY_EVALUATION", "gate": "P3_independent_development"},
                    {"code": "INSUFFICIENT_BENIGN_OPPORTUNITIES", "gate": "P6_final_evidence",
                     "minimumFinal": 3000, "isTrainingEntryMinimum": False},
                    {"code": "FINAL_TEST_UNALLOCATED", "gate": "P6_admission"}])
    expected = set(SCENARIOS.values())
    if expected - set(frozen["byScenario"]):
        gaps.append({"code": "MISSING_DECLARED_SCENARIO_REGRESSION", "scenarios": sorted(expected-set(frozen["byScenario"]))})
    return {"phase": "P3", "implementationStatus": "completed" if not gaps else "incomplete", "status": "blocked",
            "feasibilityStatus": "failed" if failures else "blocked", "modelFeasibilityGatePassed": False,
            "p6Authorized": False, "candidateOnly": True, "automaticExecutionAuthorized": False, "finalTestRead": False,
            "measuredFailures": failures, "missingEvidence": missing, "implementationGaps": gaps,
            "blockingReasons": sorted({item["code"] for item in failures + missing + gaps})}


def verify_source(source):
    """先核验源清单及路径，再读取候选/分数，拒绝被篡改或越界的既有交付。"""
    source = Path(source).resolve()
    for name, expected in read(source / "checksums.json").items():
        path = (source / name).resolve()
        if source not in path.parents or not path.is_file() or sha(path) != expected:
            raise ValueError("源交付哈希或路径不符: " + name)
    return source


def frozen_inputs(source, data):
    """校准分数使用冻结夹具，原始分数由已冻结未校准ONNX复算；核对全部输入顺序。"""
    batches = [data.load(role, source / "selection-lock.json" if role == "validation_calibration" else None) for role in ROLES]
    pre = Preprocessor(read(source / "candidate/preprocessing.json"))
    with np.load(source / "candidate/parity-fixture.npz", allow_pickle=False) as fixture:
        for name in pre.feed(batches[0]):
            np.testing.assert_array_equal(fixture[name], np.concatenate([pre.feed(b)[name] for b in batches]))
        scores = fixture["expected"].copy()
    if len(scores) != sum(len(b.rows) for b in batches):
        raise ValueError("夹具行数不符")
    original_model = source / "experiments" / read(source / "selection-lock.json")["experimentId"]
    model = session(original_model / "model.onnx")
    raw_pre = Preprocessor(read(original_model / "preprocessing.json"))
    raw = [score_session(model, raw_pre, batch) for batch in batches]
    split = np.cumsum([len(b.rows) for b in batches])[:-1]
    return batches, raw, np.split(scores, split)


def audit(source, out, dataset, contracts, public):
    """独占输出新报告，旧manifest/策略/模型以及历史JSON均不改写。"""
    source = verify_source(source); out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    old = read(source / "validation-report.json")
    plan = read(source / "experiment-plan.json")
    data = Dataset(dataset, contracts, public, plan, out / "access-audit.jsonl")
    batches, raw, scores = frozen_inputs(source, data)
    ident = read(source / "selection-lock.json")["experimentId"]
    threshold = read(source / "experiments" / ident / "report.json")["workingPoint"]["threshold"]
    report = regression(batches, raw, scores, threshold, old["policySelection"]["parameters"], out / "private")
    write(out / "regression.json", report)
    stage = stage_decision({"developmentRegression": report, "e5": old["e5"]})
    stage.update(candidateModelSha256=sha(source / "candidate/model.onnx"),
                 sourceChecksumsSha256=sha(source / "checksums.json"), regressionSha256=sha(out / "regression.json"),
                 newModelFits=0, calibrationFits=0, thresholdSearches=0)
    write(out / "stage-exit.json", stage)
    write(out / "bindings.json", {"sourceRun": source.name, "sourceHeadBoundByPriorManifest": True,
          "datasetFreezeSha256": plan["datasetFreezeSha256"],
          "candidateFiles": {p.name: sha(p) for p in sorted((source / "candidate").iterdir()) if p.is_file()},
          "code": {p.name: sha(p) for p in sorted(Path(__file__).parent.glob("*.py"))}})
    write(out / "checksums.json", {p.relative_to(out).as_posix(): sha(p) for p in sorted(out.rglob("*")) if p.is_file()})
    return stage


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "out", "dataset", "contracts", "public"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(**vars(args)), ensure_ascii=False))
