"""从哈希绑定的既有权重收尾：独立复算策略统计和Schema，不重新拟合/选模/校准。"""
from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
import shutil
import uuid

import numpy as np

from .data import Dataset, Preprocessor, contract_validator, read, sha, write
from .evaluation import Replay, choose_threshold, objective, rules, select_policy
from .export import session, score_session
from .runner import environment, source_hash


def finalize(source, out, data_root, contracts, public):
    source, out = Path(source), Path(out)
    original = read(source / "validation-report.json")
    manifest = read(source / "candidate/model-manifest.json")
    policy = read(source / "candidate/decision-policy.json")
    for field, path in [("artifactSha256", "candidate/model.onnx"), ("preprocessingSha256", "candidate/preprocessing.json"),
                        ("calibrationSha256", "candidate/calibration.json"), ("validationReportSha256", "validation-report.json")]:
        if manifest[field] != sha(source / path):
            raise ValueError("既有制品绑定已变化")
    if original["export"]["status"] != "passed" or original["finalTestRead"] or not manifest["candidateOnly"]:
        raise ValueError("原实验尚未完成训练/导出或超出候选范围")
    # 复制到新目录修正交付统计；原失败运行和所有权重原封不动保留。
    shutil.copytree(source, out)
    plan = read(out / "experiment-plan.json")
    data = Dataset(data_root, contracts, public, plan, out / "finalization-access-audit.jsonl")
    shutil.copyfile(Path(contracts) / "docs/contracts/feature-profile.json", out / "candidate/feature-profile.json")
    train, selection = data.load("train"), data.load("validation_selection")
    calibration = data.load("validation_calibration", out / "selection-lock.json")
    repaired = deepcopy(original)
    summaries = {s["id"]: s for s in repaired["modelMatrix"] + repaired["threeSeeds"]["reports"]}
    metrics_changed = []
    for ident, summary in summaries.items():
        folder = out / "experiments" / ident
        pre = Preprocessor(read(folder / "preprocessing.json"))
        scores = score_session(session(folder / "model.onnx"), pre, selection)
        replay = Replay(selection)
        best, trials = choose_threshold(replay, scores, plan["decision"]["thresholds"])
        old_best = summary["workingPoint"]
        if best["threshold"] != old_best["threshold"] or objective(best["metrics"]) != objective(old_best["metrics"]):
            raise ValueError("审计改变已冻结选型工作点，需要单独审查")
        summary["workingPoint"], summary["thresholdSearch"] = best, trials
        old = read(source / "experiments" / ident / "report.json")
        for a, b in zip(old["thresholdSearch"], trials, strict=True):
            for key in ("incorrectCandidateActions", "falseCandidateSeconds"):
                if a["metrics"][key] != b["metrics"][key]:
                    metrics_changed.append({"experiment": ident, "threshold": b["threshold"], "metric": key,
                                            "old": a["metrics"][key], "corrected": b["metrics"][key]})
        write(out / "original" / "experiments" / ident / "report.json", old)
        (folder / "report.json").unlink()  # 仅重建本函数新复制目录中的可再生摘要，原件在source及original双重保留。
        write(folder / "report.json", summary)
    repaired["modelMatrix"] = [summaries[s["id"]] for s in repaired["modelMatrix"]]
    repaired["threeSeeds"]["reports"] = [summaries[s["id"]] for s in repaired["threeSeeds"]["reports"]]
    pre = Preprocessor(read(out / "candidate/preprocessing.json"))
    with np.load(out / "candidate/parity-fixture.npz", allow_pickle=False) as fixture:
        for name in pre.feed(selection):
            actual = np.concatenate([pre.feed(b)[name] for b in [train, selection, calibration]])
            np.testing.assert_array_equal(fixture[name], actual)
        scores = fixture["expected"][len(train.rows) + len(selection.rows):].copy()
    replay = Replay(calibration)
    best, trials = select_policy(replay, scores, plan)
    if best["parameters"] != original["policySelection"]["parameters"]:
        raise ValueError("策略审计改变冻结参数，不能静默重新选择")
    rule_trials = [{"rule": name, "metrics": replay.run(values, 0.5)} for name, values in rules(calibration, plan)]
    rule_best = max(rule_trials, key=lambda t: objective(t["metrics"]))
    if rule_best["rule"] != original["e5"]["rules"]["rule"]:
        raise ValueError("规则审计改变原对照选型")
    model_best, _ = choose_threshold(replay, scores, plan["decision"]["thresholds"])
    repaired["policySelection"] = best
    repaired["alertSelection"]["metrics"] = replay.run(scores, repaired["alertSelection"]["threshold"])
    repaired["e5"].update(rules=rule_best, modelOnly=model_best, modelAndPolicy=best,
                         positiveCoverageGain=(best["metrics"]["opportunityRecallDiagnostic"] or 0) - (rule_best["metrics"]["opportunityRecallDiagnostic"] or 0))
    repaired["policyBySource"] = {}
    for source_id in sorted({r["sourceId"] for r in calibration.rows}):
        ids = [i for i, r in enumerate(calibration.rows) if r["sourceId"] == source_id]
        repaired["policyBySource"][source_id] = Replay(calibration.take(ids)).run(scores[ids], **best["parameters"])
    audit_sha, audit_files = source_hash(Path(__file__).parent)
    repaired["finalization"] = {"method": "reuse exact frozen weights/calibration; recompute candidate metrics only",
                                "trainingRepeated": False, "calibrationRefit": False, "selectionChanged": False,
                                "sourceValidationReportSha256": sha(source / "validation-report.json"),
                                "evaluationCodeSha256": audit_sha, "collateralCountingCorrection": True,
                                "changedThresholdMetrics": metrics_changed}
    replacements = {"validation-report.json": repaired, "policy-search.json": {"trials": trials, "rules": rule_trials}}
    for name, value in replacements.items():
        write(out / "original" / name, read(source / name))
        (out / name).unlink(); write(out / name, value)
    manifest["modelId"] = str(uuid.uuid4()); manifest["modelVersion"] = out.name
    manifest["validationReportSha256"] = sha(out / "validation-report.json")
    policy["modelId"] = manifest["modelId"]; policy["policyId"] = str(uuid.uuid4()); policy["policyVersion"] = out.name
    for name, value in [("model-manifest", manifest), ("decision-policy", policy)]:
        contract_validator(contracts, name).validate(value)
        write(out / "original/candidate" / (name + ".json"), read(source / "candidate" / (name + ".json")))
        (out / "candidate" / (name + ".json")).unlink(); write(out / "candidate" / (name + ".json"), value)
    write(out / "finalization-code-manifest.json", {"sha256": audit_sha, "files": audit_files})
    write(out / "finalization-environment.json", environment())
    reasons = ["MISSING_QUALIFIED_ONSET_AND_PREFIX", "INSUFFICIENT_INDEPENDENT_ATTACK_ACTIVITIES", "FINAL_TEST_UNALLOCATED"]
    metrics = best["metrics"]
    if repaired["e5"]["positiveCoverageGain"] <= 0:
        reasons.append("NO_POSITIVE_MODEL_POLICY_COVERAGE_GAIN")
    if (metrics["opportunityRecallDiagnostic"] or 0) < 0.8:
        reasons.append("DIAGNOSTIC_COVERAGE_BELOW_TARGET")
    if metrics["benignOpportunities"] < 3000:
        reasons.append("INSUFFICIENT_BENIGN_OPPORTUNITIES")
    if (metrics["precisionAtOpportunityRatios"]["0.01"] or 0) < 0.99:
        reasons.append("PRIMARY_RATIO_PRECISION_BELOW_TARGET_OR_UNDEFINED")
    exit_report = {"phase": "P3", "implementationStatus": "completed", "status": "blocked",
                   "modelFeasibilityGatePassed": False, "p6Authorized": False, "blockingReasons": reasons,
                   "rootCauses": ["sample_size_and_independence", "missing_observable_early_evidence"] +
                                 (["no_model_gain_over_rules"] if repaired["e5"]["positiveCoverageGain"] <= 0 else []),
                   "candidateOnly": True, "automaticExecutionAuthorized": False, "finalTestRead": False,
                   "experimentCount": original["fullModelFits"], "correctiveFits": 2,
                   "candidateModelSha256": sha(out / "candidate/model.onnx"), "validationReportSha256": sha(out / "validation-report.json"),
                   "trainingCodeSha256": original["trainingCodeSha256"], "evaluationCodeSha256": audit_sha,
                   "next": "Return to P2 for independent qualified early evidence and stronger benign/activity coverage; P4/P5 can proceed independently."}
    write(out / "stage-exit.json", exit_report)
    files = {p.relative_to(out).as_posix(): sha(p) for p in sorted(out.rglob("*")) if p.is_file()}
    write(out / "checksums.json", files)
    return {"status": "completed", "stageGate": "blocked", "trainingRepeated": False,
            "metricCorrections": len(metrics_changed), "weightHashUnchanged": sha(source / "candidate/model.onnx") == sha(out / "candidate/model.onnx")}


if __name__ == "__main__":
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source-run", "output", "dataset", "contracts", "public"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(finalize(args.source_run, args.output, args.dataset, args.contracts, args.public)))
