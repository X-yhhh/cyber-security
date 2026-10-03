"""P3有界实验入口：先冒烟、再选型冻结、最后独立校准与策略诊断，始终candidateOnly。"""
from __future__ import annotations

import argparse
import importlib.metadata
from pathlib import Path
import platform
import subprocess
import time
import uuid
from datetime import datetime, timezone

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, roc_auc_score

from .data import Dataset, Preprocessor, contract_validator, read, sha, write
from .evaluation import Replay, choose_threshold, classification, error_groups, objective, rules, select_policy
from .export import export, latency, parity, score_session, session
from .models import calibrate, calibrated, fit, predict


def progress(stage, **fields):
    import json
    print(json.dumps({"stage": stage, **fields}, ensure_ascii=False), flush=True)


def source_hash(root):
    files = {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob("*.py"))}
    import hashlib, json
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return digest, files


def environment():
    packages = ["numpy", "scipy", "scikit-learn", "torch", "xgboost", "lightgbm", "onnx", "onnxruntime", "onnxmltools", "pytest", "jsonschema"]
    return {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
            "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
            "cudaAvailable": torch.cuda.is_available(), "cudaVersion": torch.version.cuda,
            "packages": {name: importlib.metadata.version(name) for name in packages},
            "trainingBranch": subprocess.check_output(["git", "branch", "--show-current"], text=True).strip(),
            "trainingHead": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()}


def smoke(dataset, train, selection, plan, out):
    # 按完整parent取小批正负数据，不以逐行随机拆分制造新的验证集。
    selected = set()
    for label in (0, 1):
        selected.update(sorted({r["parentConnectionId"] for r in train.rows if r["label"] == label})[:32])
    tiny = train.take([i for i, r in enumerate(train.rows) if r["parentConnectionId"] in selected])
    preprocessing = Preprocessor.fit(tiny)
    reports = {}
    for algorithm in plan["budget"]["algorithms"]:
        start = time.perf_counter()
        model, timing = fit(algorithm, tiny, preprocessing, plan, 42, smoke=True)
        path = out / (algorithm + ".onnx")
        export(algorithm, model, preprocessing, {"method": "none"}, path)
        check = parity(path, algorithm, model, preprocessing, {"method": "none"}, [tiny, selection.take(range(min(128, len(selection.rows))))], [0.5])
        reports[algorithm] = {"fit": timing, "onnx": check, "totalSeconds": time.perf_counter() - start}
        write(out / (algorithm + "-smoke.json"), reports[algorithm])
        progress("smoke", algorithm=algorithm, status=check["status"])
        if check["status"] != "passed":
            raise ValueError("冒烟ONNX对拍失败: " + algorithm)
    write(out / "smoke-report.json", {"status": "passed", "models": reports, "finalTestRead": False})


def source_diagnostic(train, selection):
    """来源诊断只用良性，避免用攻击标签混淆来源识别；不影响模型选型。"""
    a = train.take(np.flatnonzero(train.y == 0)); b = selection.take(np.flatnonzero(selection.y == 0))
    pre = Preprocessor.fit(a)
    ya = np.asarray([r["evidenceTier"] == "controlled_task" for r in a.rows], dtype=int)
    yb = np.asarray([r["evidenceTier"] == "controlled_task" for r in b.rows], dtype=int)
    model = LogisticRegression(max_iter=2000, C=0.1, random_state=42)
    model.fit(pre.transform(a), ya, sample_weight=a.weights)
    scores = model.predict_proba(pre.transform(b))[:, 1]
    return {"task": "controlled Windows benign vs public benign", "fitRole": "train benign only",
            "reportRole": "validation_selection benign only", "rocAuc": float(roc_auc_score(yb, scores, sample_weight=b.weights)),
            "balancedAccuracy": float(balanced_accuracy_score(yb, scores >= 0.5, sample_weight=b.weights)),
            "implication": "high source separability warns of capture/domain confounding; not proof attack classifier relies on it",
            "calibrationAccess": False}


def experiment(algorithm, feature_set, train, selection, plan, out, name, seed=42):
    folder = out / "experiments" / name; folder.mkdir(parents=True)
    preprocessing = Preprocessor.fit(train, feature_set)
    write(folder / "preprocessing.json", preprocessing.parameters)
    model, timing = fit(algorithm, train, preprocessing, plan, seed)
    scores = predict(algorithm, model, preprocessing.transform(selection))
    choice, thresholds = choose_threshold(Replay(selection), scores, plan["decision"]["thresholds"])
    summary = {"id": name, "algorithm": algorithm, "featureSet": feature_set, "seed": seed, "fit": timing,
               "classification": classification(selection, scores, choice["threshold"], curves=True),
               "workingPoint": choice, "thresholdSearch": thresholds,
               "errors": error_groups(selection, scores, choice["threshold"])}
    model_path = folder / "model.onnx"
    export(algorithm, model, preprocessing, {"method": "none"}, model_path)
    summary["onnx"] = parity(model_path, algorithm, model, preprocessing, {"method": "none"},
                             [train, selection], [choice["threshold"]])
    summary["artifactSha256"] = sha(model_path)
    summary["importance"] = ({"features": [*['value:' + str(i) for i in preprocessing.parameters['indices']],
                                            *['mask:' + str(i) for i in preprocessing.parameters['indices']], 'transport', 'direction', 'serviceClass'],
                               "values": np.asarray(model.feature_importances_, dtype=float).tolist()}
                              if algorithm != "mlp" else {"available": False})
    write(folder / "report.json", summary)
    progress("experiment", id=name, recall=choice["metrics"]["opportunityRecallDiagnostic"],
             falseOpportunities=choice["metrics"]["falseBenignOpportunities"], onnx=summary["onnx"]["status"])
    return {"summary": summary, "model": model, "preprocessing": preprocessing, "train": train}


def ranking(item):
    s = item["summary"]
    return (int(s["onnx"]["status"] == "passed"), *objective(s["workingPoint"]["metrics"]), -s["classification"]["logLoss"])


def manifest(dataset, winner, report, calibration, plan_path, out, code_sha):
    """模型本体与独立策略均哈希绑定；最终评估为空，任何结果都不会授予执行能力。"""
    summary = winner["summary"]; profile = dataset.profile
    example = read(dataset.contracts / "docs/contracts/examples/model-manifest.json")
    model_id = str(uuid.uuid4())
    example.update({"modelId": model_id, "modelVersion": out.name, "createdAt": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                    "artifactSha256": sha(out / "candidate/model.onnx"), "featureProfileSha256": dataset.plan["featureProfileSha256"],
                    "extractorSha256": read(out / "candidate/extractor-binding.json")["sha256"], "preprocessingSha256": sha(out / "candidate/preprocessing.json"),
                    "calibrationSha256": sha(out / "candidate/calibration.json"), "datasetManifestSha256": dataset.plan["datasetFreezeSha256"],
                    "splitManifestSha256": sha(dataset.root / "index.jsonl"), "evaluationPlanSha256": sha(plan_path),
                    "algorithm": summary["algorithm"], "algorithmVersion": importlib.metadata.version("torch" if summary["algorithm"] == "mlp" else summary["algorithm"]),
                    "profiles": ["flow-final-v1"], "numericFeatures": profile["numericFeatures"], "categoricalFeatures": profile["categoricalFeatures"],
                    "supportedScope": [{"addressFamily": "ipv4", "transport": "tcp", "direction": "inbound", "family": "connection_abuse", "minimumCoverageMs": 5000, "coverageWindowSeconds": 5}],
                    "scoreCalibration": "platt", "runtime": {"format": "onnx", "opset": 17, "maxProbabilityAbsError": report["export"]["maxAbsError"],
                                                              "runtimeVersion": importlib.metadata.version("onnxruntime")},
                    "validationReportSha256": sha(out / "validation-report.json"), "finalEvaluationReportSha256": None,
                    "trainingRunId": str(uuid.uuid4()), "trainingCodeSha256": code_sha,
                    "outputContract": {"attackScoreName": "attack_score", "binaryLabels": {"benign": 0, "attack": 1}, "familyScoreOrder": []}})
    write(out / "candidate/model-manifest.json", example)
    params = report["policySelection"]["parameters"]
    policy = read(dataset.contracts / "docs/contracts/examples/decision-policy.json")
    policy.update({"policyId": str(uuid.uuid4()), "policyVersion": out.name, "mode": "alert_only", "modelId": model_id,
                   "profile": "flow-final-v1", "alertThreshold": report["alertSelection"]["threshold"], "autoThreshold": params["threshold"],
                   "minDistinctFlows": params["min_flows"], "minEvidenceSpanMs": params["span_ms"], "minPeerFlowStarts": params["min_starts"],
                   "maxTtlSeconds": params["ttl"], "supportedCapabilityIds": [read(out / "candidate/capability-scope.json")["id"]],
                   "protectionSetSha256": sha(out / "candidate/protection-set.json"), "evaluationPlanSha256": sha(plan_path)})
    # 能力ID仅引用未授予资格的研究提案；alert_only不等于自动发布批准。
    write(out / "candidate/decision-policy.json", policy)
    for name, item in [("model-manifest", example), ("decision-policy", policy)]:
        contract_validator(dataset.contracts, name).validate(item)


def run(dataset, train, selection, plan, plan_path, out, code_sha):
    start = time.perf_counter(); items = []
    write(out / "source-diagnostic.json", source_diagnostic(train, selection))
    for feature_set in plan["budget"]["featureSets"]:
        for algorithm in plan["budget"]["algorithms"]:
            items.append(experiment(algorithm, feature_set, train, selection, plan, out, f"{algorithm}-{feature_set}-42"))
    baseline = max(items, key=ranking)
    write(out / "round1-decision.json", {"winner": baseline["summary"]["id"], "errors": baseline["summary"]["errors"],
          "correctiveCauses": ["difficult benign contribution", "capture/host source confounding"], "maximumCorrectiveFits": 2})
    algorithm, feature_set = baseline["summary"]["algorithm"], baseline["summary"]["featureSet"]
    without_controlled = train.take([i for i, r in enumerate(train.rows) if r["evidenceTier"] != "controlled_task"])
    removed = experiment(algorithm, feature_set, without_controlled, selection, plan, out, f"{algorithm}-without-controlled-42")
    # E3去掉困难正常仅为配对消融，不能为得到更高分而删除真实正常选为交付版本。
    items.append(removed)
    nohost = experiment(algorithm, "no_host_context", train, selection, plan, out, f"{algorithm}-no-host-context-42")
    items.append(nohost)
    winner = max([item for item in items if item is not removed], key=ranking)
    if winner["summary"]["onnx"]["status"] != "passed":
        raise ValueError("没有通过ONNX可行性的候选")
    seeds = [winner]
    for seed in (43, 44):
        seeds.append(experiment(winner["summary"]["algorithm"], winner["summary"]["featureSet"], train,
                                selection, plan, out, f"winner-seed-{seed}", seed))
    lock = {"selectionFrozen": True, "calibrationUsedForSelection": False, "experimentId": winner["summary"]["id"],
            "artifactSha256": winner["summary"]["artifactSha256"], "planSha256": sha(plan_path),
            "trainingCodeSha256": code_sha, "seedPolicy": "retain pre-registered seed42; 43/44 variance only", "finalTestRead": False}
    write(out / "selection-lock.json", lock)
    progress("selection_frozen", winner=lock["experimentId"])
    calibration_batch = dataset.load("validation_calibration", out / "selection-lock.json")
    pre, model, algorithm = winner["preprocessing"], winner["model"], winner["summary"]["algorithm"]
    raw = predict(algorithm, model, pre.transform(calibration_batch))
    calibration = calibrate(raw, calibration_batch); scores = calibrated(raw, calibration)
    replay = Replay(calibration_batch)
    policy_choice, policy_trials = select_policy(replay, scores, plan)
    alert_choice, alert_trials = choose_threshold(replay, scores, plan["decision"]["thresholds"])
    alert_choice = min([t for t in alert_trials if t["threshold"] <= policy_choice["parameters"]["threshold"]],
                       key=lambda t: (-objective(t["metrics"])[0], -objective(t["metrics"])[1], t["threshold"]))
    rule_trials = [{"rule": name, "metrics": replay.run(rule_scores, 0.5)} for name, rule_scores in rules(calibration_batch, plan)]
    rule_choice = max(rule_trials, key=lambda r: objective(r["metrics"]))
    model_choice, _ = choose_threshold(replay, scores, plan["decision"]["thresholds"])
    e5 = {"rules": rule_choice, "modelOnly": model_choice, "modelAndPolicy": policy_choice,
          "sameFalseBenignOpportunityBudget": 0, "selectionRole": "validation_calibration", "unbiasedEvaluation": False,
          "positiveCoverageGain": (policy_choice["metrics"]["opportunityRecallDiagnostic"] or 0) -
                                  (rule_choice["metrics"]["opportunityRecallDiagnostic"] or 0),
          "timelyCoverageGain": None}
    folder = out / "candidate"; folder.mkdir()
    import shutil
    shutil.copyfile(dataset.contracts / "docs/contracts/feature-profile.json", folder / "feature-profile.json")
    write(folder / "preprocessing.json", pre.parameters); write(folder / "calibration.json", calibration)
    import hashlib, json
    frozen = read(dataset.contracts / "docs/p2/freeze-manifest.json")
    extractor_files = {k: v for k, v in frozen["files"].items() if k.startswith("sensor/") and
                       (k.endswith(".go") or k.endswith("go.mod") or k.endswith("go.sum"))}
    extractor_hash = hashlib.sha256(json.dumps(extractor_files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    write(folder / "extractor-binding.json", {"definition": "sha256 canonical sorted JSON of frozen Go source/module file hashes",
          "sha256": extractor_hash, "files": extractor_files, "softwareFreezeSha256": plan["softwareFreezeSha256"]})
    write(folder / "capability-scope.json", {"id": str(uuid.uuid4()), "scope": plan["scope"],
           "status": "research_proposal_not_granted", "automaticExecutionEligible": False})
    write(folder / "protection-set.json", {"status": "research_no_real_targets", "executionAllowed": False,
                                            "protectedKinds": ["management", "gateway", "dns", "registered protected peer/service"]})
    export(algorithm, model, pre, calibration, folder / "model.onnx")
    final_check = parity(folder / "model.onnx", algorithm, model, pre, calibration, [train, selection, calibration_batch],
                         sorted({alert_choice["threshold"], policy_choice["parameters"]["threshold"]}))
    write(out / "onnx-parity.json", final_check)
    if final_check["status"] != "passed":
        raise ValueError("最终校准ONNX分数或决策对拍失败")
    fixtures = [train, selection, calibration_batch]
    feeds = {name: np.concatenate([pre.feed(b)[name] for b in fixtures]) for name in pre.feed(selection)}
    expected = np.concatenate([calibrated(predict(algorithm, model, pre.transform(b)), calibration) for b in fixtures])
    np.savez_compressed(folder / "parity-fixture.npz", **feeds, expected=expected)
    report = {"phase": "P3", "scope": plan["scope"], "candidateOnly": True, "productionApproved": False,
              "evaluationPlanSha256": sha(plan_path), "trainingCodeSha256": code_sha, "datasetVerification": dataset.verification,
              "selectionFrozen": lock, "modelMatrix": [i["summary"] for i in items],
              "threeSeeds": {"seeds": [s["summary"]["seed"] for s in seeds], "reports": [s["summary"] for s in seeds],
                             "selectionRecallStd": float(np.std([s["summary"]["workingPoint"]["metrics"]["opportunityRecallDiagnostic"] for s in seeds]))},
              "calibration": calibration, "calibrationBefore": classification(calibration_batch, raw),
              "calibrationAfter": classification(calibration_batch, scores, alert_choice["threshold"], curves=True),
              "calibrationErrors": error_groups(calibration_batch, scores, alert_choice["threshold"]),
              "policyBySource": {source: Replay(calibration_batch.take(ids)).run(scores[ids], **policy_choice["parameters"])
                    for source in sorted({r["sourceId"] for r in calibration_batch.rows})
                    for ids in [[i for i, r in enumerate(calibration_batch.rows) if r["sourceId"] == source]]},
              "alertSelection": alert_choice, "policySelection": policy_choice, "e5": e5,
              "export": final_check, "latency": latency(folder / "model.onnx", pre, selection),
              "totalSeconds": time.perf_counter() - start, "finalTestRead": False,
              "limitations": ["one independent attack activity per role", "no qualified prefix selection/calibration", "no locked final_test",
                               "source/host confounding and calibration shift", "calibration and policy scores are adaptive development results",
                               "final opportunities are not onset-based timely episodes", "P1 strict recovery blocked; no real actions"],
              "e4": "not_run_no_frozen_sequence_profile", "fullModelFits": len(items) + 2}
    write(out / "validation-report.json", report)
    write(out / "policy-search.json", {"trials": policy_trials, "rules": rule_trials})
    manifest(dataset, winner, report, calibration, plan_path, out, code_sha)
    export_complete = final_check["status"] == "passed" and all(s["summary"]["onnx"]["status"] == "passed" for s in seeds)
    metrics = policy_choice["metrics"]
    reasons = ["MISSING_QUALIFIED_ONSET_AND_PREFIX", "INSUFFICIENT_INDEPENDENT_ATTACK_ACTIVITIES", "FINAL_TEST_UNALLOCATED"]
    if e5["positiveCoverageGain"] <= 0:
        reasons.append("NO_POSITIVE_MODEL_POLICY_COVERAGE_GAIN")
    if (metrics["opportunityRecallDiagnostic"] or 0) < 0.8:
        reasons.append("DIAGNOSTIC_COVERAGE_BELOW_TARGET")
    if metrics["benignOpportunities"] < 3000:
        reasons.append("INSUFFICIENT_BENIGN_OPPORTUNITIES")
    if (metrics["precisionAtOpportunityRatios"]["0.01"] or 0) < 0.99:
        reasons.append("PRIMARY_RATIO_PRECISION_BELOW_TARGET_OR_UNDEFINED")
    if not export_complete:
        reasons.append("WINNER_SEED_EXPORT_FAILURE")
    exit_report = {"phase": "P3", "implementationStatus": "completed" if export_complete else "failed",
                   "status": "blocked", "modelFeasibilityGatePassed": False, "p6Authorized": False,
                   "blockingReasons": reasons, "rootCauses": ["sample_size_and_independence", "missing_observable_early_evidence"],
                   "candidateOnly": True, "automaticExecutionAuthorized": False, "finalTestRead": False,
                   "experimentCount": report["fullModelFits"], "correctiveFits": 2,
                   "candidateModelSha256": sha(folder / "model.onnx"), "validationReportSha256": sha(out / "validation-report.json"),
                   "next": "Return to P2 for independent prefix/early task evidence; preserve these candidates as diagnostic only. P4/P5 may proceed independently."}
    write(out / "stage-exit.json", exit_report)
    all_files = {p.relative_to(out).as_posix(): sha(p) for p in sorted(out.rglob("*")) if p.is_file()}
    write(out / "checksums.json", all_files)
    progress("complete", implementation=exit_report["implementationStatus"], gate=exit_report["status"],
             winner=lock["experimentId"], seconds=report["totalSeconds"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("smoke", "run"))
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--contracts", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Windows":
        raise RuntimeError("训练只在授权Windows仓库执行")
    env = environment()
    if env["trainingBranch"] != "training/windows-cuda" or not env["cudaAvailable"]:
        raise RuntimeError("训练分支或CUDA环境不符")
    for name in ("model-manifest", "decision-policy"):
        contract_validator(args.contracts, name)
    args.output.mkdir(parents=True, exist_ok=False)
    plan = read(args.plan)
    code_sha, code_files = source_hash(Path(__file__).parent)
    write(args.output / "environment.json", env)
    write(args.output / "code-manifest.json", {"sha256": code_sha, "files": code_files})
    write(args.output / "experiment-plan.json", plan)
    dataset = Dataset(args.dataset, args.contracts, args.public, plan, args.output / "access-audit.jsonl")
    write(args.output / "dataset-verification.json", dataset.verification)
    train, selection = dataset.load("train"), dataset.load("validation_selection")
    if args.mode == "smoke":
        smoke(dataset, train, selection, plan, args.output)
    else:
        run(dataset, train, selection, plan, args.plan, args.output, code_sha)


if __name__ == "__main__":
    main()
