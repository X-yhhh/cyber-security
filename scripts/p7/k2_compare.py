#!/usr/bin/env python3
"""K2 诊断与 v8 按真实连接/快照逐条对拍，只写新报告，不改变正式 J1 结果。"""
import argparse
from pathlib import Path

from j1_audit import connection_sets, digest, read, rows, sha
from j1_run import write


def signatures(directory, thresholds):
    """原端点只在私有 ledger 中读取，报告只保留哈希和差异数量。"""
    physical = {}
    for item in rows(directory/"ledger.jsonl"):
        parent = item["parentConnectionId"]
        value = dict(firstAt=item["First"], endpoints=item["Endpoints"])
        if parent not in physical or value["firstAt"] < physical[parent]["firstAt"]:
            physical[parent] = value
    physical = {k: digest(v) for k, v in physical.items()}
    offline = {o["observationId"]: o for o in rows(directory/"offline.jsonl")}
    live = rows(directory/"live.jsonl")
    inferences = {i["observationId"]: i for i in rows(directory/"db-inferences.jsonl")}
    rules = {(r["observationId"], r["ruleId"]): r for r in rows(directory/"db-rules.jsonl")}
    alerts, _ = connection_sets(live, inferences, rules, rows(directory/"db-decisions.jsonl"), thresholds)
    classifications = {}
    for oid, inference in inferences.items():
        o = offline[oid]
        key = (physical[o["parentConnectionId"]], o["profile"], o["snapshotIndex"], o["asOf"])
        if key in classifications:
            raise ValueError("duplicate physical snapshot")
        classifications[key] = {k: inference.get(k) for k in ("status", "family", "score", "familyScores", "applicability", "errorCode")}
    return {physical[p]: sorted(alerts.get(p, set())) for p in physical}, classifications


def frozen_inputs(scenario, original):
    """只允许实现二进制重新绑定；数据、模型、数值策略和捕获并发均不可放宽。"""
    for key in ("modelSha256", "manifestSha256", "policySha256", "policyRawSha256", "m1PolicyRawSha256",
                "closeoutSha256", "guardextractSha256", "guardreplaydiffSha256", "extractorSha256",
                "splitManifestSha256", "splitLedgerSha256", "replayConcurrency", "serverThreads"):
        if scenario[key] != original[key]:
            raise ValueError("frozen input changed: " + key)
    if scenario["segments"] != original["segments"] or scenario["speed"] != 1:
        raise ValueError("segments or replay speed changed")
    if scenario["attackConcurrency"] < original["replayConcurrency"]:
        raise ValueError("capture concurrency reduced")
    if scenario["testRead"] or scenario["newFits"] != 0 or scenario["environment"] != "research":
        raise ValueError("diagnostic scope changed")
    if not 1 <= scenario.get("maxBatchSize",100) <= 512:
        raise ValueError("batch size exceeds the bounded contract")


def compare(work, baseline):
    scenario = read(work/"scenario.json")
    original = read(baseline/"scenario.json")
    frozen_inputs(scenario, original)
    policy_path = Path.home()/"Workspace/ai/artifacts/cyber-guard"/scenario["packageRef"]/"policy-research.json"
    if sha(policy_path) != scenario["policyRawSha256"]:
        raise ValueError("policy bytes changed after replay")
    policy = read(policy_path)
    thresholds = {p["family"]: p["alertThreshold"] for p in policy["familyPolicies"]}
    segments = []
    diagnostic = read(work/"diagnostic.json")
    expected = {"port_scan-1", "port_scan-2", "port_scan-3"}
    selected = {r["segmentId"] for r in diagnostic["segmentResults"]}
    if not expected.issubset(selected) or len(selected) != 4 or len(diagnostic["segmentResults"]) != 4 or len([x for x in selected if x.startswith("normal-")]) != 1:
        raise ValueError("K2 requires three scans and one normal segment")
    for result in diagnostic["segmentResults"]:
        name = result["segmentId"]
        current_alerts, current_classes = signatures(work/"round-1"/name, thresholds)
        directory = work/"round-1"/name
        transport = read(directory/"live-report.json")
        batches = [p for p in (directory/"spool").rglob("batch-*.json")]
        max_rows = max(len(read(p)["observations"]) for p in batches)
        max_bytes = max(p.stat().st_size for p in batches)
        references = []
        for number in (1, 2):
            old_alerts, old_classes = signatures(baseline/f"round-{number}"/name, thresholds)
            alerts_diff = sum(current_alerts.get(k) != old_alerts.get(k) for k in current_alerts.keys() | old_alerts.keys())
            classes_diff = sum(current_classes.get(k) != old_classes.get(k) for k in current_classes.keys() | old_classes.keys())
            references.append(dict(round=number, alertConnectionDifferences=alerts_diff, classificationDifferences=classes_diff))
        latency = result["p95EmissionToCommitUpperBoundSeconds"]
        checks = dict(p95=latency is not None and latency <= 2,
                      boundedTransport=transport["replay"]["speed"] == 1 and max_rows <= scenario.get("maxBatchSize",100) and max_bytes <= 1_048_576,
                      drained=result["pendingBatches"] == 0 and result["drainAfterLastPacketSeconds"] <= 30,
                      noDropsOrTimeouts=result["capacityDrop"] == 0 and result["inferenceTimeouts"] == 0,
                      complete=result["missingObservations"] == 0 and result["rejected"] == 0 and result["inferenceFailures"] == 0,
                      v8Identical=all(r["alertConnectionDifferences"] == r["classificationDifferences"] == 0 for r in references))
        segments.append(dict(segmentId=name, observations=result["observations"], classifications=len(current_classes),
                             alertConnections=sum(bool(v) for v in current_alerts.values()), p95Seconds=latency,
                             maxObservedBatchSize=max_rows, maxRequestBytes=max_bytes,
                             alertSignatureSha256=digest(sorted(current_alerts.items())), references=references,
                             checks=checks, passed=all(checks.values())))
    before, after = read(work/"database-before.json"), read(work/"database-after.json")
    actions = after["counts"]["guard_action"]-before["counts"]["guard_action"]
    commands = after["counts"]["guard_command"]-before["counts"]["guard_command"]
    return dict(schema="j1-k2-comparison/1", diagnosticOnly=True, j1Passed=None, J2Allowed=False,
                baseline=str(baseline), scenarioSha256=sha(work/"scenario.json"), inputHashesUnchanged=True,
                replayConcurrency=scenario["replayConcurrency"], attackConcurrency=scenario["attackConcurrency"],
                speed=scenario["speed"], serverThreads=scenario["serverThreads"],
                maxBatchSize=scenario.get("maxBatchSize",100),
                actionDelta=actions, commandDelta=commands, segments=segments,
                diagnosticChecksPassed=all(s["passed"] for s in segments) and actions == commands == 0,
                limitation="四段诊断不能替代两轮完整 J1；批次边界单测独立验证，J2/P8 仍关闭。")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.work, args.baseline)
    write(args.work/"k2-comparison.json", result)
    print("K2 diagnostic checks passed:", result["diagnosticChecksPassed"])
    if not result["diagnosticChecksPassed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
