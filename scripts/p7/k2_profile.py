#!/usr/bin/env python3
"""汇总 K2 的私有 JFR 分段计时与 spool 回执写盘，不读取数据集、不改变 J1 门槛。"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import subprocess

from j1_audit import quantile, read, sha
from j1_run import write


def seconds(value):
    """JFR JSON 使用 ISO-8601 duration；拒绝缺失/异常单位，避免把微秒误算为秒。"""
    match = re.fullmatch(r"PT(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?", value)
    if not match or not any(match.groups()):
        raise ValueError("invalid JFR duration")
    hours, minutes, secs = (float(v or 0) for v in match.groups())
    return hours * 3600 + minutes * 60 + secs


def summarize(events):
    """父阶段与子阶段分别统计，不把包含时间相加；推理的每批计时为该批全部快照之和。"""
    phases = defaultdict(list)
    batches = defaultdict(lambda: defaultdict(float))
    samples = Counter()
    rollbacks = 0
    for event in events:
        value = event["values"]
        if event["type"] == "cyber.guard.BatchPhase":
            phase = value["phase"]
            elapsed = seconds(value["duration"])
            phases[phase].append(elapsed)
            batches[phase][value["batchId"]] += elapsed
            if phase.endswith("_commit") and not value["committed"]:
                rollbacks += 1
        elif event["type"] == "jdk.ExecutionSample":
            for frame in (value.get("stackTrace") or {}).get("frames", []):
                method = frame["method"]
                name = method["type"]["name"].replace("/", ".") + "." + method["name"]
                if name.startswith("com.xyh.cybersecurity.guard."):
                    samples[name] += 1
                    break
    if not phases:
        raise ValueError("no Guard batch phases recorded")
    results = {}
    for phase, durations in sorted(phases.items()):
        per_batch = list(batches[phase].values())
        results[phase] = dict(events=len(durations), batches=len(per_batch), totalSeconds=sum(durations),
                             meanSeconds=sum(durations)/len(durations), p95Seconds=quantile(durations, .95),
                             maxSeconds=max(durations), p95PerBatchSeconds=quantile(per_batch, .95))
    return dict(phases=results, rolledBackTransactions=rollbacks,
                guardExecutionSamples=[dict(method=k, samples=v) for k, v in samples.most_common(20)],
                timing="包含时间；t1/t2 包含其内部阶段，禁止将父/子阶段相加。")


def profile(work, jfr, recording=None):
    recording = recording or work/"private/replay.jfr"
    process = subprocess.run([str(jfr), "print", "--json", "--events", "cyber.guard.BatchPhase,jdk.ExecutionSample", str(recording)],
                             check=True, capture_output=True, text=True)
    result = summarize(json.loads(process.stdout)["recording"]["events"])
    result.update(schema="j1-k2-profile/1", diagnosticOnly=True, j1Passed=None, J2Allowed=False,
                  recordingSha256=sha(recording), scenarioSha256=sha(work/"scenario.json"))
    result["spoolAck"] = []
    for path in sorted((work/"round-1").glob("*/live-report.json")):
        upload = read(path).get("upload", {})
        count = upload.get("ackedBatches", 0)
        result["spoolAck"].append(dict(segmentId=path.parent.name, ackedBatches=count,
                                      totalSeconds=upload.get("spoolAckTotalMicros", 0)/1e6,
                                      meanSeconds=upload.get("spoolAckTotalMicros", 0)/1e6/count if count else None,
                                      maxSeconds=upload.get("spoolAckMaxMicros", 0)/1e6))
    diagnostic = work/"diagnostic.json"
    if diagnostic.is_file():
        result["segments"] = [{k: row[k] for k in ("segmentId", "observations", "batches", "pendingBatches",
                                                     "p95EmissionToCommitUpperBoundSeconds", "drainAfterLastPacketSeconds",
                                                     "inferenceTimeouts", "capacityDrop")}
                              for row in read(diagnostic)["segmentResults"]]
    else:
        result["partial"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--jfr", type=Path, required=True, help="已核验 JDK 25 的 jfr 程序")
    parser.add_argument("--recording", type=Path)
    parser.add_argument("--output", type=Path, help="默认 work/profile.json；拒绝覆盖旧证据")
    args = parser.parse_args()
    destination = args.output or args.work/"profile.json"
    write(destination, profile(args.work, args.jfr, args.recording))
    print(json.dumps(dict(profile=str(destination), diagnosticOnly=True, J2Allowed=False)))


if __name__ == "__main__":
    main()
