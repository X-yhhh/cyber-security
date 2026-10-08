#!/usr/bin/env python3
"""T3.3：只用绑定的 validation 为 R4 选择独立连接下限，不拟合或执行动作。

计数遵循 10 秒证据时效和 parent 最新快照替换。它是同源慢连接的
证据并存数，不是 TCP ESTABLISHED 状态探针；最终快照也按契约计入。
标签只参与事后统计，不能决定运行时计数。低并发和漏检样本不删除。
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime
import heapq
import json
from pathlib import Path
import tempfile

import numpy as np

from freeze_multiclass_candidate import ROOT, batches, new_output, read, sha, write


SCOPE_KEYS = ("assetId", "sensorId", "bootId", "captureScopeId", "peerKey",
              "keyEpoch", "direction", "transport")
GRID = (2, 3, 5, 8, 10, 15, 20, 30, 50, 100)
R4_MINIMUM = 5


def distribution(values):
    """零值保留，返回可复算直方图，避免用分位数隐藏未覆盖样本。"""
    values = np.asarray(values, dtype=np.int64)
    if not len(values):
        return {"count": 0, "histogram": {}}
    return {"count": len(values), "min": int(values.min()), "max": int(values.max()),
            "quantiles": dict(zip(("p25", "p50", "p75", "p90", "p95"),
                                  np.quantile(values, (.25, .5, .75, .9, .95)).tolist())),
            "histogram": {str(k): v for k, v in sorted(Counter(values.tolist()).items())}}


def analyze(rows, metadata, scores, threshold, grid=GRID, fpr_max=.01):
    """只调整 dos_slow 下限；其它类别参与最新证据失效与负例统计。

来源机会为同身份/服务的 30 秒桶，含正常连接的混合桶保守计误报。
候选下限先满足 FPR，再最大化来源及机会覆盖，覆盖相同时取更大下限。
"""
    if not rows or len(rows) != len(metadata) or scores.shape != (len(rows), 5):
        raise ValueError("validation 数据/旁路/分数长度不符")
    if not np.isfinite(scores).all() or not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("非法分数或阈值")
    if not grid or any(type(n) is not int or n < 2 for n in grid) or not 0 <= fpr_max <= .01:
        raise ValueError("下限至少为 2，FPR 不得放宽现有 validation 的 1% 限制")
    times, keys, eligible, labels = [], [], [], {}
    for row, meta in zip(rows, metadata):
        if any(row[k] != meta[k] for k in ("observationId", "parentConnectionId")):
            raise ValueError("validation 旁路对齐失败")
        parent = tuple(meta[k] for k in SCOPE_KEYS) + (row["parentConnectionId"],)
        label_source = (row["label"], "website" if row.get("websiteSupplement") else "internal")
        if parent in labels and labels[parent] != label_source:
            raise ValueError("同一 parent 的标签或正常来源冲突")
        labels[parent] = label_source
        timestamp = datetime.fromisoformat(meta["asOf"].replace("Z", "+00:00"))
        if timestamp.utcoffset() is None:
            raise ValueError("旁路时间缺少时区")
        times.append(timestamp.timestamp())
        keys.append(tuple(meta[k] for k in SCOPE_KEYS) + (meta["servicePort"],))
        eligible.append(meta["transport"] == "tcp" and meta["direction"] == "inbound"
                        and meta["servicePort"] == 80 and row["input"]["serviceClass"] == "web")
    predicted = np.argmax(scores[:, 1:], axis=1) + 1
    slow_hits = (scores[:, 0].astype(np.float64) >= float(threshold)) & (predicted == 4)
    latest, parent_latest, queue = defaultdict(dict), {}, []
    counts = np.zeros(len(rows), dtype=np.int64)
    peaks, attack, normal = defaultdict(int), set(), set()
    normal_by_source = {"internal": set(), "website": set()}
    parent_max, parent_http = defaultdict(int), set()
    # 同时刻以 observationId 排序；元数据不含 snapshotIndex，禁止臆造该字段。
    order = sorted(range(len(rows)), key=lambda i: (times[i], rows[i]["observationId"]))
    for i in order:
        meta, row, t, key = metadata[i], rows[i], times[i], keys[i]
        parent = key[:-1] + (row["parentConnectionId"],)
        while queue and queue[0][0] < t - 10:
            _, old_i, old_key, old_parent = heapq.heappop(queue)
            if latest[old_key].get(old_parent) == old_i:
                del latest[old_key][old_parent]
        previous = parent_latest.pop(parent, None)
        if previous is not None:
            latest[previous].pop(parent, None)
        if eligible[i] and slow_hits[i]:
            latest[key][parent] = i
            parent_latest[parent] = key
            heapq.heappush(queue, (t, i, key, parent))
        if not eligible[i]:
            continue
        counts[i] = len(latest[key])
        parent_max[parent] = max(parent_max[parent], int(counts[i]))
        parent_http.add(parent)
        opportunity = (key, int(t // 30))
        peaks[opportunity] = max(peaks[opportunity], int(counts[i]))
        if row["label"] == "dos_slow":
            attack.add(opportunity)
        elif row["label"] == "normal":
            normal.add(opportunity)
            normal_by_source[labels[parent][1]].add(opportunity)
    slow_indices = [i for i, r in enumerate(rows) if r["label"] == "dos_slow"]
    slow_parents = [p for p, value in labels.items() if value[0] == "dos_slow"]
    if not slow_parents or not attack or not normal:
        raise ValueError("缺少 dos_slow 或同服务正常 validation，不能选值")
    trials = []
    for minimum in sorted(set(grid)):
        hit = {key for key, count in peaks.items() if count >= minimum}
        normal_rates = {source: {"opportunities": len(items), "falsePositives": len(hit & items),
                                "falsePositiveRate": len(hit & items) / len(items) if items else None}
                        for source, items in normal_by_source.items()}
        rates = [v["falsePositiveRate"] for v in normal_rates.values() if v["opportunities"]]
        trials.append({"minDistinctFlows": minimum, "autoThreshold": float(threshold),
            "attackOpportunities": len(attack), "coveredAttackOpportunities": len(hit & attack),
            "attackCoverage": len(hit & attack) / len(attack),
            "attackSources": len({k for k, _ in attack}),
            "coveredAttackSources": len({k for k, _ in hit & attack}),
            "normalOpportunities": len(normal), "normalFalsePositives": len(hit & normal),
            "falsePositiveRate": len(hit & normal) / len(normal),
            "normalSourceFpr": normal_rates, "maxObservedNormalSourceFpr": max(rates),
            "mixedLabelOpportunities": len(normal & attack),
            "slowConnections": len(slow_parents),
            "slowConnectionsAtOrAbove": sum(parent_max[p] >= minimum for p in slow_parents),
            "slowConnectionsBelow": sum(parent_max[p] < minimum for p in slow_parents)})
    # R4 明确排除历史定义的 <=4 条低并发；2/3 保留为比较，不能用其覆盖率扩大能力。
    valid = [t for t in trials if t["minDistinctFlows"] >= R4_MINIMUM and t["falsePositiveRate"] <= fpr_max
             and t["maxObservedNormalSourceFpr"] <= fpr_max and t["coveredAttackOpportunities"] > 0]
    if not valid:
        raise ValueError("没有具备正覆盖且 FPR 合格的下限")
    selected = max(valid, key=lambda t: (t["coveredAttackSources"], t["coveredAttackOpportunities"],
                                        t["minDistinctFlows"]))
    normals = {}
    for source in ("internal", "website"):
        parents = [p for p, value in labels.items() if value == ("normal", source)]
        normals[source] = {"allConnections": len(parents),
            "httpConnections": sum(p in parent_http for p in parents),
            "httpConnectionFalsePositives": sum(parent_max[p] >= selected["minDistinctFlows"] for p in parents)}
    return {"selected": selected, "alternatives": trials,
        "selectionRule": "R4 min>=5 (exclude <=4 low concurrency); FPR<=1% overall and each observed normal source; maximize covered sources, then opportunities, then minDistinctFlows",
        "minimumDomainFlows": R4_MINIMUM,
        "falsePositiveRateMax": fpr_max, "thresholdSearch": False,
        "slowSnapshotDistinctFlows": distribution(counts[slow_indices]),
        "slowConnectionMaxDistinctFlows": distribution([parent_max[p] for p in slow_parents]),
        "slowOpportunityMaxDistinctFlows": distribution([peaks[p] for p in attack]),
        "normalConnections": normals, "rows": len(rows), "connections": len(labels),
        "slowSnapshots": len(slow_indices), "slowConnections": len(slow_parents),
        "slowOutOfHttpScopeSnapshots": sum(not eligible[i] for i in slow_indices),
        "maxEvidenceAgeMs": 10000, "episodeSeconds": 30,
        "capability": "单一来源多条并发慢连接占用 HTTP 服务",
        "scope": {"addressFamily": "ipv4", "transport": "tcp", "direction": "inbound",
                  "servicePort": 80, "serviceClass": "web", "family": "dos_slow", "scope": "peer_service"},
        "outsideCoverage": {"condition": f"distinctFlows < {selected['minDistinctFlows']}",
                            "claimAllowed": False, "excludedFromEvaluation": False},
        "limitations": ["distinctFlows 是最新合格 parent 在 10 秒内的证据并存数，不能证明 TCP 连接实际仍建立或 HTTP 资源被占用",
                        "final 与 prefix 均沿用现行证据契约；低并发、漏检及错误家族样本仍保留在完整分母",
                        "validation 被重复用于选择；FPR 为样本点估计，不是现场误报保证",
                        "L3 历史 0/29 保留；L3'、P6 新评价与 G3 尚未验证，不取得自动资格"]}


def select(args):
    """校验原始 run 绑定后仅打开 validation，逐批使用现有 ONNX。"""
    output = new_output(args.output)
    source, dataset, metadata = args.source.resolve(), args.dataset.resolve(), args.metadata.resolve()
    if dataset.name != "dataset.jsonl" or dataset.parent.name != "validation" \
            or metadata.name != "metadata.jsonl" or metadata.parent.name != "validation":
        raise ValueError("仅允许 validation/dataset.jsonl 与 validation/metadata.jsonl")
    summary, pre = read(source / "reproduction-summary.json"), read(source / "preprocessing.json")
    if (summary["finalTestRead"] or not summary["candidateOnly"] or summary["featureSet"] != "no_host_context"
            or not summary["frameworkParityPassed"] or not summary["validationExitPassed"]
            or sha(dataset) != summary["datasetSha256"]["validation"]
            or sha(metadata) != summary["metadataSha256"]["validation"]):
        raise ValueError("开发输入与候选绑定不符")
    for name in ("model.onnx", "preprocessing.json"):
        if sha(source / name) != summary["artifacts"][name]:
            raise ValueError("候选输入哈希不符")
    from probe_candidate_interface import check_feature_selection, host_indices
    import onnx
    import sys
    sys.path.insert(0, str(ROOT / "scripts/p6"))
    from runtime import session, predict
    numeric = read(ROOT / "docs/contracts/feature-profile.json")["numericFeatures"]
    check_feature_selection(onnx.load(source / "model.onnx"), pre, host_indices(numeric))
    runtime = session(source / "model.onnx")
    scores = np.concatenate([predict(runtime, feed) for feed in batches(dataset, numeric, pre["vocabularies"])])
    with dataset.open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream]
    with metadata.open(encoding="utf-8") as stream:
        metas = [json.loads(line) for line in stream]
    report = analyze(rows, metas, scores, summary["alertThreshold"])
    report.update(version="host-guard-dos-slow-selection/1", datasetRole="validation",
                  candidateOnly=True, mode="alert_only", automaticExecutionEnabled=False,
                  newFits=0, testRead=False, l3Read=False, modelSha256=sha(source / "model.onnx"),
                  preprocessingSha256=sha(source / "preprocessing.json"), datasetSha256=sha(dataset),
                  metadataSha256=sha(metadata), runSummarySha256=sha(source / "reproduction-summary.json"),
                  codeSha256=sha(Path(__file__)))
    with tempfile.TemporaryDirectory(prefix="slow-selection-", dir=output.parent) as temporary:
        target = Path(temporary)
        write(target / "selection.json", report)
        write(target / "checksums.json", {"files": {"selection.json": {"sha256": sha(target / "selection.json")}}})
        target.rename(output)
    print(json.dumps({"selected": report["selected"], "distribution": report["slowConnectionMaxDistinctFlows"],
                      "testRead": False, "newFits": 0}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "dataset", "metadata", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    select(parser.parse_args())


if __name__ == "__main__":
    main()
