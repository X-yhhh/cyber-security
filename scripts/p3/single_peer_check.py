#!/usr/bin/env python3
"""在开发集上检查模型对单一对端反事实的敏感性。

只改写 hostDistinctPeers/hostFlowStarts，不读取 test、不拟合，也不改变候选文件。
统计单位为 parentConnection；任一攻击类检出率下降超过 0.20 即失败。
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "p6"))
from runtime import predict, read, session, sha, write
from evaluate import checked_candidate, inputs, model_decisions

CLASSES = ("normal", "port_scan", "brute_force", "dos_flood", "dos_slow")
HOST_FIELDS = ("hostDistinctPeers", "hostFlowStarts")


def _rows(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _connection_decisions(rows, scores, policy):
    """首个告警决定类别，所有快照共用连接分母；非命中首快照不能吞掉后续告警。"""
    first = {}
    alerts = {}
    decisions = model_decisions(scores, policy)
    for index, row in enumerate(rows):
        parent = row["parentConnectionId"]
        original = first.setdefault(parent, index)
        if row["label"] != rows[original]["label"]:
            raise ValueError("同一 parent 标签冲突")
        if decisions[index]:
            alerts.setdefault(parent, int(decisions[index]))
    labels, predicted = [], []
    for parent, index in first.items():
        row = rows[index]
        labels.append(CLASSES.index(row["label"]))
        predicted.append(alerts.get(parent, 0))
    return np.asarray(labels, dtype=np.int64), np.asarray(predicted, dtype=np.int64)


def _rates(labels, predicted):
    result = {}
    for index, name in enumerate(CLASSES[1:], 1):
        mask = labels == index
        result[name] = float(np.mean(predicted[mask] > 0)) if mask.any() else None
    normal = labels == 0
    result["normalFalsePositiveRate"] = float(np.mean(predicted[normal] > 0)) if normal.any() else None
    return result


def rewrite(rows):
    """只改三个窗口的主机上下文；对端、类别与缺失状态沿用同源快照。"""
    changed = copy.deepcopy(rows)
    for row in changed:
        for item in row["input"]["contexts"]:
            item["hostFlowStarts"] = item["peerFlowStarts"]
            item["hostDistinctPeers"] = 1
    return changed


def passed(drops):
    return set(drops) == set(CLASSES[1:]) and all(np.isfinite(value) and value <= 0.20 + 1e-12 for value in drops.values())


def check(candidate: Path, dataset: Path, output: Path):
    """执行单对端反事实并写入新证据目录。"""
    candidate = candidate.resolve()
    dataset = dataset.resolve()
    if dataset.parent.name != "validation" or dataset.name != "dataset.jsonl":
        raise ValueError("只允许 validation 开发数据，不访问 test/L3")
    split = read(dataset.parent.parent / "manifest.json")
    if sha(dataset) != split["datasetSha256"]["validation"]:
        raise ValueError("validation 哈希不符")
    rows = _rows(dataset.resolve())
    if (candidate / "model-manifest.json").exists():
        manifest, _, feature, policy, pre = checked_candidate(candidate)
    else:
        summary = read(candidate / "reproduction-summary.json")
        for name in ("model.onnx", "preprocessing.json"):
            if sha(candidate / name) != summary["artifacts"][name]:
                raise ValueError("已登记 run 制品哈希不符")
        if summary["finalTestRead"] or not summary["candidateOnly"]:
            raise ValueError("run 不是未读测试的开发候选")
        if summary["datasetSha256"]["validation"] != sha(dataset):
            raise ValueError("run 的 validation 绑定不符")
        from freeze_multiclass_candidate import ROOT
        feature = read(ROOT / "docs/contracts/feature-profile.json")
        manifest, policy, pre = summary, {"alertThreshold": summary["alertThreshold"]}, read(candidate / "preprocessing.json")
    threshold = float(policy["alertThreshold"])
    from evaluate import numeric_indices
    if (pre["fitRole"] != "train" or not pre["includeServiceClass"]
            or pre["numericIndices"] != numeric_indices(pre["featureSet"], feature)):
        raise ValueError("预处理特征契约不符")
    if not rows or not 0 <= threshold <= 1:
        raise ValueError("开发集或告警阈值非法")
    original = inputs(rows, feature, pre)
    changed_rows = rewrite(rows)
    changed = inputs(changed_rows, feature, pre)
    runtime = session(candidate / "model.onnx")
    scores = predict(runtime, original)
    counterfactual = predict(runtime, changed)
    labels, baseline = _connection_decisions(rows, scores, policy)
    cf_labels, altered = _connection_decisions(changed_rows, counterfactual, policy)
    if not np.array_equal(labels, cf_labels):
        raise ValueError("反事实连接分母改变")
    baseline_rates, altered_rates = _rates(labels, baseline), _rates(labels, altered)
    drops = {name: (baseline_rates[name] - altered_rates[name])
             for name in CLASSES[1:] if baseline_rates[name] is not None and altered_rates[name] is not None}
    result = {"version": "host-guard-single-peer-check/1", "candidateSha256": sha(candidate / "model.onnx"),
              "datasetSha256": sha(dataset), "rows": len(rows), "connections": len(labels),
              "preprocessingSha256": sha(candidate / "preprocessing.json"),
              "codeSha256": {str(path.relative_to(Path(__file__).resolve().parents[2])): sha(path)
                              for path in (Path(__file__).resolve(),
                                           Path(__file__).resolve().parents[1] / "p6/evaluate.py",
                                           Path(__file__).resolve().parents[1] / "p6/runtime.py")},
              "threshold": threshold, "hostRewrite": {"hostDistinctPeers": 1,
              "hostFlowStarts": "peerFlowStarts"}, "baseline": baseline_rates,
              "singlePeer": altered_rates, "dropByClass": drops,
              "passed": passed(drops), "datasetRole": "validation",
              "newFits": 0, "testRead": False, "candidateOnly": bool(manifest.get("candidateOnly"))}
    if not any(part in (".cache", "artifacts") for part in output.resolve().parts):
        raise ValueError("证据输出须位于受控的新目录")
    output.mkdir(parents=False, exist_ok=False)
    write(output / "report.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = check(args.candidate, args.dataset, args.output)
    print(json.dumps(result, ensure_ascii=False))
    if not result["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
