"""离线评分与候选策略回放。final机会是诊断单位，不冒充真实攻击起点或OS动作。"""
from __future__ import annotations

from collections import defaultdict, deque
import math

import numpy as np
from sklearn.metrics import average_precision_score, log_loss, roc_auc_score, roc_curve, precision_recall_curve

from .data import time_ms


def target_key(o):
    """完整目标绑定；跨主机、捕获域、boot、密钥epoch和服务的证据不得合并。"""
    return tuple(o[name] for name in ("assetId", "sensorId", "bootId", "captureScopeId", "peerKey", "keyEpoch",
                                    "addressFamily", "transport", "direction", "servicePort"))


def classification(batch, scores, threshold=0.5, curves=False):
    y, w = batch.y, batch.weights
    scores = np.asarray(scores, dtype=np.float64).reshape(-1)
    if len(scores) != len(y) or not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
        raise ValueError("非法预测分数")
    prediction = scores >= threshold
    tp = float(w[(y == 1) & prediction].sum()); fp = float(w[(y == 0) & prediction].sum())
    tn = float(w[(y == 0) & ~prediction].sum()); fn = float(w[(y == 1) & ~prediction].sum())
    result = {"snapshots": len(y), "parents": len({r["parentConnectionId"] for r in batch.rows}),
              "parentWeightedCounts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}, "threshold": float(threshold),
              "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None,
              "fpr": fp / (fp + tn) if fp + tn else None,
              "brier": float(np.average((scores - y) ** 2, weights=w)),
              "logLoss": float(log_loss(y, np.clip(scores, 1e-7, 1 - 1e-7), sample_weight=w, labels=[0, 1])),
              "rocAuc": None, "prAuc": None}
    if len(np.unique(y)) == 2:
        result["rocAuc"] = float(roc_auc_score(y, scores, sample_weight=w))
        result["prAuc"] = float(average_precision_score(y, scores, sample_weight=w))
        if curves:
            fpr, tpr, _ = roc_curve(y, scores, sample_weight=w)
            precision, recall, _ = precision_recall_curve(y, scores, sample_weight=w)
            # 仅抽稀图表，指标使用完整曲线；避免公开逐样本身份或分数。
            choose = lambda n: np.unique(np.linspace(0, n - 1, min(n, 128)).astype(int))
            a, b = choose(len(fpr)), choose(len(recall))
            result["curves"] = {"roc": [[float(fpr[i]), float(tpr[i])] for i in a],
                                "pr": [[float(recall[i]), float(precision[i])] for i in b]}
    return result


def error_groups(batch, scores, threshold):
    """按来源、任务、方向、家族、质量分组；不把相关快照当独立样本。"""
    result = {}
    for dimension in ("sourceId", "taskKind", "family", "direction", "quality"):
        groups = defaultdict(list)
        for i, (r, o) in enumerate(zip(batch.rows, batch.observations, strict=True)):
            key = (o["direction"] if dimension == "direction" else
                   "clean_research_clock_unknown" if dimension == "quality" else r.get(dimension) or "public_background")
            groups[str(key)].append(i)
        result[dimension] = {key: classification(batch.take(ids), np.asarray(scores)[ids], threshold,
                                                curves=dimension == "sourceId") for key, ids in sorted(groups.items())}
    return result


class Replay:
    """保持原时间及目标，使用最新parent证据、TTL和预算；无执行器、无网络副作用。"""
    def __init__(self, batch):
        self.batch = batch
        self.times = np.asarray([time_ms(o["asOf"]) for o in batch.observations])
        self.last = np.asarray([time_ms(o["lastPacketAt"]) for o in batch.observations])
        self.keys = [target_key(o) for o in batch.observations]
        self.order = np.argsort(self.times, kind="stable")
        opportunities = defaultdict(list)
        for i, (key, t) in enumerate(zip(self.keys, self.times, strict=True)):
            opportunities[(key, int(t // 30000))].append(i)
        self.opportunities = opportunities

    def run(self, scores, threshold, min_flows=1, span_ms=0, min_starts=0, ttl=30):
        if min_flows < 1 or span_ms < 0 or span_ms > 10000 or ttl not in (15, 30):
            raise ValueError("策略参数越界")
        scores = np.asarray(scores).reshape(-1)
        if len(scores) != len(self.times) or not np.isfinite(scores).all():
            raise ValueError("无效分数")
        evidence, last_expiry, chain_start = defaultdict(dict), {}, {}
        active, recent = defaultdict(dict), defaultdict(deque)
        actions, reasons = [], defaultdict(int)
        for i in self.order:
            o = self.batch.observations[i]; t = self.times[i]; key = self.keys[i]
            asset = key[:3]
            # 无论新分数是否过阈值都替换旧记录，禁止保留历史最高分。
            evidence[key][o["parentConnectionId"]] = int(i)
            evidence[key] = {p: j for p, j in evidence[key].items() if self.times[j] >= t - 10000}
            qualified = [j for j in evidence[key].values() if scores[j] >= threshold and t - self.last[j] <= 15000
                         and self.batch.observations[j]["contexts"][1]["coverageMs"] >= 5000]
            if len(qualified) < min_flows:
                reasons["insufficient_distinct_fresh_evidence"] += 1; continue
            if max(self.times[j] for j in qualified) - min(self.times[j] for j in qualified) < span_ms:
                reasons["insufficient_span"] += 1; continue
            if o["contexts"][1]["peerFlowStarts"] < min_starts:
                reasons["insufficient_context"] += 1; continue
            if last_expiry.get(key, -math.inf) > t:
                reasons["ttl_dedup"] += 1; continue
            active[asset] = {k: expires for k, expires in active[asset].items() if expires > t}
            while recent[asset] and recent[asset][0] <= t - 60000:
                recent[asset].popleft()
            if len(active[asset]) >= 10 or len(recent[asset]) >= 5:
                reasons["action_budget"] += 1; continue
            if key not in chain_start or t > last_expiry.get(key, -math.inf) + 1:
                chain_start[key] = t
            if t + ttl * 1000 - chain_start[key] > 120000:
                reasons["continuous_ttl_budget"] += 1; continue
            expires = t + ttl * 1000
            active[asset][key] = expires; recent[asset].append(t); last_expiry[key] = expires
            actions.append((key, t, expires, tuple(qualified)))
        by_target = defaultdict(list)
        for a in actions:
            by_target[a[0]].append(a)
        counts = defaultdict(int)
        false_seconds, benign_parents = 0.0, set()
        good_actions = 0
        rows_by_target = defaultdict(list)
        for j, key in enumerate(self.keys):
            rows_by_target[key].append(j)
        # 标注只用于事后评价，绝不参与上面的候选生成。
        for key, start, end, qualified in actions:
            labels = {self.batch.rows[j]["label"] for j in qualified}
            collateral = [j for j in rows_by_target[key] if self.batch.rows[j]["label"] == 0
                          and start <= self.times[j] < end]
            if labels == {1} and not collateral:
                good_actions += 1
            else:
                false_seconds += (end - start) / 1000
        for (key, _), ids in self.opportunities.items():
            labels = {self.batch.rows[j]["label"] for j in ids}
            positive = labels == {1}
            counts["attackOpportunities" if positive else "benignOpportunities"] += 1
            if len(labels) != 1:
                counts["ambiguousOpportunitiesCountedAsBenign"] += 1
            affected = any(start <= self.times[j] < end for _, start, end, _ in by_target[key] for j in ids)
            if affected:
                counts["coveredAttackOpportunities" if positive else "falseBenignOpportunities"] += 1
                benign_parents.update(self.batch.rows[j]["parentConnectionId"] for j in ids if self.batch.rows[j]["label"] == 0)
        positives, negatives = counts["attackOpportunities"], counts["benignOpportunities"]
        recall = counts["coveredAttackOpportunities"] / positives if positives else None
        fpr = counts["falseBenignOpportunities"] / negatives if negatives else None
        groups = {label: len({r["activityId"] for r in self.batch.rows if r["label"] == label}) for label in (0, 1)}
        duration_hours = max(1e-12, (self.times.max() - self.times.min()) / 3600000)
        return {"unit": "observed_final_target_30s_opportunity", **dict(counts), "candidateActions": len(actions),
                "correctAttackCandidateActions": good_actions, "incorrectCandidateActions": len(actions) - good_actions,
                "blockPrecisionCandidate": good_actions / len(actions) if actions else None,
                "opportunityRecallDiagnostic": recall, "falseBenignOpportunityRate": fpr,
                "falsePer1000BenignOpportunities": fpr * 1000 if fpr is not None else None,
                "affectedBenignParents": len(benign_parents), "falseCandidateSeconds": false_seconds,
                "candidateActionsPerObservedCalendarHour": len(actions) / duration_hours,
                "calendarDurationCaveat": "source days/gaps preserved; not continuous monitored host hours",
                "attackActivities": groups[1], "benignGroups": groups[0],
                "clusterConfidenceInterval": None,
                "confidenceReason": "only one independent attack activity in this role; no reliable activity bootstrap",
                "blockRecallTimely": None, "onsetToActionP95Ms": None, "evidenceToOsActionP95Ms": None,
                "timingReason": "final-only dataset lacks qualified per-episode attack onset and real executor",
                "precisionAtOpportunityRatios": {str(ratio): (ratio * recall / (ratio * recall + (1 - ratio) * fpr)
                     if recall is not None and fpr is not None and ratio * recall + (1 - ratio) * fpr > 0 else None)
                     for ratio in (0.1, 0.01, 0.001)},
                "actualActions": 0, "candidateOnly": True,
                "executionGatesUnavailable": ["research targetRef=null", "clockSkewMs unknown", "release/capability/authorization not granted"],
                "suppressed": dict(reasons)}


def objective(result):
    """相同零误伤预算；零动作不产生虚构100%精确率。"""
    feasible = result["falseBenignOpportunities"] == 0 and result["incorrectCandidateActions"] == 0
    return (int(feasible), result["opportunityRecallDiagnostic"] or 0 if feasible else -result["falseBenignOpportunities"],
            -result["candidateActions"])


def choose_threshold(replay, scores, thresholds):
    trials = [{"threshold": t, "metrics": replay.run(scores, t)} for t in thresholds]
    winner = max(trials, key=lambda item: (objective(item["metrics"]), item["threshold"]))
    return winner, trials


def select_policy(replay, scores, plan):
    d = plan["decision"]; trials = []
    for t in d["thresholds"]:
        for n in d["minDistinctFlows"]:
            for span in d["minEvidenceSpanMs"]:
                if n == 1 and span > 0:
                    continue
                for starts in d["minPeerFlowStarts"]:
                    for ttl in d["ttlSeconds"]:
                        params = dict(threshold=t, min_flows=n, span_ms=span, min_starts=starts, ttl=ttl)
                        trials.append({"parameters": params, "metrics": replay.run(scores, **params)})
    return max(trials, key=lambda item: (objective(item["metrics"]), item["parameters"]["threshold"],
                                        -item["parameters"]["ttl"])), trials


def rules(batch, plan):
    """只使用冻结可见特征；注册规则族与模型使用相同数据、目标、时间与动作预算。"""
    starts = np.asarray([o["contexts"][1]["peerFlowStarts"] for o in batch.observations])
    elapsed, inbound = batch.values[:, 0], batch.values[:, 2]
    for count in plan["rules"]["peerFlowStarts5s"]:
        yield f"rate-{count}", (starts >= count).astype(float)
    for duration in plan["rules"]["durationMs"]:
        for size in plan["rules"]["maxInboundBytes"]:
            slow = (elapsed >= duration) & (inbound <= size)
            yield f"slow-{duration}-{size}", slow.astype(float)
            for count in plan["rules"]["peerFlowStarts5s"]:
                yield f"slow-rate-{duration}-{size}-{count}", (slow & (starts >= count)).astype(float)
