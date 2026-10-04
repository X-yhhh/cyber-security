"""离线评分与候选策略回放。final机会是诊断单位，不冒充真实攻击起点或OS动作。"""
from __future__ import annotations

from collections import defaultdict, deque
import math
import hashlib
import json

import numpy as np
from sklearn.metrics import average_precision_score, log_loss, roc_auc_score, roc_curve, precision_recall_curve

from .data import time_ms
from .target_budget import TargetBudget


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

    def run(self, scores, threshold, min_flows=1, span_ms=0, min_starts=0, ttl=30, *, diagnostics=None, raw_scores=None, policy_version="target-budget-v2", target_ids=None, capture_health_since=None):
        if min_flows < 1 or min_starts < 0 or span_ms < 0 or span_ms > 10000 or ttl not in (15, 30) or not 0 <= threshold <= 1:
            raise ValueError("策略参数越界")
        scores = np.asarray(scores).reshape(-1)
        if len(scores) != len(self.times) or not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
            raise ValueError("无效分数")
        if raw_scores is not None:
            raw_scores = np.asarray(raw_scores).reshape(-1)
            if len(raw_scores) != len(scores) or not np.isfinite(raw_scores).all():
                raise ValueError("原始诊断分数无效")
        if policy_version not in ('target-budget-v2','legacy-final-diagnostic-v1'):
            raise ValueError('未知策略预算版本')
        safe = policy_version == 'target-budget-v2'
        if safe:
            target_ids = target_ids or [r.get('budgetTargetId') for r in self.batch.rows]
            if len(target_ids) != len(self.times) or any(not isinstance(k,str) or not k for k in target_ids):
                raise ValueError('新版策略要求冻结的稳定真实目标映射')
        if capture_health_since is not None and len(capture_health_since) != len(self.times):
            raise ValueError('捕获健康旁路与观察数量不符')
        budget = TargetBudget()
        evidence, last_expiry, chain_start = defaultdict(dict), {}, {}
        active, recent = defaultdict(dict), defaultdict(deque)
        actions, reasons, action_ids = [], defaultdict(int), []
        traces = []
        # 保留旧决策顺序；诊断状态不参与动作生成，也不改变冻结的机会分母。
        for index in self.order:
            i = int(index)
            o = self.batch.observations[i]; t = self.times[i]; key = self.keys[i]
            budget_key = target_ids[i] if safe else key
            asset = key[0]  # 预算归属资产；传感器/boot仍隔离证据，但不能重置同资产动作额度。
            previous = evidence[key].get(o["parentConnectionId"])
            evidence[key][o["parentConnectionId"]] = i
            expired = [j for j in evidence[key].values() if self.times[j] < t - 10000]
            evidence[key] = {p: j for p, j in evidence[key].items() if self.times[j] >= t - 10000}
            high = [j for j in evidence[key].values() if scores[j] >= threshold]
            fresh = [j for j in high if t - self.last[j] <= 15000]
            qualified = [j for j in fresh if self.batch.observations[j]["contexts"][1]["coverageMs"] >= 5000]
            if safe:
                account = budget.observe(budget_key, t, bool(qualified), capture_health_since[i] if capture_health_since is not None else None)
            span = float(max(self.times[j] for j in qualified) - min(self.times[j] for j in qualified)) if qualified else 0.0
            gates = {name: "not_checked" for name in (
                "distinct_parents", "evidence_span", "peer_flow_starts", "ttl_dedup",
                "simultaneous_rules", "actions_per_minute", "continuous_ttl")}
            trace = {"index": i, "observationId": o.get("observationId", str(i)),
                     "parentConnectionId": o["parentConnectionId"], "activityId": self.batch.rows[i].get("activityId"),
                     "captureScopeId": o["captureScopeId"], "role": self.batch.rows[i].get("split", self.batch.role),
                     "targetDigest": hashlib.sha256(json.dumps(key).encode()).hexdigest(),
                     "eventTimeMs": float(t), "rawScore": float(raw_scores[i]) if raw_scores is not None else None,
                     "score": float(scores[i]), "threshold": float(threshold),
                     "replacedObservationIndex": previous, "expiredEvidenceIndices": expired,
                     "evidenceAgeMs": 0.0, "ageBasis": "event-time replay; ingestion lag not measured", "lastPacketAgeMs": float(t - self.last[i]),
                     "coverageMs": o["contexts"][1]["coverageMs"],
                     "currentEvidenceChecks": {"score": bool(scores[i] >= threshold), "evidence_age": True,
                        "last_packet_age": bool(t - self.last[i] <= 15000),
                        "context_coverage": o["contexts"][1]["coverageMs"] >= 5000},
                     "evidenceCounts": {"latestFreshAgeParents": len(evidence[key]), "highScoreParents": len(high),
                        "freshPacketParents": len(fresh), "qualifiedParents": len(qualified),
                        "expiredAgeParents": len(expired), "lowScoreParents": len(evidence[key]) - len(high),
                        "stalePacketParents": len(high) - len(fresh), "coldContextParents": len(fresh) - len(qualified)},
                     "evidenceSpanMs": span, "peerFlowStarts": o["contexts"][1]["peerFlowStarts"],
                     "existingTtlExpiresMs": float(last_expiry[budget_key]) if budget_key in last_expiry else None,
                     "coveredByExistingTtl": bool(last_expiry.get(budget_key, -math.inf) > t),
                     "activeRules": None, "actionsLastMinute": None, "continuousBlockMs": None,
                     "gates": gates, "firstRejection": None, "candidateActionId": None} if diagnostics is not None else {}
            def reject(reason, legacy=None):
                trace["firstRejection"] = reason
                reasons[legacy or reason] += 1
                if diagnostics is not None:
                    traces.append(trace)
            gates["distinct_parents"] = "passed" if len(qualified) >= min_flows else "failed"
            if len(qualified) < min_flows:
                # 报告使合格数量首次不足的原因；更晚的有状态门槛保持未检查。
                reason = ("insufficient_distinct_parents" if len(evidence[key]) < min_flows else
                          "low_score" if len(high) < min_flows else
                          "stale_last_packet" if len(fresh) < min_flows else "insufficient_context_coverage")
                if len(evidence[key]) < min_flows <= len(evidence[key]) + len(expired):
                    reason = "expired_evidence"
                reject(reason, "insufficient_distinct_fresh_evidence"); continue
            gates["evidence_span"] = "passed" if span >= span_ms else "failed"
            if span < span_ms:
                reject("insufficient_span"); continue
            gates["peer_flow_starts"] = "passed" if o["contexts"][1]["peerFlowStarts"] >= min_starts else "failed"
            if gates["peer_flow_starts"] == "failed":
                reject("insufficient_peer_flow_starts", "insufficient_context"); continue
            gates["ttl_dedup"] = "failed" if last_expiry.get(budget_key, -math.inf) > t else "passed"
            if gates["ttl_dedup"] == "failed":
                reject("ttl_dedup"); continue
            active[asset] = {k: expires for k, expires in active[asset].items() if expires > t}
            while recent[asset] and recent[asset][0] <= t - 60000:
                recent[asset].popleft()
            trace["activeRules"], trace["actionsLastMinute"] = len(active[asset]), len(recent[asset])
            gates["simultaneous_rules"] = "passed" if len(active[asset]) < 10 else "failed"
            if len(active[asset]) >= 10:
                reject("simultaneous_rule_budget", "action_budget"); continue
            gates["actions_per_minute"] = "passed" if len(recent[asset]) < 5 else "failed"
            if len(recent[asset]) >= 5:
                reject("per_minute_action_budget", "action_budget"); continue
            if key not in chain_start or t > last_expiry.get(budget_key, -math.inf) + 1:
                chain_start[key] = t
            trace["continuousBlockMs"] = (budget.proposed_ms(budget_key,t,t+ttl*1000) if safe
                                          else float(t + ttl * 1000 - chain_start[key]))
            gates["continuous_ttl"] = "passed" if trace["continuousBlockMs"] <= 120000 else "failed"
            if gates["continuous_ttl"] == "failed":
                reject("continuous_ttl_budget"); continue
            expires = t + ttl * 1000
            if safe: budget.commit(budget_key,t,expires)
            active[asset][budget_key] = expires; recent[asset].append(t); last_expiry[budget_key] = expires
            actions.append((key, t, expires, tuple(qualified)))
            action_ids.append(i)
            trace["candidateActionId"] = f"action-{len(actions)-1}"
            if diagnostics is not None:
                traces.append(trace)
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
        if diagnostics is not None:
            diagnostics.update(observations=traces, actions=[], opportunities=[])
            for ordinal, ((key, start, end, qualified), trigger) in enumerate(zip(actions, action_ids, strict=True)):
                collateral = [j for j in rows_by_target[key] if self.batch.rows[j]["label"] == 0 and start <= self.times[j] < end]
                diagnostics["actions"].append({"id": f"action-{ordinal}", "triggerIndex": trigger,
                    "startMs": float(start), "endMs": float(end), "evidenceIndices": list(qualified),
                    "evidenceAgesMs": [float(start-self.times[j]) for j in qualified],
                    "collateralIndices": collateral,
                    "correct": {self.batch.rows[j]["label"] for j in qualified} == {1} and not collateral})
            for ordinal, ((key, bucket), ids) in enumerate(self.opportunities.items()):
                related = [(n, a) for n, a in enumerate(actions) if a[0] == key and
                           any(a[1] <= self.times[j] < a[2] for j in ids)]
                affected = [j for j in ids if any(a[1] <= self.times[j] < a[2] for _, a in related)]
                labels = {self.batch.rows[j]["label"] for j in ids}
                first = min(self.times[j] for j in ids)
                status = ("evidence_not_evaluable" if not labels <= {0, 1} else
                          "uncovered" if not affected else
                          "covered" if min(self.times[j] for j in affected) == first else "late_covered")
                diagnostics["opportunities"].append({"id": f"opportunity-{ordinal}", "bucket": bucket,
                    "observationIndices": ids, "candidateActionIds": [f"action-{n}" for n, _ in related],
                    "positive": labels == {1}, "mixedCountedAsBenign": len(labels) != 1,
                    "status": status, "affectedObservationIndices": affected,
                    "timingMeaning": "relative to first observed final in bucket; not qualified attack onset"})
        return {"policyVersion": policy_version, "unit": "observed_final_target_30s_opportunity", **dict(counts), "candidateActions": len(actions),
                "correctAttackCandidateActions": good_actions, "incorrectCandidateActions": len(actions) - good_actions,
                "blockPrecisionCandidate": good_actions / len(actions) if actions else None,
                "opportunityRecallDiagnostic": recall, "falseBenignOpportunityRate": fpr,
                "falsePer1000BenignOpportunities": fpr * 1000 if fpr is not None else None,
                "affectedBenignParents": len(benign_parents), "falseCandidateSeconds": false_seconds,
                "candidateActionsPerObservedCalendarHour": len(actions) / duration_hours,
                "calendarDurationCaveat": "source days/gaps preserved; not continuous monitored host hours",
                "attackActivities": groups[1], "benignGroups": groups[0],
                "clusterConfidenceInterval": None,
                "confidenceReason": "no independent development activity evaluation; indexed groups do not establish independent replications",
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
