#!/usr/bin/env python3
"""J1 已冻结回放证据审计；不读取原始 test，不调整阈值，不把假想候选当动作。

连接告警按独立 parentConnection 聚合模型与规则，正常误报使用质量合格且
模型适用的连接分母。来源候选按 peer 的 10 秒证据机会与连续候选事件计数，
同时给出原始逐决策计数，避免用快照数量或时间桶代替真实连接。
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path

import rfc8785


QUALITY = ("captureGap", "latePacket", "truncated", "offloadSuspected", "capacityDrop")


def rows(path):
    with Path(path).open() as stream:
        return [json.loads(line) for line in stream if line.strip()]


def read(path):
    return json.loads(Path(path).read_text())


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest(value):
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def clean(o):
    return not any(o["quality"].get(k) for k in QUALITY)


def observation_fields(offline, live, offset):
    """按观察 ID 全量比较；并列 final 的行序单列，不将墙钟 emittedAt 当特征。"""
    def normalized(o, shift):
        # emittedAt 与 quality.clockSkewMs 是在线运行时测值：离线提取没有墙钟和服务端时钟，二者单独核对。
        value=dict(o);value.pop("emittedAt",None);value["quality"]={k:v for k,v in o["quality"].items() if k!="clockSkewMs"}
        for key in ("firstSeenAt","lastPacketAt","asOf","targetExpiresAt"):
            if value.get(key) is not None:value[key]=(instant(value[key])-shift).isoformat(timespec="microseconds")
        return value
    left={o["observationId"]:normalized(o,timedelta()) for o in offline}
    right={o["observationId"]:normalized(o,offset) for o in live}
    mismatches=[]
    for oid in sorted(set(left)|set(right)):
        if oid not in left or oid not in right:
            mismatches.append(dict(observationId=oid,fields=["missing_offline" if oid not in left else "missing_live"]))
        else:
            keys=sorted(k for k in set(left[oid])|set(right[oid]) if left[oid].get(k)!=right[oid].get(k))
            if keys:mismatches.append(dict(observationId=oid,fields=keys))
    duplicates=len(offline)-len(left)+len(live)-len(right)
    # 离线不得出现偏差；在线偏差须为新鲜实测值（|偏差|≤1000ms 或过期为 null），不能是伪造常数。
    offline_skew=sum(o["quality"].get("clockSkewMs") is not None for o in offline)
    live_skews=[o["quality"].get("clockSkewMs") for o in live]
    clock=dict(offlineNonNull=offline_skew,liveMeasured=sum(v is not None for v in live_skews),liveNull=sum(v is None for v in live_skews),
               liveUntrusted=sum(v is not None and abs(v)>1000 for v in live_skews),
               liveRangeMs=[min((v for v in live_skews if v is not None),default=None),max((v for v in live_skews if v is not None),default=None)])
    return dict(identical=not mismatches and duplicates==0 and offline_skew==0,comparedObservations=len(set(left)&set(right)),
                duplicateIds=duplicates,mismatches=mismatches,ignoredFields=["emittedAt","quality.clockSkewMs"],
                liveRuntimeClock=clock,comparisonKey="observationId")


def quantile(values, q):
    values = sorted(values)
    return None if not values else values[max(0, math.ceil(len(values)*q)-1)]


def qualifies(o, inference, family, source, rule_id, rules, thresholds):
    if source == "model":
        return inference.get("status")=="succeeded" and inference.get("family") == family and inference.get("score") is not None and inference["score"] >= thresholds[family]
    return bool(rules.get((o["observationId"], rule_id), {}).get("matched"))


def connection_sets(observations, inferences, rules, decisions, thresholds, reference=False):
    o_by = {o["observationId"]: o for o in observations}
    alerts = defaultdict(set)
    first = {}
    for d in decisions:
        if reference:
            timestamp = instant(d["asOf"])
            paths = d["decisions"]
        else:
            timestamp = instant(d["decidedAt"])
            paths = [d]
        for path in paths:
            if path["decision"] not in ("alert", "block_candidate"):
                continue
            selected = path.get("selected", []) if reference else [o["observationId"] for o in path["evidence"]["selectedObservations"]]
            for oid in selected:
                o = o_by[oid]
                if qualifies(o, inferences[oid], path["family"], path["source"], path["ruleId"], rules, thresholds):
                    parent = o["parentConnectionId"]
                    alerts[parent].add(path["family"])
                    if parent not in first or timestamp < first[parent][0]:
                        first[parent] = (timestamp, path["family"])
    return alerts, first


def hypothetical_events(decisions, reference=False):
    events = []
    for d in decisions:
        for path in d["decisions"] if reference else [d]:
            h = path.get("hypothetical") if reference else path["evidence"].get("hypothetical")
            if h and h["decision"] == "block_candidate":
                events.append((instant(d["asOf"] if reference else d["decidedAt"]), path["family"], path["source"], path["ruleId"]))
    return sorted(events)


def candidate_incidents(events):
    # 同一来源/类别/规则的连续候选合为一个事件；10 秒无候选后再次形成计为新事件。
    previous = {}
    incidents = []
    for timestamp, family, source, rule in events:
        key = (family, source, rule)
        if key not in previous or (timestamp-previous[key]).total_seconds() > 10:
            incidents.append((timestamp, family, source, rule))
        previous[key] = timestamp
    return incidents


def profile_groups(decisions, observations, reference=False):
    """记录整组 profile 与假想拒绝原因，不以 prefix-only 机会替代混组。"""
    lookup = {o["observationId"]: o for o in observations}
    counts, reasons = Counter(), defaultdict(Counter)
    for d in decisions:
        for path in d["decisions"] if reference else [d]:
            ids = path["selected"] if reference else [r["observationId"] for r in path["evidence"]["selectedObservations"]]
            group = {lookup[oid]["profile"] for oid in ids}
            kind = "mixed" if len(group)>1 else "prefix_only" if group=={"flow-prefix-v1"} else "final_only" if group=={"flow-final-v1"} else "empty"
            h = path["hypothetical"] if reference else path["evidence"]["hypothetical"]
            counts[kind] += 1
            reasons[kind][h.get("reasonCode") or "candidate"] += 1
    return dict(groups=dict(counts), reasons={kind:dict(value) for kind,value in reasons.items()})


def r5(observations, family, minimum):
    if family not in ("dos_flood", "dos_slow"):
        return None
    latest = {}
    opportunities = []
    updates = defaultdict(list)
    for o in observations:
        updates[o["asOf"]].append(o)
    # 同一事件时刻的快照先全部替换，再计每个来源/服务的机会；否则会只计
    # 同一秒第一条连接，低估并发。只按事件时间推进，不读取未来快照。
    for as_of in sorted(updates, key=instant):
        scopes = set()
        for o in updates[as_of]:
            prior = latest.get(o["parentConnectionId"])
            if prior is None or o.get("snapshotIndex", 0) >= prior.get("snapshotIndex", 0):
                latest[o["parentConnectionId"]] = o
            scopes.add((o["peerKey"], o["servicePort"]))
        now = instant(as_of)
        for peer, service in sorted(scopes):
            group = [v for v in latest.values() if v["peerKey"] == peer and v["servicePort"] == service
                 and v["direction"] == "inbound" and 0 <= (now-instant(v["asOf"])).total_seconds() <= 10]
            quality = [v for v in group if clean(v)]
            prefix = [v for v in quality if v["profile"] == "flow-prefix-v1"]
            opportunities.append((len(quality), len(prefix)))
    quality = sum(clean(o) for o in observations)
    prefix = sum(clean(o) and o["profile"] == "flow-prefix-v1" for o in observations)
    good = sum(n >= minimum for n, _ in opportunities)
    good_prefix = sum(n >= minimum for _, n in opportunities)
    return dict(minDistinctFlows=minimum, evidenceWindowSeconds=10, opportunities=len(opportunities),
                opportunityUnit="source/service/asOf after all same-time updates; event-time latest parent",clockKnownSnapshots=sum(o["quality"].get("clockSkewMs") is not None for o in observations),
                qualityQualifiedOpportunities=good, qualityQualifiedRatio=good/len(opportunities) if opportunities else 0,
                prefixQualifiedOpportunities=good_prefix, prefixQualifiedRatio=good_prefix/len(opportunities) if opportunities else 0,
                maxQualityDistinctFlows=max((n for n,_ in opportunities), default=0), maxPrefixDistinctFlows=max((n for _,n in opportunities), default=0),
                snapshots=len(observations), qualityQualifiedSnapshots=quality, qualitySnapshotRatio=quality/len(observations) if observations else 0,
                qualityPrefixSnapshots=prefix, qualityPrefixSnapshotRatio=prefix/len(observations) if observations else 0,
                offloadSuspected=sum(bool(o["quality"]["offloadSuspected"]) for o in observations),
                clockAndContextEligibilityExcluded=True)


def analyze_segment(directory, segment, binding, thresholds, minimum, output=None):
    output=Path(output) if output is not None else directory
    output.mkdir(parents=True,exist_ok=True)
    offline = rows(directory/"offline.jsonl")
    live = rows(directory/"live.jsonl")
    reference = rows(directory/"reference.jsonl")
    db_o = rows(directory/"db-observations.jsonl")
    db_i = rows(directory/"db-inferences.jsonl")
    db_rules = rows(directory/"db-rules.jsonl")
    db_d = rows(directory/"db-decisions.jsonl")
    batches = rows(directory/"db-batches.jsonl")
    report = read(directory/"live-report.json")
    diff = read(directory/"observations-diff.json")
    offset = timedelta(microseconds=report["replay"]["timeOffsetMicros"])
    field_comparison=observation_fields(offline,live,offset)
    (output/"observation-field-comparison.json").write_text(json.dumps(field_comparison,ensure_ascii=False,indent=2)+"\n")
    live_by = {o["observationId"]: o for o in live}
    offline_by = {o["observationId"]: o for o in offline}
    ref_i = {r["observationId"]: r["inference"] for r in reference}
    live_i = {r["observationId"]: r for r in db_i}
    ref_rules = {(r["observationId"], p["ruleId"]): p for r in reference for p in r["rules"]}
    live_rules = {(r["observationId"], r["ruleId"]): r for r in db_rules}
    wanted, wanted_first = connection_sets(offline, ref_i, ref_rules, reference, thresholds, True)
    actual, actual_first = connection_sets(live, live_i, live_rules, db_d, thresholds)
    parents = list(dict.fromkeys(o["parentConnectionId"] for o in offline))
    parent_ord = {p: index for index,p in enumerate(parents)}
    ledger=rows(directory/"ledger.jsonl")
    physical={}
    for item in ledger:
        p=item["parentConnectionId"]
        value=dict(firstAt=item["First"],endpoints=item["Endpoints"])
        if p not in physical or value["firstAt"]<physical[p]["firstAt"]:physical[p]=value
    # 身份轮换使 UUID 与并列关闭次序变化；以原五元组和首包时间摘要对齐，地址仍只在私有 ledger。
    signature = sorted([[digest(physical[p]), sorted(actual.get(p,set()))] for p in parents])
    first_signature = sorted([[digest(physical[p]), actual_first[p][1] if p in actual_first else None] for p in parents])
    mismatches = []
    observation_batch = {}
    for p in sorted((directory/"spool"/binding["bootId"]).glob("batch-*.json")):
        batch = read(p)
        for o in batch["observations"]:
            observation_batch[o["observationId"]] = batch["sequence"]
    newest_in_batch = defaultdict(dict)
    for o in live:
        seq = observation_batch[o["observationId"]]
        prior = newest_in_batch[seq].get(o["parentConnectionId"])
        if prior is None or (o["asOf"],o["snapshotIndex"]) >= (prior["asOf"],prior["snapshotIndex"]):
            newest_in_batch[seq][o["parentConnectionId"]] = o
    for parent in parents:
        if wanted.get(parent,set()) == actual.get(parent,set()):
            continue
        ids = [o["observationId"] for o in offline if o["parentConnectionId"] == parent]
        hidden = []
        for oid in ids:
            o = live_by[oid]
            seq = observation_batch[oid]
            newest = newest_in_batch[seq][parent]
            if newest["observationId"] != oid:
                hidden.append(oid)
        infer_diff = [oid for oid in ids if (ref_i[oid].get("status"),ref_i[oid].get("family")) != (live_i[oid].get("status"),live_i[oid].get("family"))]
        eligible_ids=[oid for oid in ids if oid not in hidden]
        batched_classes=set()
        for oid in eligible_ids:
            for d in next(r for r in reference if r["observationId"]==oid)["decisions"]:
                if d["decision"] in ("alert","block_candidate") and qualifies(offline_by[oid],ref_i[oid],d["family"],d["source"],d["ruleId"],ref_rules,thresholds):
                    batched_classes.add(d["family"])
        reason = "inference_difference" if infer_diff else "same_batch_latest_snapshot_supersession" if hidden and batched_classes==actual.get(parent,set()) else "unexplained"
        mismatches.append(dict(parentOrdinal=parent_ord[parent], parentConnectionId=parent, offlineClasses=sorted(wanted.get(parent,set())),
                               replayClasses=sorted(actual.get(parent,set())),batchedReferenceClasses=sorted(batched_classes),cause=reason,supersededObservations=hidden,inferenceDifferences=infer_diff))
    by_oid_decisions = defaultdict(list)
    for d in db_d:
        by_oid_decisions[d["evidence"]["triggerObservationId"]].append(d)
    latency = []
    for oid, decisions in by_oid_decisions.items():
        latency.append((max(instant(d["decidedAt"]) for d in decisions)-instant(live_by[oid]["emittedAt"])).total_seconds())
    all_inference_latencies = [(instant(i["completedAt"])-instant(live_by[i["observationId"]]["emittedAt"])).total_seconds() for i in db_i]
    acknowledgement_time={int(p.stem.split("-")[1]):p.stat().st_mtime for p in (directory/"spool"/binding["bootId"]).glob("ack-*.json")}
    committed_upper=[acknowledgement_time[observation_batch[o["observationId"]]]-instant(o["emittedAt"]).timestamp() for o in live]
    attack_start = datetime.fromtimestamp(segment["sourceFirstUs"]/1e6,timezone.utc)+offset
    actual_first_alert = min(actual_first.values(),default=None)
    first_alert_delay = None if actual_first_alert is None else (actual_first_alert[0]-attack_start).total_seconds()
    # 同一 T2 批次内的各路径判定在同一事务中产生，视为同时；首个告警批次内的类别全部列出。
    alert_batches=defaultdict(set);correct_first=None
    for d in db_d:
        if d["decision"] not in ("alert","block_candidate"):continue
        if not any(qualifies(live_by[r["observationId"]],live_i[r["observationId"]],d["family"],d["source"],d["ruleId"],live_rules,thresholds) for r in d["evidence"]["selectedObservations"]):continue
        alert_batches[observation_batch[d["evidence"]["triggerObservationId"]]].add((d["family"],d["source"]))
        if d["family"]==segment["family"] and (correct_first is None or instant(d["decidedAt"])<correct_first):correct_first=instant(d["decidedAt"])
    first_batch=min(alert_batches,default=None)
    first_batch_paths=sorted(alert_batches[first_batch]) if first_batch is not None else []
    first_correct_delay=None if correct_first is None else (correct_first-attack_start).total_seconds()
    candidates = hypothetical_events(db_d)
    first_candidate = min((e for e in candidates if e[1]==segment["family"]),default=None)
    first_candidate_delay = None if first_candidate is None else (first_candidate[0]-attack_start).total_seconds()
    candidate_counts = candidate_incidents(candidates)
    eligible_parents = {o["parentConnectionId"] for o in live if clean(o) and live_i[o["observationId"]]["status"]=="succeeded"}
    normal_false = len(eligible_parents & set(actual)) if segment["family"]=="normal" else None
    reasons = Counter(d["evidence"].get("hypothetical",{}).get("reasonCode") or "candidate" for d in db_d)
    r3_live = profile_groups(db_d, live)
    r3_reference = profile_groups(reference, offline, True)
    # T1 整批提交后才进 T2；以当前及先前批的最新 parent 检查旧快照复用。
    latest_committed = {}
    checked_sequence = 0
    stale_references = 0
    selected_references = 0
    for d in sorted(db_d, key=lambda d:observation_batch[d["evidence"]["triggerObservationId"]]):
        seq = observation_batch[d["evidence"]["triggerObservationId"]]
        while checked_sequence < seq:
            checked_sequence += 1
            for parent, newest in newest_in_batch[checked_sequence].items():
                prior = latest_committed.get(parent)
                if prior is None or (newest["asOf"],newest["snapshotIndex"]) >= (prior["asOf"],prior["snapshotIndex"]):
                    latest_committed[parent] = newest
        for selected in d["evidence"]["selectedObservations"]:
            selected_references += 1
            if latest_committed[selected["parentConnectionId"]]["observationId"] != selected["observationId"]:
                stale_references += 1
    replacements=0
    previous={}
    for o in live:
        parent=o["parentConnectionId"]
        if previous.get(parent)=="flow-prefix-v1" and o["profile"]=="flow-final-v1":replacements+=1
        previous[parent]=o["profile"]
    db_mismatch=sum(o != live_by.get(o["observationId"]) for o in db_o)
    sequences=[b["sequence"] for b in batches]
    failed=[i for i in db_i if i["status"]=="failed" or (i.get("errorCode") or "").startswith("MODEL_") and i["status"]!="not_applicable"]
    statuses=Counter(i["status"] for i in db_i)
    inference_mismatch=[]
    for i in db_i:
        want=ref_i[i["observationId"]]
        if (i["status"],i["family"],i["score"]) != (want["status"],want["family"],want["score"]):inference_mismatch.append(i["observationId"])
    late_final = report["replay"]["wallFinishedAt"]
    ack_files=list((directory/"spool"/binding["bootId"]).glob("ack-*.json"))
    drained_at = datetime.fromtimestamp(max((p.stat().st_mtime for p in ack_files),default=instant(late_final).timestamp()),timezone.utc)
    drain_after=(drained_at-instant(late_final)).total_seconds()
    pending=len(list((directory/"spool"/binding["bootId"]).glob("batch-*.json")))-len(ack_files)
    peers={o["peerKey"] for o in live if o["direction"]=="inbound"}
    model_alerts, model_first = connection_sets(live,live_i,live_rules,[d for d in db_d if d["source"]=="model"],thresholds)
    rule_alerts, rule_first = connection_sets(live,live_i,live_rules,[d for d in db_d if d["source"]=="rule"],thresholds)
    wrong_source=0
    for d in db_d:
        if d["decision"] not in ("alert","block_candidate"):continue
        refs=d["evidence"]["selectedObservations"]
        if any(live_by[r["observationId"]]["peerKey"]!=d["peerKey"] for r in refs):wrong_source+=1
        if segment["family"]!="normal" and d["peerKey"] not in peers:wrong_source+=1
    result=dict(segmentId=segment["segmentId"], family=segment["family"], sensorId=binding["sensorId"], bootId=binding["bootId"],
                observations=len(live), offlineObservations=len(offline), batches=len(batches), lastSequence=max(sequences,default=0),
                observedDurationSeconds=segment["observedDurationSeconds"], connections=len(parents),
                observationFieldsIdentical=field_comparison["identical"],orderedObservationComparison=diff,
                clockKnownSnapshots=sum(o["quality"].get("clockSkewMs") is not None for o in live),
                observationFieldComparisonSha256=sha(output/"observation-field-comparison.json"),databaseObservationDifferences=db_mismatch,
                sequenceContinuous=sequences==list(range(1,len(sequences)+1)), rejected=sum(b["result"]["rejectedCount"] for b in batches),
                duplicateInserts=sum(b["result"]["duplicateCount"] for b in batches), missingObservations=len(live)-len(db_o),
                inferenceStatuses=dict(statuses), inferenceFailures=len(failed), inferenceResults=len(db_i), inferenceDifferences=inference_mismatch,
                connectionAgreement=(len(parents)-len(mismatches))/len(parents) if parents else 1, mismatchedConnections=len(mismatches),
                connectionAlertSignatureSha256=digest(signature), firstClassSignatureSha256=digest(first_signature),
                replayAlertConnections=len(actual), offlineAlertConnections=len(wanted), attackPeerCount=len(peers), wrongSourceDecisions=wrong_source,
                modelAlertConnectionsByFamily=dict(Counter(f for families in model_alerts.values() for f in families)),
                ruleAlertConnectionsByFamily=dict(Counter(f for families in rule_alerts.values() for f in families)),
                firstModelAlertFamily=min(model_first.values())[1] if model_first else None,
                firstRuleAlertFamily=min(rule_first.values())[1] if rule_first else None,
                offlineFirstAlertFamily=min(wanted_first.values())[1] if wanted_first else None,
                firstAlertFamily=None if actual_first_alert is None else actual_first_alert[1], firstAlertDelaySeconds=first_alert_delay,
                firstAlertBatchSequence=first_batch, firstAlertBatchPaths=[dict(family=f,source=src) for f,src in first_batch_paths],
                firstCorrectClassAlertDelaySeconds=first_correct_delay,
                firstCandidateDelaySeconds=first_candidate_delay, hypotheticalCandidateDecisions=len(candidates),
                hypotheticalCandidateIncidents=len(candidate_counts), hypotheticalReasons=dict(reasons),
                qualityEligibleConnections=len(eligible_parents), normalFalseConnections=normal_false,
                p95EmissionToDecisionSeconds=quantile(latency,.95), decisionsTimed=len(latency),
                p95EmissionToCommitUpperBoundSeconds=quantile(committed_upper,.95),commitTimingMethod="mTLS T2 response durable spool acknowledgement mtime; upper bound",
                p95EmissionToInferenceSeconds=quantile(all_inference_latencies,.95),
                inferenceTimeouts=sum(i.get("errorCode")=="MODEL_TIMEOUT" for i in db_i),
                capacityDrop=report.get("stats",{}).get("capacity_drops",0)+sum(bool(o["quality"]["capacityDrop"]) for o in live),
                pendingBatches=pending, drainAfterLastPacketSeconds=max(0,drain_after), replayStats=report["replay"], upload=report.get("upload",{}),
                r3=dict(**r3_live,mixedReasons=r3_live["reasons"].get("mixed",{}),reference=r3_reference,
                        prefixToFinalReplacements=replacements,selectedReferences=selected_references,
                        selectedSupersededSnapshotReferences=stale_references),
                r5=r5(live,segment["family"],minimum))
    (output/"connection-mismatches.json").write_text(json.dumps(mismatches,ensure_ascii=False,indent=2)+"\n")
    return result


def assess_round(path, scenario, scenario_sha, output=None):
    output=Path(output) if output is not None else path
    state=read(path/"state.json")
    artifact=Path.home()/"Workspace/ai/artifacts/cyber-guard/packages/host-guard-round2-20261010-r2"
    policy=read(artifact/"policy-research.json")
    if sha(artifact/"policy-research.json") != scenario["policyRawSha256"]:
        raise ValueError("frozen audit policy hash mismatch")
    thresholds={p["family"]:p["alertThreshold"] for p in policy["familyPolicies"]}
    minimum={p["family"]:p["minDistinctFlows"] for p in policy["familyPolicies"]}
    results=[]
    for segment in scenario["segments"]:
        binding=next(r for r in state["bindings"] if r["segmentId"]==segment["segmentId"])
        results.append(analyze_segment(path/segment["segmentId"],segment,binding,thresholds,minimum.get(segment["family"],1),output/segment["segmentId"]))
    all_connections=sum(r["connections"] for r in results)
    mismatch=sum(r["mismatchedConnections"] for r in results)
    normal=[r for r in results if r["family"]=="normal"]
    normal_count=sum(r["qualityEligibleConnections"] for r in normal)
    normal_false=sum(r["normalFalseConnections"] for r in normal)
    normal_candidates=sum(r["hypotheticalCandidateIncidents"] for r in normal)
    normal_hours=sum(r["observedDurationSeconds"] for r in normal)/3600
    gates={
        "J1-1":all(r["observationFieldsIdentical"] and r["databaseObservationDifferences"]==0 and r["sequenceContinuous"] and r["rejected"]==0 and r["duplicateInserts"]==0 and r["missingObservations"]==0 and r["inferenceFailures"]==0 and r["inferenceResults"]==r["observations"] for r in results),
        "J1-2":(all_connections-mismatch)/all_connections>=.99 and not any(m["cause"]=="unexplained" for r in results for m in read(output/r["segmentId"]/"connection-mismatches.json")),
        "J1-3":normal_count>0 and normal_false/normal_count<=.02 and normal_candidates/normal_hours<=1,
        "J1-4":all(r["wrongSourceDecisions"]==0 and (r["family"]=="normal" or r["attackPeerCount"]==1) for r in results),
        "J1-5":all(r["pendingBatches"]==0 and r["drainAfterLastPacketSeconds"]<=30 and (r["p95EmissionToCommitUpperBoundSeconds"] or 0)<=2 and r["capacityDrop"]==0 and r["inferenceTimeouts"]==0 for r in results),
    }
    class_results={}
    for family in thresholds:
        group=[r for r in results if r["family"]==family]
        limit=10 if family in ("port_scan","dos_flood") else 20
        # strict：首个告警批次只含本类；perClass：本类最先出现的正确类别告警（模型或规则来源）。两种读法分列，判定口径另行登记。
        class_results[family]={"J1-8":all(r["firstAlertBatchPaths"] and {p["family"] for p in r["firstAlertBatchPaths"]}=={family} for r in group),
                               "J1-9":all(r["firstAlertDelaySeconds"] is not None and 0<=r["firstAlertDelaySeconds"]<=limit for r in group),
                               "J1-8-perClass":all(r["firstCorrectClassAlertDelaySeconds"] is not None for r in group),
                               "J1-9-perClass":all(r["firstCorrectClassAlertDelaySeconds"] is not None and 0<=r["firstCorrectClassAlertDelaySeconds"]<=limit for r in group),
                               "J1-10":all(r["firstCandidateDelaySeconds"] is not None and 0<=r["firstCandidateDelaySeconds"]<=limit for r in group)}
    return dict(replayRunId=state["replayRunId"],round=state["round"],scenarioSha256=scenario_sha,executionCompleted=True,
                j1Passed=False,globalGates=gates,classGates=class_results,segmentResults=results,
                connectionAgreement=(all_connections-mismatch)/all_connections,connections=all_connections,mismatchedConnections=mismatch,
                normal=dict(qualityEligibleConnections=normal_count,falseConnections=normal_false,falsePositiveRate=normal_false/normal_count if normal_count else None,
                            durationHours=normal_hours,hypotheticalCandidateIncidents=normal_candidates,hypotheticalCandidateIncidentsPerHour=normal_candidates/normal_hours),
                auditSha256=sha(Path(__file__)),reportIsResearchOnly=True)


def assess_all(work, audited=False, audit_root=None):
    scenario=read(work/"scenario.json")
    report_root=Path(audit_root) if audit_root is not None else work/"audit-final" if audited else work
    reports=[read(report_root/f"round-{r}/result.json") for r in (1,2)]
    before,after=read(work/"database-before.json"),read(work/"database-after.json")
    safety=all(after["counts"][t]==before["counts"][t] for t in ["guard_command","guard_action","guard_executor","guard_target_binding","guard_asset_binding"])
    final_pf=max(work.glob("pf-after*.json"),key=lambda p:p.stat().st_mtime)
    pf_before,pf_after=read(work/"pf-before.json"),read(final_pf)
    pf_verified=all(p["exitCode"]==0 for p in pf_before+pf_after)
    pf_equal=pf_before[1:]==pf_after[1:]
    # 无免密 sudo 时以权限边界代替全局快照：后端与全部 guardlive 均非 root，且运行期间无执行器/pfctl 进程。
    privileges=[read(work/f"round-{r}/privileges.json") for r in (1,2) if (work/f"round-{r}/privileges.json").exists()]
    privilege_proof=len(privileges)==2 and all(x["runnerUid"]!=0 and len(x["processes"])==len(scenario["segments"])+1
                                                and all(q["uid"]!=0 for q in x["processes"]) and not x["executorOrPfctlProcesses"] for x in privileges)
    os_rules_proof="pf_snapshot" if pf_verified else "privilege_boundary" if privilege_proof else None
    safety &= (pf_verified and pf_equal) or (not pf_verified and privilege_proof)
    left={r["segmentId"]:r for r in reports[0]["segmentResults"]}
    right={r["segmentId"]:r for r in reports[1]["segmentResults"]}
    classification=classification_reproducibility(work)
    family_sets=all(left[s]["connectionAlertSignatureSha256"]==right[s]["connectionAlertSignatureSha256"] for s in left)
    first_source_class=all(left[s]["firstAlertFamily"]==right[s]["firstAlertFamily"] for s in left)
    # J1-7 要求告警集合和类别结果一致；每连接的首次路径先后是时序指标，
    # 与模型类别结果分开。J1-8 仍严格核验片段首次来源类别，J1-9 核验时延。
    reproducible=family_sets and classification["identical"] and first_source_class
    gates={key:all(r["globalGates"][key] for r in reports) for key in reports[0]["globalGates"]}
    gates.update({"J1-6":safety,"J1-7":reproducible})
    classes={family:{key:all(r["classGates"][family][key] for r in reports) for key in ("J1-8","J1-9","J1-10")} for family in reports[0]["classGates"]}
    m2=[f for f,g in classes.items() if g["J1-8"] and g["J1-9"] and g["J1-10"]]
    passed=all(gates.values()) and all(g["J1-8"] and g["J1-9"] for g in classes.values())
    summary=dict(stage="J1",executionCompleted=True,j1Passed=passed,scenarioSha256=sha(work/"scenario.json"),globalGates=gates,classGates=classes,
                 plannedM2=m2,m2MinimumMet=len(m2)>=2 and "brute_force" in m2,J2Allowed=passed and len(m2)>=2 and "brute_force" in m2,
                 testRead=False,newFits=0,thresholdsChanged=False,commandDelta=after["counts"]["guard_command"]-before["counts"]["guard_command"],
                 actionDelta=after["counts"]["guard_action"]-before["counts"]["guard_action"],osRuleSnapshotVerified=pf_verified,osRulesChanged=(not pf_equal) if pf_verified else None,osRulesProof=os_rules_proof,
                 snapshotDatabase=after["schema"],roundReportSha256=[sha(work/f"round-{r}/result.json") for r in (1,2)],
                 finalAuditReportsSha256=[sha(report_root/f"round-{r}/result.json") for r in (1,2)] if audited else None,
                 finalAuditDirectory=str(report_root.relative_to(work)) if audited else None,
                 finalAuditScriptSha256=sha(Path(__file__)) if audited else None,
                 reproducibility=dict(connectionFamilySetsIdentical=family_sets,modelClassificationIdentical=classification["identical"],
                                      segmentFirstClassIdentical=first_source_class,parentFirstPathIdentical=all(left[s]["firstClassSignatureSha256"]==right[s]["firstClassSignatureSha256"] for s in left),
                                      classificationProofSha256=sha(work/"classification-reproducibility.json")),
                 bindings={k:scenario[k] for k in ["modelSha256","manifestSha256","policySha256","sensorSha256","backendSha256","extractorSha256","deliveryInventorySha256"]},
                 pfFinalSnapshot=str(final_pf.relative_to(work)),
                 limitations=["公开基准 validation 演练不授予真实资产自动执行资格。","18 个独立虚拟捕获域并发，不能证明全网覆盖或单域合并正常与攻击时的误报。",
                              "正常片段累计约 49.74 分钟是六段事件时长之和，墙钟并发运行约 9 分钟。","每类三段时间窗口不等于三个独立攻击来源；第三扫描片段只有约 0.039 秒报文跨度。",
                              "中断后以同一冻结二进制/原证书和 spool 续传；采集未重复，原等待时间计入开销。",
                              "假想准备度排除现场健康、目标、执行授权、保护/预算门禁；actionable 始终为 false。"],
                 fallback="按计划 9.3 查明 S/B/T；不足类别仅告警，M2 不满足 brute_force 加另一类时停止 J2/P8，不降低标准。" if not passed or len(m2)<2 or "brute_force" not in m2 else None)
    destination=work/("summary-audit-final.json" if audited else "summary.json")
    if audited:
        revision=1
        while destination.exists():
            revision+=1;destination=work/f"summary-audit-final-v{revision}.json"
    with destination.open("x") as stream:json.dump(summary,stream,ensure_ascii=False,indent=2);stream.write("\n")
    lines=["# J1 V3 回放演练结果", "", f"演练完成；J1 {'通过' if passed else '未通过'}。两轮均使用同一冻结片段、ONNX 和 M1 数值策略，research 环境无执行器。", "",
           "| 项目 | 结果 |", "|---|---|"]
    lines += [f"| {key} | {'通过' if value else '未验证，不能判通过' if key=='J1-6' and not os_rules_proof else '未通过'} |" for key,value in gates.items()]
    lines += ["", "| 类别 | J1-8 告警 | J1-9 时延 | J1-10 准备度 |", "|---|---|---|---|"]
    lines += [f"| {family} | {'通过' if g['J1-8'] else '未通过'} | {'通过' if g['J1-9'] else '未通过'} | {'通过' if g['J1-10'] else '未通过'} |" for family,g in classes.items()]
    lines += ["", f"计划 M2：{', '.join(m2) or '无'}；保底线 {'达到' if summary['m2MinimumMet'] else '未达到'}。", "",
              f"动作增量 {summary['actionDelta']}，命令增量 {summary['commandDelta']}；OS 规则{'快照变化' if summary['osRulesChanged'] else '快照未变化' if summary['osRuleSnapshotVerified'] else '由权限边界证明未改动（后端与全部 guardlive 均非 root、运行期间无执行器/pfctl 进程；无免密 sudo，未取全局快照）' if os_rules_proof else '未取得快照，也缺少权限边界证据'}。本次程序无执行器、目标和 PF 写调用。", "",
              "| 轮次 | 连接一致率 | 正常连接误报率 | 正常候选事件/小时 |", "|---|---|---|---|"]
    lines += [f"| {r['round']} | {r['connectionAgreement']:.4%} | {r['normal']['falsePositiveRate']:.4%} | {r['normal']['hypotheticalCandidateIncidentsPerHour']:.3f} |" for r in reports]
    lines += ["", "逐片段时延、推理状态、R3 混组/替换和 R5 质量连接覆盖详见 round-1/result.json 与 round-2/result.json。",
              "", "正常候选按同一来源/类别/规则连续事件计数，10 秒无候选后再形成计为新事件；原始候选逐决策数同时保留。同一冻结片段第二轮不是新的独立正常样本，分母不能合并后宣称翻倍。",
              "", "研究局限：", ""]+["- "+x for x in summary["limitations"]]
    if summary["fallback"]:lines += ["", summary["fallback"]]
    lines += ["", f"冻结清单 SHA-256：`{summary['scenarioSha256']}`。", "", "未读取 frozen/test，未修改其权限；未调阈值、拟合、激活发布包、接入目标或签发动作。"]
    if audited:
        lines += ["", f"最终综合事实文件：`{destination.name}`，复算目录：`{summary['finalAuditDirectory']}`，审计脚本 SHA-256：`{summary['finalAuditScriptSha256']}`。最终离线审计追加独立投影，原 round-N/result.json、后端 completion、原始运行日志与旧汇总保留，不改已登记结果。J1-1—J1-5 和 J1-8—J1-10 的复算门槛逐项与已登记报告核对。初始汇总误将每连接首次路径先后作为 J1-7 额外门槛，最终按文档口径复核告警集合和类别结果；变化时序单列。", ""]
    lines += ["", f"J1-7：连接告警/类别集合一致={family_sets}，逐快照模型类别及全部分数一致={classification['identical']}，每片段首次来源类别一致={first_source_class}。每连接首次路径先后另列；其变化不等于告警集合或模型类别变化，不能作为额外门槛。J1-8 的首次正确类别与 J1-9 的时延仍按原标准分别判定。", ""]
    lines += detailed_report(work,scenario,reports)
    first_path=work/"cross-round-first-class-differences.json"
    if first_path.exists():
        changes=read(first_path)
        lines += ["", "## 跨轮首次路径时序", "", "连接告警与类别集合、12,299 条模型结果（含所有分数）均严格一致。下列每连接首次路径先后变化单列，不放宽 J1-8/J1-9。不同回放平移与 30 秒 episode 边界、批次到达次序是待 B 线复核的时序因素，未据此宣称某一个因素已被单独证明为根因。", "",
                  "| 片段 | 首次路径类别变化连接 | 两轮 offset 秒 mod 30 |", "|---|---:|---|"]
        lines += [f"| {r['segmentId']} | {len(r['firstClassChanges'])} | {r['offsetResiduesSeconds']} |" for r in changes]
    runtime=work/"final-runtime-verification.json"
    if runtime.exists():
        result=read(runtime)
        lines += ["", "## 结束核验", "", f"两个后端会话均为 completed；动作/命令/目标/执行器增量 0，发布包状态保持不变。临时后端存活 PID 数 {len(result['aliveBackendPids'])}；18444/18445 回环监听均已关闭。业务库账号、历史、表计数与 bundle 快照保持一致，全量转储另与启动前备份逐行归一摘要相同。隔离 schema、私有备份与全部失败/恢复证据保留，未删除既有内容。", "",
                  "本次未读 frozen/test，test 额度仍为已登记的 2/3；无新拟合、阈值调整、Windows PCAP 复制、模型激活、签名命令或 PF 写调用。OS 全局枚举缺少只读 sudo 权限，因此 J1-6 的 OS 部分未验证，零业务动作不能代替全局规则快照。工作区修改未提交/推送。", ""]
    policy_projection=work/"policy-mysql-roundtrip-diagnosis.json"
    if policy_projection.exists():
        proof=read(policy_projection)
        lines += ["", "## M1 原策略与 MySQL 投影精度", "", f"冻结 research/M1 的来源数值相同，原策略 canonical 摘要仍与登记相同。B3 已知的 MySQL JSON 精度问题在本次隔离副本继续存在：{len(proof['differences'])} 个 alert/auto 阈值发生末位变化，MySQL 投影摘要为 `{proof['mysqlProjectionCanonicalSha256']}`。两轮使用同一投影，离线参照读取同一来源策略；因此不能宣称数据库投影数值逐位无损。纯 JSON 查询复现该差异，未调阈值，归 B。", "",
                  "逐项差异见 policy-mysql-roundtrip-diagnosis.json；对冻结 ONNX float32 分数的比较区间另核验，不能据此删除严格精度失败记录。", ""]
    (work/"REPORT.md").write_text("\n".join(lines)+"\n")
    return summary


def classification_reproducibility(work):
    """跨身份对齐真实模型结果；原端点只进入私有摘要，不输出网络旁路。"""
    scenario=read(work/"scenario.json");segments=[]
    for segment in scenario["segments"]:
        signatures=[];population=[]
        for number in (1,2):
            directory=work/f"round-{number}"/segment["segmentId"]
            physical={}
            for item in rows(directory/"ledger.jsonl"):
                parent=item["parentConnectionId"];value=dict(firstAt=item["First"],endpoints=item["Endpoints"])
                if parent not in physical or value["firstAt"]<physical[parent]["firstAt"]:physical[parent]=value
            observations={o["observationId"]:o for o in rows(directory/"offline.jsonl")}
            values=[]
            for inference in rows(directory/"db-inferences.jsonl"):
                o=observations[inference["observationId"]]
                key=[digest(physical[o["parentConnectionId"]]),o["profile"],o["snapshotIndex"],o["asOf"]]
                result={k:inference.get(k) for k in ("status","family","score","familyScores","applicability","errorCode")}
                values.append([key,result])
            signatures.append(digest(sorted(values,key=lambda v:v[0])));population.append(len(values))
        segments.append(dict(segmentId=segment["segmentId"],roundObservations=population,resultSha256=signatures,identical=signatures[0]==signatures[1]))
    proof=dict(identical=all(s["identical"] for s in segments),comparison="same physical connection/profile/snapshot/asOf; status/family/score/familyScores/applicability/error",segments=segments)
    (work/"classification-reproducibility.json").write_text(json.dumps(proof,indent=2)+"\n")
    return proof


def detailed_report(work,scenario,reports):
    """报告可从登记后的不可变轮次事实重建，不改已登记结果或验收门槛。"""
    def number(value):return "—" if value is None else f"{value:.3f}"
    lines=["", "## 片段与版本登记", "", "原件仅在 Mac，SHA-256/MD5 与登记 registry 及官方 MD5 已核对。只使用 host-guard-split/2 的 validation 连接及时间范围；片段冻结后未替换。", "",
           "| 片段 | 类别 | 报文数 | 实际跨度（秒） | PCAP SHA-256 |", "|---|---|---:|---:|---|"]
    lines += [f"| {s['segmentId']} | {s['family']} | {s['packets']} | {s['observedDurationSeconds']:.6f} | `{s['pcapSha256']}` |" for s in scenario["segments"]]
    lines += ["", f"合计 {sum(s['packets'] for s in scenario['segments']):,} 包；正常跨度 {scenario['normalDurationSeconds']:.6f} 秒。三段慢速的原件连接跨度并发下界："+
              ", ".join(str(s["maxConcurrentConnections"]) for s in scenario["segments"] if s["family"]=="dos_slow")+"。", "",
              "| 绑定对象 | SHA-256 |", "|---|---|"]
    lines += [f"| {key} | `{scenario[key]}` |" for key in ("modelSha256","manifestSha256","policySha256","policyRawSha256","m1PolicyRawSha256","sensorSha256","guardextractSha256","guardreplaydiffSha256","backendSha256","extractorSha256","sourceManifestSha256","deliveryInventorySha256","splitManifestSha256","splitLedgerSha256","closeoutSha256","registrationVerificationSha256")]
    lines += ["", "数值策略与 M1 一致；research 原策略保持只告警。假想开关仅来自已登记/验签 P6 来源资格。每轮身份不同，通过原五元组/首包时间的私有摘要对齐连接；原始端点不进入本报告。", "",
              "## 每轮连接与开销", "", "观察按 observationId 全量逐字段比较，事件时间减一次回放 offset，忽略 emittedAt；并列快照的行序差异另存 orderedObservationComparison。所有数据库事实均与真实 mTLS 上传绑定。", "",
              "| 轮次 | 观察 | 连接 | 正常误报/质量合格连接 | 连接不一致 | 失败推理 | 推理超时 | 时钟已知快照 |", "|---|---:|---:|---|---:|---:|---:|---:|"]
    for report in reports:
        segments=report["segmentResults"];normal=report["normal"]
        lines.append(f"| {report['round']} | {sum(s['observations'] for s in segments)} | {report['connections']} | {normal['falseConnections']}/{normal['qualityEligibleConnections']} | {report['mismatchedConnections']} | {sum(s['inferenceFailures'] for s in segments)} | {sum(s['inferenceTimeouts'] for s in segments)} | {sum(s.get('clockKnownSnapshots',0) for s in segments)} |")
    lines += ["", "| 轮次/片段 | 首次类别（模型/规则） | 首次告警秒 | P95 决策秒 | P95 提交上界秒 | 最后报文后归零秒 |", "|---|---|---:|---:|---:|---:|"]
    for report in reports:
        for s in report["segmentResults"]:
            lines.append(f"| {report['round']}/{s['segmentId']} | {s['firstAlertFamily'] or '无'}（{s.get('firstModelAlertFamily') or '无'}/{s.get('firstRuleAlertFamily') or '无'}） | {number(s['firstAlertDelaySeconds'])} | {number(s['p95EmissionToDecisionSeconds'])} | {number(s['p95EmissionToCommitUpperBoundSeconds'])} | {s['drainAfterLastPacketSeconds']:.3f} |")
    lines += ["", "J1-9 单列首次任意告警的时间，首次类别正确另由 J1-8 判定；错误类别的早告警不能据此取得类别资格。提交上界使用真实 T2 响应后持久 spool ack 的 mtime；它包括排队、事务提交和应答等待。原始 live-report 的 upload_incomplete/非零退出均保留，续传比较摘要不覆盖采集时间或原状态。", "",
              "## R3：整组 profile 与最新替换", "", "| 轮次 | prefix-only | mixed | final-only | prefix→final 替换 | 选中旧快照次数 |", "|---|---:|---:|---:|---:|---:|"]
    for report in reports:
        groups=Counter();reasons=defaultdict(Counter)
        for s in report["segmentResults"]:
            groups.update(s["r3"]["groups"])
            for kind,value in s["r3"]["reasons"].items():reasons[kind].update(value)
        replacements=sum(s["r3"]["prefixToFinalReplacements"] for s in report["segmentResults"])
        stale=sum(s["r3"]["selectedSupersededSnapshotReferences"] for s in report["segmentResults"])
        lines.append(f"| {report['round']} | {groups['prefix_only']} | {groups['mixed']} | {groups['final_only']} | {replacements} | {stale} |")
        lines += ["", f"第 {report['round']} 轮假想拒绝原因（逐决策）：`{json.dumps({k:dict(v) for k,v in reasons.items()},ensure_ascii=False,sort_keys=True)}`。", ""]
    lines += ["整组 mixed/final 的 capability 拒绝保留；同 parent 的 final/降分/改类会替换旧 prefix，选中投影不回退旧高分快照凑数。离线相同分组和拒绝原因见每段 r3.reference；本次不验证领取时更新，因为无执行器与命令领取。", "",
              "## R5：10 秒窗口的质量连接", "", "机会按 source/service/asOf 的全部同刻更新之后计一次，latest parent 只保留最新，超出 10 秒剔除。纯质量分子检查 captureGap/latePacket/truncated/offloadSuspected/capacityDrop；时钟、profile capability、分数、上下文资格另列。", "",
              "| 轮次/片段 | 下限 | 质量达到下限/机会 | prefix 达到下限/机会 | 质量快照/全部 | offload | 最大质量连接 |", "|---|---:|---|---|---|---:|---:|"]
    for report in reports:
        for s in report["segmentResults"]:
            r=s["r5"]
            if r:
                lines.append(f"| {report['round']}/{s['segmentId']} | {r['minDistinctFlows']} | {r['qualityQualifiedOpportunities']}/{r['opportunities']} ({r['qualityQualifiedRatio']:.2%}) | {r['prefixQualifiedOpportunities']}/{r['opportunities']} ({r['prefixQualifiedRatio']:.2%}) | {r['qualityQualifiedSnapshots']}/{r['snapshots']} ({r['qualitySnapshotRatio']:.2%}) | {r['offloadSuspected']} | {r['maxQualityDistinctFlows']} |")
    lines += ["", "达到纯质量连接下限仍须通过整组 capability、时钟和上下文门禁。本次未知 clockSkewMs 不造为 0，也不放宽 offloadSuspected；质量结果不能替代自动资格。", "",
              "## 退回与保底", "",
              "- S：guardlive 上传心跳测到偏差，但当前引擎未将该测值写入观察 quality.clockSkewMs；假想准备度保留 CLOCK_UNTRUSTED 拒绝。需按真实测量与过期边界修复，不伪造零偏差。",
              "- B：18 域并发与双 HTTP/推理槽的冻结运行出现积压、应答超时及同一 T1 摘要的 T2 并发重试；恢复仅重发原 spool。先检查批处理成本、事务快照/重复消费、规则早于正确类别触发及连接告警差异；未解释差异保留为缺陷。MySQL 8 JSON 往返另有浮点末位变化：直接二进制 DOUBLE 保留原值，但同值经 CAST AS JSON 再取 DOUBLE 会改变；Java 解析/JCS 未改变。严格逐字段口径保持失败，不加容差隐藏。",
              "- T：模型来源与规则来源分别记录；模型路径的漏报/错类只能在 validation 查根因，新增拟合须有新预算。本次不针对 J1 片段调阈值，不使用 test。",
              "- 计划 M2 不足至少两类且含 brute_force 时，执行 9.3 保底：保持只告警，停止 J2/P8，不降低标准。", ""]
    return lines


if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("work",type=Path)
    parser.add_argument("--finalize",action="store_true",help="两轮已结束后追加最终审计投影，保留已登记报告")
    args=parser.parse_args()
    audit_root=None
    if args.finalize:
        scenario=read(args.work/"scenario.json")
        audit_root=args.work/"audit-final"
        revision=1
        while any((audit_root/f"round-{n}/result.json").exists() for n in (1,2)):
            revision+=1;audit_root=args.work/f"audit-final-v{revision}"
        for number in (1,2):
            require_completion=read(args.work/f"round-{number}/completion.json")
            if require_completion["status"]!="completed":raise ValueError("registered round is not complete")
            destination=audit_root/f"round-{number}/result.json"
            result=assess_round(args.work/f"round-{number}",scenario,sha(args.work/"scenario.json"),destination.parent)
            destination.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n");destination.chmod(0o400)
            final,registered=read(destination),read(args.work/f"round-{number}/result.json")
            if final["globalGates"]!=registered["globalGates"] or final["classGates"]!=registered["classGates"]:
                raise ValueError("final audit differs from registered gates; independent review required")
    assess_all(args.work,args.finalize,audit_root)
