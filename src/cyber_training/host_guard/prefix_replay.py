"""新版 prefix 确定性研究决策器：顺序检查、最新 parent、连续预算与健康事件。

连续预算耗尽时输出一次 escalate_manual（每个预算 generation 一次），之后的合格
证据只形成人工移交告警，不放宽 120 秒上限。仅计算离线候选区间。能力、现场时钟、targetRef 及授权检查的模拟须在计划显式
登记；不创建 OS 命令。标签、来源名和角色均不参与分数/策略选择或预算重置。
"""
from collections import defaultdict, deque
import math

import numpy as np

from .capture_health import HealthChain, IDENTITY, stamp
from .evaluation import target_key

VERSION = 'host-guard-decision/2026-10-05.2'
SIMULATED = {'capability', 'pcap_clock', 'target_binding', 'authorization', 'rule_expiry'}


def simulate(batch, scores, parameters, plan, health=None):
    """在 emittedAt 处理事件，健康恢复只由已到达的完整旁证推进。

    所有角色合并后调用；目标映射必须来自冻结旁路，不从 boot/epoch 生成。
    TTL 到期仅为标注的离线模拟规则清零，现场必须使用真实执行回执。
    """
    if plan['versions']['decision'] != VERSION or set(plan['offlineSimulation']) != SIMULATED:
        raise ValueError('新版离线决策版本或模拟范围未登记')
    threshold = parameters['threshold']
    flows, span_ms, starts = (parameters.get(k, default) for k, default in
                             [('min_flows', 1), ('span_ms', 0), ('min_starts', 0)])
    ttl = parameters.get('ttl', 30)
    if (not 0 <= threshold <= 1 or type(flows) is not int or flows < 1 or starts < 0
            or not 0 <= span_ms <= 10000 or not 5 <= ttl <= 60):
        raise ValueError('策略参数越过固定安全范围')
    scores = np.asarray(scores).reshape(-1)
    if len(scores) != len(batch.rows) or not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
        raise ValueError('分数数量或范围不符')
    targets = [r.get('budgetTargetId') for r in batch.rows]
    if any(not isinstance(t, str) or not t for t in targets): raise ValueError('缺少稳定预算目标')
    observations = batch.observations
    times = [stamp(o['asOf']) for o in observations]
    emitted = [stamp(o['emittedAt']) for o in observations]
    last = [stamp(o['lastPacketAt']) for o in observations]
    keys = [target_key(o) for o in observations]
    events = [(emitted[i], 0, i) for i in range(len(observations))]
    health = health or dict(records=[], bindings=[], targets={})
    chain = HealthChain(health['bindings'])
    events.extend((stamp(r['intervalEnd']), 1, i) for i, r in enumerate(health['records']))
    evidence, accounts = defaultdict(dict), {}
    active, recent = defaultdict(dict), defaultdict(deque)
    actions, traces, resets, escalations, reasons = [], [], [], [], defaultdict(int)

    def account(target):
        return accounts.setdefault(target, dict(blocked=0, lastEnd=-math.inf,
                                                lastEvidence=-math.inf, generation=0, escalated=None))

    def clean(o):
        return all(o['quality'].get(k) is False for k in
                   ('captureGap', 'latePacket', 'truncated', 'offloadSuspected', 'capacityDrop'))

    def supported(o):
        scope = plan['scope']
        return o.get('contractVersion') == plan['versions']['observation'] and all(
            o.get(k) == scope[k] for k in ('profile', 'addressFamily', 'transport', 'direction', 'servicePort'))

    def context(o):
        matches = [c for c in o['contexts'] if c['windowSeconds'] == 5]
        return matches[0] if len(matches) == 1 else dict(coverageMs=0, peerFlowStarts=0)

    for at, kind, index in sorted(events):
        if kind == 1:
            record = health['records'][index]
            state = chain.accept(record)
            for target, identity in health['targets'].items():
                sessions = health.get('targetSessions', {}).get(target, [dict(identity=identity)])
                for session in sessions:
                    observer = session['identity']
                    if tuple(observer[k] for k in IDENTITY) != tuple(record[k] for k in IDENTITY): continue
                    a = account(target)
                    if not a['blocked'] or at - max(a['lastEnd'], a['lastEvidence']) < 120000: continue
                    proof = chain.proof(observer, a['lastEnd'], at)
                    if proof is None: continue
                    resets.append(dict(targetId=target, atMs=at, previousBlockedMs=a['blocked'],
                                       revision=a['generation'] + 1, proof=proof, ruleState='simulated_expired'))
                    a.update(blocked=0, generation=a['generation'] + 1, escalated=None)
            continue
        i = index; o = observations[i]; key = keys[i]; target = targets[i]; a = account(target)
        previous = evidence[key].get(o['parentConnectionId'])
        # 到达较晚的旧快照不得覆盖较新的 asOf，也不能驱动重复动作。
        late = previous is not None and times[previous] >= times[i]
        if not late: evidence[key][o['parentConnectionId']] = i
        evidence[key] = {p: j for p, j in evidence[key].items() if at - times[j] <= 10000}
        fresh = [j for j in evidence[key].values() if 0 <= at - times[j] <= 10000
                 and 0 <= at - last[j] <= 15000 and clean(observations[j]) and supported(observations[j])
                 and (observations[j]['quality'].get('clockSkewMs') is None
                      or abs(observations[j]['quality']['clockSkewMs']) <= 1000)]
        high = [j for j in fresh if scores[j] >= threshold]
        span = max((times[j] for j in high), default=at) - min((times[j] for j in high), default=at)
        reason = subreason = None
        if not supported(o): reason = 'CAPABILITY_NOT_SUPPORTED'
        elif not clean(o): reason = 'QUALITY_UNSUPPORTED'
        elif o['quality'].get('clockSkewMs') is not None and abs(o['quality']['clockSkewMs']) > 1000:
            reason = 'CLOCK_UNTRUSTED'
        elif not 0 <= at - last[i] <= 15000: reason = 'TARGET_REF_STALE'
        elif late or not 0 <= at - times[i] <= 10000: reason = 'EVIDENCE_STALE'
        elif not high: reason = 'SCORE_BELOW_AUTO'
        elif len(high) < flows or span < span_ms: reason = 'EVIDENCE_INSUFFICIENT'
        elif any(context(observations[j])['coverageMs'] < 5000 for j in high) or context(o)['peerFlowStarts'] < starts:
            reason = 'CONTEXT_CONDITION_UNMET'
        if reason is None:
            # 完整 T5/T6/T7 成立才推进；预算/TTL 拒绝仍保持攻击证据时钟。
            a['lastEvidence'] = at
            asset = o['assetId']
            active[asset] = {k: end for k, end in active[asset].items() if end > at}
            while recent[asset] and recent[asset][0] <= at - 60000: recent[asset].popleft()
            proposed = a['blocked'] + max(0, at + ttl * 1000 - max(at, a['lastEnd']))
            if target in plan.get('protectedBudgetTargets', []): subreason = 'PROTECTED_TARGET'
            elif a['lastEnd'] > at: subreason = 'TTL_DEDUP'
            elif proposed > 120000: subreason = 'CONTINUOUS_TARGET_BUDGET'
            elif len(active[asset]) >= 10: subreason = 'ASSET_ACTIVE_RULES'
            elif len(recent[asset]) >= 5: subreason = 'ASSET_ACTION_RATE'
            if subreason:
                reason = 'PROTECTION_OR_BUDGET_BLOCKED'
                if subreason == 'CONTINUOUS_TARGET_BUDGET' and a['escalated'] != a['generation']:
                    # 转人工是契约规定的终态输出，不是新动作；同一额度代只发一次。
                    a['escalated'] = a['generation']
                    escalations.append(dict(id='escalation-' + str(len(escalations)), targetId=target, atMs=at,
                                            generation=a['generation'], previousBlockedMs=a['blocked'],
                                            triggerIndex=i, evidenceIndices=high, outcome='escalate_manual'))
            else:
                end = at + ttl * 1000
                a.update(blocked=proposed, lastEnd=end)
                active[asset][target] = end; recent[asset].append(at)
                actions.append(dict(id='action-' + str(len(actions)), targetId=target, startMs=at, endMs=end,
                                    triggerIndex=i, evidenceIndices=high))
        reasons[subreason or reason or 'BLOCK_CANDIDATE'] += 1
        traces.append(dict(index=i, eventTimeMs=at, asOfMs=times[i], reasonCode=reason,
                           subreason=subreason, parentCount=len(high), evidenceSpanMs=span,
                           targetBlockedMs=a['blocked'], lastEvidenceAtMs=a['lastEvidence'] if math.isfinite(a['lastEvidence']) else None,
                           qualifiedEvidence=reason in (None, 'PROTECTION_OR_BUDGET_BLOCKED'),
                           escalated=a['escalated'] == a['generation']))
    return dict(actions=actions, observations=traces, budgetResets=resets, escalations=escalations,
                reasons=dict(reasons),
                simulatedChecks=sorted(SIMULATED), decisionVersion=VERSION, candidateOnly=True,
                modelFits=0, realOsActionTimingMeasured=False)
