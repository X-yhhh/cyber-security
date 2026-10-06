"""正式prefix时间线分母与独立活动评价；只生成候选动作，无OS或网络副作用。

评价版本 host-guard-evaluation/2026-10-05.2：固定分母拆为自动处置期与人工移交期，
不放宽 120 秒连续阻断上限，也不删除任何攻击机会。
"""
from bisect import bisect_left, bisect_right
from collections import defaultdict
import math

import numpy as np

from .capture_health import HealthChain, IDENTITY, stamp
from .data import Batch
from .prefix_contract import BEHAVIORS
from .prefix_replay import simulate

VERSION = 'host-guard-evaluation/2026-10-05.2'


def combine(batches):
    """按原事件时钟全域回放，稳定资产预算不得因角色/捕获域/epoch而重置。"""
    return Batch([dict(r, split=b.role) for b in batches for r in b.rows],
                 [o for b in batches for o in b.observations],
                 np.concatenate([b.values for b in batches]), np.concatenate([b.missing for b in batches]),
                 np.concatenate([b.categories for b in batches]), 'all_development')


def overlap(a, b, c, d):
    return a < d and c < b


def union_size(intervals):
    merged = []
    for start, end in sorted(intervals):
        if start >= end: continue
        if merged and start <= merged[-1][1]: merged[-1][1] = max(end, merged[-1][1])
        else: merged.append([start, end])
    return sum(end - start for start, end in merged)


ACTION_HORIZON = dict(maxContinuousBlockMs=120000, cooldownMs=120000, maxTtlMs=60000,
                      phaseRule='first_attack_activity_or_authenticated_cooldown')
DEFAULT_EVALUATION = dict(timing=dict(offlineCandidateReserveMs=2000, defaultShortWindowStartToActionMs=10000),
                          latencyRegistrations=[], actionHorizon=ACTION_HORIZON)


def behavior_of(entry):
    """评价分层只接受登记映射；未知原场景不得静默充当行为。"""
    original = entry.get('originalScenario', entry.get('scenario'))
    mapped = BEHAVIORS.get(original, original if original in ('slowloris', 'slowhttptest') else None)
    declared = entry.get('behaviorScenario', mapped)
    if declared is None or (mapped is not None and declared != mapped):
        raise ValueError('未登记或不一致的行为映射: ' + str(original))
    return declared


def source_of(entry):
    return entry.get('sourceDomainId', entry.get('sourceId', entry['scenario']))


def activity_of(entry):
    return entry.get('activityId', entry['episodeId'])


def start_to_action_limit(binding, evaluation):
    """返回登记的起点到动作时效；同一行为/来源只允许一条冻结登记。"""
    limit = evaluation['timing']['defaultShortWindowStartToActionMs']
    registrations = [r for r in evaluation.get('latencyRegistrations', [])
                     if r['behaviorScenario'] == behavior_of(binding) and r['sourceDomainId'] == source_of(binding)]
    if len(registrations) > 1: raise ValueError('来源/行为时效重复登记')
    return registrations[0]['startToActionLimitMs'] if registrations else limit


def health_segments(health):
    """按区间终点顺序验证认证健康链，返回各观察器身份的连续合格区间。"""
    segments = defaultdict(list)
    if not health or not health.get('records'): return segments
    chain = HealthChain(health['bindings'])
    for record in sorted(health['records'], key=lambda r: (stamp(r['intervalEnd']), r['sequence'])):
        state = chain.accept(record)
        if state['since'] is None: continue
        runs = segments[tuple(record[k] for k in IDENTITY)]
        if runs and runs[-1][0] == state['since']: runs[-1][1] = state['end']
        else: runs.append([state['since'], state['end']])
    return segments


def activity_phases(timeline, evaluation, health=None):
    """策略无关的自动处置期划分，只由标签时间线、登记时效和认证健康决定。

    同一稳定目标的首个攻击活动具备完整 120 秒额度；之后的活动仅当认证健康
    完整覆盖上一攻击活动结束到本活动起点，且间隔不短于冷却加最大 TTL 时才
    重新具备额度，否则整段属于人工移交期。处置期为 [起点, 起点+登记时效+120秒)。
    划分不读取分数或动作，因此三臂配对分母相同，策略无法通过提前耗尽额度挪动分母。
    """
    horizon = evaluation.get('actionHorizon')
    if not horizon or any(horizon.get(k) != v for k, v in ACTION_HORIZON.items()):
        raise ValueError('评价计划缺少或改写了自动处置期登记')
    spans = {}
    for e in timeline:
        if e['label'] != 1: continue
        span = spans.setdefault((activity_of(e), e['targetId']), [math.inf, -math.inf, e])
        span[0], span[1] = min(span[0], e['startMs']), max(span[1], e['endMs'])
    segments = health_segments(health)
    targets = (health or {}).get('targets', {})
    phases, previous = {}, {}
    for key, (onset, end, binding) in sorted(spans.items(), key=lambda item: (item[1][0], item[0])):
        target = key[1]; prior = previous.get(target)
        session = next((s for s in (health or {}).get('targetSessions', {}).get(target, [])
                        if key[0] in s['activityIds']), None)
        identity = session['identity'] if session else targets.get(target)
        runs = segments.get(tuple(identity[k] for k in IDENTITY), []) if identity else []
        same_session = (not (health or {}).get('targetSessions') or
                        (session is not None and prior is not None and prior[1] in session['activityIds']))
        if prior is None: eligible, basis = True, 'first_attack_activity_on_target'
        elif (onset - prior[0] >= horizon['cooldownMs'] + horizon['maxTtlMs']
              and same_session
              and any(s <= prior[0] and onset <= t for s, t in runs)):
            eligible, basis = True, 'authenticated_health_cooldown'
        else: eligible, basis = False, 'budget_not_provably_restored'
        limit = start_to_action_limit(binding, evaluation)
        phases[key] = dict(onsetMs=onset, endMs=end, eligible=eligible, basis=basis, startToActionLimitMs=limit,
                           actionHorizonEndMs=onset + limit + horizon['maxContinuousBlockMs'] if eligible else onset)
        previous[target] = (max(prior[0] if prior is not None else -math.inf, end), key[0])
    return phases


def handoff_state(decisions):
    """按目标整理转人工、额度恢复与合格告警时刻；均来自无标签决策器。"""
    decisions = decisions or {}
    escalations, resets, alerts = defaultdict(list), defaultdict(list), defaultdict(list)
    for e in decisions.get('escalations', []): escalations[e['targetId']].append(e['atMs'])
    for r in decisions.get('budgetResets', []): resets[r['targetId']].append(r['atMs'])
    for target, at in decisions.get('alerts', []): alerts[target].append(at)
    for table in (escalations, resets, alerts):
        for values in table.values(): values.sort()

    def escalated(target, at):
        index = bisect_right(escalations[target], at)
        if not index: return False
        last = escalations[target][index - 1]
        return not any(last < r <= at for r in resets[target])

    def alerted(target, start, stop):
        values = alerts[target]; index = bisect_left(values, start)
        return index < len(values) and values[index] < stop
    return escalated, alerted


def timeline_metrics(timeline, actions, role=None, scenario=None, *, evaluation=None, source=None,
                     decisions=None, health=None):
    """按原始活动起点切桶，分自动处置期和人工移交期计算；空隙不算覆盖。

    处置期机会要求所属活动首次响应及时且被有效区间覆盖；移交期机会要求
    有效阻断仍在，或该目标已转人工且桶内有合格告警。无观察、迟现、无响应及
    预算拒绝都留在固定分母；整段阻断覆盖仅作描述。来源/行为只用于事后
    查找登记时效和统计，绝不传给在线动作生成器。正常/攻击区间分别计数。
    """
    evaluation = evaluation or DEFAULT_EVALUATION
    selected = [e for e in timeline if (role is None or e['split'] == role)
                and (scenario is None or e['label'] == 0 or behavior_of(e) == scenario)
                and (source is None or source_of(e) == source)]
    phases = activity_phases(timeline, evaluation, health)
    escalated, alerted = handoff_state(decisions)
    by_activity = defaultdict(list)
    origins = {}
    for e in timeline:
        key = (activity_of(e), e['targetId'])
        origins[key] = min(origins.get(key, math.inf), e['startMs'])
    for e in selected:
        by_activity[(activity_of(e), e['targetId'], e['label'])].append(e)
    counts = defaultdict(int)
    delays = []; detail = []; activity_results = []
    grouped = defaultdict(lambda: dict(attack=0, covered=0, benign=0, false=0, handoffAttack=0, handoffCovered=0))
    for (activity, target, label), entries in by_activity.items():
        onset = origins[(activity, target)]
        binding = entries[0]; group = binding['leakageGroupId']
        if any(e['leakageGroupId'] != group for e in entries): raise ValueError('同活动被拆组')
        intervals = [(e['startMs'], e['endMs']) for e in entries]
        end = max(e['endMs'] for e in entries)
        relevant = [a for a in actions if a['targetId'] == target and
                    any(overlap(s, t, a['startMs'], a['endMs']) for s, t in intervals)]
        first = min((max(onset, a['startMs']) for a in relevant if a['attackEvidence']), default=None)
        deadline = start_to_action_limit(binding, evaluation) - evaluation['timing']['offlineCandidateReserveMs']
        if deadline < 0: raise ValueError('动作时效不足执行预留')
        timely = first is not None and first - onset <= deadline
        phase = phases.get((activity, target)) if label == 1 else None
        if label == 1:
            if first is not None: delays.append(first - onset)
            activity_results.append(dict(activityId=activity, targetId=target, originalStartMs=onset,
                firstCandidateMs=first, onsetToCandidateMs=None if first is None else first-onset,
                timely=timely, candidateDeadlineMs=deadline, noResponse=first is None,
                actionEligible=phase['eligible'], phaseBasis=phase['basis'],
                actionHorizonEndMs=phase['actionHorizonEndMs']))
        for bucket in range(math.ceil((end - onset) / 30000)):
            start, stop = onset + bucket * 30000, min(end, onset + (bucket + 1) * 30000)
            pieces = [(max(start, s), min(stop, t)) for s, t in intervals if overlap(start, stop, s, t)]
            if not pieces: continue
            blocked = union_size([(max(s, a['startMs']), min(t, a['endMs']))
                for s, t in pieces for a in relevant if overlap(s, t, a['startMs'], a['endMs'])])
            observed = any(e.get('hasObservation', True) and overlap(start, stop, e['startMs'], e['endMs']) for e in entries)
            handed = escalated(target, stop) and alerted(target, start, stop)
            if label == 1:
                action_phase = start < phase['actionHorizonEndMs']
                hit = blocked > 0 and timely if action_phase else blocked > 0 or handed
                counts['attack'] += 1; counts['noObservation'] += int(not observed)
                counts['fullCovered'] += int(blocked > 0 and timely)
                counts['action' if action_phase else 'handoff'] += 1
                counts['covered' if action_phase else 'handoffCovered'] += int(hit)
                grouped[group]['attack' if action_phase else 'handoffAttack'] += 1
                grouped[group]['covered' if action_phase else 'handoffCovered'] += int(hit)
                phase_name = 'action' if action_phase else 'handoff'
            else:
                hit = blocked > 0; phase_name = None
                counts['benign'] += 1; counts['false'] += int(hit); counts['benignAlerted'] += int(handed)
                grouped[group]['benign'] += 1; grouped[group]['false'] += int(hit)
            detail.append(dict(groupId=group, activityId=activity, targetId=target, bucket=bucket,
                label=label, phase=phase_name, covered=hit, startMs=start, endMs=stop, blockedMs=blocked,
                eligibleMs=union_size(pieces), noObservation=not observed, handoffAlert=handed, originalStartMs=onset))
    scoped_actions = [a for a in actions if any(e['targetId'] == a['targetId'] and
        overlap(e['startMs'], e['endMs'], a['startMs'], a['endMs']) for e in selected)]
    incorrect = []; collateral = set()
    for action in scoped_actions:
        negatives = [e for e in timeline if e['label'] == 0 and e['targetId'] == action['targetId'] and overlap(e['startMs'], e['endMs'], action['startMs'], action['endMs'])]
        positives = [e for e in timeline if e['label'] == 1 and e['targetId'] == action['targetId'] and e['startMs'] <= action['startMs'] < e['endMs']]
        collateral.update(e.get('parentConnectionId', e['episodeId']) for e in negatives)
        if negatives or not positives or not action['attackEvidence']: incorrect.append(action['id'])
    groups = {label: len({e['leakageGroupId'] for e in selected if e['label'] == label}) for label in (0, 1)}
    ratio = lambda a, b: a / b if b else None
    return dict(unit='qualified_label_timeline_target_30s_bucket', evaluationPhases='action_horizon_and_manual_handoff',
        attackOpportunities=counts['attack'], actionAttackOpportunities=counts['action'],
        benignOpportunities=counts['benign'], coveredAttackOpportunities=counts['covered'],
        falseBenignOpportunities=counts['false'],
        blockRecallTimelyCandidate=ratio(counts['covered'], counts['action']),
        handoffAttackOpportunities=counts['handoff'], handoffCoveredOpportunities=counts['handoffCovered'],
        handoffContinuity=ratio(counts['handoffCovered'], counts['handoff']),
        benignHandoffAlertOpportunities=counts['benignAlerted'],
        fullDurationCoveredOpportunities=counts['fullCovered'],
        fullDurationBlockCoverage=ratio(counts['fullCovered'], counts['attack']),
        candidateActions=len(scoped_actions),
        incorrectCandidateActions=len(incorrect), blockPrecisionCandidate=(len(scoped_actions)-len(incorrect))/len(scoped_actions) if scoped_actions else None,
        affectedBenignParents=len(collateral), attackBucketsWithoutObservation=counts['noObservation'],
        onsetToCandidateP95Ms=float(np.percentile(delays,95)) if delays else None,
        attackActivities=len(activity_results), noResponseActivities=sum(r['noResponse'] for r in activity_results),
        lateResponseActivities=sum(not r['timely'] and not r['noResponse'] for r in activity_results),
        timelyActivityRate=sum(r['timely'] for r in activity_results)/len(activity_results) if activity_results else None,
        actionEligibleActivities=sum(r['actionEligible'] for r in activity_results),
        blockedAttackMs=sum(r['blockedMs'] for r in detail if r['label']==1),
        eligibleAttackMs=sum(r['eligibleMs'] for r in detail if r['label']==1),
        latencyCondition='original activity onset; latency percentile accompanies all missing and late activities',
        fullDurationNote='descriptive only; not full-duration protection and not a gate',
        realOsActionTimingMeasured=False,candidateOnly=True,groups=groups,clusterCounts=dict(grouped),
        opportunities=detail,activityResponses=activity_results)


def replay(batch, scores, parameters, timeline, *, plan, health=None):
    """先按无标签决策器回放，再使用旁路真值评价；全角色预算不重置。"""
    details = simulate(batch, scores, parameters, plan, health)
    actions = [dict(a, attackEvidence=all(batch.rows[i]['label']==1 for i in a['evidenceIndices']))
               for a in details['actions']]
    decisions = dict(escalations=details['escalations'], budgetResets=details['budgetResets'],
                     alerts=[(batch.rows[t['index']]['budgetTargetId'], t['eventTimeMs'])
                             for t in details['observations'] if t['qualifiedEvidence']])
    return dict(diagnostic={k: v for k,v in details.items() if k not in ('actions','observations')},
                metrics=timeline_metrics(timeline,actions,evaluation=plan['evaluation'],decisions=decisions,health=health),
                actions=actions,observations=details['observations'],decisions=decisions)


def objective(metrics):
    feasible = metrics['falseBenignOpportunities'] == 0 and metrics['incorrectCandidateActions'] == 0
    return (int(feasible), metrics['blockRecallTimelyCandidate'] or 0 if feasible else -metrics['falseBenignOpportunities'],
            metrics['handoffContinuity'] or 0, -metrics['candidateActions'])


def cluster_gain(model, rule, replicates=2000, seed=20261004):
    """同一独立组配对重采样；组数不足和区间跨零均不宣称模型收益确证。"""
    if model['groups'][1] < 5 or model['groups'][0] < 5:
        return dict(estimate=None, interval=None, reason='fewer than five independent groups per class', positiveGainEstablished=False)
    if model['clusterCounts'].keys() != rule['clusterCounts'].keys(): raise ValueError('配对组分母不同')
    groups = sorted(g for g,c in model['clusterCounts'].items() if c['attack'] > 0)
    if any(model['clusterCounts'][g]['attack'] != rule['clusterCounts'][g]['attack'] for g in groups):
        raise ValueError('配对攻击机会分母不同')
    differences = np.asarray([(model['clusterCounts'][g]['covered']-rule['clusterCounts'][g]['covered']) /
                              model['clusterCounts'][g]['attack'] for g in groups])
    generator = np.random.default_rng(seed)
    gains = differences[generator.integers(0,len(groups),size=(replicates,len(groups)))].mean(axis=1)
    interval = np.quantile(gains,[.025,.975]).tolist()
    return dict(estimate=float(differences.mean()),interval=interval,replicates=replicates,seed=seed,
                unit='paired_attack_leakage_group_equal_weight_bootstrap',positiveGainEstablished=interval[0]>0,
                limitation='five groups is a minimum only; not proof of 99 percent precision')
