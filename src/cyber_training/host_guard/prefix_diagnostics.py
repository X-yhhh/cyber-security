"""P3-A 零拟合确定性诊断；历史数据只作完整性/可达性诊断，不升级为合格新语料。

阻断按根因分为结构/实现类与补采类；只有后者可交给采集门禁，前者必须先修规则或实现。
"""
import argparse
from collections import Counter, defaultdict
import json
import math
from pathlib import Path

import numpy as np

from .data import Batch, read, sha, vector, write
from .prefix_contract import BEHAVIORS
from .prefix_corpus import verify
from .prefix_evaluation import VERSION as EVALUATION_VERSION, activity_phases, replay, timeline_metrics
from .prefix_plan import load_health, subject_sha256


def evidence_delays(starts, traces, rows):
    """按事件时刻取每项活动首次完整合格证据，不依赖语料的行顺序。"""
    available = {}
    for trace in traces:
        activity_id = rows[trace['index']]['activityId']
        if activity_id in starts and trace['qualifiedEvidence']:
            delay = max(0, trace['eventTimeMs'] - starts[activity_id])
            available[activity_id] = min(available.get(activity_id, math.inf), delay)
    return available


def empirical_latency(delays):
    """小样本 P95 使用经验分位向上取值，避免插值产生未观测的更早截止。"""
    return (float(np.percentile(delays, 50)),
            float(np.percentile(delays, 95, method='higher')))


def diagnose(dataset, profile, plan, output, runtime_plan_sha256):
    """常数 1 分数只测结构，不使用真值生成分数，不产生候选模型或生产动作。"""
    if plan['versions']['evaluation']!=EVALUATION_VERSION:raise ValueError('评价版本与代码不符')
    verified=verify(dataset,plan['scenarios'])
    rows=[json.loads(line) for line in (dataset/'index.jsonl').open(encoding='utf-8')]
    observations=[json.loads(line) for line in (dataset/'observations.jsonl').open(encoding='utf-8')]
    activity={}
    for r in rows:
        r['behaviorScenario']=BEHAVIORS[r['scenario']]
        r['sourceDomainId']=r.get('sourceDomainId',r['sourceId'])
        identity=(r['sourceId'],r['sourceDomainId'],r['behaviorScenario'],r['split'])
        if activity.setdefault(r['activityId'],identity)!=identity: raise ValueError('活动来源/角色冲突')
        r['sampleWeight']=1.0
    timeline=[]
    for line in (dataset/'label-timeline.jsonl').open(encoding='utf-8'):
        ep=json.loads(line); source,domain,behavior,role=activity[ep['activityId']]
        timeline.append(dict(ep,sourceId=source,sourceDomainId=domain,behaviorScenario=behavior))
    tensors=[vector(o,profile) for o in observations]
    batch=Batch(rows,observations,*[np.asarray([t[i] for t in tensors]) for i in range(3)],'all_development')
    health=load_health(plan,dataset)
    parameters=plan['preFitDiagnostics']['parameters']
    scores=np.ones(len(rows),dtype=np.float32)
    preliminary=replay(batch,scores,parameters,timeline,plan=plan,health=health)
    starts={}
    for ep in timeline:
        if ep['label']==1: starts[ep['activityId']]=min(starts.get(ep['activityId'],math.inf),ep['startMs'])
    available=evidence_delays(starts,preliminary['observations'],rows)
    values=defaultdict(list)
    for activity_id,delay in available.items():
        _,domain,behavior,_=activity[activity_id]
        values[(behavior,domain)].append(delay)
    registrations=[]
    for (behavior,domain),delays in sorted(values.items()):
        p50,p95=empirical_latency(delays)
        registrations.append(dict(behaviorScenario=behavior,sourceDomainId=domain,
            evidenceAvailableP50Ms=float(p50),evidenceAvailableP95Ms=float(p95),
            activities=len(delays),evidenceToActionP95Ms=2000,
            startToActionLimitMs=max(10000,math.ceil((p95+2000)/1000)*1000),
            eligibility='alert_only',automaticApprovalRef=None))
    plan['evaluation']['latencyRegistrations']=registrations
    result=replay(batch,scores,parameters,timeline,plan=plan,health=health)
    sources=sorted({ep['sourceDomainId'] for ep in timeline if ep['label']==1})
    measure=lambda **f:timeline_metrics(timeline,result['actions'],evaluation=plan['evaluation'],
                                        decisions=result['decisions'],health=health,**f)
    by_source={source:measure(source=source) for source in sources}
    by_behavior={behavior:measure(scenario=behavior) for behavior in plan['scenarios']}
    phases=activity_phases(timeline,plan['evaluation'],health)
    # 结构上界：每个具备额度的活动只计处置期机会，假设证据、速率均理想；
    # 低于 80% 说明登记网格/时效本身不可达，不能由模型或补采同类轨迹修复。
    grid=max(math.floor(120/ttl)*(math.ceil(ttl/30)+1) for ttl in plan['decision']['ttlSeconds'])
    bounds=[]
    for source,metrics in by_source.items():
        per_activity=defaultdict(int)
        for opportunity in metrics['opportunities']:
            if opportunity['label']==1 and opportunity['phase']=='action':
                per_activity[(opportunity['activityId'],opportunity['targetId'])]+=1
        count=sum(per_activity.values());covered=sum(min(n,grid) for n in per_activity.values())
        bounds.append(dict(sourceDomainId=source,actionAttackOpportunities=count,
            handoffAttackOpportunities=metrics['handoffAttackOpportunities'],
            gridOptimisticActionCoverageUpperBound=covered/count if count else None,
            assumptions='action horizon only; ideal evidence/rate; phases fixed by label timeline, registered latency and authenticated health',
            isModelMetric=False))
    # 门禁只在 gateRoles 上判定；train 仅诊断。登记的支持来源必须在门禁角色有攻击机会，
    # 仅出现在 train 的来源须预先登记为诊断来源，不能充当任何支持格子的通过证据。
    structural=[];repairable=list(verified['blockers'])
    scope={r['sourceDomainId']:r['role'] for r in plan['sourceScope']}
    supported=sorted(s for s,r in scope.items() if r=='supported_research')
    gate={}
    for role in plan['evaluation']['gateRoles']:
        for kind,names,key in (('BEHAVIOR',plan['scenarios'],'scenario'),('SOURCE',supported,'source')):
            for name in names:
                metrics=measure(role=role,**{key:name});gate[f'{role}:{kind}:{name}']=metrics
                if not metrics['attackOpportunities']:continue
                if not metrics['actionAttackOpportunities']:
                    pending=not health['records'] and all(r['phaseBasis']=='budget_not_provably_restored'
                                                          for r in metrics['activityResponses'])
                    # 仅因缺认证健康而无法证明额度恢复时可由带观察器的新采集修复；其余为结构问题。
                    (repairable if pending else structural).append(
                        f"{'ACTION_PHASE_PENDING_CAPTURE_HEALTH' if pending else kind+'_WITHOUT_ACTION_ELIGIBLE_OPPORTUNITY'}:{role}:{name}")
                elif metrics['blockRecallTimelyCandidate']<.8:
                    structural.append(f'ACTION_HORIZON_{kind}_REACHABILITY_BELOW_80_PERCENT:{role}:{name}')
                if metrics['handoffAttackOpportunities'] and metrics['handoffContinuity']<.8:
                    structural.append(f'HANDOFF_{kind}_CONTINUITY_BELOW_80_PERCENT:{role}:{name}')
    for source in sources:
        if source not in scope:structural.append('SOURCE_SCOPE_NOT_REGISTERED:'+source)
        elif scope[source]=='supported_research' and not any(gate[f'{r}:SOURCE:{source}']['attackOpportunities']
                for r in plan['evaluation']['gateRoles']):
            structural.append('SUPPORTED_SOURCE_WITHOUT_GATE_ROLE_EVIDENCE:'+source)
    for bound in bounds:
        if bound['gridOptimisticActionCoverageUpperBound'] is not None and bound['gridOptimisticActionCoverageUpperBound']<.8:
            structural.append('REGISTERED_POLICY_GRID_STRUCTURALLY_UNREACHABLE:'+bound['sourceDomainId'])
    if not health['records']: repairable.append('AUTHENTICATED_CONTINUOUS_HEALTH_UNAVAILABLE')
    blockers=structural+repairable
    phase_summary=defaultdict(lambda:defaultdict(int))
    for (activity_id,_),phase in phases.items():
        phase_summary[activity[activity_id][1]][phase['basis']]+=1
    def compact(m):return {k:v for k,v in m.items() if k not in ('opportunities','activityResponses','clusterCounts')}
    report=dict(version='p3-a-prefix-diagnostics-v2',status='blocked' if blockers else 'passed',
        runtimePlanSha256=runtime_plan_sha256,
        runtimeSubjectSha256=subject_sha256(plan),
        decisionVersion=result['diagnostic']['decisionVersion'],evaluationVersion=EVALUATION_VERSION,
        datasetFreezeSha256=sha(dataset/'readiness.json'),modelFits=0,finalTestRead=False,
        diagnosticScores='constant1 for every observation; no label-dependent scoring',
        diagnosticOnly=True,trainingAllowed=False,oldInputUpgraded=False,
        latencyRegistrations=registrations,bySource={k:compact(v) for k,v in by_source.items()},
        byBehavior={k:compact(v) for k,v in by_behavior.items()},optimisticBounds=bounds,
        gateRoleMetrics={k:compact(v) for k,v in gate.items()},sourceScope=scope,
        activityPhases={k:dict(v) for k,v in phase_summary.items()},
        budgetResets=result['diagnostic']['budgetResets'],escalations=len(result['decisions']['escalations']),
        reasonCounts=result['diagnostic']['reasons'],
        blockers=sorted(set(blockers)),blockerClasses=dict(structuralOrImplementation=sorted(set(structural)),
            collectionRepairable=sorted(set(repairable))),simulatedChecks=result['diagnostic']['simulatedChecks'],
        candidateOnly=True,automaticExecutionAuthorized=False)
    output.mkdir(parents=True,exist_ok=False)
    write(output/'diagnostics.json',report)
    write(output/'latency-registration.json',registrations)
    with (output/'decision-trace.jsonl').open('x',encoding='utf-8') as stream:
        for trace in result['observations']:stream.write(json.dumps(trace)+'\n')
    write(output/'simulated-actions.json',result['actions'])
    write(output/'timeline-metrics.json',dict(bySource=by_source,byBehavior=by_behavior))
    write(output/'escalations.json',result['decisions']['escalations'])
    print(json.dumps(dict(status=report['status'],modelFits=0,bySource={s:{k:v for k,v in m.items() if k in
        ('actionAttackOpportunities','coveredAttackOpportunities','blockRecallTimelyCandidate',
         'handoffAttackOpportunities','handoffContinuity','fullDurationBlockCoverage')} for s,m in by_source.items()},
        optimisticBounds=bounds,blockers=report['blockers']),ensure_ascii=False))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('dataset','profile','plan','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    diagnose(args.dataset,read(args.profile),read(args.plan),args.output,sha(args.plan))


if __name__=='__main__':main()
