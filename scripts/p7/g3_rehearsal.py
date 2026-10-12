#!/usr/bin/env python3
"""从真实隔离回放文件核算 K7-R。缺证据即失败；不授予正式 G3 资格。"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from executor.common import canonical
from scripts.p7.lab_report import timestamp


class GateError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise GateError(code)


def load(path):
    return json.loads(Path(path).read_bytes())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_name(proof):
    return 'rule:'+proof['ruleId'] if proof['source']=='rule' else proof['source']


def rejection_stages(decisions, hypothetical):
    """按契约统计首个拒绝阶段；假想路径跳过的部署门不冒充已实测。"""
    stages = {'CAPABILITY_NOT_SUPPORTED': 'T1', 'QUALITY_UNSUPPORTED': 'T2',
              'CLOCK_UNTRUSTED': 'T3', 'TARGET_REF_STALE': 'T4',
              'EVIDENCE_STALE': 'T5', 'SCORE_BELOW_AUTO': 'T5',
              'EVIDENCE_INSUFFICIENT': 'T6', 'CONTEXT_CONDITION_UNMET': 'T7',
              'AUTHORIZATION_INACTIVE': 'T8', 'PROTECTION_OR_BUDGET_BLOCKED': 'T9',
              'FAMILY_AUTO_DISABLED': 'source_auto_disabled', 'MODEL_AUTO_DISABLED': 'source_auto_disabled'}
    counts = dict.fromkeys([f'T{i}' for i in range(1, 10)], 0)
    for decision in decisions:
        proof = decision['evidence']['hypothetical'] if hypothetical else decision['evidence']
        reason = proof.get('reasonCode')
        if reason is not None:
            stage = stages.get(reason, 'other')
            counts[stage] = counts.get(stage, 0) + 1
    return counts


def gate(state, runtime, rows, sensor, decisions, report_input, substitute, before, after):
    """比较原始时刻与固定偏移，逐场景/来源评估；绝不补造时延或清理事实。"""
    require(state.get('mode')=='rehearse' and state.get('evidenceKind')=='synthetic', 'G3_REHEARSAL_MODE_INVALID')
    manifest=state['manifest']
    offsets=manifest['time']['scenarioOffsets']
    require(manifest['contractVersion']=='host-guard-lab/1.1' and set(offsets)=={r['scenarioId'] for r in rows},'G3_REHEARSAL_CLOCK_INVALID')
    require(len(rows)==18 and Counter(r['family'] for r in rows)==dict(port_scan=3,brute_force=3,dos_flood=3,dos_slow=3,normal=6),'G3_REHEARSAL_SCENARIOS_INCOMPLETE')
    require(runtime.get('realBackend') is True and runtime.get('realSensor') is True and runtime.get('speed')==1
            and runtime.get('realPF') is False and runtime.get('packetInjection') is False,'G3_REHEARSAL_RUNTIME_INVALID')
    replays={r['scenarioId']:r for r in sensor['replays']}
    complete=state.get('captureComplete') is True and state.get('reportImported') is True and len(replays)==18
    intervals={}
    timing_ok=True
    for row in rows:
        sid=row['scenarioId']; replay=replays.get(sid)
        if replay is None:
            timing_ok=False;continue
        start=timestamp(row['sourceStart'])+timedelta(microseconds=offsets[sid])
        end=timestamp(row['sourceEnd'])+timedelta(microseconds=offsets[sid])
        capture=timestamp(row['captureStart'])+timedelta(microseconds=offsets[sid])
        intervals[sid]=(start,end,capture)
        timing_ok &= (replay.get('speed')==1 and replay.get('timeOffsetMicros')==offsets[sid]
                      and replay.get('pcapSha256')==row['pcapSha256'] and replay.get('packets',0)>0
                      and timestamp(replay['wallStartedAt'])<=start and timestamp(replay['wallFinishedAt'])>=end)
    normals=[r for r in rows if r['family']=='normal']
    attacks=[r for r in rows if r['family']!='normal']
    normal_ms=sum(int((timestamp(r['sourceEnd'])-timestamp(r['sourceStart'])).total_seconds()*1000) for r in normals if r['scenarioId'] in replays)
    concurrent=all(all(intervals[n['scenarioId']][0]<=intervals[a['scenarioId']][0]
                       and intervals[n['scenarioId']][1]>=intervals[a['scenarioId']][1]
                       for n in normals if n['scenarioId'] in intervals)
                   for a in attacks if a['scenarioId'] in intervals) and len(intervals)==18
    by_scenario={r['scenarioId']:[] for r in rows}
    for d in decisions:
        require(d['scenarioId'] in by_scenario and isinstance(d['evidence'].get('hypothetical'),dict),'G3_REHEARSAL_DECISION_INVALID')
        require(d['evidence']['hypothetical'].get('actionable') is False,'G3_REHEARSAL_ACTIONABLE_PROJECTION')
        by_scenario[d['scenarioId']].append(d)
    traces=[]
    classes=[]
    for family in ('port_scan','brute_force','dos_slow'):
        source_rows=[]
        for row in [r for r in rows if r['family']==family]:
            sid=row['scenarioId']; limit=10000 if family=='port_scan' else 20000
            for source in (('model','rule:scan-ports') if family=='port_scan' else ('model',)):
                ds=[d for d in by_scenario[sid] if d['evidence']['family']==family and source_name(d['evidence'])==source]
                alerts=[d for d in ds if d['evidence']['hypothetical']['decision'] in ('alert','block_candidate')]
                candidates=[d for d in ds if d['evidence']['hypothetical']['decision']=='block_candidate']
                def first(items):
                    return min(items,key=lambda d:timestamp(d['decidedAt'])) if items else None
                alert=first(alerts);candidate=first(candidates)
                start=intervals.get(sid,(None,))[0]
                def latency(d):
                    return round((timestamp(d['decidedAt'])-start).total_seconds()*1000,3) if d and start else None
                cand_ms=latency(candidate)
                distinct=candidate['evidence']['hypothetical']['distinctParents'] if candidate else None
                minimum=5 if family=='dos_slow' else None
                passed=cand_ms is not None and 0<=cand_ms<=limit and (minimum is None or distinct>=minimum)
                item=dict(scenarioId=sid,family=family,source=source,firstAlertLatencyMs=latency(alert),
                          firstCandidateLatencyMs=cand_ms,firstAlertDecisionId=alert['id'] if alert else None,
                          firstCandidateDecisionId=candidate['id'] if candidate else None,distinctParents=distinct,
                          minDistinctFlows=minimum,thresholdMs=limit,passed=passed,
                          rejectionReasons=dict(Counter(d['evidence']['hypothetical'].get('reasonCode') or 'candidate' for d in ds)),
                          deploymentRejectionReasons=dict(Counter(d['evidence'].get('reasonCode') or 'none' for d in ds)),
                          firstRejectionStages=rejection_stages(ds,True),
                          deploymentFirstRejectionStages=rejection_stages(ds,False))
                traces.append(item);source_rows.append(item)
        classes.append(dict(family=family,passed=all(r['passed'] for r in source_rows),sources=source_rows))
    normal_decisions=[d for r in normals for d in by_scenario[r['scenarioId']]]
    normal_candidates=[d for d in normal_decisions if d['evidence']['hypothetical']['decision']=='block_candidate']
    normal_alerts=[d for d in normal_decisions if d['evidence']['hypothetical']['decision'] in ('alert','block_candidate')]
    poll=[r for r in substitute if r.get('kind')=='observation']
    poll_times=sorted(timestamp(r['at']) for r in poll)
    span_ok=False
    if poll_times and intervals:
        earliest=min(v[2] for v in intervals.values());latest=max(v[1] for v in intervals.values())
        # stopped 本身也是一次独立的最终 inventory；最后一次轮询到退出不得超过短租约窗口。
        terminal=timestamp(substitute[-1]['at']) if substitute[-1].get('kind')=='stopped' else poll_times[-1]
        observed_times=poll_times+[terminal]
        span_ok=poll_times[0]<=earliest and terminal>=latest and all(0<=(b-a).total_seconds()<=15 for a,b in zip(observed_times,observed_times[1:]))
    clean=span_ok and len(poll)>=2 and substitute[-1].get('kind')=='stopped' and all(r.get('installedRules')==[] and r.get('commandIds',[])==[] for r in substitute)
    clean &= not any(r.get('kind')=='failure' for r in substitute)
    unlinked_commands=report_input.get('unlinkedCommandIds');unlinked_decisions=report_input.get('unlinkedDecisionIds')
    link_ok=unlinked_commands==[] and unlinked_decisions==[]
    parity=before==after
    normal_ok=normal_ms>=1800000 and not normal_candidates and clean and concurrent
    passed=complete and timing_ok and concurrent and all(c['passed'] for c in classes) and normal_ok and link_ok and clean and parity
    return dict(schema='g3-rehearsal-gate/1',evidenceKind='synthetic',formalG3Eligible=False,passed=passed,
                countingMethod='real backend hypothetical_evidence_readiness; deployment gates closed',classes=classes,
                inputComplete=complete,timingVerified=timing_ok,normalAlwaysConcurrent=concurrent,
                normal=dict(scenarioCount=6,cumulativeMs=normal_ms,alertCount=len(normal_alerts),candidateCount=len(normal_candidates),
                            alertsPerHour=len(normal_alerts)*3600000/normal_ms if normal_ms else None,
                            candidatesPerHour=len(normal_candidates)*3600000/normal_ms if normal_ms else None,
                            substituteInstallCount=0 if clean else None,substituteInstallsPerHour=0 if clean and normal_ms else None,passed=normal_ok),
                linkage=dict(unlinkedCommandIds=unlinked_commands,unlinkedDecisionIds=unlinked_decisions,passed=link_ok),
                cleanup=dict(observationCount=len(poll),coversReplay=span_ok,verifiedEmpty=clean,passed=clean),
                businessDatabaseUnchanged=parity,scenarioTrace=traces,
                limitations=['synthetic rehearsal only; no real PF',
                             'T1-T9 counts record first rejection; hypothetical live health, target, authorization and budget gates are not exercised',
                             'dos_flood remains alert-only','L3 slow 0/29 unchanged'])


def from_directory(directory):
    names=['state.json','runtime.json','frozen-scenarios.json','sensor-report.json','decisions.json','report-input.json',
           'business-before.json','business-after.json']
    values=[load(directory/n) for n in names]
    substitute=[json.loads(line) for line in (directory/'substitute.jsonl').read_text().splitlines()]
    state,runtime,rows,sensor,decisions,report_input,before,after=values
    result=gate(state,runtime,rows,sensor,decisions,report_input,substitute,before,after)
    result.update(sessionId=state['sessionId'],runDirectory=str(directory.resolve()),
                  sourceSha256={n:sha(directory/n) for n in names+['substitute.jsonl']})
    return result


def evaluate_directory(directory):
    """失败尝试也落诊断门禁；缺失文件只表示未完成，不能推断模型失败。"""
    directory=Path(directory)
    try:
        return from_directory(directory)
    except (OSError,ValueError,KeyError,TypeError) as error:
        paths=['state.json','runtime.json','frozen-scenarios.json','sensor-report.json',
               'decisions.json','report-input.json','substitute.jsonl',
               'business-before.json','business-after.json']
        failure=load(directory/'failure.json') if (directory/'failure.json').is_file() else None
        before=load(directory/'business-before.json') if (directory/'business-before.json').is_file() else None
        after=load(directory/'business-after.json') if (directory/'business-after.json').is_file() else None
        return dict(schema='g3-rehearsal-gate/1',evidenceKind='synthetic',formalG3Eligible=False,
                    passed=False,evaluationStatus='incomplete',runDirectory=str(directory.resolve()),
                    reason=str(error) if isinstance(error,GateError) else 'G3_REHEARSAL_EVIDENCE_INCOMPLETE',
                    failure=failure,missingEvidence=[n for n in paths if not (directory/n).is_file()],
                    classes=[dict(family=f,status='not_evaluated',passed=False,sources=[])
                             for f in ('port_scan','brute_force','dos_slow')],
                    businessDatabaseUnchanged=before==after if before is not None and after is not None else None,
                    sourceSha256={n:sha(directory/n) for n in paths+['failure.json'] if (directory/n).is_file()})


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-dir',type=Path,required=True)
    parser.add_argument('--output',type=Path);args=parser.parse_args()
    try:
        result=evaluate_directory(args.run_dir)
        with (args.output or args.run_dir/'gate.json').open('xb') as stream:stream.write(canonical(result)+b'\n')
        print(json.dumps(dict(passed=result['passed'],formalG3Eligible=False)))
    except (OSError,ValueError,KeyError,TypeError) as error:
        print(str(error) if isinstance(error,GateError) else 'G3_REHEARSAL_EVIDENCE_INVALID',file=sys.stderr)
        return 2
    return 0


if __name__=='__main__':
    raise SystemExit(main())
