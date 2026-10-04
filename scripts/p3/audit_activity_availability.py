#!/usr/bin/env python3
"""P3-C从冻结索引和已有正常任务核实独立性缺口，不采集、不重分区、不读取final_test。"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def lines(path):
    with Path(path).open() as f:
        for line in f:yield json.loads(line)


def audit(dataset, controlled, output, freeze):
    """用同一冻结分母计数。背景桶/快照/parent绝不提升成独立实验或未暴露活动。"""
    frozen=json.loads(freeze.read_text())
    for name,digest in frozen['datasetFiles'].items():
        if sha(dataset/name)!=digest:raise ValueError('冻结数据哈希不符: '+name)
    rows=list(lines(dataset/'index.jsonl'))
    if {r['split'] for r in rows} != {'train','validation_selection','validation_calibration'}:
        raise ValueError('数据角色变化，必须重新审查；不读取未知分区')
    run=json.loads((controlled/'run.json').read_text())
    if not run['passed'] or not run['listenerClosed']:raise ValueError('受控任务未完成或未清理')
    sessions=run['sessions']
    if len({s['activityId'] for s in sessions}) != len(sessions):raise ValueError('重复正常批次')
    attack=[]
    for activity in sorted({r['activityId'] for r in rows if r['label']==1}):
        group=[r for r in rows if r['activityId']==activity]
        roles=sorted({r['split'] for r in group})
        if len(roles)!=1:raise ValueError('攻击活动跨角色')
        attack.append(dict(activityId=activity,role=roles[0],sourceIds=sorted({r['sourceId'] for r in group}),
            observations=len(group),parents=len({r['parentConnectionId'] for r in group}),
            exposed=True,independentDevelopmentEligible=False,finalTestEligible=False))
    observations=[o for p in sorted(controlled.glob('session-*/observations.jsonl')) for o in lines(p)]
    profiles=Counter(o['profile'] for o in observations)
    kinds=Counter()
    benign=[]
    for session in sessions:
        for k in session['kinds']:kinds[k]+=1
        benign.append(dict(activityId=session['activityId'], role=session['role'], ordinal=session['ordinal'],
            connections=session['connections'], kinds=session['kinds'],
            exposed=True,independentDevelopmentEligible=False,finalTestEligible=False))
    report=dict(version='p3-activity-availability-v1',status='blocked',datasetFreezeSha256=sha(freeze),
        datasetFiles=frozen['datasetFiles'],controlledRunSha256=sha(controlled/'run.json'),
        attackActivities=attack,independentAttackActivitiesTotal=len(attack),
        controlledBenignActivities=benign,controlledBenignActivitiesTotal=len(benign),
        controlledTaskKindsBySession=dict(kinds),controlledObservationProfiles=dict(profiles),
        maxControlledConnectionElapsedMs=max(o['features']['elapsedMs'] for o in observations),
        controlledLongConnectionsOver30s=sum(o['features']['elapsedMs']>30000 for o in observations),
        indexedBenignGroups=len({r['activityId'] for r in rows if r['label']==0}),
        indexedBackgroundGroupsAreIndependentTasks=False,
        independentDevelopmentAttackGroups=0,independentDevelopmentBenignGroups=0,
        minimumPlannedIndependentDevelopmentGroupsPerClass=5,
        independentDevelopmentRolesAllocated=False,finalTestAllocated=False,finalTestRead=False,
        roleChangePerformed=False,newCapturePerformed=False,newRawDownloadBytes=0,
        prefixDatasetFrozen=False,trainingEntryPassed=False,
        reasons=['NO_UNEXPOSED_INDEPENDENT_DEVELOPMENT_GROUPS', 'ONSET_QUALIFICATION_NOT_PASSED',
                 'NEW_SOURCE_AVAILABILITY_NOT_ESTABLISHED', 'LONG_CONNECTION_BENIGN_TASK_MISSING'],
        nextBenignTask=dict(status='prepared_not_executed',host='win-dev',interface='Npcap loopback',
            server='127.0.0.1:80',client='127.0.0.2',maxSeconds=1800,maxConcurrency=4,
            requiredKinds=['slow_download','long_connection_30_to_60_seconds','normal_concurrency','legitimate_retry','range_resume'],
            groups=5,contextGapSeconds=155,requiresCurrentScopedAuthorization=True,
            prior30MinuteAuthorizationReusable=False,firewallChanges=False,
            acceptance=['body_integrity','no_capture_drops','distinct_tasks_and_parents','listener_released'],
            dependency='resolve attack onset and independent attack activity route before collecting more negatives'))
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as f:json.dump(report,f,indent=2,ensure_ascii=False);f.write('\n')
    print(json.dumps({k:report[k] for k in ['status','independentAttackActivitiesTotal','controlledBenignActivitiesTotal',
          'independentDevelopmentAttackGroups','independentDevelopmentBenignGroups','maxControlledConnectionElapsedMs',
          'controlledObservationProfiles','trainingEntryPassed']}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ['dataset','controlled','output','freeze']:p.add_argument('--'+n,type=Path,required=True)
    audit(**vars(p.parse_args()))
