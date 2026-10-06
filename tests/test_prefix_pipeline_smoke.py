"""仅用人工夹具执行完整训练/冻结/独立评价/ONNX路径，不代表真实数据或模型成绩。"""
from pathlib import Path
import json
import uuid

import numpy as np

from cyber_training.host_guard.data import Batch, read, write
from cyber_training.host_guard.prefix_runner import run
from cyber_training.host_guard.prefix_corpus import sha


def test_synthetic_pipeline_creates_bound_prefix_candidate(tmp_path):
    contracts = Path('contracts/host-guard-v5-rc2')
    assert contracts.exists()
    profile = read(contracts / 'docs/contracts/feature-profile.json')
    roles = ['train','validation_selection','validation_calibration','independent_development']
    batches = {}; timeline = []
    from datetime import datetime, timezone
    for ordinal, role in enumerate(roles):
        rows=[]; obs=[]; values=np.ones((80,43),dtype=np.float32); masks=np.zeros_like(values)
        asset=str(uuid.uuid4())
        for i in range(80):
            label=i%2; t=1_600_000_000 + ordinal*10000 + i*200
            at=lambda x:datetime.fromtimestamp(x,timezone.utc).isoformat()
            parent=str(uuid.uuid4()); group=f'{role}-{label}-{i//2}'
            o=dict(assetId=asset,sensorId=str(uuid.uuid4()),bootId=str(uuid.uuid4()),captureScopeId=str(uuid.uuid4()),
                peerKey='fixture',keyEpoch=1,addressFamily='ipv4',transport='tcp',direction='inbound',servicePort=80,
                parentConnectionId=parent,observationId=str(uuid.uuid4()),asOf=at(t),lastPacketAt=at(t),emittedAt=at(t),
                contractVersion='host-guard/5.0.0-rc.2',profile='flow-prefix-v1',
                quality=dict(captureGap=False,latePacket=False,truncated=False,offloadSuspected=False,capacityDrop=False,clockSkewMs=None),
                contexts=[dict(windowSeconds=w,coverageMs=w*1000,peerFlowStarts=1) for w in (1,5,30)])
            row=dict(label=label,parentConnectionId=parent,activityId=group,leakageGroupId=group,scenario='controlled_slowloris',
                     sampleWeight=1.0,budgetTargetId=f'{role}-{i}',split=role,sourceId='synthetic_fixture')
            rows.append(row); obs.append(o); values[i,0]=10000; values[i,2]=100+label*2000
            timeline.append(dict(episodeId=parent,parentConnectionId=parent,activityId=group,leakageGroupId=group,
                scenario='controlled_slowloris',split=role,label=label,targetId=row['budgetTargetId'],startMs=t*1000,endMs=t*1000+20000,hasObservation=True))
        batches[role]=Batch(rows,obs,values,masks,np.asarray([['tcp','inbound','web']]*80),role)
    plan=read(Path('docs/host-guard-p3/experiment-plan.json'))
    plan['scope']['profile']='flow-prefix-v1';plan['scenarios']=['slowloris']
    plan['budget'].update(algorithms=['lightgbm'],featureSets=['base'],treeRounds=3,
        maximumFullFits=3,maxGpuSeconds=14400)
    plan['decision'].update(thresholds=[.5,1.0],minDistinctFlows=[1],minEvidenceSpanMs=[0],minPeerFlowStarts=[0],ttlSeconds=[15])
    plan['maximumPolicyTrials']=2
    path=tmp_path/'experiment-plan.json';write(path,plan)
    class FixtureDataset:
        def load(self,role,lock=None):
            if role=='validation_calibration': assert read(lock)['selectionFrozen'] is True
            if role=='independent_development': assert read(lock)['pipelineFrozen'] is True
            return batches[role]
        def timeline(self,roles):return [e for e in timeline if e['split'] in roles]
    data=FixtureDataset();data.contracts=contracts;data.profile=profile;data.root=tmp_path
    write(tmp_path/'partitions.json',{'fixture':True})
    out=tmp_path/'synthetic-prefix-smoke';out.mkdir()
    write(out/'experiment-plan.json',plan)
    run(data,plan,path,out)
    manifest=read(out/'candidate/model-manifest.json')
    assert manifest['profiles']==['flow-prefix-v1'] and manifest['candidateOnly'] is True
    assert manifest['finalEvaluationReportSha256'] is None
    assert read(out/'candidate/decision-policy.json')['mode']=='alert_only'
    report=read(out/'validation-report.json')
    assert report['parity']['status']=='passed' and report['fullModelFits']==3
    assert report['parity']['nativeParity'][0]['status']=='passed'
    assert report['exposures']['independent_development']=='frozen_pipeline_evaluation'
    assert read(out/'pipeline-lock.json')['files']['model.onnx']==sha(out/'candidate/model.onnx')
    assert not read(out/'stage-exit.json')['p6Authorized']
