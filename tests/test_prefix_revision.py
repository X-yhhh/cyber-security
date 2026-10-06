"""P3-A 真实边界回归：无训练、无网络、无 OS 动作的确定性夹具。"""
from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace

import numpy as np
import pytest

from cyber_training.host_guard.capture_health import HealthChain, content_hash
from cyber_training.host_guard.prefix_replay import simulate, SIMULATED
from cyber_training.host_guard.prefix_diagnostics import empirical_latency, evidence_delays
from cyber_training.host_guard.prefix_evaluation import (ACTION_HORIZON, activity_phases, replay,
    timeline_metrics, cluster_gain)


def at(ms): return datetime.fromtimestamp(ms/1000,timezone.utc).isoformat()


def plan():
    return dict(versions=dict(decision='host-guard-decision/2026-10-05.2',observation='host-guard/5.0.0-rc.2'),
        scope=dict(profile='flow-prefix-v1',addressFamily='ipv4',transport='tcp',direction='inbound',servicePort=80),
        offlineSimulation=sorted(SIMULATED))


def batch(times, targets=None, parents=None, roles=None):
    observations=[]; rows=[]
    for i,t in enumerate(times):
        target=targets[i] if targets else 'target'
        parent=parents[i] if parents else str(i)
        observations.append(dict(contractVersion='host-guard/5.0.0-rc.2',profile='flow-prefix-v1',
            assetId='asset',sensorId='sensor',bootId='boot',captureScopeId='capture',peerKey=target,keyEpoch=1,
            addressFamily='ipv4',transport='tcp',direction='inbound',servicePort=80,
            parentConnectionId=parent,observationId=str(i),asOf=at(t),lastPacketAt=at(t),emittedAt=at(t),
            contexts=[dict(windowSeconds=5,coverageMs=5000,peerFlowStarts=3)],
            quality=dict(captureGap=False,latePacket=False,truncated=False,offloadSuspected=False,capacityDrop=False,clockSkewMs=None)))
        rows.append(dict(budgetTargetId=target,split=roles[i] if roles else 'train',label=1))
    return SimpleNamespace(rows=rows,observations=observations)


def health(end=270000, gap=None, unknown=False):
    identity=dict(assetId='asset',sensorId='sensor',captureScopeId='observer-scope',observerSessionId='observer')
    binding=dict(identity,configSha256='a'*64,buildSha256='b'*64)
    records=[]; previous=None
    for seq,t in enumerate(range(0,end,5000)):
        counter=dict(packetsSeen=10,kernelDrops=None if unknown else 0,capacityDrops=0)
        row=dict(binding,healthVersion='host-guard-capture-health/1.0.0',healthWindowId=str(seq),
            sequence=seq,intervalStart=at(t),intervalEnd=at(t+5000),previousSha256=previous,
            counterStart=counter,counterEnd=counter,captureGap=t==gap,clockSkewMs=0)
        records.append(row);previous=content_hash(row)
    return dict(records=records,bindings=[binding],targets={'target':identity})


def episode(start=1000,end=61000):
    return dict(activityId='original',episodeId='ep',targetId='target',startMs=start,endMs=end,
                leakageGroupId='g',split='independent_development',scenario='slowloris',label=1)


def action(start,end): return dict(id='a',targetId='target',startMs=start,endMs=end,attackEvidence=True)


def test_bucket_does_not_restart_original_onset():
    result=timeline_metrics([episode()], [action(32000,61000)])
    assert result['attackOpportunities']==2
    assert result['coveredAttackOpportunities']==0
    assert result['lateResponseActivities']==1
    assert result['onsetToCandidateP95Ms']==31000


def test_prefit_latency_uses_first_event_and_observed_upper_percentile():
    rows=[dict(activityId='a'),dict(activityId='a'),dict(activityId='b')]
    traces=[dict(index=0,eventTimeMs=39000,qualifiedEvidence=True),
            dict(index=1,eventTimeMs=24000,qualifiedEvidence=True),
            dict(index=2,eventTimeMs=18000,qualifiedEvidence=False)]
    assert evidence_delays({'a':1000,'b':1000},traces,rows)=={'a':23000}
    p50,p95=empirical_latency([12000,14000,22000,39065.3])
    assert p50==18000 and p95==39065.3


def test_frozen_source_deadline_reserves_execution_time():
    evaluation=dict(timing=dict(offlineCandidateReserveMs=2000,defaultShortWindowStartToActionMs=10000),actionHorizon=ACTION_HORIZON,
        latencyRegistrations=[dict(behaviorScenario='slowloris',sourceDomainId='slowloris',startToActionLimitMs=17000)])
    assert timeline_metrics([episode()], [action(16000,61000)],evaluation=evaluation)['coveredAttackOpportunities']==2
    assert timeline_metrics([episode()], [action(16001,61000)],evaluation=evaluation)['coveredAttackOpportunities']==0


def test_disjoint_intervals_do_not_count_gap_as_attack_coverage():
    episodes=[episode(0,1000),dict(episode(20000,25000),episodeId='ep2')]
    result=timeline_metrics(episodes,[action(2000,19000)])
    assert result['blockedAttackMs']==0 and result['coveredAttackOpportunities']==0


def test_last_low_score_snapshot_replaces_historical_high_score():
    b=batch([0,1000,2000],parents=['p','p','q'])
    result=simulate(b,[1,0,1],dict(threshold=.5,min_flows=2),plan())
    assert result['actions']==[]


def test_evidence_span_and_context_needed_before_evidence_clock_advances():
    result=simulate(batch([0,1000]),[1,1],dict(threshold=.5,min_flows=3),plan())
    assert all(r['lastEvidenceAtMs'] is None for r in result['observations'])


def test_emission_delay_does_not_refresh_old_evidence():
    b=batch([0]);b.observations[0]['emittedAt']=at(11000)
    result=simulate(b,[1],dict(threshold=.5),plan())
    assert not result['actions'] and result['observations'][0]['reasonCode']=='EVIDENCE_STALE'


def test_quality_rejection_precedes_clock_and_stale_target():
    b=batch([0]);b.observations[0]['quality'].update(captureGap=True,clockSkewMs=2000)
    b.observations[0]['emittedAt']=at(16000)
    assert simulate(b,[1],dict(threshold=.5),plan())['observations'][0]['reasonCode']=='QUALITY_UNSUPPORTED'


def test_epoch_and_role_change_never_reset_target_budget():
    b=batch([0,30000,60000,90000,400000],roles=['train']*4+['independent_development'])
    b.observations[-1].update(bootId='newboot',captureScopeId='newcapture',keyEpoch=2)
    result=simulate(b,[1]*5,dict(threshold=.5),plan())
    assert len(result['actions'])==4
    assert result['observations'][-1]['subreason']=='CONTINUOUS_TARGET_BUDGET'


@pytest.mark.parametrize('broken',[None,'unknown','gap'])
def test_recovery_requires_continuous_authenticated_health(broken):
    b=batch([0,30000,60000,90000,120000,265000])
    h=health(unknown=broken=='unknown',gap=150000 if broken=='gap' else None)
    result=simulate(b,[1]*6,dict(threshold=.5),plan(),h)
    assert len(result['actions'])==(5 if broken is None else 4)
    assert len(result['budgetResets'])==(1 if broken is None else 0)
    assert result['observations'][4]['lastEvidenceAtMs']==120000


def test_health_identity_and_config_must_match_external_binding():
    h=health(10000);h['bindings'][0]['configSha256']='c'*64
    chain=HealthChain(h['bindings'])
    for record in h['records']:chain.accept(record)
    assert chain.proof(h['targets']['target'],0,10000) is None


def test_unknown_drop_counters_and_future_windows_are_not_proof():
    h=health(10000,unknown=True);chain=HealthChain(h['bindings'])
    for record in h['records']:chain.accept(record)
    assert chain.proof(h['targets']['target'],0,10000) is None
    h=health(10000);chain=HealthChain(h['bindings']);chain.accept(h['records'][0])
    assert chain.proof(h['targets']['target'],0,10000) is None


def test_duplicate_health_sequence_conflict_is_rejected():
    h=health(5000);chain=HealthChain(h['bindings']);chain.accept(h['records'][0])
    changed=deepcopy(h['records'][0]);changed['captureGap']=True
    with pytest.raises(ValueError,match='冲突'):chain.accept(changed)


def test_asset_rate_limit_is_shared_across_targets():
    b=batch(list(range(6)),targets=[str(i) for i in range(6)])
    result=simulate(b,[1]*6,dict(threshold=.5),plan())
    assert len(result['actions'])==5
    assert result['observations'][-1]['subreason']=='ASSET_ACTION_RATE'


def test_e5_weights_attack_groups_equally_not_large_bucket_counts():
    model=dict(groups={0:5,1:5},clusterCounts={str(i):dict(attack=1000 if i==0 else 1,covered=1000 if i==0 else 0) for i in range(5)})
    rules=deepcopy(model)
    for counts in rules['clusterCounts'].values():counts['covered']=0 if counts['attack']==1000 else 1
    report=cluster_gain(model,rules,replicates=100)
    assert report['estimate']==pytest.approx(-.6)
    assert not report['positiveGainEstablished']


def test_parameter_selection_replays_earlier_roles_before_reporting_calibration(tmp_path):
    pytest.importorskip('onnx')
    from cyber_training.host_guard.prefix_runner import select_parameters, policy_trial
    p=plan()
    p.update(decision=dict(thresholds=[.5],minDistinctFlows=[1],minEvidenceSpanMs=[0],
             minPeerFlowStarts=[0],ttlSeconds=[30]),
        evaluation=dict(timing=dict(offlineCandidateReserveMs=2000,defaultShortWindowStartToActionMs=10000),actionHorizon=ACTION_HORIZON),
        budget=dict(maximumPolicyTrials=4,policyTrialAllocation=dict(model_and_policy=1,rules=1,model=1,model_selection=1)))
    b=batch([0,30000,60000,90000,400000],roles=['train']*4+['validation_calibration'])
    timeline=[dict(episode(t,t+30000),activityId=str(i),episodeId=str(i),
                   split=b.rows[i]['split'],leakageGroupId=str(i)) for i,t in enumerate([0,30000,60000,90000,400000])]
    choice,trials=select_parameters(b,[1]*5,timeline,p,out=tmp_path)
    assert choice['metrics']['attackOpportunities']==1
    assert choice['metrics']['coveredAttackOpportunities']==0
    with pytest.raises(RuntimeError,match='预算'):policy_trial(tmp_path,p,'model_and_policy')
    policy_trial(tmp_path,p,'rules')


def long_attack(times, end):
    """单目标持续攻击：每 5 秒一个新 parent 的合格快照，标签时间线覆盖整段。"""
    b=batch(times,parents=[str(t) for t in times])
    for row in b.rows: row.update(activityId='long',leakageGroupId='g',scenario='slowloris')
    p=dict(plan(),evaluation=dict(timing=dict(offlineCandidateReserveMs=2000,defaultShortWindowStartToActionMs=10000),
           actionHorizon=ACTION_HORIZON,latencyRegistrations=[]))
    return b,p,[dict(episode(0,end),activityId='long')]


def test_budget_exhaustion_escalates_once_and_keeps_120_second_cap():
    b,p,_=long_attack(list(range(1000,600000,5000)),600000)
    result=simulate(b,[1]*len(b.rows),dict(threshold=.5),p)
    assert sum(a['endMs']-a['startMs'] for a in result['actions'])<=120000
    assert len(result['escalations'])==1 and result['escalations'][0]['outcome']=='escalate_manual'
    assert all(t['qualifiedEvidence'] for t in result['observations'])


def test_long_attack_splits_action_horizon_and_handoff_without_dropping_buckets():
    b,p,timeline=long_attack(list(range(1000,600000,5000)),600000)
    metrics=replay(b,[1]*len(b.rows),dict(threshold=.5),timeline,plan=p)['metrics']
    assert metrics['attackOpportunities']==20
    assert metrics['actionAttackOpportunities']==5 and metrics['handoffAttackOpportunities']==15
    assert metrics['blockRecallTimelyCandidate']==1.0
    assert metrics['handoffContinuity']==1.0
    assert metrics['fullDurationBlockCoverage']==pytest.approx(5/20)


def test_handoff_needs_escalation_and_fresh_alert_not_just_old_block():
    b,p,timeline=long_attack(list(range(1000,130000,5000)),600000)
    metrics=replay(b,[1]*len(b.rows),dict(threshold=.5),timeline,plan=p)['metrics']
    assert metrics['handoffAttackOpportunities']==15 and metrics['handoffCoveredOpportunities']==0


def test_low_scores_produce_no_handoff_or_action_credit():
    b,p,timeline=long_attack(list(range(1000,600000,5000)),600000)
    metrics=replay(b,[0]*len(b.rows),dict(threshold=.5),timeline,plan=p)['metrics']
    assert metrics['coveredAttackOpportunities']==0 and metrics['handoffCoveredOpportunities']==0


def two_activities(second_start):
    return [dict(episode(0,60000),activityId='first',episodeId='a'),
            dict(episode(second_start,second_start+60000),activityId='second',episodeId='b',leakageGroupId='g2')]


def test_second_activity_on_same_target_without_health_is_handoff_only():
    phases=activity_phases(two_activities(400000),dict(actionHorizon=ACTION_HORIZON,
        timing=dict(defaultShortWindowStartToActionMs=10000),latencyRegistrations=[]))
    assert phases[('first','target')]['eligible']
    assert not phases[('second','target')]['eligible']


@pytest.mark.parametrize('second_start,expected',[(240000,True),(239000,False)])
def test_authenticated_health_and_cooldown_restore_action_phase(second_start,expected):
    h=health(400000)
    phases=activity_phases(two_activities(second_start),dict(actionHorizon=ACTION_HORIZON,
        timing=dict(defaultShortWindowStartToActionMs=10000),latencyRegistrations=[]),h)
    assert phases[('second','target')]['eligible'] is expected


def test_unknown_health_does_not_restore_action_phase():
    phases=activity_phases(two_activities(300000),dict(actionHorizon=ACTION_HORIZON,
        timing=dict(defaultShortWindowStartToActionMs=10000),latencyRegistrations=[]),health(400000,unknown=True))
    assert not phases[('second','target')]['eligible']


def test_distinct_health_sessions_do_not_bridge_gap_or_reset_budget():
    first = health(150000)
    second = health(400000)
    identity = dict(second['targets']['target'], captureScopeId='scope-2', observerSessionId='session-2')
    binding = dict(second['bindings'][0], **identity)
    previous = None
    for row in second['records']:
        row.update(binding)
        row['intervalStart'] = at(400000 + int(datetime.fromisoformat(row['intervalStart']).timestamp() * 1000))
        row['intervalEnd'] = at(400000 + int(datetime.fromisoformat(row['intervalEnd']).timestamp() * 1000))
        row['previousSha256'] = previous
        previous = content_hash(row)
    sessions = [dict(identity=first['targets']['target'], activityIds=['first']),
                dict(identity=identity, activityIds=['second', 'third'])]
    combined = dict(records=first['records'] + second['records'],
                    bindings=first['bindings'] + [binding], targets=first['targets'],
                    targetSessions={'target': sessions})
    episodes = [dict(episode(0, 60000), activityId='first'),
                dict(episode(410000, 470000), activityId='second'),
                dict(episode(650000, 710000), activityId='third')]
    evaluation = dict(actionHorizon=ACTION_HORIZON,
                      timing=dict(defaultShortWindowStartToActionMs=10000), latencyRegistrations=[])
    phases = activity_phases(episodes, evaluation, combined)
    assert not phases[('second', 'target')]['eligible']
    assert phases[('third', 'target')]['eligible']
    replayed = simulate(batch([0, 30000, 60000, 90000, 410000]), [1] * 5,
                        dict(threshold=.5), plan(), combined)
    assert not replayed['budgetResets']
    assert len(replayed['actions']) == 4


def test_phase_registration_cannot_be_relaxed():
    for change in (dict(maxContinuousBlockMs=600000),dict(cooldownMs=0)):
        with pytest.raises(ValueError,match='自动处置期'):
            activity_phases([episode()],dict(actionHorizon=dict(ACTION_HORIZON,**change),
                timing=dict(defaultShortWindowStartToActionMs=10000),latencyRegistrations=[]))


def test_unregistered_scenario_is_rejected_by_evaluation():
    with pytest.raises(ValueError,match='行为映射'):
        timeline_metrics([dict(episode(),scenario='unknown_tool')],[],scenario='slowloris')


def test_observer_output_restores_budget_in_replay_and_phases(tmp_path):
    """采集端观察器的真实输出必须能被评价器验证并用于恢复额度。"""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'p3'))
    import capture_health_observer as obs
    clock = SimpleNamespace(t=0.0)
    observer = obs.open_session(tmp_path / 'observer', asset_id='asset', sensor_id='sensor', authorization_id='auth',
        authorized_until='2027-01-01T00:00:00+00:00', stats=lambda: dict(packetsSeen=1, kernelDrops=0, capacityDrops=0),
        config={}, build_sha256='b' * 64, monotonic=lambda: clock.t, wall=lambda: clock.t)
    for _ in range(100):
        clock.t += 4.9; observer.tick()
    records = [__import__('json').loads(line) for line in (tmp_path / 'observer' / obs.RECORDS).read_text().splitlines()]
    h = dict(records=records, bindings=[observer.binding], targets={'target': observer.identity})
    result = simulate(batch([0, 30000, 60000, 90000, 120000, 265000]), [1] * 6, dict(threshold=.5), plan(), h)
    assert result['budgetResets'][0]['atMs'] < 265000 and len(result['actions']) == 5
    phases = activity_phases([dict(episode(0, 60000), activityId='first', episodeId='a'),
                              dict(episode(250000, 310000), activityId='second', episodeId='b', leakageGroupId='g2')],
                             dict(actionHorizon=ACTION_HORIZON, timing=dict(defaultShortWindowStartToActionMs=10000),
                                  latencyRegistrations=[]), h)
    assert phases[('second', 'target')]['eligible']
