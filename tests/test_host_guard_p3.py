"""数据角色、未来信息、重复parent、目标隔离及过期证据的独立回归夹具。"""
from copy import deepcopy
from datetime import datetime, timezone

import numpy as np
import pytest

from cyber_training.host_guard.data import Batch, Dataset, Preprocessor, contract_validator, vector, write
from cyber_training.host_guard.evaluation import Replay, classification, target_key
from cyber_training.host_guard.models import calibrate, calibrated, fit


def timestamp(seconds):
    return datetime.fromtimestamp(1_600_000_000 + seconds, timezone.utc).isoformat().replace("+00:00", "Z")


def batch(events, role="train"):
    """events: (time, parent, label, metadata overrides)，所有地址/身份均为合成。"""
    rows, obs = [], []
    for t, parent, label, updates in events:
        o = {"assetId": "asset", "sensorId": "sensor", "bootId": "boot", "captureScopeId": "capture",
             "peerKey": "peer", "keyEpoch": "epoch", "addressFamily": "ipv4", "transport": "tcp",
             "direction": "inbound", "servicePort": 80, "parentConnectionId": parent,
             "asOf": timestamp(t), "lastPacketAt": timestamp(t),
             "contexts": [{"windowSeconds": w, "coverageMs": w * 1000, "peerFlowStarts": 5} for w in [1, 5, 30]]}
        o.update(updates); obs.append(o)
        rows.append({"label": label, "parentConnectionId": parent, "activityId": str(label), "sampleWeight": 1.0, "budgetTargetId": str((o["assetId"],o["peerKey"],o["servicePort"]))})
    return Batch(rows, obs, np.ones((len(rows), 43), dtype=np.float32), np.zeros((len(rows), 43), dtype=np.float32),
                 np.asarray([["tcp", "inbound", "web"]] * len(rows)), role)


def test_preprocessing_rejects_selection_and_calibration():
    for role in ["validation_selection", "validation_calibration"]:
        with pytest.raises(ValueError, match="train"):
            Preprocessor.fit(batch([(1, "a", 0, {})], role))


def test_model_fit_rejects_validation_before_using_runtime():
    with pytest.raises(ValueError, match="train"):
        fit("mlp", batch([(1, "a", 0, {})], "validation_calibration"), None, {}, 42)


def test_calibration_rejects_training():
    with pytest.raises(ValueError, match="校准"):
        calibrate([0.2], batch([(1, "a", 0, {})]))


def test_dataset_final_role_fails_before_any_file_access():
    data = Dataset.__new__(Dataset)
    with pytest.raises(ValueError, match="禁止访问"):
        data.load("final_test")


def test_calibration_requires_valid_selection_lock(tmp_path):
    data = Dataset.__new__(Dataset)
    with pytest.raises(ValueError, match="冻结"):
        data.load("validation_calibration")
    write(tmp_path / "lock.json", {"selectionFrozen": True, "calibrationUsedForSelection": True})
    with pytest.raises(ValueError, match="选型锁"):
        data.load("validation_calibration", tmp_path / "lock.json")


def test_exclusive_evidence_creation(tmp_path):
    path = tmp_path / "evidence.json"; write(path, {"count": 1})
    with pytest.raises(FileExistsError):
        write(path, {"count": 2})


def test_missing_is_imputed_from_train_not_zero():
    a = batch([(1, "a", 0, {}), (2, "b", 1, {})]); a.values[:, 0] = [9, 99]
    pre = Preprocessor.fit(a)
    b = batch([(3, "c", 0, {})], "validation_selection"); b.values[0, 0] = 0; b.missing[0, 0] = 1
    transformed = pre.transform(b)
    assert transformed[0, 0] == 0
    assert transformed[0, 43] == 1
    b.missing[0, 0] = 0
    assert pre.transform(b)[0, 0] < 0


def test_unknown_category_has_reserved_zero():
    a = batch([(1, "a", 0, {}), (2, "b", 1, {})]); pre = Preprocessor.fit(a)
    a.categories = np.asarray([["udp", "outbound", "other"]] * 2)
    assert np.all(pre.codes(a) == 0)


def test_metadata_never_changes_model_tensor():
    a = batch([(1, "a", 0, {}), (2, "b", 1, {})]); pre = Preprocessor.fit(a)
    b = deepcopy(a); b.rows[0]["label"] = 1; b.observations[0]["peerKey"] = "different"
    b.observations[0]["servicePort"] = 9999; b.observations[0]["asOf"] = timestamp(999)
    np.testing.assert_array_equal(pre.transform(a), pre.transform(b))


def test_latest_lower_parent_score_removes_prior_high():
    b = batch([(10, "same", 1, {}), (11, "same", 1, {}), (12, "other", 1, {})])
    result = Replay(b).run([0.99, 0.1, 0.99], 0.9, min_flows=2)
    assert result["candidateActions"] == 0


def test_repeated_parent_does_not_make_distinct_flows():
    b = batch([(10, "same", 1, {}), (11, "same", 1, {}), (12, "same", 1, {})])
    assert Replay(b).run([1, 1, 1], 0.9, min_flows=3)["candidateActions"] == 0


@pytest.mark.parametrize("field", ["assetId", "sensorId", "bootId", "captureScopeId", "peerKey", "keyEpoch", "direction", "transport", "servicePort"])
def test_target_boundaries_never_combine(field):
    b = batch([(10, "a", 1, {}), (11, "b", 1, {field: "other"})])
    assert target_key(b.observations[0]) != target_key(b.observations[1])
    assert Replay(b).run([1, 1], 0.9, min_flows=2)["candidateActions"] == 0


def test_evidence_age_and_last_packet_freshness():
    b = batch([(10, "a", 1, {}), (21, "b", 1, {})])
    assert Replay(b).run([1, 1], 0.9, min_flows=2)["candidateActions"] == 0
    b = batch([(30, "a", 1, {"lastPacketAt": timestamp(10)})])
    assert Replay(b).run([1], 0.9)["candidateActions"] == 0


def test_ttl_deduplicates_but_zero_actions_precision_undefined():
    b = batch([(10, "a", 1, {}), (11, "b", 1, {}), (12, "c", 1, {})])
    assert Replay(b).run([1, 1, 1], 0.9)["candidateActions"] == 1
    result = Replay(b).run([0, 0, 0], 0.9)
    assert result["blockPrecisionCandidate"] is None
    assert result["blockRecallTimely"] is None


def test_future_observation_cannot_satisfy_earlier_span():
    b = batch([(10, "a", 1, {}), (10.1, "b", 1, {}), (15, "c", 1, {})])
    assert Replay(b.take([0, 1])).run([1, 1], 0.9, min_flows=2, span_ms=1000)["candidateActions"] == 0
    assert Replay(b).run([1, 1, 1], 0.9, min_flows=2, span_ms=1000)["candidateActions"] == 1


def test_action_rate_budget_applies_across_targets():
    b = batch([(10 + i, str(i), 1, {"peerKey": str(i)}) for i in range(8)])
    assert Replay(b).run(np.ones(8), 0.9)["candidateActions"] == 5


def test_calibration_positive_monotonic_and_finite():
    b = batch([(1, "a", 0, {}), (2, "b", 0, {}), (3, "c", 1, {}), (4, "d", 1, {})], "validation_calibration")
    c = calibrate([0.1, 0.2, 0.8, 0.9], b)
    values = calibrated([0, 0.1, 0.9, 1], c)
    assert np.isfinite(values).all() and np.all(np.diff(values) >= 0)


def test_ttl_collateral_benign_counts_as_incorrect_action():
    b = batch([(10, "attack", 1, {}), (11, "benign", 0, {})])
    result = Replay(b).run([1, 0], 0.9)
    assert result["candidateActions"] == 1
    assert result["incorrectCandidateActions"] == 1
    assert result["falseCandidateSeconds"] == 30
    assert result["affectedBenignParents"] == 1


def test_schema_rejects_invalid_calendar_date_without_optional_dependency(tmp_path):
    write(tmp_path / "docs/contracts/demo.schema.json", {"type": "string", "format": "date-time"})
    validator = contract_validator(tmp_path, "demo")
    assert validator.is_valid("2026-10-04T00:00:00Z")
    assert not validator.is_valid("2026-02-31T00:00:00Z")
    assert not validator.is_valid("2026-19-04T00:00:00Z")


def test_artifact_verifier_rejects_tampering_before_onnx_load(tmp_path):
    from cyber_training.host_guard.verify import verify
    write(tmp_path / "candidate/preprocessing.json", {"changed": True})
    write(tmp_path / "checksums.json", {"candidate/preprocessing.json": "0" * 64})
    with pytest.raises(ValueError, match="哈希不符"):
        verify(tmp_path)


def test_artifact_verifier_rejects_path_escape(tmp_path):
    from cyber_training.host_guard.verify import verify
    write(tmp_path / "checksums.json", {"../outside.json": "0" * 64})
    with pytest.raises(ValueError, match="路径逃逸"):
        verify(tmp_path)


def test_diagnostic_evidence_causes_and_unchecked_state():
    cases = [([0], {}, {}, 'low_score'),
             ([1], {'lastPacketAt': timestamp(-10)}, {}, 'stale_last_packet'),
             ([1], {'contexts': [{'windowSeconds': w, 'coverageMs': 0, 'peerFlowStarts': 0} for w in (1,5,30)]}, {}, 'insufficient_context_coverage'),
             ([1], {}, {'min_flows': 2}, 'insufficient_distinct_parents'),
             ([1], {}, {'min_starts': 6}, 'insufficient_peer_flow_starts')]
    for scores, changes, parameters, cause in cases:
        diagnostics = {}
        Replay(batch([(10, 'a', 1, changes)])).run(scores, .9, diagnostics=diagnostics, **parameters)
        trace = diagnostics['observations'][0]
        assert trace['firstRejection'] == cause
        assert trace['gates']['actions_per_minute'] == 'not_checked'


def test_diagnostics_age_eviction_and_latest_replacement():
    diagnostics = {}
    Replay(batch([(1, 'old', 1, {}), (12, 'new', 1, {}), (13, 'new', 1, {})])).run(
        [1, 1, .1], .9, min_flows=2, diagnostics=diagnostics)
    assert diagnostics['observations'][1]['firstRejection'] == 'expired_evidence'
    assert diagnostics['observations'][1]['expiredEvidenceIndices'] == [0]
    assert diagnostics['observations'][2]['replacedObservationIndex'] == 1


def test_ttl_covered_is_distinct_from_uncovered_opportunity():
    diagnostics = {}
    b = batch([(10, 'a', 1, {}), (11, 'b', 1, {}), (80, 'c', 1, {})])
    result = Replay(b).run([1, 1, 0], .9, diagnostics=diagnostics)
    assert result['coveredAttackOpportunities'] == 1
    assert [o['status'] for o in diagnostics['opportunities']] == ['covered', 'uncovered']
    assert diagnostics['observations'][1]['firstRejection'] == 'ttl_dedup'
    assert diagnostics['observations'][1]['coveredByExistingTtl']
    assert diagnostics['opportunities'][0]['candidateActionIds'] == ['action-0']


def test_late_final_coverage_is_not_onset_timing():
    diagnostics = {}
    Replay(batch([(10, 'a', 1, {}), (11, 'b', 1, {})])).run([0, 1], .9, diagnostics=diagnostics)
    assert diagnostics['opportunities'][0]['status'] == 'late_covered'
    assert 'not qualified attack onset' in diagnostics['opportunities'][0]['timingMeaning']


def test_projection_does_not_reset_competing_source_budget():
    from cyber_training.host_guard.regression import summarize
    b = batch([(10+i, str(i), 1, {'peerKey': str(i)}) for i in range(8)])
    d = {}; Replay(b).run(np.ones(8), .9, diagnostics=d)
    a = summarize(b, d, range(5)); other = summarize(b, d, range(5,8))
    assert a['candidateActions'] == 5 and other['candidateActions'] == 0
    assert other['firstRejections'] == {'per_minute_action_budget': 3}
    assert other['coveredAttackOpportunities'] == 0


def test_collateral_and_mixed_denominator_in_diagnostics():
    d = {}; b = batch([(10, 'attack', 1, {}), (11, 'normal', 0, {})])
    Replay(b).run([1, 0], .9, diagnostics=d)
    assert d['opportunities'][0]['mixedCountedAsBenign']
    assert not d['opportunities'][0]['positive']
    assert not d['actions'][0]['correct'] and d['actions'][0]['collateralIndices'] == [1]


def test_shared_stage_decision_cannot_hide_selection_failure():
    from cyber_training.host_guard.regression import stage_decision
    metric = lambda recall: dict(opportunityRecallDiagnostic=recall, falseBenignOpportunities=0, incorrectCandidateActions=0)
    policy = {'byRole': {'train': metric(1), 'validation_selection': metric(4/28), 'validation_calibration': metric(81/84)},
              'byScenario': {'cic2017_slowloris': dict(metric(1), role='train'),
                             'cic2017_slowhttptest': dict(metric(4/28), role='validation_selection'),
                             'cic2018_slowloris': dict(metric(81/84), role='validation_calibration')}}
    report = {'developmentRegression': {'workingPoints': {'raw_model': {'byRole': {'validation_selection': metric(19/28)}},
                                                         'frozen_policy': policy}}, 'e5': {'positiveCoverageGain': .94}}
    result = stage_decision(report)
    assert {'SELECTION_COVERAGE_BELOW_TARGET', 'FROZEN_POLICY_SCENARIO_COVERAGE_BELOW_TARGET'} <= set(result['blockingReasons'])
    assert result['feasibilityStatus'] == 'failed' and not result['p6Authorized']
    assert result['implementationGaps'] == []


def test_regression_source_verification_rejects_tampered_fixture(tmp_path):
    from cyber_training.host_guard.regression import verify_source
    write(tmp_path/'checksums.json', {'candidate/parity-fixture.npz': '0'*64})
    with pytest.raises(ValueError, match='哈希或路径'):
        verify_source(tmp_path)


def test_asset_budget_is_shared_across_sensor_and_boot():
    b = batch([(10+i, str(i), 1, {'peerKey': str(i), 'sensorId': 'sensor-'+str(i), 'bootId': 'boot-'+str(i)}) for i in range(8)])
    d = {}; result = Replay(b).run(np.ones(8), .9, diagnostics=d)
    assert result['candidateActions'] == 5
    assert d['observations'][-1]['firstRejection'] == 'per_minute_action_budget'


def test_target_budget_gap_and_epoch_cannot_extend_120_seconds():
    events=[]
    for n in range(6):
        for j in range(3):
            events.append((10+n*30.002+j*.0001,f'p{n}-{j}',1,{'bootId':f'boot-{n}','keyEpoch':str(n)}))
    b=batch(events);d={};r=Replay(b).run(np.ones(len(events)),.9,min_flows=3,diagnostics=d)
    assert r['candidateActions']==4
    assert sum(a['endMs']-a['startMs'] for a in d['actions'])==120000
    assert any(x['firstRejection']=='continuous_ttl_budget' for x in d['observations'])


def test_new_policy_fails_closed_without_target_mapping():
    b=batch([(10,'a',1,{})]);b.rows[0].pop('budgetTargetId')
    with pytest.raises(ValueError,match='稳定真实目标'):
        Replay(b).run([1],.9)


def test_label_timeline_keeps_unobserved_attack_and_collateral_lifetime():
    from cyber_training.host_guard.target_budget import evaluate_timeline
    r=evaluate_timeline([dict(episodeId='attack',targetId='target',startMs=0,endMs=90000,label=1)],
        [dict(actionId='a',targetId='target',startMs=10000,endMs=40000)],
        [dict(parentConnectionId='benign',targetId='target',startMs=0,endMs=100000)],['target'])
    assert len(r['opportunities'])==3
    assert r['opportunities'][-1]['blockedMs']==0
    assert r['collateral']==[dict(parentConnectionId='benign',actionId='a')]


def test_budget_requires_proven_healthy_cooldown():
    from cyber_training.host_guard.target_budget import TargetBudget
    b=TargetBudget();b.observe('target',0,True);b.commit('target',0,120000)
    b.observe('target',300000,False)
    assert b.proposed_ms('target',300000,330000)==150000
    b.observe('target',300000,False,healthy_since=120000)
    assert b.proposed_ms('target',300000,330000)==30000
