"""独立验证prefix准入、未来访问、时间线分母、附带误伤和预算，不进行业务数据拟合。"""
from copy import deepcopy
import json
from pathlib import Path

import numpy as np
import pytest

from cyber_training.host_guard.data import Batch, Preprocessor
from cyber_training.host_guard.prefix_corpus import ROLES, group_admission
from cyber_training.host_guard.prefix_data import PrefixDataset
from cyber_training.host_guard.prefix_evaluation import timeline_metrics, cluster_gain
from cyber_training.host_guard.prefix_runner import budget_check, stage_exit, calibrated_export


def group_rows():
    return [dict(label=label, split=role, leakageGroupId=f'{role}-{label}-{i}', scenario='controlled_slowloris')
            for role in ROLES for label in (0, 1) for i in range(5 if role == 'independent_development' else 1)]


def ep(label, start=0, end=60000, group='g', parent='p', observed=True):
    return dict(episodeId=parent, parentConnectionId=parent, targetId='target', startMs=start, endMs=end,
                leakageGroupId=group, split='independent_development', scenario='slowloris', label=label, hasObservation=observed)


def action(start, end):
    return dict(id='a', targetId='target', startMs=start, endMs=end, attackEvidence=True)


def test_five_training_groups_cannot_fill_independent_minimum():
    rows = group_rows()
    assert group_admission(rows)['trainingAllowed']
    for r in rows:
        if r['label'] == 1 and r['split'] == 'independent_development': r['split'] = 'train'
    report = group_admission(rows)
    assert not report['trainingAllowed']
    assert 'INDEPENDENT_DEVELOPMENT_FEWER_THAN_FIVE_ATTACK_GROUPS' in report['blockers']


def test_each_declared_scenario_requires_each_role():
    rows = group_rows()
    assert group_admission(rows, ['slowloris'])['trainingAllowed']
    report = group_admission(rows, ['slowloris', 'slowhttptest'])
    assert 'SCENARIO_NOT_PRESENT_IN_ALL_DEVELOPMENT_ROLES:slowhttptest' in report['blockers']


def test_unmapped_original_scenario_is_rejected_not_counted():
    rows = group_rows(); rows[1]['scenario'] = 'unregistered_tool'
    with pytest.raises(ValueError, match='行为映射'): group_admission(rows)


def test_unknown_and_final_roles_are_rejected():
    data = PrefixDataset.__new__(PrefixDataset)
    for role in ['final_test', 'unknown']:
        with pytest.raises(ValueError, match='禁止'): data.load(role)
    with pytest.raises(ValueError, match='冻结'): data.load('independent_development')


def test_pipeline_lock_requires_all_four_bindings(tmp_path):
    data = PrefixDataset.__new__(PrefixDataset); data.plan = {'planSha256': 'plan'}
    lock = tmp_path / 'lock.json'
    lock.write_text(json.dumps(dict(planSha256='plan', pipelineFrozen=True, independentUsedForSelection=False, files={'model.onnx': 'hash'})))
    with pytest.raises(ValueError, match='绑定'): data.load('independent_development', lock)


def test_unobserved_episode_is_retained():
    metrics = timeline_metrics([ep(1, observed=False)], [])
    assert metrics['attackOpportunities'] == 2
    assert metrics['attackBucketsWithoutObservation'] == 2
    assert metrics['blockRecallTimelyCandidate'] == 0


def test_late_action_is_not_timely_coverage():
    metrics = timeline_metrics([ep(1, end=30000)], [action(11000, 29000)])
    assert metrics['blockRecallTimelyCandidate'] == 0
    assert metrics['onsetToCandidateP95Ms'] == 11000


def test_existing_ttl_covers_next_bucket_without_new_action():
    metrics = timeline_metrics([ep(1)], [action(5000, 60000)])
    assert metrics['coveredAttackOpportunities'] == 2


def test_normal_connection_overlap_counts_without_normal_snapshot():
    metrics = timeline_metrics([ep(1), ep(0, 9000, 12000, parent='normal', observed=False)], [action(5000, 20000)])
    assert metrics['affectedBenignParents'] == 1
    assert metrics['incorrectCandidateActions'] == 1
    assert metrics['falseBenignOpportunities'] == 1


def test_no_actions_have_undefined_precision():
    assert timeline_metrics([ep(0)], [])['blockPrecisionCandidate'] is None


def test_cluster_confidence_needs_five_actual_groups_per_class():
    metrics = timeline_metrics([ep(1)], [])
    assert cluster_gain(metrics, metrics)['interval'] is None


def test_paired_gain_crossing_zero_is_not_established():
    model = dict(groups={0: 5, 1: 5}, clusterCounts={str(i):dict(attack=10, covered=5, benign=1, false=0) for i in range(5)}, coveredAttackOpportunities=25, attackOpportunities=50)
    assert not cluster_gain(model, deepcopy(model), replicates=100)['positiveGainEstablished']


def test_budget_counts_failed_fits_before_next_fit():
    plan = dict(budget=dict(maximumFullFits=1, maxTotalSeconds=14400, maxGpuSeconds=14400))
    import time
    with pytest.raises(RuntimeError, match='预算'): budget_check(plan, [{'status':'failed'}], time.perf_counter())


def test_failed_scenario_cannot_be_hidden_by_other_role():
    good = timeline_metrics([ep(1)], [action(0,60000)])
    bad = timeline_metrics([ep(1)], [])
    stage = stage_exit({'validation_calibration':good, 'independent_development':bad},
                       {'independent_development':{'slowloris':bad}}, {'positiveGainEstablished':True}, {'status':'passed'})
    assert stage['status'] == 'failed'
    assert not stage['p6Authorized']


def test_peer_context_excludes_host_global_fields():
    n = 2
    batch = Batch([{'label':i, 'sampleWeight':1.0, 'parentConnectionId':str(i)} for i in range(n)], [],
                  np.ones((n,43),dtype=np.float32), np.zeros((n,43),dtype=np.float32), np.asarray([['tcp','inbound','web']]*n), 'train')
    indices = Preprocessor.fit(batch, 'peer_context').parameters['indices']
    assert all(i in indices for i in [17,26,35])
    assert all(i not in indices for i in [21,22,30,31,39,40])


def test_calibrated_onnx_is_numerically_real(tmp_path):
    import onnx
    from onnx import helper, TensorProto
    import onnxruntime as ort
    from cyber_training.host_guard.models import calibrated
    graph = helper.make_graph([helper.make_node('Identity',['x'],['attack_score'])], 'fixture',
       [helper.make_tensor_value_info('x',TensorProto.FLOAT,[None,1])], [helper.make_tensor_value_info('attack_score',TensorProto.FLOAT,[None,1])])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid('',17)]); model.ir_version=10
    source=tmp_path/'source.onnx'; dest=tmp_path/'calibrated.onnx'; onnx.save(model,source)
    calibration=dict(method='platt',slope=1.7,intercept=-.3)
    calibrated_export(source,calibration,dest)
    values=np.asarray([0,1e-6,.01,.49,.5,.51,.99,1],dtype=np.float32).reshape(-1,1)
    actual=ort.InferenceSession(str(dest),providers=['CPUExecutionProvider']).run(None,{'x':values})[0].reshape(-1)
    expected=calibrated(values.reshape(-1),calibration)
    np.testing.assert_allclose(actual,expected,atol=1e-6,rtol=0)
    assert np.array_equal(actual>=.5,expected>=.5)


def test_constant_lightgbm_preserves_native_probability(tmp_path):
    from lightgbm import LGBMClassifier
    from cyber_training.host_guard.prefix_runner import export_prefix
    from cyber_training.host_guard.export import parity
    rows=[dict(label=i%2,sampleWeight=1.0,parentConnectionId=str(i)) for i in range(20)]
    batch=Batch(rows,[],np.ones((20,43),dtype=np.float32),np.zeros((20,43),dtype=np.float32),np.asarray([['tcp','inbound','web']]*20),'train')
    pre=Preprocessor.fit(batch,'base')
    model=LGBMClassifier(n_estimators=3,verbosity=-1,n_jobs=1)
    model.fit(pre.transform(batch),batch.y)
    path=tmp_path/'constant.onnx';export_prefix('lightgbm',model,pre,path)
    result=parity(path,'lightgbm',model,pre,{'method':'none'},[batch],[.5,1.0])
    assert result['status']=='passed' and result['maxAbsError']==0


def test_xgboost_json_export_preserves_native_probability(tmp_path):
    from xgboost import XGBClassifier
    from cyber_training.host_guard.export import export, parity
    rng = np.random.default_rng(17)
    count = 96
    numeric = rng.uniform(0, 8, size=(count, 43)).astype(np.float32)
    numeric_missing = np.zeros_like(numeric)
    labels = (numeric[:, 0] + numeric[:, 17] * .4 > 5).astype(np.int64)
    rows = [dict(label=int(label), sampleWeight=1.0, parentConnectionId=str(index))
            for index, label in enumerate(labels)]
    batch = Batch(rows, [], numeric, numeric_missing,
                  np.asarray([['tcp', 'inbound', 'web']] * count), 'train')
    pre = Preprocessor.fit(batch, 'peer_context')
    model = XGBClassifier(n_estimators=12, max_depth=3, learning_rate=.2, n_jobs=1,
                          random_state=17, tree_method='hist', device='cpu', eval_metric='logloss')
    model.fit(pre.transform(batch), batch.y)
    path = tmp_path / 'xgboost.onnx'
    export('xgboost', model, pre, {'method': 'none'}, path)
    result = parity(path, 'xgboost', model, pre, {'method': 'none'}, [batch], [.25, .5, .75])
    assert result['status'] == 'passed'
    assert result['maxAbsError'] <= 1e-4


def _preprocessing_session(parameters):
    import onnx
    import onnxruntime as ort
    from onnx import TensorProto, helper
    from cyber_training.host_guard.export import _preprocessing
    nodes, constants = _preprocessing(parameters)
    columns = len(parameters['indices']) * 2 + 3
    graph = helper.make_graph(nodes, 'preprocessing_only',
        [helper.make_tensor_value_info('numeric_values', TensorProto.FLOAT, [None, 43]),
         helper.make_tensor_value_info('numeric_missing', TensorProto.FLOAT, [None, 43]),
         helper.make_tensor_value_info('categorical_codes', TensorProto.INT64, [None, 3])],
        [helper.make_tensor_value_info('features', TensorProto.FLOAT, [None, columns])], constants)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid('', 17)]); model.ir_version = 10
    onnx.checker.check_model(model)
    return ort.InferenceSession(model.SerializeToString(), providers=['CPUExecutionProvider'])


def _wide_batch(count=4096, seed=23):
    """覆盖计数、字节和毫秒量级；numpy float32 log 在这类值上常与 ORT 差 1 ulp。"""
    rng = np.random.default_rng(seed)
    numeric = np.exp(rng.uniform(0, 16, size=(count, 43))).astype(np.float32)
    numeric[:, :8] = rng.integers(0, 5000, size=(count, 8)).astype(np.float32)
    missing = (rng.random((count, 43)) < .05).astype(np.float32)
    numeric[missing == 1] = 0
    labels = (np.log1p(numeric[:, 9]) + .4 * np.log1p(numeric[:, 17]) > 11).astype(np.int64)
    rows = [dict(label=int(label), sampleWeight=1.0, parentConnectionId=str(i)) for i, label in enumerate(labels)]
    return Batch(rows, [], numeric, missing, np.asarray([['tcp', 'inbound', 'web']] * count), 'train')


def test_fit_emits_portable_v2_preprocessing():
    assert Preprocessor.fit(_wide_batch(256), 'peer_context').parameters['version'] == 'p3-preprocess-v2'


def test_v2_preprocessing_onnx_features_are_bitwise_identical():
    batch = _wide_batch()
    pre = Preprocessor.fit(batch, 'peer_context')
    actual = _preprocessing_session(pre.parameters).run(['features'], pre.feed(batch))[0]
    expected = pre.transform(batch)
    assert actual.dtype == expected.dtype == np.float32
    np.testing.assert_array_equal(actual, expected)


def test_v1_preprocessing_keeps_historical_float32_semantics():
    from cyber_training.host_guard.export import _preprocessing
    batch = _wide_batch(512)
    parameters = dict(Preprocessor.fit(batch, 'peer_context').parameters, version='p3-preprocess-v1')
    pre = Preprocessor(parameters)
    mean = np.asarray(parameters['meanLog'], dtype=np.float32)
    scale = np.asarray(parameters['scaleLog'], dtype=np.float32)
    filled = np.where(batch.missing == 1, mean, np.log(batch.values + np.float32(1)))
    ids = parameters['indices']
    legacy = np.concatenate([((filled - mean) / scale)[:, ids], batch.missing[:, ids],
                             pre.codes(batch).astype(np.float32)], axis=1).astype(np.float32)
    np.testing.assert_array_equal(pre.transform(batch), legacy)
    nodes, constants = _preprocessing(parameters)
    assert [n.op_type for n in nodes][:6] == ['Add', 'Log', 'Equal', 'Where', 'Sub', 'Div']
    assert all(c.data_type == 1 for c in constants if c.name in ('p3_mean', 'p3_scale'))


def test_unknown_preprocessing_version_is_rejected():
    from cyber_training.host_guard.export import _preprocessing
    batch = _wide_batch(64)
    parameters = dict(Preprocessor.fit(batch, 'peer_context').parameters, version='p3-preprocess-v9')
    with pytest.raises(ValueError):
        Preprocessor(parameters).transform(batch)
    with pytest.raises(ValueError):
        _preprocessing(parameters)


def test_xgboost_train_rows_on_hist_split_points_keep_parity(tmp_path):
    """hist 分裂点取自训练特征，train 行自身就落在分裂点上；特征差 1 ulp 即改走分支。"""
    from xgboost import XGBClassifier
    from cyber_training.host_guard.export import export, parity
    batch = _wide_batch(2048, seed=31)
    pre = Preprocessor.fit(batch, 'peer_context')
    model = XGBClassifier(n_estimators=60, max_depth=4, learning_rate=.2, n_jobs=1, random_state=31,
                          tree_method='hist', device='cpu', eval_metric='logloss', base_score=.5)
    model.fit(pre.transform(batch), batch.y)
    path = tmp_path / 'xgboost-hist.onnx'
    export('xgboost', model, pre, {'method': 'none'}, path)
    result = parity(path, 'xgboost', model, pre, {'method': 'none'}, [batch], [.5, .8, .95, .99])
    assert result['status'] == 'passed' and result['thresholdFlips'] == 0
    assert result['maxAbsError'] <= 1e-5


def _rebound_fixture(tmp_path):
    from cyber_training.host_guard.data import sha, write
    name = 'xgboost-peer_context-42'
    prior, rebind = tmp_path / 'run' / 'prior', tmp_path / 'run' / 'rebind'
    (prior / 'experiments' / name).mkdir(parents=True); (rebind / 'experiments' / name).mkdir(parents=True)
    (prior / 'experiments' / name / 'native-model.json').write_text('{}', encoding='utf-8')
    (rebind / 'experiments' / name / 'preprocessing.json').write_text('{"version": "p3-preprocess-v2"}', encoding='utf-8')
    (rebind / 'experiments' / name / 'model.onnx').write_bytes(b'onnx')
    (prior / 'fit-ledger.jsonl').write_text(json.dumps(dict(id=name, status='started')) + '\n'
                                            + json.dumps(dict(id=name, status='passed', gpuSeconds=1.0)) + '\n', encoding='utf-8')
    entry = dict(id=name, algorithm='xgboost', status='passed', modelFitPerformed=False, parity=dict(status='passed'),
                 nativeModelSha256=sha(prior / 'experiments' / name / 'native-model.json'),
                 preprocessingSha256=sha(rebind / 'experiments' / name / 'preprocessing.json'),
                 artifactSha256=sha(rebind / 'experiments' / name / 'model.onnx'))
    (rebind / 'rebind-ledger.jsonl').write_text(json.dumps(entry) + '\n', encoding='utf-8')
    (rebind / 'policy-trials.jsonl').write_text(json.dumps(dict(arm='model_selection', ordinal=1)) + '\n', encoding='utf-8')
    write(rebind / 'rebind-report.json', dict(status='parity_remediated_awaiting_review', newModelFits=0, finalTestRead=False))
    files = {n: sha(rebind / n) for n in ('rebind-report.json', 'rebind-ledger.jsonl', 'policy-trials.jsonl')}
    plan = dict(remediation=dict(modelRefit=False, priorRun='prior', reboundExperiments=[name],
                                 priorFitLedgerSha256=sha(prior / 'fit-ledger.jsonl'), rebind=dict(files=files)))
    return plan, rebind


def test_resume_inherits_registered_zero_fit_rebind(tmp_path):
    from cyber_training.host_guard.prefix_runner import load_rebound
    plan, rebind = _rebound_fixture(tmp_path)
    out = tmp_path / 'out'
    rebound, ledger = load_rebound(plan, rebind, out)
    assert list(rebound) == ['xgboost-peer_context-42']
    assert ledger == [dict(id='xgboost-peer_context-42', status='passed', gpuSeconds=1.0)]
    assert (out / 'policy-trials.jsonl').read_bytes() == (rebind / 'policy-trials.jsonl').read_bytes()
    assert (out / 'experiments' / 'xgboost-peer_context-42' / 'model.onnx').read_bytes() == b'onnx'


def test_resume_rejects_tampered_rebind_artifact(tmp_path):
    from cyber_training.host_guard.prefix_runner import load_rebound
    plan, rebind = _rebound_fixture(tmp_path)
    (rebind / 'experiments' / 'xgboost-peer_context-42' / 'model.onnx').write_bytes(b'changed')
    with pytest.raises(ValueError):
        load_rebound(plan, rebind, tmp_path / 'out')


def test_resume_rejects_plan_without_zero_fit_registration(tmp_path):
    from cyber_training.host_guard.prefix_runner import load_rebound
    plan, rebind = _rebound_fixture(tmp_path)
    plan['remediation']['modelRefit'] = True
    with pytest.raises(ValueError):
        load_rebound(plan, rebind, tmp_path / 'out')
