"""Windows有界prefix训练、独立完整策略评价及候选冻结；准入失败在任何拟合前退出。"""
import argparse
from datetime import datetime, timezone
import hashlib
import itertools
import json
import math
import multiprocessing
from pathlib import Path
import platform
import shutil
import time
import uuid

import numpy as np

from .data import Preprocessor, contract_validator, read, sha, write
from .evaluation import classification, rules
from .export import export, parity, score_session, session, latency
from .models import calibrate, calibrated, fit, predict
from .prefix_corpus import verify
from .prefix_data import PrefixDataset
from .prefix_plan import compatibility, load_health, parameter_grid
from .prefix_evaluation import combine, replay, objective, timeline_metrics, cluster_gain
from .runner import environment, source_hash


def measure(timeline, result, plan, **filters):
    """所有角色评价共用同一转人工/恢复/告警事实和认证健康，避免各调用点口径漂移。"""
    return timeline_metrics(timeline, result['actions'], evaluation=plan['evaluation'],
                            decisions=result['decisions'], health=plan.get('_health'), **filters)


def budget_check(plan, ledger, started):
    """失败拟合照样计数；整轮墙钟和累计GPU拟合秒数不得超出登记预算。"""
    budget = plan['budget']
    if len(ledger) >= budget['maximumFullFits'] or time.perf_counter() - started >= budget['maxTotalSeconds']:
        raise RuntimeError('完整拟合数或墙钟预算耗尽')
    if sum(r.get('gpuSeconds', 0) for r in ledger) >= budget['maxGpuSeconds']:
        raise RuntimeError('GPU预算耗尽')


def fit_worker(algorithm, feature_set, train, selection, plan, seed, folder):
    """可信子进程只导出JSON/ONNX/无pickle数组；父进程可在单次期限强制终止。"""
    try:
        pre = Preprocessor.fit(train, feature_set)
        model, timing = fit(algorithm, train, pre, plan, seed)
        if algorithm == 'lightgbm': model.booster_.save_model(str(folder / 'native-model.txt'))
        else: model.save_model(str(folder / 'native-model.json'))
        export_prefix(algorithm, model, pre, folder / 'model.onnx')
        check = parity(folder / 'model.onnx', algorithm, model, pre, {'method': 'none'}, [train, selection], plan['decision']['thresholds'])
        write(folder / 'preprocessing.json', pre.parameters)
        np.savez_compressed(folder / 'native-scores.npz', train=predict(algorithm, model, pre.transform(train)),
                            selection=predict(algorithm, model, pre.transform(selection)))
        write(folder / 'fit.json', dict(timing=timing, parity=check))
    except BaseException as exc:
        write(folder / 'failure.json', dict(type=type(exc).__name__))
        raise


def export_prefix(algorithm, model, pre, path):
    """修复无分裂LightGBM树被第三方转换器输出为零的边界，不改变已有final导出。

    只有模型结构证明每棵树均为常数叶时使用显式常数概率图；常数模型仍必须
    经过收益/覆盖裁决，不能凭导出成功成为有效候选。
    """
    if algorithm != 'lightgbm' or any('split_index' in tree['tree_structure'] for tree in model.booster_.dump_model()['tree_info']):
        export(algorithm, model, pre, {'method':'none'}, path); return
    import onnx
    from onnx import helper, numpy_helper, TensorProto
    columns=len(pre.parameters['indices'])*2+3
    probability=np.float32(model.predict_proba(np.zeros((1,columns),dtype=np.float32))[0,1])
    nodes=[helper.make_node('ReduceSum',['numeric_values','constant_axes'],['constant_rows'],keepdims=1),
           helper.make_node('Mul',['constant_rows','constant_zero'],['constant_shape']),
           helper.make_node('Add',['constant_shape','constant_probability'],['attack_score'])]
    constants=[numpy_helper.from_array(np.asarray([1],dtype=np.int64),'constant_axes'),
               numpy_helper.from_array(np.asarray(0,dtype=np.float32),'constant_zero'),
               numpy_helper.from_array(np.asarray(probability,dtype=np.float32),'constant_probability')]
    graph=helper.make_graph(nodes,'constant_prefix_model',
        [helper.make_tensor_value_info('numeric_values',TensorProto.FLOAT,[None,43]),
         helper.make_tensor_value_info('numeric_missing',TensorProto.FLOAT,[None,43]),
         helper.make_tensor_value_info('categorical_codes',TensorProto.INT64,[None,3])],
        [helper.make_tensor_value_info('attack_score',TensorProto.FLOAT,[None,1])],constants)
    output=helper.make_model(graph,opset_imports=[helper.make_opsetid('',17)]);output.ir_version=10
    onnx.checker.check_model(output);onnx.save(output,path)


def experiment(algorithm, feature_set, train, selection, timeline, plan, out, name, seed, ledger, started):
    budget_check(plan, ledger, started)
    folder = out / 'experiments' / name; folder.mkdir(parents=True, exist_ok=False)
    entry = dict(id=name, seed=seed, algorithm=algorithm, featureSet=feature_set, status='started')
    ledger.append(entry)
    with (out / 'fit-ledger.jsonl').open('a', encoding='utf-8') as stream: stream.write(json.dumps(entry) + '\n')
    before = time.perf_counter()
    process = multiprocessing.get_context('spawn').Process(target=fit_worker,
         args=(algorithm, feature_set, train, selection, plan, seed, folder))
    process.start()
    remaining = min(plan['budget']['maxSecondsPerFit'], plan['budget']['maxTotalSeconds'] - (before - started))
    if algorithm == 'xgboost': remaining = min(remaining, plan['budget']['maxGpuSeconds'] - sum(r.get('gpuSeconds',0) for r in ledger))
    process.join(max(0, remaining))
    elapsed = time.perf_counter() - before
    entry.update(seconds=elapsed, gpuSeconds=elapsed if algorithm == 'xgboost' else 0)
    if process.is_alive():
        process.terminate(); process.join(10)
        entry['status'] = 'timeout'
        write(folder / 'timeout.json', entry)
        raise TimeoutError('单次拟合实际期限已终止子进程')
    if process.exitcode or not (folder / 'fit.json').is_file():
        entry['status'] = 'failed'; raise RuntimeError('模型拟合失败，已计入预算')
    report = read(folder / 'fit.json')
    if report['parity']['status'] != 'passed': raise RuntimeError('拟合ONNX对拍失败')
    pre = Preprocessor(read(folder / 'preprocessing.json'))
    tuning_batch = combine([train, selection])
    inference = session(folder / 'model.onnx')
    scores = score_session(inference, pre, tuning_batch)
    selection_scores = score_session(inference, pre, selection)
    trials = []
    for t in plan['decision']['thresholds']:
        policy_trial(out, plan, 'model_selection')
        result = replay(tuning_batch, scores, dict(threshold=t), timeline, plan=plan, health=plan.get('_health'))
        trials.append(dict(threshold=t, metrics=measure(timeline, result, plan, role='validation_selection')))
    choice = max(trials, key=lambda r: (objective(r['metrics']), r['threshold']))
    native_path = folder / ('native-model.txt' if algorithm == 'lightgbm' else 'native-model.json')
    entry.update(status='passed', workingPoint=choice, classification=classification(selection, selection_scores, choice['threshold']),
                 artifactSha256=sha(folder / 'model.onnx'), parity=report['parity'])
    entry['nativeModelSha256'] = sha(native_path)
    write(folder / 'report.json', entry)
    with (out / 'fit-ledger.jsonl').open('a', encoding='utf-8') as stream: stream.write(json.dumps(entry) + '\n')
    print(json.dumps(dict(stage='experiment', id=name, recall=choice['metrics']['blockRecallTimelyCandidate'])), flush=True)
    return entry


def native_scores(original, winner, pre, batch):
    """只读取本次拟合且哈希绑定的文本/JSON权重，避免可执行pickle并验证真实框架结果。"""
    algorithm = winner['algorithm']
    path = original / ('native-model.txt' if algorithm == 'lightgbm' else 'native-model.json')
    if sha(path) != winner['nativeModelSha256']: raise ValueError('本次原生权重被修改')
    if algorithm == 'lightgbm':
        import lightgbm
        return lightgbm.Booster(model_file=str(path)).predict(pre.transform(batch)).astype(np.float32)
    import xgboost
    model = xgboost.XGBClassifier(); model.load_model(path)
    return predict(algorithm, model, pre.transform(batch))


def calibrated_export(source, calibration, dest):
    """在已哈希绑定的ONNX上追加冻结Platt图，不重建权重或复用历史成绩。"""
    import onnx
    from onnx import helper, numpy_helper
    model = onnx.load(str(source), load_external_data=False)
    if len(model.graph.output) != 1 or model.graph.output[0].name != 'attack_score': raise ValueError('输出契约不符')
    for node in model.graph.node:
        for names in (node.input, node.output):
            for i, name in enumerate(names):
                if name == 'attack_score': names[i] = 'prefix_raw_score'
    for name, value in [('prefix_clip_min', 1e-6), ('prefix_clip_max', 1 - 1e-6), ('prefix_one', 1),
                        ('prefix_slope', calibration['slope']), ('prefix_intercept', calibration['intercept'])]:
        model.graph.initializer.append(numpy_helper.from_array(np.asarray(value, dtype=np.float32), name))
    steps = [('Clip', ['prefix_raw_score', 'prefix_clip_min', 'prefix_clip_max'], 'prefix_clipped'),
             ('Sub', ['prefix_one', 'prefix_clipped'], 'prefix_complement'),
             ('Div', ['prefix_clipped', 'prefix_complement'], 'prefix_odds'),
             ('Log', ['prefix_odds'], 'prefix_logit'),
             ('Mul', ['prefix_logit', 'prefix_slope'], 'prefix_scaled'),
             ('Add', ['prefix_scaled', 'prefix_intercept'], 'prefix_affine'),
             ('Sigmoid', ['prefix_affine'], 'attack_score')]
    model.graph.node.extend(helper.make_node(op, inputs, [output]) for op, inputs, output in steps)
    onnx.checker.check_model(model); onnx.save(model, str(dest))


def policy_trial(out, plan, arm):
    """所有阈值、规则、种子诊断选择都按实际次数计账，异常尝试也不返还。"""
    ledger=out/'policy-trials.jsonl'
    entries=[json.loads(line) for line in ledger.open(encoding='utf-8')] if ledger.exists() else []
    if len(entries)>=plan['budget']['maximumPolicyTrials'] or sum(r['arm']==arm for r in entries)>=plan['budget']['policyTrialAllocation'][arm]:
        raise RuntimeError('阈值/策略选择预算耗尽')
    with ledger.open('a',encoding='utf-8') as stream: stream.write(json.dumps(dict(arm=arm,ordinal=len(entries)+1))+'\n')


def select_parameters(batch, scores, timeline, plan, deadline=math.inf, *, out, arm='model_and_policy', grid=None):
    """有限校准网格，独立开发集不参与模型、校准或策略的选择。"""
    trials = []
    for params in (parameter_grid(plan) if grid is None else grid):
        if time.perf_counter() >= deadline: raise TimeoutError('整轮策略预算耗尽')
        policy_trial(out, plan, arm)
        result = replay(batch, scores, params, timeline, plan=plan, health=plan.get('_health'))
        trials.append(dict(parameters=params, metrics=measure(timeline, result, plan, role='validation_calibration')))
    winner = max(trials, key=lambda r: (objective(r['metrics']), r['parameters']['threshold'], -r['parameters']['ttl']))
    return winner, trials


def stage_exit(by_role, by_scene, gain, parity_report, by_source=None):
    """实测失败与证据不足分别裁决；P6及自动资格另行准入。"""
    failures = []; missing = []
    for role, metrics in by_role.items():
        if role == 'train': continue
        if metrics['falseBenignOpportunities'] or metrics['incorrectCandidateActions']:
            failures.append(dict(code='FALSE_ACTION_BUDGET_EXCEEDED', role=role))
    for role, scenes in by_scene.items():
        if role == 'train': continue
        for scene, metrics in scenes.items():
            if metrics['actionAttackOpportunities'] == 0:
                missing.append(dict(code='SCENARIO_WITHOUT_INDEPENDENT_EPISODES', role=role, scenario=scene))
            elif metrics['blockRecallTimelyCandidate'] < .8:
                failures.append(dict(code='FROZEN_POLICY_SCENARIO_COVERAGE_BELOW_TARGET', role=role, scenario=scene,
                                     actual=metrics['blockRecallTimelyCandidate'], target=.8))
            if metrics['handoffAttackOpportunities'] and metrics['handoffContinuity'] < .8:
                failures.append(dict(code='FROZEN_POLICY_HANDOFF_CONTINUITY_BELOW_TARGET', role=role, scenario=scene,
                                     actual=metrics['handoffContinuity'], target=.8))
    if not gain['positiveGainEstablished']: missing.append(dict(code='MODEL_GAIN_NOT_ESTABLISHED'))
    for role,sources in (by_source or {}).items():
        if role == 'train': continue
        for source,metrics in sources.items():
            if metrics['attackOpportunities'] and (not metrics['actionAttackOpportunities']
                    or metrics['blockRecallTimelyCandidate'] < .8
                    or (metrics['handoffAttackOpportunities'] and metrics['handoffContinuity'] < .8)
                    or metrics['falseBenignOpportunities'] or metrics['incorrectCandidateActions']):
                failures.append(dict(code='SUPPORTED_SOURCE_REGRESSION_FAILED',role=role,source=source))
    if parity_report['status'] != 'passed': failures.append(dict(code='ONNX_PARITY_FAILED'))
    return dict(status='failed' if failures else 'blocked' if missing else 'passed', measuredFailures=failures,
                missingEvidence=missing, candidateOnly=True, automaticExecutionAuthorized=False,
                p6Authorized=False, finalTestRead=False, realOsActionTimingMeasured=False)


def ranking(record):
    """主种子选型：完整策略目标优先，再比 parent 加权 logloss，最后按实验 ID 稳定打平。"""
    return (objective(record['workingPoint']['metrics']), -record['classification']['logLoss'], record['id'])


def run(dataset, plan, plan_path, out):
    start = time.perf_counter(); ledger = []
    plan['_health'] = load_health(plan, dataset.root)
    train = dataset.load('train'); selection = dataset.load('validation_selection')
    selection_timeline = dataset.timeline(['train','validation_selection']); candidates = []
    for algorithm, features in itertools.product(plan['budget']['algorithms'], plan['budget']['featureSets']):
        candidates.append(experiment(algorithm, features, train, selection, selection_timeline, plan, out,
                                    f'{algorithm}-{features}-42', 42, ledger, start))
    winner = max(candidates, key=ranking)
    seeds = [winner]
    for seed in (43, 44):
        seeds.append(experiment(winner['algorithm'], winner['featureSet'], train, selection, selection_timeline,
                     plan, out, f'winner-seed-{seed}', seed, ledger, start))
    finish(dataset, plan, plan_path, out, train, selection, winner, seeds, ledger, start)


def load_rebound(plan, rebind, out):
    """只接收新版计划登记且逐文件哈希一致的零拟合重绑定结果，复制进本次输出后再使用。

    返回 (按实验 ID 的重绑定记录, 历史拟合账本)。历史账本原样继承，使完整拟合与
    策略试验按整轮累计；任何证据、权重、预处理或 ONNX 被改动都拒绝接续。
    """
    remediation = plan.get('remediation') or {}
    binding = remediation.get('rebind')
    if not binding or remediation.get('modelRefit') is not False:
        raise ValueError('运行计划未登记零拟合重绑定')
    for name, digest in binding['files'].items():
        if sha(rebind / name) != digest: raise ValueError('重绑定证据被修改: ' + name)
    report = read(rebind / 'rebind-report.json')
    if report['status'] != 'parity_remediated_awaiting_review' or report['newModelFits'] != 0 or report['finalTestRead']:
        raise ValueError('重绑定报告状态不符')
    prior = rebind.parent / remediation['priorRun']
    if sha(prior / 'fit-ledger.jsonl') != remediation['priorFitLedgerSha256']: raise ValueError('历史拟合账本被修改')
    entries = [json.loads(line) for line in (rebind / 'rebind-ledger.jsonl').open(encoding='utf-8')]
    if ([e['id'] for e in entries] != remediation['reboundExperiments']
            or any(e['status'] != 'passed' or e['parity']['status'] != 'passed' or e['modelFitPerformed'] for e in entries)):
        raise ValueError('重绑定实验集合或对拍状态不符')
    rebound = {}
    for entry in entries:
        native = 'native-model.txt' if entry['algorithm'] == 'lightgbm' else 'native-model.json'
        folder = out / 'experiments' / entry['id']; folder.mkdir(parents=True, exist_ok=False)
        for source, name, digest in ((prior / 'experiments' / entry['id'], native, entry['nativeModelSha256']),
                                     (rebind / 'experiments' / entry['id'], 'preprocessing.json', entry['preprocessingSha256']),
                                     (rebind / 'experiments' / entry['id'], 'model.onnx', entry['artifactSha256'])):
            if sha(source / name) != digest: raise ValueError('重绑定产物哈希不符: ' + entry['id'] + '/' + name)
            shutil.copyfile(source / name, folder / name)
        write(folder / 'report.json', entry)
        rebound[entry['id']] = entry
    history = {}
    for line in (prior / 'fit-ledger.jsonl').open(encoding='utf-8'):
        record = json.loads(line); history.setdefault(record['id'], {}).update(record)
    shutil.copyfile(prior / 'fit-ledger.jsonl', out / 'fit-ledger.jsonl')
    shutil.copyfile(rebind / 'policy-trials.jsonl', out / 'policy-trials.jsonl')
    return rebound, list(history.values())


def resume(dataset, plan, plan_path, out, rebind):
    """零拟合重绑定后接续本轮：只新增 winner-seed-44 一次拟合，选型冻结后与 run 共用 finish。"""
    binding = plan['remediation']['rebind']
    start = time.perf_counter() - binding['priorElapsedSeconds']
    plan['_health'] = load_health(plan, dataset.root)
    rebound, ledger = load_rebound(plan, rebind, out)
    train = dataset.load('train'); selection = dataset.load('validation_selection')
    selection_timeline = dataset.timeline(['train', 'validation_selection'])
    candidates = [rebound[f'{algorithm}-{features}-42'] for algorithm, features
                  in itertools.product(plan['budget']['algorithms'], plan['budget']['featureSets'])]
    winner = max(candidates, key=ranking)
    if winner['id'] != binding['winner']: raise ValueError('接续时选型优胜者与登记不符')
    seeds = [winner, rebound['winner-seed-43'],
             experiment(winner['algorithm'], winner['featureSet'], train, selection, selection_timeline,
                        plan, out, 'winner-seed-44', 44, ledger, start)]
    finish(dataset, plan, plan_path, out, train, selection, winner, seeds, ledger, start)


def finish(dataset, plan, plan_path, out, train, selection, winner, seeds, ledger, start):
    """选型冻结后的校准、三臂策略、独立开发评价与候选冻结；run 与 resume 共用同一路径。"""
    write(out / 'selection-lock.json', dict(selectionFrozen=True, calibrationUsedForSelection=False,
         experimentId=winner['id'], artifactSha256=winner['artifactSha256'], planSha256=sha(plan_path),
         seedPolicy='retain42;43/44variance_only', finalTestRead=False))
    calibration_batch = dataset.load('validation_calibration', out / 'selection-lock.json')
    original = out / 'experiments' / winner['id']; pre = Preprocessor(read(original / 'preprocessing.json'))
    raw_session = session(original / 'model.onnx')
    raw_calibration = native_scores(original, winner, pre, calibration_batch)
    calibration = calibrate(raw_calibration, calibration_batch)
    tuning_batch = combine([train, selection, calibration_batch])
    calibration_scores = calibrated(native_scores(original, winner, pre, tuning_batch), calibration)
    calibration_timeline=dataset.timeline(['train','validation_selection','validation_calibration'])
    choice, trials = select_parameters(tuning_batch, calibration_scores, calibration_timeline, plan,
                                      start + plan['budget']['maxTotalSeconds'], out=out)
    # 三臂各自选择预登记参数，规则对照不沿用为模型选择的组合条件。
    rule_trials=[]
    rule_grid=[dict(threshold=.5,min_flows=n,span_ms=0,min_starts=p,ttl=t)
               for n,p,t in itertools.product(plan['decision']['minDistinctFlows'],
                    plan['decision']['minPeerFlowStarts'],plan['decision']['ttlSeconds'])]
    for name, scores in rules(tuning_batch, plan):
        _, tests=select_parameters(tuning_batch,scores,calibration_timeline,plan,
            start+plan['budget']['maxTotalSeconds'],out=out,arm='rules',grid=rule_grid)
        rule_trials.extend(dict(test,name=name) for test in tests)
    rule_choice=max(rule_trials,key=lambda r:(objective(r['metrics']),r['name']))
    model_grid=[dict(threshold=t,ttl=ttl) for t,ttl in itertools.product(plan['decision']['thresholds'],plan['decision']['ttlSeconds'])]
    model_choice, model_trials=select_parameters(tuning_batch,calibration_scores,calibration_timeline,plan,
        start+plan['budget']['maxTotalSeconds'],out=out,arm='model',grid=model_grid)
    folder = out / 'candidate'; folder.mkdir()
    calibrated_export(original / 'model.onnx', calibration, folder / 'model.onnx')
    write(folder / 'preprocessing.json', pre.parameters); write(folder / 'calibration.json', calibration)
    write(folder / 'decision-parameters.json', dict(model_and_policy=choice['parameters'],model=model_choice['parameters'],rules=dict(name=rule_choice['name'],parameters=rule_choice['parameters'])))
    write(out / 'pipeline-lock.json', dict(pipelineFrozen=True, independentUsedForSelection=False,
         planSha256=sha(plan_path), files={name: sha(folder / name) for name in ('model.onnx', 'preprocessing.json', 'calibration.json', 'decision-parameters.json')}))
    independent = dataset.load('independent_development', out / 'pipeline-lock.json')
    batches = [train, selection, calibration_batch, independent]; whole = combine(batches)
    feeds = pre.feed(whole); expected = calibrated(native_scores(original, winner, pre, whole), calibration)
    actual = score_session(session(folder / 'model.onnx'), pre, whole)
    thresholds = [winner['workingPoint']['threshold'], choice['parameters']['threshold']]
    error = float(np.max(np.abs(actual - expected))); flips = [int(np.count_nonzero((actual >= t) != (expected >= t))) for t in thresholds]
    parity_report = dict(status='passed' if error <= 1e-4 and not any(flips) else 'failed', maxAbsError=error,
                         decisionFlips=flips, thresholds=thresholds, rows=len(actual),
                         nativeParity=[s['parity'] for s in seeds])
    np.savez_compressed(folder / 'parity-fixture.npz', **feeds, expected=expected)
    timeline = dataset.timeline([b.role for b in batches])
    full = replay(whole, actual, choice['parameters'], timeline, plan=plan, health=plan['_health'])
    by_role = {b.role: measure(timeline, full, plan, role=b.role) for b in batches}
    by_scene = {b.role: {s: measure(timeline, full, plan, role=b.role, scenario=s) for s in plan['scenarios']} for b in batches}
    by_source = {b.role: {s['sourceDomainId']: measure(timeline, full, plan, role=b.role,
        source=s['sourceDomainId']) for s in plan['sourceScope']
        if s['role']=='supported_research'} for b in batches}
    rule_scores = dict(rules(whole, plan))[rule_choice['name']]
    rule_full = replay(whole, rule_scores, rule_choice['parameters'], timeline, plan=plan, health=plan['_health'])
    independent_rule = measure(timeline, rule_full, plan, role='independent_development')
    model_full = replay(whole, actual, model_choice['parameters'], timeline, plan=plan, health=plan['_health'])
    gain = cluster_gain(by_role['independent_development'], independent_rule)
    code_sha, code_files = source_hash(Path(__file__).parent)
    report = dict(version='p3-prefix-validation-v2', candidateOnly=True, byRole=by_role, byScenario=by_scene, bySource=by_source,
         e5=dict(rules=independent_rule, model=measure(timeline, model_full, plan, role='independent_development'),
                 modelAndPolicy=by_role['independent_development'], pairedGain=gain),
         classification={b.role: classification(b, score_session(session(folder / 'model.onnx'), pre, b), choice['parameters']['threshold']) for b in batches},
         exposures=dict(train='fit_diagnostic', validation_selection='model_selection', validation_calibration='calibration_policy_selection', independent_development='frozen_pipeline_evaluation'),
         policySelection=choice, ruleSelection=rule_choice, modelSelection=model_choice, fullModelFits=len(ledger), calibrationFits=1,
         threeSeeds=dict(seeds=[42, 43, 44], retained=42, recallStd=float(np.std([s['workingPoint']['metrics']['blockRecallTimelyCandidate'] or 0 for s in seeds]))),
         parity=parity_report, finalTestRead=False, trainingCodeSha256=code_sha,
         elapsedSeconds=time.perf_counter() - start, gpuSeconds=sum(r.get('gpuSeconds', 0) for r in ledger),
         resourceLimitations='CPU LightGBM and CUDA XGBoost; real OS timing is not measured')
    write(out / 'validation-report.json', report); write(out / 'policy-search.json', dict(trials=trials, rules=rule_trials, model=model_trials))
    write(out / 'code-manifest.json', dict(sha256=code_sha, files=code_files)); write(out / 'fit-ledger.json', ledger)
    shutil.copyfile(dataset.contracts / 'docs/contracts/feature-profile.json', folder / 'feature-profile.json')
    write(folder / 'capability-scope.json', dict(id=str(uuid.uuid4()), scope=plan['scope'], status='research_candidate', automaticExecutionEligible=False))
    write(folder / 'protection-set.json', dict(executionAllowed=False, protectedKinds=['management', 'gateway', 'dns']))
    frozen = read(dataset.contracts / 'docs/p2/freeze-manifest.json')
    extractor = {k: v for k, v in frozen['files'].items() if k.startswith('sensor/') and k.endswith(('.go', 'go.mod', 'go.sum'))}
    extractor_sha = hashlib.sha256(json.dumps(extractor, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    write(folder / 'extractor-binding.json', dict(sha256=extractor_sha, files=extractor))
    manifest = read(dataset.contracts / 'docs/contracts/examples/model-manifest.json')
    import importlib.metadata
    model_id = str(uuid.uuid4())
    manifest.update(modelId=model_id, modelVersion=out.name, createdAt=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
        artifactSha256=sha(folder / 'model.onnx'), featureProfileSha256=plan['featureProfileSha256'], extractorSha256=extractor_sha,
        preprocessingSha256=sha(folder / 'preprocessing.json'), calibrationSha256=sha(folder / 'calibration.json'),
        datasetManifestSha256=plan['datasetFreezeSha256'], splitManifestSha256=sha(dataset.root / 'partitions.json'),
        evaluationPlanSha256=sha(plan_path), algorithm=winner['algorithm'], algorithmVersion=importlib.metadata.version(winner['algorithm']),
        profiles=['flow-prefix-v1'], numericFeatures=dataset.profile['numericFeatures'], categoricalFeatures=dataset.profile['categoricalFeatures'],
        validationReportSha256=sha(out / 'validation-report.json'), finalEvaluationReportSha256=None,
        trainingCodeSha256=code_sha, trainingRunId=str(uuid.uuid4()), candidateOnly=True,
        runtime=dict(format='onnx', opset=17, maxProbabilityAbsError=error, runtimeVersion=importlib.metadata.version('onnxruntime')))
    contract_validator(dataset.contracts, 'model-manifest').validate(manifest)
    write(folder / 'model-manifest.json', manifest)
    policy = read(dataset.contracts / 'docs/contracts/examples/decision-policy.json')
    params = choice['parameters']
    policy.update(policyId=str(uuid.uuid4()), policyVersion=out.name, mode='alert_only', modelId=model_id,
        profile='flow-prefix-v1', alertThreshold=params['threshold'], autoThreshold=params['threshold'],
        minDistinctFlows=params['min_flows'], minEvidenceSpanMs=params['span_ms'], minPeerFlowStarts=params['min_starts'],
        maxTtlSeconds=params['ttl'], protectionSetSha256=sha(folder / 'protection-set.json'), evaluationPlanSha256=sha(plan_path),
        supportedCapabilityIds=[read(folder / 'capability-scope.json')['id']])
    contract_validator(dataset.contracts, 'decision-policy').validate(policy); write(folder / 'decision-policy.json', policy)
    write(out / 'stage-exit.json', stage_exit(by_role, by_scene, gain, parity_report, by_source))
    write(out / 'checksums.json', {p.relative_to(out).as_posix(): sha(p) for p in sorted(out.rglob('*')) if p.is_file()})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['check', 'run', 'resume'])
    for name in ('dataset', 'contracts', 'plan', 'output'): p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--rebind', type=Path, help='resume 模式下登记的零拟合重绑定目录')
    args = p.parse_args(); args.output.mkdir(parents=True, exist_ok=False)
    plan = read(args.plan); plan['planSha256'] = sha(args.plan)
    verification = compatibility(plan, args.dataset, args.contracts); write(args.output / 'runtime-check.json', verification)
    shutil.copyfile(args.plan, args.output / 'experiment-plan.json')
    if args.mode == 'check':
        print(json.dumps(verification))
        if not verification['trainingAllowed']: raise SystemExit(2)
        return
    if not verification['trainingAllowed']:
        write(args.output / 'stage-exit.json', dict(status='blocked', blockingReasons=verification['blockers'],
             newModelFits=0, candidateOnly=True, finalTestRead=False, automaticExecutionAuthorized=False))
        raise SystemExit(2)
    env = environment()
    if platform.system() != 'Windows' or env['trainingBranch'] != 'training/windows-cuda' or not env['cudaAvailable']:
        raise RuntimeError('训练主机、分支或CUDA环境不符')
    write(args.output / 'environment.json', env)
    dataset = PrefixDataset(args.dataset, args.contracts, plan, args.output / 'access-audit.jsonl')
    if args.mode == 'resume':
        if args.rebind is None: raise ValueError('resume 必须指定 --rebind')
        resume(dataset, plan, args.plan, args.output, args.rebind)
    else:
        run(dataset, plan, args.plan, args.output)


if __name__ == '__main__':
    main()
