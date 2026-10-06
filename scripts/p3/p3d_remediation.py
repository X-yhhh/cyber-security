"""P3-D 预处理 v2 修复：登记新运行计划，并对既有原生权重做零拟合重导出与选型重放。

只读取 train 与 validation_selection；不拟合、不复用失败 ONNX、不删除历史账本。
校准、独立开发角色以及 winner-seed-44 拟合须在审查新计划与本报告后另行执行。
"""
import argparse
import json
import shutil
from pathlib import Path

import numpy as np

from cyber_training.host_guard.data import PREPROCESS_V1, PREPROCESS_V2, Preprocessor, read, sha, write
from cyber_training.host_guard.evaluation import classification
from cyber_training.host_guard.export import export, parity, score_session, session
from cyber_training.host_guard.models import predict
from cyber_training.host_guard.prefix_data import PrefixDataset
from cyber_training.host_guard.prefix_evaluation import combine, objective, replay
from cyber_training.host_guard.prefix_plan import compatibility, load_health
from cyber_training.host_guard.prefix_runner import measure, policy_trial

MAIN = ['lightgbm-base-42', 'lightgbm-peer_context-42', 'xgboost-base-42', 'xgboost-peer_context-42']
SEEDS = ['winner-seed-43']
STATUS = 'p3d_remediation_preprocess_v2_rebind'
RESUME_STATUS = 'p3d_resume_after_preprocess_v2_rebind'
PREPROCESSING = ('p3-preprocess-v2: float32 input promoted to float64 for log(x+1), train-only weighted mean '
                 'imputation, centering and scaling, rounded to float32 once; mask preserved; train vocabulary '
                 'unknown=0; ONNX embeds the same float64 sequence; no IDs, ports, absolute timestamps, source or labels')


def ledger_entries(path):
    return [json.loads(line) for line in path.open(encoding='utf-8')]


def prepare(args):
    plan = read(args.base_plan)
    prior = args.prior_run
    fits = ledger_entries(prior / 'fit-ledger.jsonl')
    trials = ledger_entries(prior / 'policy-trials.jsonl')
    started = [r['id'] for r in fits if r['status'] == 'started']
    if started != MAIN + SEEDS or any(r['arm'] != 'model_selection' for r in trials):
        raise ValueError('历史拟合或策略账本与登记的修复范围不符')
    allocation = plan['budget']['policyTrialAllocation']
    plan.update(version='host-guard-p3-prefix-runtime-20261006-v5', date='2026-10-06', status=STATUS,
                preprocessing=PREPROCESSING)
    plan['export'] = dict(plan['export'], preprocessingVersion=PREPROCESS_V2)
    plan['remediation'] = dict(
        id='p3d-preprocess-v2-20261006',
        supersedesRuntimePlanSha256=sha(args.base_plan),
        priorRun=prior.name,
        priorFitLedgerSha256=sha(prior / 'fit-ledger.jsonl'),
        priorPolicyTrialsSha256=sha(prior / 'policy-trials.jsonl'),
        consumed=dict(fullFits=len(started), policyTrials=dict(model_selection=len(trials))),
        remaining=dict(fullFits=plan['budget']['maximumFullFits'] - len(started),
                       policyTrials={arm: cap - (len(trials) if arm == 'model_selection' else 0)
                                     for arm, cap in allocation.items()}),
        rootCause=('numpy float32 log 依平台 SIMD 实现，与 onnxruntime float32 Log 相差 1 ulp；XGBoost hist '
                   '分裂点恰为训练特征值，落在分裂点上的 train 行改走分支，winner-seed-43 最大分差 3.04e-4'),
        scope=['Preprocessor.transform 新增 p3-preprocess-v2（float64 计算后一次舍入 float32）',
               'ONNX 内嵌预处理按 v2 生成同序 double 算子',
               'XGBoost 原生 JSON 树导出器（工作区既有修改，随本计划代码哈希一并绑定）'],
        modelRefit=False,
        failedOnnxReused=False,
        reboundExperiments=MAIN + SEEDS,
        fitTimePreprocessing=('既有 5 个原生模型以 p3-preprocess-v1 特征拟合；重绑定只改变推理数值精度，'
                              'meanLog/scaleLog/indices/vocabularies 逐项不变'),
        parityGate=dict(maxProbabilityAbsError=plan['export']['maxProbabilityAbsError'],
                        thresholdDecisionFlipsAllowed=plan['export']['thresholdDecisionFlipsAllowed'], relaxed=False),
        rolesReadByRebind=['train', 'validation_selection'],
        reviewRequiredBefore=['winner-seed-44 拟合', 'selection-lock', 'validation_calibration 读取',
                              'independent_development 读取'])
    from cyber_training.host_guard import prefix_plan
    code_root = Path(prefix_plan.__file__).parent
    registry = read(args.dataset / 'health-registry.json')
    plan['datasetFreezeSha256'] = sha(args.dataset / 'readiness.json')
    plan['softwareFreezeSha256'] = sha(args.contracts / 'docs/p2/freeze-manifest.json')
    plan['featureProfileSha256'] = sha(args.contracts / 'docs/contracts/feature-profile.json')
    plan['codeFiles'] = {p.name: sha(p) for p in code_root.glob('*.py')}
    plan['captureHealth'] = dict(manifest='health-registry.json', sha256=sha(args.dataset / 'health-registry.json'),
                                 authenticatedCollectionRef=[s['authenticatedCollectionRef'] for s in registry['sessions']])
    relative = args.diagnostics.resolve().relative_to(args.dataset.resolve().parent).as_posix()
    plan['preFitDiagnostics'] = dict(plan['preFitDiagnostics'], file='../' + relative + '/diagnostics.json', sha256=None)
    args.output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def prepare_resume(args):
    """在零拟合修复计划之上登记接续：绑定重绑定证据与用户审查，代码哈希按当前文件重算。"""
    plan = read(args.base_plan)
    rebind = args.rebind
    report = read(rebind / 'rebind-report.json')
    if (plan['status'] != STATUS or not plan['preFitDiagnostics'].get('sha256')
            or report['status'] != 'parity_remediated_awaiting_review' or report['planSha256'] != sha(args.base_plan)
            or report['newModelFits'] != 0 or not report['winner']['unchanged']):
        raise ValueError('零拟合修复计划或重绑定报告不满足接续条件')
    remediation = plan['remediation']
    remediation['supersedesRemediationPlanSha256'] = sha(args.base_plan)
    remediation['rebind'] = dict(
        directory=rebind.name,
        files={name: sha(rebind / name) for name in ('rebind-report.json', 'rebind-ledger.jsonl',
                                                      'policy-trials.jsonl', 'prior-fit-ledger.jsonl')},
        winner=report['winner']['v2'],
        priorElapsedSeconds=127,
        priorElapsedBasis='上一轮 run 约 67 秒加零拟合重绑定约 60 秒（按输出文件时间戳）；不含此前导出器诊断脚本')
    remediation['review'] = dict(status='approved', by='user', date='2026-10-06',
                                 scope=['winner-seed-44 拟合（第 6 次完整拟合）', 'selection-lock',
                                        'validation_calibration 读取与校准/三臂策略选择',
                                        'independent_development 读取与冻结评价', '候选冻结与阶段出口'])
    plan.update(version='host-guard-p3-prefix-runtime-20261006-v6', status=RESUME_STATUS)
    from cyber_training.host_guard import prefix_plan
    plan['codeFiles'] = {p.name: sha(p) for p in Path(prefix_plan.__file__).parent.glob('*.py')}
    relative = args.diagnostics.resolve().relative_to(args.dataset.resolve().parent).as_posix()
    plan['preFitDiagnostics'] = dict(plan['preFitDiagnostics'], file='../' + relative + '/diagnostics.json', sha256=None)
    args.output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def finalize(args):
    plan = read(args.base_plan)
    report = read(args.diagnostics / 'diagnostics.json')
    if report['status'] != 'passed' or report['modelFits'] != 0 or plan['status'] not in (STATUS, RESUME_STATUS):
        raise ValueError('拟合前诊断未通过或计划状态不符')
    if report['latencyRegistrations'] != plan['evaluation']['latencyRegistrations']:
        raise ValueError('诊断时效登记与计划不一致，不能静默改写')
    plan['preFitDiagnostics']['sha256'] = sha(args.diagnostics / 'diagnostics.json')
    args.output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class BoosterProbability:
    """只为对拍提供 predict_proba；权重来自哈希绑定的 LightGBM 文本模型。"""
    def __init__(self, booster):
        self.booster = booster

    def predict_proba(self, x):
        p = self.booster.predict(x)
        return np.column_stack([1 - p, p])


def load_native(folder, algorithm):
    if algorithm == 'lightgbm':
        import lightgbm
        booster = lightgbm.Booster(model_file=str(folder / 'native-model.txt'))
        if not any('split_index' in tree['tree_structure'] for tree in booster.dump_model()['tree_info']):
            raise ValueError('常数 LightGBM 需走专用导出，不在本次修复范围')
        return folder / 'native-model.txt', booster, BoosterProbability(booster)
    import xgboost
    model = xgboost.XGBClassifier(); model.load_model(folder / 'native-model.json')
    return folder / 'native-model.json', model, model


def rebind(args):
    plan = read(args.plan); plan['planSha256'] = sha(args.plan)
    if plan.get('status') != STATUS or plan['remediation']['modelRefit'] is not False:
        raise ValueError('不是登记的零拟合修复计划')
    args.output.mkdir(parents=True, exist_ok=False)
    verification = compatibility(plan, args.dataset, args.contracts)
    write(args.output / 'runtime-check.json', verification)
    if not verification['trainingAllowed']:
        raise SystemExit(2)
    prior = args.prior_run
    remediation = plan['remediation']
    if (sha(prior / 'fit-ledger.jsonl') != remediation['priorFitLedgerSha256']
            or sha(prior / 'policy-trials.jsonl') != remediation['priorPolicyTrialsSha256']):
        raise ValueError('历史账本与计划登记不符')
    shutil.copyfile(args.plan, args.output / 'experiment-plan.json')
    shutil.copyfile(prior / 'fit-ledger.jsonl', args.output / 'prior-fit-ledger.jsonl')
    # 继承历史策略试验计数，使选型预算按整轮累计而不是从零开始。
    shutil.copyfile(prior / 'policy-trials.jsonl', args.output / 'policy-trials.jsonl')
    plan['_health'] = load_health(plan, args.dataset)
    dataset = PrefixDataset(args.dataset, args.contracts, plan, args.output / 'access-audit.jsonl')
    train = dataset.load('train'); selection = dataset.load('validation_selection')
    timeline = dataset.timeline(['train', 'validation_selection'])
    tuning = combine([train, selection])
    passed = {r['id']: r for r in ledger_entries(prior / 'fit-ledger.jsonl') if r['status'] == 'passed'}
    entries = []
    for name in MAIN + SEEDS:
        source = prior / 'experiments' / name
        algorithm = 'lightgbm' if name.startswith('lightgbm') else 'xgboost'
        native_path, model, scorer = load_native(source, algorithm)
        native_sha = sha(native_path)
        if name in passed and passed[name]['nativeModelSha256'] != native_sha:
            raise ValueError('原生权重与历史账本不符: ' + name)
        historical = read(source / 'preprocessing.json')
        if historical.get('version') != PREPROCESS_V1:
            raise ValueError('历史预处理版本不符: ' + name)
        parameters = dict(historical, version=PREPROCESS_V2)
        pre = Preprocessor(parameters)
        folder = args.output / 'experiments' / name; folder.mkdir(parents=True)
        write(folder / 'preprocessing.json', parameters)
        export(algorithm, model, pre, {'method': 'none'}, folder / 'model.onnx')
        check = parity(folder / 'model.onnx', algorithm, scorer, pre, {'method': 'none'}, [train, selection],
                       plan['decision']['thresholds'])
        np.savez_compressed(folder / 'native-scores.npz', train=predict(algorithm, scorer, pre.transform(train)),
                            selection=predict(algorithm, scorer, pre.transform(selection)))
        entry = dict(id=name, algorithm=algorithm, featureSet=historical['featureSet'], modelFitPerformed=False,
                     nativeModelSha256=native_sha, historicalPreprocessingSha256=sha(source / 'preprocessing.json'),
                     preprocessingSha256=sha(folder / 'preprocessing.json'), artifactSha256=sha(folder / 'model.onnx'),
                     parity=check, historicalWorkingPoint=passed.get(name, {}).get('workingPoint'))
        if check['status'] != 'passed':
            entry['status'] = 'parity_failed'; entries.append(entry)
            break
        inference = session(folder / 'model.onnx')
        scores = score_session(inference, pre, tuning)
        selection_scores = score_session(inference, pre, selection)
        trials = []
        for threshold in plan['decision']['thresholds']:
            policy_trial(args.output, plan, 'model_selection')
            result = replay(tuning, scores, dict(threshold=threshold), timeline, plan=plan, health=plan['_health'])
            trials.append(dict(threshold=threshold, metrics=measure(timeline, result, plan, role='validation_selection')))
        choice = max(trials, key=lambda r: (objective(r['metrics']), r['threshold']))
        entry.update(status='passed', workingPoint=choice,
                     classification=classification(selection, selection_scores, choice['threshold']))
        entries.append(entry)
        write(folder / 'report.json', entry)
    with (args.output / 'rebind-ledger.jsonl').open('x', encoding='utf-8') as stream:
        for entry in entries:
            stream.write(json.dumps(entry, ensure_ascii=False) + '\n')
    complete = len(entries) == len(MAIN + SEEDS) and all(e['status'] == 'passed' for e in entries)
    ranking = lambda r: (objective(r['workingPoint']['metrics']), -r['classification']['logLoss'], r['id'])
    winner = max((e for e in entries if e['id'] in MAIN), key=ranking)['id'] if complete else None
    historical = [passed[name] for name in MAIN]
    historical_winner = max(historical, key=ranking)['id']
    trials_used = ledger_entries(args.output / 'policy-trials.jsonl')
    report = dict(
        version='p3d-preprocess-v2-rebind-v1', status='parity_remediated_awaiting_review' if complete else 'failed',
        planSha256=plan['planSha256'], modelFits=0, newModelFits=0, finalTestRead=False,
        rolesRead=['train', 'validation_selection'], candidateOnly=True, automaticExecutionAuthorized=False,
        rows=len(train.rows) + len(selection.rows),
        parity={e['id']: dict(status=e['parity']['status'], maxAbsError=e['parity']['maxAbsError'],
                              thresholdFlips=e['parity']['thresholdFlips']) for e in entries},
        workingPoints={e['id']: dict(v1=(e['historicalWorkingPoint'] or {}).get('threshold'),
                                     v2=e.get('workingPoint', {}).get('threshold')) for e in entries},
        winner=dict(v1=historical_winner, v2=winner, unchanged=winner == historical_winner),
        policyTrials=dict(total=len(trials_used), modelSelection=sum(r['arm'] == 'model_selection' for r in trials_used),
                          inherited=remediation['consumed']['policyTrials']['model_selection']),
        fullFits=dict(consumed=remediation['consumed']['fullFits'], added=0,
                      remaining=remediation['remaining']['fullFits']),
        nextStepsRequireReview=remediation['reviewRequiredBefore'])
    write(args.output / 'rebind-report.json', report)
    write(args.output / 'checksums.json', {p.relative_to(args.output).as_posix(): sha(p)
                                           for p in sorted(args.output.rglob('*')) if p.is_file()})
    print(json.dumps(report, ensure_ascii=False))
    if not complete:
        raise SystemExit(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['prepare', 'prepare-resume', 'finalize', 'rebind'])
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--contracts', type=Path, required=True)
    parser.add_argument('--prior-run', type=Path, required=True)
    parser.add_argument('--base-plan', type=Path)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--diagnostics', type=Path)
    parser.add_argument('--rebind', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    {'prepare': prepare, 'prepare-resume': prepare_resume, 'finalize': finalize, 'rebind': rebind}[args.mode](args)


if __name__ == '__main__':
    main()
