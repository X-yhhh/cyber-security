"""P3-B 受控复现：按显式登记参数复现候选，第二轮使用独立只追加预算。

``fit`` 只在 Windows 训练端运行：先核验冻结数据、旁路、代码清单和预处理参数，
再向全局台账预留 1 次拟合（失败也计数），随后保存原生 LightGBM 文本模型、
train/validation 全量框架概率、int64 输入 ONNX，并与 v3 原 ONNX 输出逐行比对。
``verify`` 为零拟合，任一平台用同一 ONNX 对照 Windows 框架概率并重算 validation
审计。两者都不读取 test/L3，不生成动作或发布包，候选保持 candidateOnly/alert_only。
"""
from __future__ import annotations

import argparse
from collections import Counter
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import sys

import numpy as np

try:
    from .multiclass_train import (CLASSES, NUMERIC, Preprocessor, default_config, export_onnx, fit_model,
                                   sample_weights, sha256, write_new, append_event)
    from .multiclass_audit import (Connections, choose_alert, compare_outputs, distribution, feed_for,
                                   load_development, policy_preview, predict, session, tune_rules, HASHES, SIDECAR_HASHES)
except ImportError:
    from multiclass_train import (CLASSES, NUMERIC, Preprocessor, default_config, export_onnx, fit_model,
                                  sample_weights, sha256, write_new, append_event)
    from multiclass_audit import (Connections, choose_alert, compare_outputs, distribution, feed_for,
                                  load_development, policy_preview, predict, session, tune_rules, HASHES, SIDECAR_HASHES)

CODE_FILES = ('multiclass_train.py', 'multiclass_audit.py', 'multiclass_reproduce.py')
PACKAGES = ('numpy', 'lightgbm', 'scikit-learn', 'onnx', 'onnxmltools', 'onnxruntime')


def ledger_count(ledger: Path) -> int:
    """历史 run 的已完成拟合与每次预留之和；预留后失败的拟合同样计入。"""
    events = [json.loads(line) for line in ledger.read_text(encoding='utf-8').splitlines() if line.strip()]
    return sum(e['completedFits'] for e in events if e['event'] == 'historical-run') + \
        sum(1 for e in events if e['event'] == 'fit-reserved')


def initialize_ledger(ledger: Path, inventory: Path) -> None:
    """首次使用时把零拟合清点结果转为只追加台账；已有台账不重写。"""
    if ledger.exists():
        return
    value = json.loads(inventory.read_text(encoding='utf-8'))
    for run in value['runs']:
        append_event(ledger, {'event': 'historical-run', 'run': run['run'], 'completedFits': run['completedFits'],
                              'eventSha256': run['eventSha256'], 'inventorySha256': sha256(inventory)})
    if ledger_count(ledger) != value['provenFitLowerBound']:
        raise ValueError('台账初始化与清点下界不一致')


def reserve_fit(ledger: Path, run: str, budget: int, target: str, authorization: dict) -> int:
    """拟合前预留；超出书面预算即拒绝，不能靠删除失败 run 腾出名额。"""
    lock = ledger.with_name(ledger.name + '.lock')
    lock.mkdir()
    try:
        count = ledger_count(ledger)
        if count + 1 > budget:
            raise RuntimeError(f'累计拟合预算不足: 已计 {count}，上限 {budget}')
        append_event(ledger, {'event': 'fit-reserved', 'run': run, 'target': target, 'countAfter': count + 1,
                              'budget': budget, 'authorization': authorization})
        return count + 1
    finally:
        lock.rmdir()


def checked_round(args):
    """新台账绑定书面授权及历史台账字节；旧轮次只读，不能重置或混入本轮。"""
    if args.ledger.resolve() == args.historical_ledger.resolve() or sha256(args.historical_ledger) != args.historical_ledger_sha256:
        raise ValueError('历史台账路径或哈希非法')
    authorization = json.loads(args.authorization.read_text(encoding='utf-8'))
    if (args.budget < 1 or authorization.get('budget') != args.budget
            or authorization.get('target') != args.target or authorization.get('featureSet') != args.feature_set
            or authorization.get('seed') != args.seed
            or any(not isinstance(authorization.get(k), str) or not authorization[k].strip()
                   for k in ('date', 'by', 'scope', 'countingRule', 'roundId'))):
        raise ValueError('授权说明缺项或与拟合参数不符')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', args.target):
        raise ValueError('目标名必须为单一名称')
    binding = {'event': 'round-opened', 'roundId': authorization['roundId'],
               'authorizationSha256': sha256(args.authorization), 'budget': args.budget,
               'historicalLedgerSha256': args.historical_ledger_sha256,
               'historicalFitCount': ledger_count(args.historical_ledger)}
    args.ledger.parent.mkdir(parents=True, exist_ok=True)
    if not args.ledger.exists():
        with args.ledger.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(binding, ensure_ascii=False, sort_keys=True) + '\n')
    first = json.loads(args.ledger.read_text(encoding='utf-8').splitlines()[0])
    if first != binding:
        raise ValueError('本轮台账绑定不同；不得重用历史或其他轮次台账')
    return authorization


def code_manifest(root: Path) -> dict:
    """记录实际执行的源码与依赖；缺依赖时如实记 null，不推断版本。"""
    versions = {}
    for name in PACKAGES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return {'files': {name: sha256(root / name) for name in CODE_FILES}, 'packages': versions,
            'python': sys.version.split()[0], 'platform': platform.platform(), 'config': default_config()}


def framework_output(probabilities: np.ndarray) -> np.ndarray:
    """原生概率转成与 ONNX 相同的 [attack_score, family_scores] 布局。"""
    return np.column_stack([1.0 - probabilities[:, 0], probabilities[:, 1:]]).astype(np.float32)


def max_difference(expected: np.ndarray, actual: np.ndarray) -> float:
    return float(np.max(np.abs(expected.astype(np.float64) - actual.astype(np.float64))))


def split_counts(path: Path, numeric_indices: list[int]) -> dict:
    """按冻结选列还原树输入名；分裂次数不是增益或因果归因。"""
    import onnx
    counts = Counter()
    for node in onnx.load(path).graph.node:
        if node.op_type == 'TreeEnsembleClassifier':
            attrs = {a.name: onnx.helper.get_attribute_value(a) for a in node.attribute}
            for feature, mode in zip(attrs['nodes_featureids'], attrs['nodes_modes']):
                if mode != b'LEAF':
                    counts[int(feature)] += 1
    selected = [NUMERIC[index] for index in numeric_indices]
    names = selected + ['missing:' + n for n in selected] + ['transport', 'direction', 'serviceClass']
    return {'importanceType': 'tree split count; not gain or causal attribution',
            'splitCounts': [{'feature': names[i], 'count': n} for i, n in counts.most_common()]}


def fit(args):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', args.target):
        raise ValueError('目标名必须为单一名称')
    import lightgbm
    reference = args.reference_run / 'models' / args.target
    if sha256(reference / 'model.onnx') != args.reference_model_sha256:
        raise ValueError('参照模型哈希不符')
    output_hashes = {'train': args.reference_train_sha256, 'validation': args.reference_validation_sha256}
    for role, digest in output_hashes.items():
        if sha256(args.reference_outputs / f'{role}-onnx.npy') != digest:
            raise ValueError(f'参照 {role} 输出哈希不符')
    binding = json.loads((args.reference_outputs / 'reference-bindings.json').read_text(encoding='utf-8'))
    if (binding['modelSha256'] != args.reference_model_sha256 or binding['outputs'] != output_hashes
            or binding['datasetSha256'] != HASHES or binding['metadataSha256'] != SIDECAR_HASHES
            or binding['preprocessingSha256'] != sha256(reference / 'preprocessing.json')
            or binding['target'] != args.target or binding['featureSet'] != args.feature_set
            or binding['seed'] != args.seed or binding['testRead'] or binding['newFits'] != 0):
        raise ValueError('参照输出登记不符')
    # 授权与台账只读核验先于建目录和读全量数据，失败时不留下不可复用的 run 目录。
    authorization = checked_round(args)
    args.run.mkdir(parents=False, exist_ok=False)
    manifest = code_manifest(Path(__file__).resolve().parent)
    write_new(args.run / 'code-manifest.json', manifest)
    train = load_development(args.frozen, args.sidecars, 'train')
    validation = load_development(args.frozen, args.sidecars, 'validation')
    pre = Preprocessor(args.feature_set, True).fit(train)
    expected = json.loads((reference / 'preprocessing.json').read_text(encoding='utf-8'))
    if json.loads(json.dumps(pre.parameters())) != expected:
        raise ValueError('预处理参数与 v3 不同，停止且不占用拟合预算')
    write_new(args.run / 'preprocessing.json', pre.parameters())
    x_train, x_validation = pre.transform(train), pre.transform(validation)
    weights, balance = sample_weights(train, default_config()['class_weight_cap'])
    count = reserve_fit(args.ledger, args.run.name, args.budget, args.target, authorization)
    model, info = fit_model('lightgbm', x_train, train.labels, weights, args.seed, default_config(), (x_validation, validation.labels))
    model.booster_.save_model(str(args.run / 'native-model.txt'))
    native = lightgbm.Booster(model_file=str(args.run / 'native-model.txt'))
    outputs, comparisons = {}, {}
    for role, data, x in (('train', train, x_train), ('validation', validation, x_validation)):
        probabilities = np.asarray(model.predict_proba(x), dtype=np.float64)
        reloaded = np.asarray(native.predict(x), dtype=np.float64)
        np.save(args.run / f'framework-{role}.npy', probabilities, allow_pickle=False)
        comparisons[role] = {'nativeReloadMaxAbsError': max_difference(probabilities, reloaded)}
        outputs[role] = framework_output(probabilities)
    export_onnx(model, 'lightgbm', pre, args.run / 'model.onnx')
    runtime = session(args.run / 'model.onnx')
    if next(i.type for i in runtime.get_inputs() if i.name == 'categorical_codes') != 'tensor(int64)':
        raise ValueError('导出图类别输入不是契约 int64')
    onnx_outputs = {}
    for role, data in (('validation', validation), ('train', train)):
        onnx_outputs[role] = predict(runtime, feed_for(data, pre, runtime))
        np.save(args.run / f'onnx-{role}.npy', onnx_outputs[role], allow_pickle=False)
    index = Connections(validation)
    alert = choose_alert(index, onnx_outputs['validation'])
    reproduction = {}
    for role in ('train', 'validation'):
        comparisons[role]['frameworkVsOnnx'] = compare_outputs(outputs[role], onnx_outputs[role], alert)
        original = np.load(args.reference_outputs / f'{role}-onnx.npy', allow_pickle=False)
        reproduction[role] = compare_outputs(original, onnx_outputs[role], alert) | {
            'maxAbsError': max_difference(original, onnx_outputs[role]),
            'bitIdentical': bool(np.array_equal(original, onnx_outputs[role]))}
    report = index.report(index.decisions(onnx_outputs['validation'], alert))
    identical = all(r['bitIdentical'] for r in reproduction.values())
    summary = {'stage': 'P3-B', 'run': args.run.name, 'target': args.target, 'fitCountAfter': count,
               'featureSet': args.feature_set, 'seed': args.seed, 'roundId': authorization['roundId'],
               'reservationLedgerSha256': sha256(args.ledger), 'historicalLedgerSha256': args.historical_ledger_sha256,
               'referenceOutputSha256': output_hashes, 'referenceBindingsSha256': sha256(args.reference_outputs / 'reference-bindings.json'),
               'budget': args.budget, 'authorization': authorization, 'fit': info,
               'classBalanceFactors': balance, 'candidateOnly': True, 'finalTestRead': False, 'mode': 'alert_only',
               'datasetSha256': HASHES, 'metadataSha256': SIDECAR_HASHES,
               'codeManifestSha256': sha256(args.run / 'code-manifest.json'),
               'artifacts': {name: sha256(args.run / name) for name in (
                   'native-model.txt', 'model.onnx', 'preprocessing.json', 'framework-train.npy',
                   'framework-validation.npy', 'onnx-train.npy', 'onnx-validation.npy')},
               'nativeFormat': 'LightGBM text model; no pickle/joblib',
               'alertThreshold': alert, 'validation': report,
               'validationExitPassed': report['attackDetection'] >= .85 and report['falsePositiveRate'] <= .02,
               'parity': comparisons,
               'frameworkParityPassed': all(c['frameworkVsOnnx']['status'] == 'passed' and c['nativeReloadMaxAbsError'] <= 1e-9
                                            for c in comparisons.values()),
               'reproduction': {'referenceModelSha256': args.reference_model_sha256, 'byRole': reproduction,
                                'bitIdentical': identical,
                                'conclusion': 'same predictions as v3 candidate' if identical
                                else 'new model; v3 scores must not be reused'}}
    write_new(args.run / 'reproduction-summary.json', summary)
    append_event(args.ledger, {'event': 'fit-completed', 'run': args.run.name, 'target': args.target,
                               'summarySha256': sha256(args.run / 'reproduction-summary.json')})
    print(json.dumps({'run': args.run.name, 'fitCountAfter': count, 'bitIdentical': identical,
                      'frameworkParityPassed': summary['frameworkParityPassed'], 'alertThreshold': alert,
                      'macroF1': report['macroF1'], 'attackDetection': report['attackDetection'],
                      'falsePositiveRate': report['falsePositiveRate']}, ensure_ascii=False), flush=True)


def verify(args):
    """零拟合：本平台运行同一 ONNX，对照 Windows 框架概率，并重算 validation 审计。"""
    args.output.mkdir(parents=True, exist_ok=False)
    summary = json.loads((args.run / 'reproduction-summary.json').read_text(encoding='utf-8'))
    for name, digest in summary['artifacts'].items():
        if sha256(args.run / name) != digest:
            raise ValueError(f'复现产物哈希不符: {name}')
    pre = Preprocessor.restore(json.loads((args.run / 'preprocessing.json').read_text(encoding='utf-8')))
    runtime = session(args.run / 'model.onnx')
    comparisons = {}
    validation_output = None
    for role in ('validation', 'train'):
        data = load_development(args.frozen, args.sidecars, role)
        actual = predict(runtime, feed_for(data, pre, runtime))
        framework = framework_output(np.load(args.run / f'framework-{role}.npy', allow_pickle=False))
        windows_onnx = np.load(args.run / f'onnx-{role}.npy', allow_pickle=False)
        comparisons[role] = {'frameworkVsLocalOnnx': compare_outputs(framework, actual, summary['alertThreshold']),
                             'windowsOnnxVsLocalOnnx': compare_outputs(windows_onnx, actual, summary['alertThreshold'])}
        if role == 'validation':
            validation, validation_output = data, actual
            np.save(args.output / 'validation-onnx.npy', actual, allow_pickle=False)
        else:
            del data
    index = Connections(validation)
    alert = choose_alert(index, validation_output)
    report = index.report(index.decisions(validation_output, alert))
    common = {'candidateOnly': True, 'finalTestRead': False, 'newFits': 0, 'mode': 'alert_only',
              'modelSha256': sha256(args.run / 'model.onnx'), 'alertThreshold': alert,
              'runtime': {'os': platform.system(), 'python': platform.python_version(),
                          'onnxruntime': __import__('onnxruntime').__version__, 'provider': 'CPUExecutionProvider'}}
    write_new(args.output / 'validation-report.json', common | report)
    write_new(args.output / 'score-distributions.json', distribution(index, validation_output))
    write_new(args.output / 'rules-comparison.json', tune_rules(validation, index, validation_output, alert))
    write_new(args.output / 'policy-preview.json', policy_preview(validation, validation_output, alert))
    write_new(args.output / 'feature-importance.json', split_counts(args.run / 'model.onnx', pre.indices))
    passed = all(v['status'] == 'passed' for c in comparisons.values() for v in c.values())
    result = common | {'platformParity': comparisons, 'platformParityPassed': passed,
                       'alertMatchesWindows': alert == summary['alertThreshold'],
                       'validationExitPassed': report['attackDetection'] >= .85 and report['falsePositiveRate'] <= .02,
                       'macroF1': report['macroF1'], 'attackDetection': report['attackDetection'],
                       'falsePositiveRate': report['falsePositiveRate']}
    write_new(args.output / 'verification.json', result)
    print(json.dumps(result, ensure_ascii=False), flush=True)


def reference_outputs(args):
    """登记 run 的现有图零拟合推理开发集；原图类别类型沿用，不读测试角色。"""
    if not re.fullmatch(r'[A-Za-z0-9_-]+', args.target):
        raise ValueError('目标名必须为单一名称')
    source = args.reference_run / 'models' / args.target
    summary = json.loads((args.reference_run / 'run-summary.json').read_text(encoding='utf-8'))
    records = [item for item in summary['fits'] if item['name'] == args.target]
    if len(records) != 1 or summary['finalTestRead'] or summary['status'] != 'completed':
        raise ValueError('参照 run 未登记或已读取 test')
    record = records[0]
    if record['artifactSha256'] != args.reference_model_sha256 or sha256(source / 'model.onnx') != args.reference_model_sha256:
        raise ValueError('参照模型与 run 哈希不符')
    if record['export'] != 'passed' or record['featureSet'] not in ('full', 'no_host_context'):
        raise ValueError('参照特征或导出状态不符')
    pre_path = source / 'preprocessing.json'
    pre = Preprocessor.restore(json.loads(pre_path.read_text(encoding='utf-8')))
    if pre.feature_set != record['featureSet'] or not pre.include_service_class:
        raise ValueError('参照预处理不符')
    args.output.mkdir(parents=True, exist_ok=True)
    names = ('train-onnx.npy', 'validation-onnx.npy', 'reference-bindings.json')
    if any((args.output / name).exists() for name in names):
        raise ValueError('参照输出已存在，禁止覆盖')
    runtime = session(source / 'model.onnx')
    rows, hashes = {}, {}
    for role in ('train', 'validation'):
        data = load_development(args.frozen, args.sidecars, role)
        actual = predict(runtime, feed_for(data, pre, runtime))
        if actual.shape != (len(data.rows), 5) or not np.isfinite(actual).all():
            raise ValueError('参照输出维度不符')
        with (args.output / f'{role}-onnx.npy').open('xb') as stream:
            np.save(stream, actual, allow_pickle=False)
        rows[role], hashes[role] = len(actual), sha256(args.output / f'{role}-onnx.npy')
    result = {'target': args.target, 'modelSha256': args.reference_model_sha256,
              'featureSet': record['featureSet'], 'seed': record['seed'], 'rows': rows,
              'preprocessingSha256': sha256(pre_path), 'outputs': hashes,
              'runSummarySha256': sha256(args.reference_run / 'run-summary.json'),
              'datasetSha256': HASHES, 'metadataSha256': SIDECAR_HASHES,
              'codeManifest': code_manifest(Path(__file__).resolve().parent), 'newFits': 0, 'testRead': False}
    write_new(args.output / 'reference-bindings.json', result)
    print(json.dumps(result, ensure_ascii=False), flush=True)


def parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    fit_parser = sub.add_parser('fit')
    fit_parser.add_argument('--run', type=Path, required=True)
    fit_parser.add_argument('--reference-run', type=Path, required=True)
    fit_parser.add_argument('--reference-outputs', type=Path, required=True)
    fit_parser.add_argument('--ledger', type=Path, required=True)
    fit_parser.add_argument('--target', required=True)
    fit_parser.add_argument('--feature-set', choices=('full', 'no_host_context'), required=True)
    fit_parser.add_argument('--seed', type=int, required=True)
    for name in ('reference-model-sha256', 'reference-train-sha256', 'reference-validation-sha256', 'historical-ledger-sha256'):
        fit_parser.add_argument('--' + name, required=True)
    fit_parser.add_argument('--budget', type=int, required=True)
    fit_parser.add_argument('--authorization', type=Path, required=True)
    fit_parser.add_argument('--historical-ledger', type=Path, required=True)
    verify_parser = sub.add_parser('verify')
    verify_parser.add_argument('--run', type=Path, required=True)
    verify_parser.add_argument('--output', type=Path, required=True)
    reference_parser = sub.add_parser('reference')
    reference_parser.add_argument('--reference-run', type=Path, required=True)
    reference_parser.add_argument('--target', required=True)
    reference_parser.add_argument('--reference-model-sha256', required=True)
    reference_parser.add_argument('--output', type=Path, required=True)
    for item in (fit_parser, verify_parser, reference_parser):
        item.add_argument('--frozen', type=Path, required=True)
        item.add_argument('--sidecars', type=Path, required=True)
    return parser


def main():
    args = parser().parse_args()
    {'fit': fit, 'verify': verify, 'reference': reference_outputs}[args.command](args)


if __name__ == '__main__':
    main()
