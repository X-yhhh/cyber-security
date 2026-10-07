"""P3-B 受控复现：在负责人书面调整的累计预算内只复现一次 main-lightgbm-seed42。

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

TARGET = 'main-lightgbm-seed42'
AUTHORIZATION = {'date': '2026-10-07', 'by': '项目负责人', 'budget': 33,
                 'scope': '仅复现 main-lightgbm-seed42 一次，用于补齐原生模型与完整 train 框架对拍',
                 'countingRule': 'smoke、中断与工程故障重跑全部计入；预留即计数，失败不退还'}
REFERENCE_ONNX = {'train': '72b6c6c97d138c8401f2c3b673e79aab549a69e2fb21f6793993fe4022915606',
                  'validation': '6f6ff75b269828d2e7e01d52df77a649563788075c9c4a262658af608b9ac3df'}
REFERENCE_MODEL = '4951673b3255d3b52d138b4b16ca4ebb4e389986b1f50a42827f6efc3f5ec238'
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


def reserve_fit(ledger: Path, run: str, budget: int = AUTHORIZATION['budget']) -> int:
    """拟合前预留；超出书面预算即拒绝，不能靠删除失败 run 腾出名额。"""
    count = ledger_count(ledger)
    if count + 1 > budget:
        raise RuntimeError(f'累计拟合预算不足: 已计 {count}，上限 {budget}')
    append_event(ledger, {'event': 'fit-reserved', 'run': run, 'target': TARGET, 'countAfter': count + 1,
                          'budget': budget, 'authorization': AUTHORIZATION})
    return count + 1


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


def split_counts(path: Path) -> dict:
    """树分裂次数，仅描述模型使用了哪些输入，不是增益或因果归因。"""
    import onnx
    counts = Counter()
    for node in onnx.load(path).graph.node:
        if node.op_type == 'TreeEnsembleClassifier':
            attrs = {a.name: onnx.helper.get_attribute_value(a) for a in node.attribute}
            for feature, mode in zip(attrs['nodes_featureids'], attrs['nodes_modes']):
                if mode != b'LEAF':
                    counts[int(feature)] += 1
    names = NUMERIC + ['missing:' + n for n in NUMERIC] + ['transport', 'direction', 'serviceClass']
    return {'importanceType': 'tree split count; not gain or causal attribution',
            'splitCounts': [{'feature': names[i], 'count': n} for i, n in counts.most_common()]}


def fit(args):
    import lightgbm
    args.run.mkdir(parents=False, exist_ok=False)
    reference = args.reference_run / 'models' / TARGET
    if sha256(reference / 'model.onnx') != REFERENCE_MODEL:
        raise ValueError('v3 参照模型哈希不符')
    for role, digest in REFERENCE_ONNX.items():
        if sha256(args.reference_outputs / f'{role}-onnx.npy') != digest:
            raise ValueError(f'v3 参照 {role} 输出哈希不符')
    manifest = code_manifest(Path(__file__).resolve().parent)
    write_new(args.run / 'code-manifest.json', manifest)
    train = load_development(args.frozen, args.sidecars, 'train')
    validation = load_development(args.frozen, args.sidecars, 'validation')
    pre = Preprocessor('full', True).fit(train)
    expected = json.loads((reference / 'preprocessing.json').read_text(encoding='utf-8'))
    if json.loads(json.dumps(pre.parameters())) != expected:
        raise ValueError('预处理参数与 v3 不同，停止且不占用拟合预算')
    write_new(args.run / 'preprocessing.json', pre.parameters())
    x_train, x_validation = pre.transform(train), pre.transform(validation)
    weights, balance = sample_weights(train, default_config()['class_weight_cap'])
    initialize_ledger(args.ledger, args.inventory)
    count = reserve_fit(args.ledger, args.run.name)
    model, info = fit_model('lightgbm', x_train, train.labels, weights, 42, default_config(), (x_validation, validation.labels))
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
    summary = {'stage': 'P3-B', 'run': args.run.name, 'target': TARGET, 'fitCountAfter': count,
               'budget': AUTHORIZATION['budget'], 'authorization': AUTHORIZATION, 'fit': info,
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
               'reproduction': {'referenceModelSha256': REFERENCE_MODEL, 'byRole': reproduction,
                                'bitIdentical': identical,
                                'conclusion': 'same predictions as v3 candidate' if identical
                                else 'new model; v3 scores must not be reused'}}
    write_new(args.run / 'reproduction-summary.json', summary)
    append_event(args.ledger, {'event': 'fit-completed', 'run': args.run.name, 'target': TARGET,
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
    write_new(args.output / 'feature-importance.json', split_counts(args.run / 'model.onnx'))
    passed = all(v['status'] == 'passed' for c in comparisons.values() for v in c.values())
    result = common | {'platformParity': comparisons, 'platformParityPassed': passed,
                       'alertMatchesWindows': alert == summary['alertThreshold'],
                       'validationExitPassed': report['attackDetection'] >= .85 and report['falsePositiveRate'] <= .02,
                       'macroF1': report['macroF1'], 'attackDetection': report['attackDetection'],
                       'falsePositiveRate': report['falsePositiveRate']}
    write_new(args.output / 'verification.json', result)
    print(json.dumps(result, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    fit_parser = sub.add_parser('fit')
    fit_parser.add_argument('--run', type=Path, required=True)
    fit_parser.add_argument('--reference-run', type=Path, required=True)
    fit_parser.add_argument('--reference-outputs', type=Path, required=True)
    fit_parser.add_argument('--ledger', type=Path, required=True)
    fit_parser.add_argument('--inventory', type=Path, required=True)
    verify_parser = sub.add_parser('verify')
    verify_parser.add_argument('--run', type=Path, required=True)
    verify_parser.add_argument('--output', type=Path, required=True)
    for item in (fit_parser, verify_parser):
        item.add_argument('--frozen', type=Path, required=True)
        item.add_argument('--sidecars', type=Path, required=True)
    args = parser.parse_args()
    fit(args) if args.command == 'fit' else verify(args)


if __name__ == '__main__':
    main()
