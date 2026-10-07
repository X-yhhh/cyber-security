"""P3-B 零拟合收尾：仅开发集推理、来源预览、规则对比和跨平台证据。

不加载 test/L3、不拟合模型、不生成动作或发布包。旧结果只读保留；输出新目录。
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime
import heapq
import json
from pathlib import Path
import platform
import time

import numpy as np
import onnxruntime as ort

try:
    from .multiclass_train import CLASSES, NUMERIC, Dataset, Preprocessor, sha256, write_new
except ImportError:
    from multiclass_train import CLASSES, NUMERIC, Dataset, Preprocessor, sha256, write_new

HASHES = {
    'train': '9f2a19313725b373b774e796a6523cbec37d46727ceecb55bb925596ad873572',
    'validation': '2e168dfac592207e0448529ff93d8a6ccbcbeec265253dd0354bfc463940d568',
}
SIDECAR_HASHES = {
    'train': '9bbbd28aa8d706abb70c10b102edbe42a7a42ed4dd919a4bb5807bf882fe2cb3',
    'validation': 'e23001fa5824a921be099875ae7ffa1abd427bef574c9bf12d97e2c4b4440296',
}


def load_development(frozen, sidecars, role):
    """先核验开发旁路与冻结文件，身份只用于评估，禁止进入模型输入。"""
    metadata = sidecars / role / 'metadata.jsonl'
    if sha256(metadata) != SIDECAR_HASHES[role]:
        raise ValueError('旁路哈希不符')
    return Dataset.load(frozen / role / 'dataset.jsonl', role, HASHES[role], metadata)


def session(path):
    options = ort.SessionOptions()
    options.intra_op_num_threads = 8
    options.inter_op_num_threads = 1
    return ort.InferenceSession(str(path), sess_options=options, providers=['CPUExecutionProvider'])


def feed_for(data, pre, runtime):
    code_type = next(i.type for i in runtime.get_inputs() if i.name == 'categorical_codes')
    return {'numeric_values': data.values, 'numeric_missing': data.missing,
            'categorical_codes': pre.codes(data).astype(np.int64 if code_type == 'tensor(int64)' else np.float32)}


def predict(runtime, feed):
    attack, family = runtime.run(['attack_score', 'family_scores'], feed)
    output = np.column_stack([attack[:, 0], family]).astype(np.float32)
    if not np.isfinite(output).all() or np.any(output < -1e-6) or np.any(output > 1.000001):
        raise ValueError('ONNX 输出非法')
    return output


class Connections:
    """预建 parent 与时间索引，逐阈值评价不再重复构造 8 万个列表。"""

    def __init__(self, data):
        self.data = data
        parents, self.first, self.inverse = np.unique(data.parent_ids, return_index=True, return_inverse=True)
        self.count = len(parents)
        self.labels = data.labels[self.first]
        if not np.array_equal(self.labels[self.inverse], data.labels):
            raise ValueError('同一连接标签冲突')
        self.sources = data.source_ids[self.first]
        self.scenarios = np.asarray([data.rows[i].get('originalScenario', data.rows[i].get('activityId'))
                                     for i in self.first])
        self.times = np.asarray([datetime.fromisoformat(m['asOf'].replace('Z', '+00:00')).timestamp()
                                 for m in data.metadata])
        self.order = np.argsort(self.times, kind='stable')

    def selected(self, hits):
        ranked = np.where(hits[self.order], np.arange(len(hits)), len(hits))
        first_hit = np.full(self.count, len(hits), dtype=np.int64)
        np.minimum.at(first_hit, self.inverse[self.order], ranked)
        exists = first_hit < len(hits)
        indices = self.order[np.minimum(first_hit, len(hits) - 1)]
        return indices, exists

    def decisions(self, output, threshold):
        indices, exists = self.selected(output[:, 0].astype(np.float64) >= float(threshold))
        return np.where(exists, np.argmax(output[indices, 1:], axis=1) + 1, 0)

    def report(self, predicted):
        return report_predictions(self.labels, predicted, self.sources, self.scenarios)


def report_predictions(labels, predicted, sources, scenarios):
    """检出允许错分至其他攻击类；类别召回率独立报告。"""
    matrix = np.zeros((5, 5), dtype=np.int64)
    np.add.at(matrix, (labels, predicted), 1)
    tp = np.diag(matrix)
    recall = tp / np.maximum(matrix.sum(axis=1), 1)
    precision = tp / np.maximum(matrix.sum(axis=0), 1)
    f1 = 2 * tp / np.maximum(matrix.sum(axis=1) + matrix.sum(axis=0), 1)
    detection = {CLASSES[i]: float(np.mean(predicted[labels == i] != 0))
                 for i in range(1, 5) if np.any(labels == i)}
    fprs = {str(s): float(np.mean(predicted[(sources == s) & (labels == 0)] != 0))
            for s in sorted(set(sources)) if np.any((sources == s) & (labels == 0))}
    scenario = {}
    for s in sorted(set(scenarios)):
        mask = scenarios == s
        cm = np.zeros((5, 5), dtype=np.int64)
        np.add.at(cm, (labels[mask], predicted[mask]), 1)
        attacks = mask & (labels > 0)
        normal = mask & (labels == 0)
        scenario[str(s)] = {'connections': int(mask.sum()), 'confusionMatrix': cm.tolist(),
                            'attackDetection': float(np.mean(predicted[attacks] != 0)) if attacks.any() else None,
                            'falsePositiveRate': float(np.mean(predicted[normal] != 0)) if normal.any() else None}
    return {'connections': len(labels), 'confusionMatrix': matrix.tolist(), 'macroF1': float(f1.mean()),
            'recall': dict(zip(CLASSES, recall.tolist())), 'precision': dict(zip(CLASSES, precision.tolist())),
            'attackDetection': float(np.mean(list(detection.values()))) if detection else None,
            'attackDetectionByClass': detection, 'falsePositiveRate': float(np.mean(list(fprs.values()))),
            'normalSourceFpr': fprs, 'scenarioMetrics': scenario}


def choose_alert(index, output):
    grid = sorted(set([0.0, 1.0, *np.quantile(output[:, 0], np.linspace(0, 1, 101)).tolist()]))
    maximum = np.zeros(index.count, dtype=np.float64)
    np.maximum.at(maximum, index.inverse, output[:, 0])
    choices = []
    for threshold in grid:
        hit = maximum >= threshold
        fpr = np.mean([hit[(index.labels == 0) & (index.sources == s)].mean()
                       for s in ('internal', 'website')])
        detection = np.mean([hit[index.labels == i].mean() for i in range(1, 5)])
        if fpr <= .01:
            choices.append((float(detection), -float(threshold), threshold))
    if not choices:
        raise ValueError('无合法告警阈值')
    return float(max(choices)[2])


def source_key(meta, family):
    """包括资产/传感器/启动/捕获范围/epoch；非扫描类按服务端口隔离。"""
    keys = ('assetId', 'sensorId', 'bootId', 'captureScopeId', 'peerKey', 'keyEpoch', 'direction', 'transport')
    result = tuple(meta[k] for k in keys)
    return result if family == 1 else result + (meta['servicePort'],)


def simulate_sources(data, output, threshold, family, minimum, age_seconds=10):
    """最新快照替换旧分，按事件时间过期，parent 去重；只产生研究命中。

    标签仅用于事后 30 秒来源机会计数；含正常连接的混合机会保守计误封。
    不假造在线授权、targetRef、T1-T9、动作预算或已批准自动资格。
    """
    timestamps = [datetime.fromisoformat(m['asOf'].replace('Z', '+00:00')).timestamp() for m in data.metadata]
    order = np.argsort(timestamps, kind='stable')
    keys = [source_key(m, family) for m in data.metadata]
    normal, attack = set(), set()
    for i, t in enumerate(timestamps):
        opportunity = (keys[i], int(t // 30))
        if data.labels[i] == 0:
            normal.add(opportunity)
        elif data.labels[i] == family:
            attack.add(opportunity)
    latest = defaultdict(dict)
    queue = []
    hits = set()
    predictions = np.argmax(output[:, 1:], axis=1) + 1
    for i in order:
        i = int(i)
        t, key, parent = timestamps[i], keys[i], str(data.parent_ids[i])
        while queue and queue[0][0] < t - age_seconds:
            _, old_i, old_key, old_parent = heapq.heappop(queue)
            if latest[old_key].get(old_parent) == old_i:
                del latest[old_key][old_parent]
        latest[key].pop(parent, None)
        if float(output[i, 0]) >= threshold and predictions[i] == family:
            latest[key][parent] = i
            heapq.heappush(queue, (t, i, key, parent))
        if len(latest[key]) >= minimum:
            hits.add((key, int(t // 30)))
    return {'normalOpportunities': len(normal), 'attackOpportunities': len(attack),
            'normalFalseBlocks': len(hits & normal), 'coveredAttackOpportunities': len(hits & attack),
            'attackCoverage': len(hits & attack) / len(attack) if attack else 0.0,
            'attackSources': len({key for key, _ in attack}),
            'coveredAttackSources': len({key for key, _ in hits & attack}),
            'mixedLabelOpportunities': len(normal & attack)}


def policy_preview(data, output, alert):
    result = {'previewOnly': True, 'automaticExecutionEnabled': False, 'maxEvidenceAgeMs': 10000,
              'evaluationUnit': 'source x class x 30s bucket; mixed normal counted conservatively',
              'alertThreshold': alert, 'classes': {}, 'allTrials': {}}
    predicted = output[:, 1:].argmax(axis=1) + 1
    for c in range(1, 5):
        values = output[(predicted == c) & (output[:, 0] >= alert), 0]
        grid = sorted(set([alert, 1.0, *np.quantile(values, np.linspace(0, 1, 9)).tolist()])) if len(values) else [alert, 1.0]
        trials = []
        for threshold in grid:
            for minimum in (2, 3, 5):
                trials.append({'autoThreshold': float(threshold), 'minDistinctFlows': minimum,
                               **simulate_sources(data, output, float(threshold), c, minimum)})
        valid = [t for t in trials if t['normalFalseBlocks'] == 0]
        best = max(valid, key=lambda t: (t['coveredAttackSources'], t['attackCoverage'], -t['autoThreshold'], -t['minDistinctFlows'])) if valid else None
        result['classes'][CLASSES[c]] = {'parameters': best, 'mode': 'alert_only',
                                        'eligibility': 'P6/G3 pending' if best and best['attackCoverage'] else 'insufficient validation coverage'}
        result['allTrials'][CLASSES[c]] = trials
    return result


def tune_rules(data, index, model_output, alert):
    """固定四条规则结构，validation 搜阈值；每条分配 0.25% FPR 预算。"""
    ports = np.asarray([m['servicePort'] for m in data.metadata])
    rules = [(1, 'contexts.5.peerDistinctServicePorts', np.ones(len(ports), dtype=bool)),
             (2, 'contexts.30.peerFlowStarts', np.isin(ports, [21, 22])),
             (3, 'contexts.1.peerBytesInbound', np.isin(ports, [80, 443])),
             (4, 'contexts.30.peerFlowStarts', np.isin(ports, [80, 443]) & (data.values[:, 0] >= 10000))]
    matched = np.zeros((len(ports), 4), dtype=bool)
    parameters = []
    for c, field, gate in rules:
        values = data.values[:, NUMERIC.index(field)].astype(np.float64)
        best = None
        for threshold in sorted(set([*np.quantile(values, np.linspace(0, 1, 101)).tolist(), float(values.max()) + 1])):
            hit = gate & (values >= threshold)
            _, exists = index.selected(hit)
            fpr = np.mean([exists[(index.labels == 0) & (index.sources == s)].mean() for s in ('internal', 'website')])
            recall = float(exists[index.labels == c].mean())
            if fpr <= .0025 and (best is None or recall > best[0]):
                best = (recall, threshold, hit, float(fpr))
        matched[:, c - 1] = best[2]
        parameters.append({'family': CLASSES[c], 'field': field, 'threshold': best[1],
                           'servicePorts': None if c == 1 else ([21, 22] if c == 2 else [80, 443]),
                           'minElapsedMs': 10000 if c == 4 else 0, 'validationFpr': best[3], 'automatic': False})
    rule_hit = matched.any(axis=1)
    chosen, exists = index.selected(rule_hit)
    rule_prediction = np.where(exists, matched[chosen].argmax(axis=1) + 1, 0)
    model_hit = model_output[:, 0].astype(np.float64) >= alert
    chosen, exists = index.selected(rule_hit | model_hit)
    combined = np.where(exists, np.where(model_hit[chosen], model_output[chosen, 1:].argmax(axis=1) + 1,
                                         matched[chosen].argmax(axis=1) + 1), 0)
    model = index.decisions(model_output, alert)
    return {'version': 'host-guard-rules/1-validation-preview', 'rules': parameters,
            'tieBreak': 'model at same instant; rule class order otherwise',
            'ruleOnly': index.report(rule_prediction), 'modelOnly': index.report(model), 'combinedOr': index.report(combined),
            'modelAdditionalAttacks': int(((index.labels > 0) & (model > 0) & (rule_prediction == 0)).sum()),
            'ruleFalseAlarmsNotRaisedByModel': int(((index.labels == 0) & (rule_prediction > 0) & (model == 0)).sum()),
            'orDoesNotCorrectRuleFalseAlarms': True}


def distribution(index, output):
    maximum = np.zeros(index.count, dtype=np.float32)
    np.maximum.at(maximum, index.inverse, output[:, 0])
    summary = {}
    for c, name in enumerate(CLASSES):
        row_values = output[index.data.labels == c]
        summary[name] = {'snapshotCount': len(row_values), 'outputMean': row_values.mean(axis=0).tolist(),
                         'outputStd': row_values.std(axis=0).tolist(),
                         'outputQuantiles': np.quantile(row_values, [0, .05, .5, .95, 1], axis=0).tolist(),
                         'parentMaxAttackQuantiles': np.quantile(maximum[index.labels == c], [0, .05, .5, .95, 1]).tolist()}
    constants = {str(label): index.report(np.full(index.count, label)) for label in range(5)}
    return {'rawScoresNotThresholdZeroed': True, 'byClass': summary, 'constantClassBaselines': constants,
            'scoreHasVariation': bool(np.ptp(output[:, 0]) > 1e-4)}


def patch_categorical(source, destination):
    """只补 int64->float32 输入 Cast，不修改任何树和预处理参数。"""
    import onnx
    model = onnx.load(source)
    categorical = next(i for i in model.graph.input if i.name == 'categorical_codes')
    if categorical.type.tensor_type.elem_type != onnx.TensorProto.FLOAT:
        raise ValueError('原 ONNX 类别输入不是预期 float32')
    categorical.type.tensor_type.elem_type = onnx.TensorProto.INT64
    for node in model.graph.node:
        for i, name in enumerate(node.input):
            if name == 'categorical_codes':
                node.input[i] = 'audit_categorical_float'
    model.graph.node.insert(0, onnx.helper.make_node('Cast', ['categorical_codes'], ['audit_categorical_float'], to=onnx.TensorProto.FLOAT))
    onnx.checker.check_model(model)
    onnx.save(model, destination)
    split_counts = Counter()
    for node in model.graph.node:
        if node.op_type == 'TreeEnsembleClassifier':
            attrs = {a.name: onnx.helper.get_attribute_value(a) for a in node.attribute}
            for feature, mode in zip(attrs['nodes_featureids'], attrs['nodes_modes']):
                if mode != b'LEAF':
                    split_counts[int(feature)] += 1
    return {'importanceType': 'tree split count; not gain or causal attribution',
            'splitCounts': [{'feature': (NUMERIC + ['missing:' + n for n in NUMERIC] + ['transport', 'direction', 'serviceClass'])[i],
                             'count': n} for i, n in split_counts.most_common()]}


def compare_outputs(expected, actual, alert):
    labels = lambda a: np.where(a[:, 0].astype(np.float64) >= alert, a[:, 1:].argmax(axis=1) + 1, 0)
    errors = np.max(np.abs(expected - actual), axis=0)
    flips = int(np.count_nonzero(labels(expected) != labels(actual)))
    return {'rows': len(actual), 'maxAttackError': float(errors[0]), 'maxFamilyError': float(errors[1:].max()),
            'classFlips': flips, 'status': 'passed' if errors.max() <= 1e-4 and flips == 0 else 'failed'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--frozen', type=Path, required=True)
    parser.add_argument('--sidecars', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=['audit', 'runtime'], default='audit')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    summary = json.loads((args.run / 'run-summary.json').read_text(encoding='utf-8'))
    selected = summary['selected']
    artifact = args.run / 'models' / selected
    pre = Preprocessor.restore(json.loads((artifact / 'preprocessing.json').read_text(encoding='utf-8')))
    runtime = session(artifact / 'model.onnx')
    validation = load_development(args.frozen, args.sidecars, 'validation')
    feed = feed_for(validation, pre, runtime)
    output = predict(runtime, feed)
    np.save(args.output / 'validation-onnx.npy', output, allow_pickle=False)
    index = Connections(validation)
    alert = choose_alert(index, output)
    started = time.perf_counter()
    latencies = []
    for i in range(120):
        one = {k: v[i:i+1] for k, v in feed.items()}
        tick = time.perf_counter()
        runtime.run(None, one)
        if i >= 20:
            latencies.append((time.perf_counter() - tick) * 1000)
    common = {'candidateOnly': True, 'finalTestRead': False, 'newFits': 0,
              'modelSha256': sha256(artifact / 'model.onnx'), 'selected': selected,
              'datasetSha256': HASHES, 'metadataSha256': SIDECAR_HASHES,
              'runtime': {'os': platform.system(), 'python': platform.python_version(), 'onnxruntime': ort.__version__,
                          'provider': 'CPUExecutionProvider', 'threads': 8},
              'alertThreshold': alert, 'singleSnapshotLatencyMs': {'samples': 100, 'warmup': 20,
                  'p50': float(np.median(latencies)), 'p95': float(np.quantile(latencies, .95)), 'max': max(latencies)}}
    write_new(args.output / 'runtime.json', common)
    print(json.dumps({'stage': 'validation-inferred', 'mode': args.mode}), flush=True)
    if args.mode == 'runtime':
        del validation, index, feed, output
        train = load_development(args.frozen, args.sidecars, 'train')
        train_output = predict(runtime, feed_for(train, pre, runtime))
        np.save(args.output / 'train-onnx.npy', train_output, allow_pickle=False)
        write_new(args.output / 'train-runtime.json', common | {'rows': len(train.rows), 'frameworkParity': 'unverified-original-native-model-not-saved'})
        print(json.dumps({'stage': 'runtime-complete', 'trainRows': len(train.rows)}), flush=True)
        return
    corrected = []
    for fit in summary['fits']:
        report = dict(fit['validation'])
        matrix = np.asarray(report['confusionMatrix'])
        report['attackDetection'] = float(np.mean(1 - matrix[1:, 0] / matrix[1:].sum(axis=1)))
        corrected.append({'name': fit['name'], 'algorithm': fit['algorithm'], 'seed': fit['seed'],
                          'validation': report, 'onnxParity': fit['onnxParity']})
    eligible = [f for f in corrected if f['onnxParity'] and f['onnxParity']['status'] == 'passed'
                and f['validation']['falsePositiveRate'] <= .01]
    corrected_selected = max(eligible, key=lambda f: (f['validation']['macroF1'], f['validation']['attackDetection']))['name']
    if corrected_selected != selected:
        raise ValueError('修正指标导致选型变化，须重新审计新候选')
    write_new(args.output / 'corrected-matrix.json', {'selectionChanged': False, 'selected': corrected_selected, 'fits': corrected})
    model_report = index.report(index.decisions(output, alert))
    write_new(args.output / 'validation-report.json', common | model_report)
    write_new(args.output / 'score-distributions.json', distribution(index, output))
    print(json.dumps({'stage': 'metrics-complete', 'macroF1': model_report['macroF1']}), flush=True)
    write_new(args.output / 'rules-comparison.json', tune_rules(validation, index, output, alert))
    print(json.dumps({'stage': 'rules-complete'}), flush=True)
    write_new(args.output / 'policy-preview.json', policy_preview(validation, output, alert))
    print(json.dumps({'stage': 'policy-complete'}), flush=True)
    selected_fit = next(f for f in corrected if f['name'] == selected)
    ablation = []
    for f in corrected:
        if f['name'].startswith('ablation-'):
            f1_drop = selected_fit['validation']['macroF1'] - f['validation']['macroF1']
            detection_drop = selected_fit['validation']['attackDetection'] - f['validation']['attackDetection']
            ablation.append({'name': f['name'], 'macroF1Drop': f1_drop, 'attackDetectionDrop': detection_drop,
                             'shortcutFlag': f1_drop > .10 or detection_drop > .10, 'sameAlgorithmConfiguration': True})
    seeds = {algorithm: {metric: {'min': min(values), 'max': max(values), 'std': float(np.std(values))}
                         for metric in ('macroF1', 'attackDetection')
                         for values in [[f['validation'][metric] for f in corrected if f['name'].startswith('main-' + algorithm)]]}
             for algorithm in ('xgboost', 'lightgbm')}
    write_new(args.output / 'ablation-and-seeds.json', {'ablations': ablation, 'seeds': seeds})
    patched = args.output / 'model-int64.onnx'
    write_new(args.output / 'feature-importance.json', patch_categorical(artifact / 'model.onnx', patched))
    patched_session = session(patched)
    actual = predict(patched_session, feed_for(validation, pre, patched_session))
    write_new(args.output / 'input-contract-parity.json', compare_outputs(output, actual, alert) |
              {'originalSha256': common['modelSha256'], 'patchedSha256': sha256(patched), 'weightsChanged': False})
    write_new(args.output / 'audit-completion.json', common | {'status': 'evidence-complete-with-open-gates',
              'validationExitPassed': model_report['attackDetection'] >= .85 and model_report['falsePositiveRate'] <= .02,
              'P3BClosed': False, 'P3CReady': False, 'unresolved': [
                  'cumulative fitting budget exceeded before this audit',
                  'Windows train versus original framework parity unavailable: native model was not saved',
                  'reference model export parity failed; excluded from deployable selection'],
              'secondsAfterInference': time.perf_counter() - started})
    print(json.dumps({'stage': 'audit-complete', 'P3BClosed': False}), flush=True)


if __name__ == '__main__':
    main()
