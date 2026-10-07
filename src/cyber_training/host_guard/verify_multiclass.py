"""P3-B 双平台零拟合核验与预算清点；不会读取任何 test/L3 内容。"""
import argparse
import json
from pathlib import Path
import platform

import numpy as np

try:
    from .multiclass_audit import (HASHES, compare_outputs, load_development, session, feed_for, predict,
                                  Preprocessor, sha256, write_new)
except ImportError:
    from multiclass_audit import (HASHES, compare_outputs, load_development, session, feed_for, predict,
                                 Preprocessor, sha256, write_new)


def inventory(root, output):
    """仅统计 P3-B 子目录，保留不完整 run；fit 数是可证明的下界。"""
    runs = []
    for run in sorted(root.glob('run-*')):
        if not run.is_dir():
            continue
        path = run / 'run-events.jsonl'
        events = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()] if path.exists() else []
        complete = [e for e in events if e.get('event') == 'fit-completed']
        models = sorted(p.parent.name for p in (run / 'models').glob('*/validation-metrics.json'))
        runs.append({'run': run.name, 'completedFits': len(complete), 'modelMetricFiles': models,
                     'summaryPresent': (run / 'run-summary.json').exists(),
                     'eventSha256': sha256(path) if path.exists() else None})
    count = sum(r['completedFits'] for r in runs)
    write_new(output, {'runs': runs, 'provenFitLowerBound': count, 'budget': 30,
                       'exceeded': count > 30, 'furtherTrainingDisabled': True,
                       'incompleteAttemptsMayContainAdditionalFits': True, 'finalTestRead': False})


def verify(args):
    """比较原图、int64 Cast 修复图与远端推理；不把运行时一致冒充框架一致。"""
    args.output.mkdir(parents=True, exist_ok=False)
    original = args.run / 'models' / 'main-lightgbm-seed42'
    pre = Preprocessor.restore(json.loads((original / 'preprocessing.json').read_text()))
    patched = args.audit / 'model-int64.onnx'
    runtime = session(patched)
    alert = json.loads((args.audit / 'runtime.json').read_text())['alertThreshold']
    comparisons = {}
    for role in ('validation', 'train'):
        data = load_development(args.frozen, args.sidecars, role)
        actual = predict(runtime, feed_for(data, pre, runtime))
        expected = np.load(args.windows / (role + '-onnx.npy'), allow_pickle=False)
        comparisons[role] = compare_outputs(expected, actual, alert)
        comparisons[role]['reference'] = 'Windows original ONNX; ' + platform.system() + ' int64 input repair'
        comparisons[role]['expectedSha256'] = sha256(args.windows / (role + '-onnx.npy'))
        del data, actual, expected
    prior = json.loads((original / 'onnx-parity.json').read_text())
    result = {'candidateOnly': True, 'finalTestRead': False, 'newFits': 0, 'comparisons': comparisons,
              'originalModelSha256': sha256(original / 'model.onnx'), 'int64ModelSha256': sha256(patched),
              'priorWindowsValidationFrameworkParity': prior,
              'windowsTrainFrameworkParity': {'status': 'unverified', 'reason': 'original native model and framework outputs were not saved'},
              'crossPlatformPassed': all(v['status'] == 'passed' for v in comparisons.values()),
              'B5FullyPassed': False, 'P3BClosed': False, 'P3CReady': False}
    write_new(args.output / 'verification.json', result)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--run', type=Path)
    parser.add_argument('--audit', type=Path)
    parser.add_argument('--windows', type=Path)
    parser.add_argument('--frozen', type=Path)
    parser.add_argument('--sidecars', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.inventory:
        inventory(args.inventory, args.output)
    else:
        verify(args)
