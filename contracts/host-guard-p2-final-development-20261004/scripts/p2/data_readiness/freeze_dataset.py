#!/usr/bin/env python3
"""重新冻结数据版本，引用原 rc.2 软件冻结清单，不覆盖既有软件验收。

公开文件与忽略目录输入仅记录 SHA-256；密钥本体/密钥哈希不进入清单。
收件端只需交付的数据集与公开文件，完整复算的原件继续在受控目录保留。
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def build(run, dataset):
    public = list((ROOT / 'scripts/p2/data_readiness').glob('*.py'))
    public += [p for p in (ROOT / 'docs/p2/data-readiness').iterdir() if p.suffix in ('.json', '.md') and
               p.name not in ('freeze-manifest.json', 'windows-delivery-verification.json')]
    public += [ROOT / 'docs/p2/freeze-manifest.json']
    public_hashes = {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(public)}
    inputs = []
    for directory in (run, ROOT / 'artifacts/p2/run-20261004'):
        if directory.name == 'run-20261004':
            inputs.extend(directory / name for name in ('wednesday-labels.jsonl', 'wednesday-joins.jsonl',
                 'partition-index.jsonl', 'partition-manifest.json', 'train-extraction.json', 'validation-extraction.json'))
        else:
            # 只冻结当前成功输入和完整记录旁路，失败历史另行保留。
            inputs.extend(directory / name for name in ('calibration-labels.jsonl', 'calibration-joins.jsonl',
               'calibration-complete-extraction.json', 'calibration-complete-observations.jsonl', 'calibration-complete-ledger.jsonl',
               'public-benign-carving.json', 'public-benign-registration.json', 'local-dataset-verification.json',
               'schema-validation.json', 'new-capture-parity.json', 'prefix-review/decisions.jsonl', 'prefix-review/prefix-candidates.jsonl'))
            for host in directory.glob('public-web-*'):
                inputs.extend(host / name for name in ('config.json', 'labels.jsonl', 'joins.jsonl', 'extraction.json', 'observations.jsonl', 'ledger.jsonl'))
            controlled = directory / 'p2-benign-development-20261004'
            inputs.extend(controlled / name for name in ('run.json', 'extraction-complete.json'))
            for session in controlled.glob('session-*'):
                inputs.extend(session / name for name in ('capture.json', 'session.json', 'connections.jsonl', 'config.json', 'raw.pcap', 'extraction.json', 'observations.jsonl', 'ledger.jsonl'))
    input_hashes = {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(inputs)}
    data_hashes = {name: sha(dataset / name) for name in ('index.jsonl', 'observations.jsonl', 'readiness.json')}
    body = dict(version='p2-data-freeze-v1', date='2026-10-04', datasetId='host-guard-p2-final-development-20261004',
         purpose='final-profile feasibility research; no early-block or release qualification',
         contractVersion='host-guard/5.0.0-rc.2', baseSoftwareFreezeSha256=sha(ROOT / 'docs/p2/freeze-manifest.json'),
         publicFiles=public_hashes, inputEvidenceFiles=input_hashes, datasetFiles=data_hashes,
         finalTestAllocated=False, trainingExecuted=False, keyMaterialIncluded=False)
    body['collectionSha256'] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return body


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--dataset', type=Path, required=True)
    p.add_argument('--output', type=Path, default=ROOT / 'docs/p2/data-readiness/freeze-manifest.json')
    p.add_argument('--check', action='store_true')
    a = p.parse_args()
    report = build(a.run.resolve(), a.dataset.resolve())
    text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if a.check:
        if a.output.read_text(encoding='utf-8') != text:
            raise SystemExit('补齐数据冻结清单与当前文件不一致')
    else:
        with a.output.open('x', encoding='utf-8', newline='\n') as f:
            f.write(text)
    print(json.dumps({'status': 'passed', 'collectionSha256': report['collectionSha256'],
                      'publicFiles': len(report['publicFiles']), 'inputEvidenceFiles': len(report['inputEvidenceFiles'])}))
