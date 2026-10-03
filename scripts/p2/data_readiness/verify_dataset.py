#!/usr/bin/env python3
"""收件端仅用 Python 标准库验证冻结研究集的身份、分区、权重及完整性。

不训练、不校准、不访问 final_test。摘要哈希与实际索引/观察必须一致，
重复/活动跨分区、非 final 输入、端口改写或非研究环境均拒绝。
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def signature(o):
    """沿用 P2 rc.2 冻结的 final 近重复规则，接收端从观察重算而非信任索引。"""
    f = dict(o['features'])
    f['elapsedMs'] = round(f['elapsedMs'] / 100)
    for name in ('iatMeanUs', 'iatStdUs'):
        f[name] = None if f[name] is None else round(f[name] / 1000)
    for name in ('lengthMean', 'lengthStd'):
        f[name] = round(f[name])
    value = [o['transport'], o['direction'], o['serviceClass'], f]
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify(root):
    report = json.loads((root / 'readiness.json').read_text(encoding='utf-8'))
    for name, field in [('index.jsonl', 'indexSha256'), ('observations.jsonl', 'observationsSha256')]:
        if sha(root / name) != report[field]:
            raise ValueError('数据集哈希不符: ' + name)
    ids, counts = set(), collections.Counter()
    groups = {key: collections.defaultdict(set) for key in ('parentConnectionId', 'activityId', 'duplicateGroup')}
    weights = collections.defaultdict(float)
    parents, activities = collections.defaultdict(set), collections.defaultdict(set)
    with (root / 'index.jsonl').open(encoding='utf-8') as index, (root / 'observations.jsonl').open(encoding='utf-8') as observations:
        for a, b in zip(index, observations, strict=True):
            r, o = json.loads(a), json.loads(b)
            ident, parent = o['observationId'], o['parentConnectionId']
            if ident in ids or r['observationId'] != ident or r['parentConnectionId'] != parent:
                raise ValueError('身份重复/绑定不符')
            ids.add(ident)
            if r['split'] not in ('train', 'validation_selection', 'validation_calibration') or r['label'] not in (0, 1):
                raise ValueError('非法分区/标签')
            if (o['addressFamily'], o['transport'], o['direction'], o['servicePort'], o['profile']) != ('ipv4', 'tcp', 'inbound', 80, 'flow-final-v1'):
                raise ValueError('观察超出研究范围')
            if o['environment'] != 'research' or o['targetRef'] is not None or o['contractVersion'] != 'host-guard/5.0.0-rc.2':
                raise ValueError('环境/目标引用/契约错误')
            if o['closeReason'] in ('eof', 'new_syn') or any(v is True for k, v in o['quality'].items() if k != 'clockSkewMs'):
                raise ValueError('不完整连接或质量故障')
            if signature(o) != r['duplicateGroup']:
                raise ValueError('近重复签名不符')
            for key in groups:
                groups[key][r[key]].add(r['split'])
            if not 0 < r['sampleWeight'] <= 1:
                raise ValueError('非法样本权重')
            weights[parent] += r['sampleWeight']
            key = r['split'] + '/' + str(r['label'])
            counts[key] += 1
            parents[key].add(parent)
            activities[key].add(r['activityId'])
    if any(len(v) != 1 for group in groups.values() for v in group.values()):
        raise ValueError('父连接/活动/近重复组跨分区')
    if any(abs(w - 1) > 1e-9 for w in weights.values()):
        raise ValueError('每个 parent 总权重不为1')
    if dict(counts) != report['snapshots'] or {k: len(v) for k, v in parents.items()} != report['parents'] or {k: len(v) for k, v in activities.items()} != report['activities']:
        raise ValueError('报告计数与实际内容不符')
    if report['finalTestRead'] or report['finalAcceptanceEligible'] or report['prefixResearchReady']:
        raise ValueError('超出本数据集资格')
    return dict(status='passed', snapshots=len(ids), parents=len(weights),
                activities=len(groups['activityId']), roles=sorted({r for v in groups['activityId'].values() for r in v}),
                parentWeightsVerified=True, parentActivityDuplicatesDisjoint=True,
                indexSha256=report['indexSha256'], observationsSha256=report['observationsSha256'],
                trainingExecuted=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset', type=Path, required=True)
    p.add_argument('--report', type=Path)
    a = p.parse_args()
    result = verify(a.dataset)
    if a.report:
        with a.report.open('x', encoding='utf-8', newline='\n') as f:
            json.dump(result, f, indent=2)
            f.write('\n')
    print(json.dumps(result))
