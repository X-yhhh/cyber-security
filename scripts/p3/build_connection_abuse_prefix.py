#!/usr/bin/env python3
"""把 Friday 的连接滥用来源证据接入 rc.2 prefix 观察。

与 build_qualified_prefix.py 的关键区别：connection_abuse 的起点是**首个 SYN**，
不是 HTTP 载荷。已验证 guardjoin 对 Portscan/DDoS 100% synStart，onsetCandidateUs
为 null 是正确语义（没有 HTTP 请求可作起点），不能据此判失败。

Portscan 与 DDoS 是同一捕获内的两个独立活动：时段不重叠（16:55-18:23 / 18:56-19:16）、
行为模式不同（999 端口扫描 vs 单端口 80 洪泛）。按 150 秒合并规则不构成同一活动。

Unknown 不映射正常；不批准训练；输出为新版本，不覆盖旧冻结清单。
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib, json
from pathlib import Path


def sha(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def lines(p):
    with p.open() as f:
        for line in f:
            yield json.loads(line)


def us(s):
    return round(datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp() * 1e6)


def target_key(asset, local, peer):
    # 稳定处置目标旁路：剥除临时客户端端口，不使用 boot/epoch/HMAC 身份重置预算。
    return hashlib.sha256(json.dumps([asset, local, peer.rsplit(':', 1)[0], 'ipv4', 'tcp']).encode()).hexdigest()


# 两个活动的来源登记：同一捕获、同一攻击机，但时段与行为不同。
ACTIVITIES = {
    'friday_portscan': dict(
        label='Portscan',
        activityId='cic2017-friday-portscan',
        associationGroup='cic2017-friday-portscan',
        sourceMode='horizontal scan: many distinct destination ports, SYN-only connections',
        onsetMode='first_forward_syn',
    ),
    'friday_ddos': dict(
        label='DDoS',
        activityId='cic2017-friday-ddos',
        associationGroup='cic2017-friday-ddos',
        sourceMode='single-port flood: sustained packets to one service port',
        onsetMode='first_forward_syn',
    ),
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ['labels', 'joins', 'observations', 'ledger', 'extraction', 'config', 'output']:
        p.add_argument('--' + n, type=Path, required=True)
    p.add_argument('--profile', default='flow-final-v1', choices=('flow-prefix-v1', 'flow-final-v1'),
                   help='扫描连接存活毫秒级，物理上无 1 秒 prefix；默认 final')
    a = p.parse_args()

    ex = json.loads(a.extraction.read_text())
    # 提取件自洽核验：状态、版本、观察哈希
    if ex['status'] != 'completed' or ex['version'] != 'host-guard/5.0.0-rc.2':
        raise ValueError('提取器版本/状态不符')
    if ex['observationsSha256'] != sha(a.observations):
        raise ValueError('观察文件哈希与提取摘要不符')
    if ex['configSha256'] != sha(a.config):
        raise ValueError('配置哈希与提取摘要不符')
    if sum(1 for _ in lines(a.ledger)) != sum(1 for _ in lines(a.observations)):
        raise ValueError('账本与观察行数不一致')

    joins = {r['labelId']: r for r in lines(a.joins)}
    labels = list(lines(a.labels))

    counts = Counter()
    rows = []
    observations = []
    timeline = {}
    seen = set()
    asset = None
    parent_sources = {}

    # 按 (label, origin) 建立来源连接索引，用于 parent 起点精确绑定。
    # 结构起点判据：join 匹配 + synStart + 单一 SYN epoch。
    # 不能用 onsetStructuralChecksPassed——那是 HTTP 慢请求起点字段，对 SYN 起点扫描类连接
    # 天然为 false（实测 253,494 条被该字段误拒），套用会得到零观察。
    bykey = defaultdict(list)
    for lab in labels:
        if lab['label'] not in ('Portscan', 'DDoS'):
            continue
        j = joins.get(lab['id'])
        if j is None or j['join'] != 'matched' or not j['synStart']:
            counts['join_or_syn_unmatched'] += 1
            continue
        if j['distinctSynSequences'] != 1:
            counts['multiple_syn_epochs_excluded'] += 1
            continue
        if j['offloadPackets'] or j['timestampRegressions'] or j['badHeaders']:
            counts['connection_quality_rejected'] += 1
            continue
        bykey[tuple(sorted((lab['origin'], lab['responder'])))].append(lab)

    activity_of_label = {'Portscan': 'friday_portscan', 'DDoS': 'friday_ddos'}

    for o, led in zip(lines(a.observations), lines(a.ledger), strict=True):
        if led['observationId'] != o['observationId'] or led['parentConnectionId'] != o['parentConnectionId']:
            raise ValueError('观察/账本顺序或身份不符')
        if o['observationId'] in seen:
            raise ValueError('重复观察身份')
        seen.add(o['observationId'])
        asset = o['assetId'] if asset is None else asset
        if o['assetId'] != asset:
            raise ValueError('混合资产捕获')

        # 用账本端点直接定位来源连接：O(1) 查表，不做观察×标签的暴力匹配。
        ep = led['Endpoints']
        key = tuple(sorted((ep['Peer'], ep['Local'])))
        parent = o['parentConnectionId']
        bound = parent_sources.get(parent)
        if bound is None:
            candidates = [lab for lab in bykey.get(key, [])
                          if abs(lab['start'] - us(o['firstSeenAt'])) <= 1_000_000]
            if len(candidates) != 1:
                counts['no_unique_qualified_source_connection'] += 1
                continue
            bound = candidates[0]
            parent_sources[parent] = bound
        lab = bound
        act = activity_of_label[lab['label']]
        reg = ACTIVITIES[act]
        asof = us(o['asOf'])
        start_us = lab['start']
        end_us = lab['end']

        # 记录每条源连接的时间线（即使没有合格观察也要保留分母）。
        if lab['id'] not in timeline:
            local = lab['responder']
            peer = lab['origin']
            timeline[lab['id']] = dict(
                episodeId=lab['id'],
                targetId=target_key(asset, local, peer),
                startMs=start_us / 1000, endMs=end_us / 1000, label=1,
                hasObservation=False,
                attackStartBasis='publisher-labelled SYN as conservative bound',
                sourceLabelId=lab['id'],
                activityId=reg['activityId'], scenario=act,
                intervalBasis='publisher_labelled_connection_with_first_syn_onset',
            )

        # 范围与质量过滤
        if (o['profile'], o['addressFamily'], o['transport'], o['direction']) != (a.profile, 'ipv4', 'tcp', 'inbound'):
            counts['profile_or_scope'] += 1
            continue
        if any(v is True for v in o['quality'].values()):
            counts['quality'] += 1
            continue
        if not start_us < asof <= end_us:
            counts['outside_source_connection_window'] += 1
            continue

        timeline[lab['id']]['hasObservation'] = True
        rows.append(dict(
            observationId=o['observationId'],
            parentConnectionId=o['parentConnectionId'],
            scenario=act,
            sourceId='cic2017_corrected',
            activityId=reg['activityId'],
            associationGroup=reg['associationGroup'],
            split='development_unassigned',
            label=1,
            family='connection_abuse',
            sourceLabelId=lab['id'],
            evidenceTier='publisher_documented',
            labelRuleVersion='source-syn-onset-v1',
            firstSeenAt=o['firstSeenAt'],
            asOf=o['asOf'],
            budgetTargetId=target_key(asset, o['targetRef'].get('peer', lab['origin']) if o.get('targetRef') else lab['origin'],
                                      o['targetRef'].get('local', lab['responder']) if o.get('targetRef') else lab['responder']),
        ))
        observations.append(o)

    # 同目标重叠连接只组成一个攻击区间，不能把数百 parent 当作数百独立活动。
    target_spans = defaultdict(list)
    for row in timeline.values():
        target_spans[row['targetId']].append(row)
    episodes = []
    for target, spans in target_spans.items():
        merged = []
        for row in sorted(spans, key=lambda r: r['startMs']):
            if merged and row['startMs'] <= merged[-1]['endMs']:
                merged[-1]['endMs'] = max(merged[-1]['endMs'], row['endMs'])
                merged[-1]['hasObservation'] |= row['hasObservation']
                merged[-1]['sourceLabelIds'].append(row['sourceLabelId'])
            else:
                merged.append(dict(targetId=target, startMs=row['startMs'], endMs=row['endMs'], label=1,
                                   hasObservation=row['hasObservation'], sourceLabelIds=[row['sourceLabelId']],
                                   activityId=row['activityId'], scenario=row['scenario']))
        for ordinal, row in enumerate(merged):
            row['episodeId'] = hashlib.sha256(
                json.dumps([target, row['startMs'], row['endMs'], ordinal]).encode()).hexdigest()
            row['basis'] = 'union_of_qualified_source_connection_intervals; conservative onset bounds'
            episodes.append(row)

    if not a.output.exists():
        a.output.mkdir(parents=True)
    for name, values in [('index.jsonl', rows), ('observations.jsonl', observations),
                         ('label-connection-timeline.jsonl', list(timeline.values())),
                         ('label-timeline.jsonl', episodes)]:
        path = a.output / name
        if path.exists():
            raise FileExistsError(f'输出已存在，拒绝覆盖: {path}')
        with path.open('x') as f:
            for row in values:
                f.write(json.dumps(row) + '\n')

    activities = sorted({r['scenario'] for r in rows})
    result = dict(
        version='connection-abuse-prefix-development-v1',
        status='qualified_development_unpartitioned' if rows else 'no_qualified_observations',
        profile=a.profile,
        onsetMode='first_forward_syn',
        prefixPhysicallyUnavailable=(a.profile == 'flow-final-v1'),
        observations=len(rows),
        parents=len({r['parentConnectionId'] for r in rows}),
        sourceConnectionSegments=len(timeline),
        sourceConnectionSegmentsWithoutQualifiedObservation=sum(not r['hasObservation'] for r in timeline.values()),
        targetAttackIntervals=len(episodes),
        independentActivities=len(activities),
        activities=activities,
        excludedObservationReasons=dict(counts),
        inputHashes={str(p.name): sha(p) for p in [a.labels, a.joins, a.extraction, a.config]},
        outputHashes={name: sha(a.output / name) for name in
                      ['index.jsonl', 'observations.jsonl', 'label-connection-timeline.jsonl', 'label-timeline.jsonl']},
        rolesFrozen=False, trainingAllowed=False, modelFits=0, finalRead=False,
        blockers=['CROSS_SOURCE_INDEPENDENCE_NOT_EVALUATED', 'ROLES_AND_NEAR_DUPLICATE_GROUPS_NOT_FROZEN'],
    )
    (a.output / 'readiness.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
