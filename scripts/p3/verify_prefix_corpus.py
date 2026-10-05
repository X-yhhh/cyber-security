#!/usr/bin/env python3
"""从冻结文件重算 prefix 准入；修改 trainingAllowed 布尔值不能绕过独立组门槛。

只读取开发观察与封存清单，不打开封存 PCAP。该模块可按哈希复制到 Windows；
训练入口和本机交付使用相同校验。完整性通过与训练准入通过分别报告。
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path

from prefix_contract import BEHAVIORS, metadata, early_edges

ROLES = ('train', 'validation_selection', 'validation_calibration', 'independent_development')
CONTRACT = 'host-guard/5.0.0-rc.2'
PROFILE = 'flow-prefix-v1'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def lines(path):
    with Path(path).open(encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def time_ms(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('时间必须带时区')
    return parsed.timestamp() * 1000


def context_sources(row):
    """来源组改名不改变上下文谱系；旧索引没有独立域字段时沿用 sourceId。"""
    values = {row['sourceId']}
    if 'contextSourceId' in row:
        values.add(row['contextSourceId'])
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError('来源或上下文域身份无效')
    return values


def grouping_summary(rows, partition):
    """分别报告采集来源组、活动和防泄漏组，合并原因只取实际归并边。

    同一个粗粒度签名可能匹配多个 parent；匹配次数与连通分量归并边数不等价。
    本摘要不参与选型，也不能取代从观察序列重新核验独立性。
    """
    by_scene = defaultdict(list)
    for row in rows:
        by_scene[row['scenario']].append(row)
    return dict(
        sourceGroups=len({r['sourceId'] for r in rows}),
        mergeEdgesByReason=dict(sorted(Counter(edge['reason'] for edge in partition['edges']).items())),
        nearDuplicateParentMatches=partition['nearDuplicateMatches'],
        byScenario={scene: dict(
            activities=len({r['activityId'] for r in values}),
            sourceGroups=len({r['sourceId'] for r in values}),
            leakageGroups=len({r['leakageGroupId'] for r in values}),
            roleGroups={role: len({r['leakageGroupId'] for r in values if r['split'] == role}) for role in ROLES},
        ) for scene, values in sorted(by_scene.items())},
    )


def behavior(row):
    """按登记映射取行为；旧索引缺字段时显式映射，未知原场景拒绝而非静默回退。"""
    original = row.get('originalScenario', row.get('scenario'))
    if original not in BEHAVIORS:
        raise ValueError('未登记的行为映射: ' + str(original))
    if row.get('behaviorScenario', BEHAVIORS[original]) != BEHAVIORS[original]:
        raise ValueError('behaviorScenario 与原场景不符')
    return BEHAVIORS[original]


def group_admission(rows, scenarios=None):
    """类/角色/场景组数取实际索引，独立开发的五组必须在该角色内满足。"""
    counts = Counter()
    groups = defaultdict(set)
    scenes = defaultdict(set)
    for row in rows:
        label, role, group = str(row['label']), row['split'], row['leakageGroupId']
        if role not in ROLES or label not in ('0', '1'):
            raise ValueError('未知角色或Unknown标签')
        counts[(role, label)] += 1
        groups[(role, label)].add(group)
        if label == '1':
            scenes[(behavior(row), role)].add(group)
    scenarios = sorted(scenarios if scenarios is not None else {s for s, _ in scenes})
    blockers = []
    for label, kind in [('0', 'BENIGN'), ('1', 'ATTACK')]:
        if len(set().union(*(groups[(r, label)] for r in ROLES))) < 5:
            blockers.append('FEWER_THAN_FIVE_INDEPENDENT_' + kind + '_GROUPS')
        if len(groups[('independent_development', label)]) < 5:
            blockers.append('INDEPENDENT_DEVELOPMENT_FEWER_THAN_FIVE_' + kind + '_GROUPS')
        for role in ROLES:
            if not counts[(role, label)]:
                blockers.append('ROLE_MISSING_CLASS:' + role + ':' + label)
    if not scenarios:
        blockers.append('NO_DECLARED_ATTACK_SCENARIO')
    for scenario in scenarios:
        if any(not scenes[(scenario, role)] for role in ROLES):
            blockers.append('SCENARIO_NOT_PRESENT_IN_ALL_DEVELOPMENT_ROLES:' + scenario)
    return dict(trainingAllowed=not blockers, blockers=sorted(set(blockers)),
                roleCounts={r: {label: counts[(r, label)] for label in ('0', '1')} for r in ROLES},
                roleClassGroups={r: {label: len(groups[(r, label)]) for label in ('0', '1')} for r in ROLES},
                sceneRoleAttackGroups={s: {r: len(scenes[(s, r)]) for r in ROLES} for s in scenarios})


def near_vector(features):
    """沿用v2完整parent粗粒度序列，禁止只换身份使相同业务进入不同角色。"""
    fields = [('elapsedMs', 1000), ('bytesInbound', 32), ('bytesOutbound', 32),
              ('packetsInbound', 1), ('packetsOutbound', 1), ('lengthMin', 8),
              ('lengthMax', 8), ('lengthMean', 8), ('synCount', 1),
              ('synAckCount', 1), ('rstCount', 1), ('finCount', 1)]
    return [None if features[k] is None else round(features[k] / bucket) for k, bucket in fields] + [features['handshakeSeen']]


def verify(root, scenarios=None):
    """核验哈希、逐观察身份/质量、整组隔离和时间线；遇到损坏拒绝而非忽略。"""
    root = Path(root).resolve()
    report = read(root / 'readiness.json')
    if report.get('finalRead') is not False or report.get('modelFits') != 0:
        raise ValueError('新冻结集已经暴露最终数据或用于拟合')
    required = {'index.jsonl', 'observations.jsonl', 'partitions.json', 'p6-sealed-manifest.json'}
    if not required <= report['outputHashes'].keys():
        raise ValueError('冻结文件不完整')
    for name, expected in report['outputHashes'].items():
        path = (root / name).resolve()
        if root not in path.parents or sha(path) != expected:
            raise ValueError('冻结哈希或文件路径不符: ' + name)
    sealed = read(root / 'p6-sealed-manifest.json')
    if any(sealed.get(k) is not False for k in ('featuresRead', 'labelsRead', 'modelScoresRead', 'evaluationAllowed')):
        raise ValueError('P6封存边界不符')
    sealed_hashes = {r['sha256'] for r in sealed['captures']}
    partition = read(root / 'partitions.json')
    revised = partition['version'] == 'prefix-corpus-partition-v5'
    bindings = {}
    activities = {}
    for group in partition['groups']:
        if group['role'] not in ROLES or group['groupId'] in bindings:
            raise ValueError('分区角色或组身份无效')
        bindings[group['groupId']] = group['role']
        for activity in group['activities']:
            if activity in activities:
                raise ValueError('同一活动被拆为多个组')
            activities[activity] = group['groupId']
    rows = []
    seen = set()
    parents = {}
    sequences = defaultdict(list)
    cohorts = defaultdict(lambda: [math.inf, -math.inf, set(), set()])
    bad_flags = ('captureGap', 'latePacket', 'truncated', 'offloadSuspected', 'capacityDrop')
    for row, obs in zip(lines(root / 'index.jsonl'), lines(root / 'observations.jsonl'), strict=True):
        ident, parent = row['observationId'], row['parentConnectionId']
        if ident in seen or ident != obs['observationId'] or parent != obs['parentConnectionId']:
            raise ValueError('重复或错配的观察身份')
        seen.add(ident)
        if row['label'] not in (0, 1) or isinstance(row['label'], bool):
            raise ValueError('非法标签')
        if (obs['contractVersion'], obs['profile'], obs['direction'], obs['transport'], obs['addressFamily'], obs['servicePort']) != (CONTRACT, PROFILE, 'inbound', 'tcp', 'ipv4', 80):
            raise ValueError('特征profile或支持范围不符')
        if any(obs['quality'].get(k) is not False for k in bad_flags):
            raise ValueError('不合格观察质量')
        first, last, at, emitted = map(time_ms, (obs[k] for k in ('firstSeenAt', 'lastPacketAt', 'asOf', 'emittedAt')))
        if not first <= last <= at <= emitted or abs(obs['features']['elapsedMs'] - (at - first)) > .01:
            raise ValueError('因果时序或观察年龄不符')
        if row['firstSeenAt'] != obs['firstSeenAt'] or row['asOf'] != obs['asOf']:
            raise ValueError('索引时刻不符')
        group = row['leakageGroupId']
        if revised:
            normalized = metadata(row)
            if any(row.get(k) != normalized[k] for k in ('plannedRole', 'behaviorScenario', 'originalScenario', 'scenarioMappingVersion', 'sourceDomainId', 'contextSourceId')):
                raise ValueError('新版旁路字段缺失或行为映射不符')
        if bindings.get(group) != row['split'] or activities.get(row['activityId']) != group:
            raise ValueError('分区或活动被修改')
        binding = (group, row['split'], row['activityId'], row['cohortId'], row['label'], row['budgetTargetId'])
        if parents.setdefault(parent, binding) != binding:
            raise ValueError('parent跨角色/活动/组')
        if row.get('captureSha256') in sealed_hashes:
            raise ValueError('封存捕获混入开发材料')
        if not isinstance(row.get('budgetTargetId'), str) or not row['budgetTargetId']:
            raise ValueError('缺少稳定目标预算旁路')
        sequences[parent].append((at, near_vector(obs['features'])))
        c = cohorts[row['cohortId']]
        c[0], c[1] = min(c[0], first), max(c[1], at)
        c[2].update(context_sources(row)); c[3].add(group)
        rows.append(row)
    signatures = {}
    for parent, sequence in sequences.items():
        if len(sequence) < 2:
            continue
        digest = hashlib.sha256(json.dumps([v for _, v in sorted(sequence, key=lambda x: x[0])], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        group = parents[parent][0]
        if signatures.setdefault(digest, group) != group:
            raise ValueError('跨组整parent近重复')
    values = list(cohorts.values())
    if revised:
        for left, right, window in early_edges(sequences, {p: binding[0] for p, binding in parents.items()}):
            if left != right:
                raise ValueError('跨组共同早期轨迹: ' + str(window))
    for i, c in enumerate(values):
        if len(c[3]) != 1:
            raise ValueError('来源日/cohort被拆组')
        for d in values[:i]:
            if c[2] & d[2] and c[0] < d[1] + 150000 and d[0] < c[1] + 150000 and c[3] != d[3]:
                raise ValueError('同源150秒上下文跨组')
    if len(rows) != report['observations'] or len(parents) != report['parents']:
        raise ValueError('冻结分母不符')
    admission = group_admission(rows, scenarios)
    if not revised:
        admission['blockers'].append('P3_A_ROLE_BEHAVIOR_EARLY_TRAJECTORY_NOT_FROZEN')
    if admission['roleCounts'] != report['roleCounts'] or admission['roleClassGroups'] != report['roleClassGroups']:
        raise ValueError('声明的角色计数不符')
    timeline_path = root / 'label-timeline.jsonl'
    if 'label-timeline.jsonl' not in report['outputHashes']:
        admission['blockers'].append('QUALIFIED_LABEL_TIMELINE_NOT_FROZEN')
    else:
        ids = set()
        timeline = defaultdict(list)
        for ep in lines(timeline_path):
            if ep['episodeId'] in ids or ep['label'] not in (0, 1) or not all(math.isfinite(ep[k]) for k in ('startMs','endMs')) or ep['startMs'] >= ep['endMs']:
                raise ValueError('时间线身份/标签/区间无效')
            ids.add(ep['episodeId'])
            if activities.get(ep['activityId']) != ep['leakageGroupId'] or bindings.get(ep['leakageGroupId']) != ep['split']:
                raise ValueError('时间线跨角色或活动')
            if revised and (metadata(ep)['plannedRole'] != ep['split'] or ep.get('behaviorScenario') != metadata(ep)['behaviorScenario']):
                raise ValueError('标签时间线 plannedRole 或行为映射不符')
            timeline[(ep['activityId'],ep['targetId'],ep['label'])].append((ep['startMs'],ep['endMs']))
        for row in rows:
            at = time_ms(row['asOf'])
            if not any(start<=at<=end+.001 for start,end in timeline[(row['activityId'],row['budgetTargetId'],row['label'])]):
                raise ValueError('合格观察缺少对应的真值时间线')
    admission['trainingAllowed'] = not admission['blockers']
    grouping = grouping_summary(rows, partition)
    if 'groupingSummary' in report and report['groupingSummary'] != grouping:
        raise ValueError('声明的归组原因或来源计数不符')
    return dict(version='prefix-corpus-verification-v2', integrityPassed=True, **admission,
                observations=len(rows), parents=len(parents), activities=len(activities),
                leakageGroups=len(bindings), crossRoleParents=0, crossRoleActivities=0,
                crossRoleNearDuplicates=0, finalTestRead=False, modelFits=0,
                groupingSummary=grouping,
                readinessSha256=sha(root / 'readiness.json'), verifierSha256=sha(Path(__file__)))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset', type=Path, required=True)
    p.add_argument('--output', type=Path)
    p.add_argument('--require-training', action='store_true')
    args = p.parse_args()
    result = verify(args.dataset)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    print(json.dumps(result, ensure_ascii=False))
    if args.require_training and not result['trainingAllowed']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
