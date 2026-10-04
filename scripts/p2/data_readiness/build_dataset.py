#!/usr/bin/env python3
"""补充已冻结 P2 数据，生成互斥训练/选型/校准索引、观察与可复算资格报告。

只接受完整来源关联或逐连接受控真值；任何 parent 的歧义/不支持标签均
整体排除。所有角色执行近重复排除，保留父连接权重，禁止把快照数量当活动数。
"""
import argparse
import bisect
import collections
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/p2'))
from build_partition import digest, lines, micros, signature
from prepare_labels import sha

ROLES = ('train', 'validation_selection', 'validation_calibration')


def save(path, obj):
    with path.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write('\n')


def verify_extraction(root, prefix=''):
    """摘要不是可信断言，读取账本/观察前重新核对其哈希和 config 绑定。"""
    report = json.loads((root / (prefix + 'extraction.json')).read_text())
    for field, name in [('observationsSha256', prefix + 'observations.jsonl'),
                        ('localLedgerSha256', prefix + 'ledger.jsonl')]:
        if sha(root / name) != report[field]:
            raise ValueError('提取输入哈希不匹配: ' + name)
    if report['status'] != 'completed':
        raise ValueError('提取未完成')
    config_name = 'calibration-config.json' if prefix == 'calibration-complete-' else prefix + 'config.json'
    if sha(root / config_name) != report['configSha256']:
        raise ValueError('配置与提取摘要不符')
    if report['version'] != 'host-guard/5.0.0-rc.2' or report['mode'] != 'research_offline':
        raise ValueError('提取器契约或环境不符')
    if report['binarySha256'] not in {sha(ROOT / 'sensor/bin/guardextract'), sha(ROOT / 'sensor/bin/guardextract.exe')}:
        raise ValueError('不是本次登记的冻结提取器')
    return report


def eligible(o):
    """固定 final 研究范围；未知方向、质量故障、EOF 和新 SYN 替换均不可加入。"""
    if (o['addressFamily'], o['transport'], o['direction'], o['servicePort']) != ('ipv4', 'tcp', 'inbound', 80):
        return 'scope'
    if any(v is True for k, v in o['quality'].items() if k != 'clockSkewMs'):
        return 'quality'
    if o['profile'] != 'flow-final-v1':
        return 'prefix_not_in_final_dataset'
    if o['closeReason'] in ('eof', 'new_syn'):
        return 'incomplete_connection'
    return None


def row_for(o, role, activity, label, source, tier, label_id, task=None):
    return dict(observationId=o['observationId'], parentConnectionId=o['parentConnectionId'],
                split=role, activityId=activity, label=label, family='connection_abuse' if label else None,
                sourceId=source, evidenceTier=tier, sourceLabelId=label_id, taskKind=task,
                duplicateGroup=signature(o), firstSeenAt=o['firstSeenAt'], asOf=o['asOf'])


def public_rows(root, role, source, activity, allowed_attack, labels_name='labels.jsonl',
                joins_name='joins.jsonl', observation_prefix='', boundary=None, limits=None):
    """按完整连接窗口唯一关联；先判定所有观察的 parent 标签，再选 final。"""
    extraction = verify_extraction(root, observation_prefix)
    capture = ROOT / 'data/raw/p2/cic2018/thursday-victim-complete-records.pcap' if observation_prefix else root / 'capture.pcap'
    if sha(capture) != extraction['pcapSha256']:
        raise ValueError('来源捕获与提取摘要不符')
    normalization_path = (root / labels_name).with_suffix('.normalization.json')
    normalization = json.loads(normalization_path.read_text())
    if sha(root / labels_name) != normalization['normalizedSha256']:
        raise ValueError('规范标签哈希不符')
    if limits and (extraction['partitionStart'], extraction['partitionEnd']) != limits:
        raise ValueError('公开背景分区时间不符')
    joins = {r['labelId']: r for r in lines(root / joins_name)}
    labels = list(lines(root / labels_name))
    if len(joins) != len(labels) or {r['id'] for r in labels} != set(joins):
        raise ValueError('标签与关联不是一一对应')
    bykey = collections.defaultdict(list)
    for r in labels:
        bykey[tuple(sorted((r['origin'], r['responder'])))].append(r)
    for rows in bykey.values():
        rows.sort(key=lambda r: r['start'])
    starts = {k: [r['start'] for r in rows] for k, rows in bykey.items()}
    rejected, identities, result = set(), collections.defaultdict(set), []
    counts = collections.Counter()
    for o, ledger in zip(lines(root / (observation_prefix + 'observations.jsonl')),
                         lines(root / (observation_prefix + 'ledger.jsonl')), strict=True):
        if o['observationId'] != ledger['observationId'] or o['parentConnectionId'] != ledger['parentConnectionId']:
            raise ValueError('观察/旁路顺序或 parent 不符')
        if o['transport'] != 'tcp':
            counts['unsupported_protocol'] += 1
            continue
        parent = o['parentConnectionId']
        ends = ledger['Endpoints']
        key = tuple(sorted((ends['Local'], ends['Peer'])))
        begin, end = micros(o['firstSeenAt']), micros(o['lastPacketAt'])
        candidates = [r for r in bykey.get(key, [])[:bisect.bisect_right(starts.get(key, []), begin + 1)] if r['end'] + 1 >= end]
        reason = None
        if len(candidates) != 1:
            reason = 'no_unique_covering_label'
        else:
            label = candidates[0]
            if joins[label['id']]['join'] != 'matched' or label['overlaps']:
                reason = 'unmatched_or_ambiguous'
            elif label['label'] != 'BENIGN' and label['label'] not in allowed_attack:
                reason = 'attempted_or_unsupported_family'
            elif boundary is not None and (label['end'] >= boundary - 150000000 or end >= boundary - 150000000):
                reason = 'capture_tail_isolation'
            elif limits and ((limits[0] and label['start'] < micros(limits[0])) or
                             (limits[1] and label['end'] > micros(limits[1]))):
                reason = 'label_crosses_partition'
        if reason:
            rejected.add(parent)
            counts[reason] += 1
            continue
        binary = int(label['label'] != 'BENIGN')
        # 客户端同一15分钟背景会话即便涉及多个服务器也只能算一个组。
        # 与攻击分区一致的300秒隔离，防止按服务器拆开同一浏览活动。
        group = digest([source, activity, 'attack']) if binary else digest(
            [source, 'background-peer-window', ends['Peer'].rsplit(':', 1)[0], label['start'] // 900000000])
        identities[parent].add((group, binary))
        issue = eligible(o)
        if issue:
            counts[issue] += 1
            if issue == 'incomplete_connection':
                rejected.add(parent)
            continue
        result.append((row_for(o, role, group, binary, source, 'publisher_documented', label['id']), o))
    rejected.update(p for p, values in identities.items() if len(values) != 1)
    retained = [(r, o) for r, o in result if r['parentConnectionId'] not in rejected]
    counts['whole_parent_excluded_snapshots'] = len(result) - len(retained)
    return retained, dict(counts)


def controlled_rows(root):
    report = json.loads((root / 'run.json').read_text())
    if not report['passed'] or not report['listenerClosed'] or report['elapsedSeconds'] > 1800:
        raise ValueError('授权任务未通过或超时/未关闭监听')
    selected, counts = [], collections.Counter()
    previous_end = None
    boots = set()
    summaries = []
    for s in report['sessions']:
        if s['role'] not in ROLES or not s['passed']:
            raise ValueError('任务角色或状态无效')
        start, end = micros(s['beganUtc']), micros(s['endedUtc'])
        if previous_end is not None and start - previous_end < 150000000:
            raise ValueError('独立任务间缺少 150 秒隔离')
        previous_end = end
        directory = root / f"session-{s['ordinal']:02d}"
        ex = verify_extraction(directory)
        config = json.loads((directory / 'config.json').read_text())
        if config['bootId'] in boots or sha(directory / 'config.json') != ex['configSha256']:
            raise ValueError('批次 boot 重复或配置绑定错误')
        boots.add(config['bootId'])
        if sha(directory / 'raw.pcap') != ex['pcapSha256']:
            raise ValueError('受控原件与提取不符')
        tasks = list(lines(directory / 'connections.jsonl'))
        if not tasks or any(not t['passed'] for t in tasks):
            raise ValueError('存在未通过的受控业务任务')
        by_peer = collections.defaultdict(list)
        for t in tasks:
            if t['server'] != ['127.0.0.1', 80] or t['peer'][0] != '127.0.0.2' or t['role'] != s['role']:
                raise ValueError('任务超出授权端点/角色')
            by_peer[f"127.0.0.2:{t['peer'][1]}"].append(t)
        rejected, samples = set(), []
        matched_tasks = set()
        for o, ledger in zip(lines(directory / 'observations.jsonl'), lines(directory / 'ledger.jsonl'), strict=True):
            if o['observationId'] != ledger['observationId'] or o['bootId'] != config['bootId']:
                raise ValueError('任务观察身份不符')
            endpoint = ledger['Endpoints']
            matches = [t for t in by_peer.get(endpoint['Peer'], []) if
                       micros(t['startedUtc']) - 100000 <= micros(o['firstSeenAt']) <= micros(t['endedUtc']) + 100000 and
                       micros(o['lastPacketAt']) <= micros(t['endedUtc']) + 1000000]
            parent = o['parentConnectionId']
            if endpoint['Local'] != '127.0.0.1:80' or len(matches) != 1:
                rejected.add(parent)
                counts['no_unique_task_connection'] += 1
                continue
            t = matches[0]
            issue = eligible(o)
            if issue:
                counts[issue] += 1
                if issue == 'incomplete_connection':
                    rejected.add(parent)
                continue
            matched_tasks.add((t['taskId'], t['peer'][1]))
            samples.append((row_for(o, s['role'], s['activityId'], 0, 'controlled-win-loopback',
                                    'controlled_task', digest(t), t['kind']), o))
        kept = [(r, o) for r, o in samples if r['parentConnectionId'] not in rejected]
        selected.extend(kept)
        summaries.append(dict(role=s['role'], ordinal=s['ordinal'], activityId=s['activityId'],
                              recordedConnections=len(tasks), matchedFinalConnections=len(matched_tasks),
                              retainedFinalSnapshots=len(kept), kinds=s['kinds'],
                              beganUtc=s['beganUtc'], endedUtc=s['endedUtc'],
                              tasksSha256=sha(directory / 'connections.jsonl'),
                              captureSha256=sha(directory / 'raw.pcap'), extractionSha256=sha(directory / 'extraction.json')))
    return selected, dict(counts), summaries


def deduplicate(selected):
    """全部角色一同排查，跨角色签名涉及的完整父连接均排除，不选一边保留。"""
    by_signature, by_parent, by_activity = (collections.defaultdict(set) for _ in range(3))
    ids = set()
    for r, _ in selected:
        if r['split'] not in ROLES or r['observationId'] in ids:
            raise ValueError('角色非法或观察重复')
        ids.add(r['observationId'])
        by_signature[r['duplicateGroup']].add(r['split'])
        by_parent[r['parentConnectionId']].add(r['split'])
        by_activity[r['activityId']].add(r['split'])
    if any(len(v) != 1 for groups in (by_parent, by_activity) for v in groups.values()):
        raise ValueError('父连接或独立活动跨角色')
    dupes = {k for k, v in by_signature.items() if len(v) > 1}
    parents = {r['parentConnectionId'] for r, _ in selected if r['duplicateGroup'] in dupes}
    retained = [(r, o) for r, o in selected if r['parentConnectionId'] not in parents]
    weights = collections.Counter(r['parentConnectionId'] for r, _ in retained)
    for r, _ in retained:
        r['sampleWeight'] = 1 / weights[r['parentConnectionId']]
    return retained, dict(crossRoleDuplicateGroups=len(dupes), wholeParentsExcluded=len(parents),
                         snapshotsExcluded=len(selected) - len(retained))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--controlled', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    run, base = a.run, ROOT / 'artifacts/p2/run-20261004'
    a.output.mkdir()
    selected, exclusions = [], {}
    index = {r['observationId']: r for r in lines(base / 'partition-index.jsonl')}
    original_manifest = json.loads((base / 'partition-manifest.json').read_text())
    if sha(base / 'partition-index.jsonl') != original_manifest['indexSha256']:
        raise ValueError('原分区索引哈希不符')
    found = set()
    for split in ('train', 'validation'):
        verify_extraction(base, split + '-')
        for o in lines(base / f'{split}-observations.jsonl'):
            if o['observationId'] not in index:
                continue
            r = index[o['observationId']]
            if eligible(o):
                raise ValueError('原冻结数据不满足 final 范围')
            r.update(split='train' if split == 'train' else 'validation_selection', sourceId='cic2017-wednesday', taskKind=None)
            selected.append((r, o))
            found.add(o['observationId'])
    if found != set(index):
        raise ValueError('原分区索引缺观察')
    reg = json.loads((run / 'public-benign-registration.json').read_text())
    for entry in reg['registrations']:
        limits = ('', '2017-07-05T13:10:30Z') if entry['role'] == 'train' else ('2017-07-05T13:15:30Z', '')
        rows, rejected = public_rows(run / entry['name'], entry['role'], entry['sourceId'], entry['activityId'], set(), limits=limits)
        selected.extend(rows)
        exclusions[entry['name']] = rejected
    derivative = json.loads((ROOT / 'data/raw/p2/cic2018/thursday-victim-complete-records.pcap.derivation.json').read_text())
    rows, rejected = public_rows(run, 'validation_calibration', 'cic2018-thursday', 'victim-thursday', {'DoS Slowloris'},
            labels_name='calibration-labels.jsonl', joins_name='calibration-joins.jsonl',
            observation_prefix='calibration-complete-', boundary=derivative['lastCompleteTimestampUs'])
    selected.extend(rows)
    exclusions['calibration_public'] = rejected
    rows, rejected, sessions = controlled_rows(a.controlled)
    selected.extend(rows)
    exclusions['controlled'] = rejected
    selected, dedup = deduplicate(selected)
    counts, source_counts, kinds = collections.Counter(), collections.Counter(), collections.Counter()
    parents, activities, source_parents = (collections.defaultdict(set) for _ in range(3))
    with (a.output / 'index.jsonl').open('x', encoding='utf-8', newline='\n') as ix, (a.output / 'observations.jsonl').open('x', encoding='utf-8', newline='\n') as obs:
        for r, o in sorted(selected, key=lambda item: (item[0]['split'], item[0]['observationId'])):
            ix.write(json.dumps(r, separators=(',', ':')) + '\n')
            obs.write(json.dumps(o, separators=(',', ':')) + '\n')
            key = r['split'] + '/' + str(r['label'])
            counts[key] += 1
            parents[key].add(r['parentConnectionId'])
            activities[key].add(r['activityId'])
            source_key = r['sourceId'] + '/' + key
            source_counts[source_key] += 1
            source_parents[source_key].add(r['parentConnectionId'])
            if r['taskKind']:
                kinds[r['split'] + '/' + r['taskKind']] += 1
    checks = dict(rolesHaveBothClasses=all(parents[r + '/' + str(y)] for r in ROLES for y in (0, 1)),
                  independentPositiveActivities=len({r['activityId'] for r, _ in selected if r['label']}) == 3,
                  multipleBenignSessionsEachRole=all(len({r['activityId'] for r, _ in selected if r['split'] == role and r['evidenceTier'] == 'controlled_task'}) >= 2 for role in ROLES),
                  allBenignKindsEachRole=all(kinds[r + '/' + k] > 0 for r in ROLES for k in sessions[0]['kinds']),
                  parentActivityDuplicateDisjoint=True, controlledCaptureClosed=True,
                  profileFinalOnly=all(o['profile'] == 'flow-final-v1' for _, o in selected))
    checks['rolesHaveBothClasses'] = bool(checks['rolesHaveBothClasses'])
    report = dict(version='p2-data-readiness-v1', status='passed' if all(checks.values()) else 'blocked',
        scope='bounded final-profile model feasibility research only', checks=checks,
        contractVersion='host-guard/5.0.0-rc.2', baseFreezeSha256=sha(ROOT / 'docs/p2/freeze-manifest.json'),
        planSha256=sha(ROOT / 'docs/p2/data-readiness/plan.json'),
        snapshots=dict(counts), parents={k: len(v) for k, v in parents.items()},
        activities={k: len(v) for k, v in activities.items()}, bySourceSnapshots=dict(source_counts),
        bySourceParents={k: len(v) for k, v in source_parents.items()}, controlledKinds=dict(kinds),
        controlledSessions=sessions, duplicateExclusions=dedup, exclusions=exclusions,
        indexSha256=sha(a.output / 'index.jsonl'), observationsSha256=sha(a.output / 'observations.jsonl'),
        finalResearchReady=all(checks.values()), prefixResearchReady=False,
        independentFinalTestAllocated=False, finalTestRead=False, finalAcceptanceEligible=False,
        limitations=['each role has only one positive attack activity; population confidence and family-wide generalization unproven',
          '2017 supplemental public server views cover only traffic seen in benchmark capture; not full server telemetry',
          'public attack-target BENIGN support remains sparse; controlled loopback is additional source and cannot prove production false-positive rates',
          'P3 must report public-only and controlled-only strata and source/host diagnostics; pooled scores are insufficient',
          '2018 source member has a damaged final record; intact derivative, boundary exclusion and original are bound separately',
          'prefix selection/calibration supervision is not complete; final models cannot claim early blocking',
          'P1 platform recovery and physical NIC capture qualification remain separate'],
        trainingExecuted=False, firewallModified=False)
    save(a.output / 'readiness.json', report)
    print(json.dumps({k: report[k] for k in ('status', 'snapshots', 'parents', 'activities', 'duplicateExclusions', 'checks')}))


if __name__ == '__main__':
    main()
