#!/usr/bin/env python3
"""在 Windows 对既有受控 PCAP 离线复算；成功活动可追溯连接仅进入 L3 test。

不运行采集、网络任务或训练。任务/旁路身份不进入模型输入；原角色不继承。
攻击端口未由原任务登记，因此仅在端点、时段、数量和健康全部一致时关联。
"""
import argparse
import collections
import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path

from multiclass_common import (PLAN, LABEL_VERSION, CLASS_VERSION, applicable,
    controlled_root, create, defective, digest, endpoint, line, micros, model_input,
    rows, write_json)
from capture_health import HealthChain


def verified_health(folder):
    """核对已登记观察器原件、哈希链与每段健康状态，不启动观察器或采集。"""
    registry = json.loads((folder / 'health-registry.json').read_text(encoding='utf-8-sig'))
    binding_path = folder / 'observer-binding.json'
    binding = json.loads(binding_path.read_text(encoding='utf-8-sig'))['binding']
    records_path = folder / 'health-records.jsonl'
    if (digest(binding_path)['sha256'] != registry['bindingSha256']
            or registry['observerBindings'] != [binding]
            or digest(records_path)['sha256'] != registry['recordsSha256']):
        raise ValueError('健康登记与原件哈希不符')
    chain, states = HealthChain([binding]), {}
    for record in rows(records_path):
        state = chain.accept(record)
        if record['sequence'] in states:
            raise ValueError('健康链重复序号')
        states[record['sequence']] = state
    if len(states) != registry['records'] or not states:
        raise ValueError('健康记录数不符')
    return binding, states, {'registrySha256': digest(folder / 'health-registry.json')['sha256'],
                            'recordsSha256': registry['recordsSha256'], 'bindingSha256': registry['bindingSha256'],
                            'records': len(states)}


def health_coverage(health, binding, states, start_us, end_us):
    """任务前后采样作为锚点；末包须由后续已存在且连续的健康区间实际覆盖。

    采样水位可能落后末包，不把 after 当最终覆盖上限；断链、身份漂移、丢包
    或未知计数仍拒绝。观察器 packetsSeen 不替代任务 PCAP 的真实丢包统计。
    """
    for anchor in (health['before'], health['after']):
        state = states.get(anchor['sequence'])
        if (anchor['observerSessionId'] != binding['observerSessionId']
                or anchor['captureScopeId'] != binding['captureScopeId'] or not state
                or state['sha256'] != anchor['sha256'] or state['since'] is None
                or abs(state['since'] - anchor['healthySinceMs']) > .001
                or abs(state['end'] - anchor['throughMs']) > .001):
            raise ValueError('任务健康锚点不符')
    if health['after']['sequence'] < health['before']['sequence']:
        raise ValueError('任务健康锚点倒序')
    for sequence, state in states.items():
        if (sequence >= health['after']['sequence'] and state['since'] is not None
                and state['since'] <= start_us / 1000 <= end_us / 1000 <= state['end']):
            return {'sequence': sequence, 'sha256': state['sha256'],
                    'healthySinceMs': state['since'], 'throughMs': state['end']}
    raise ValueError('完整健康链未覆盖连接区间')


def verified_task(task, event):
    """受控任务证据不完整或采集丢包时拒绝整个活动，而非补标签。"""
    capture = task['capture']
    stats = capture['stats']
    if (not task['success'] or not event['success'] or task.get('error')
            or not task['listenerClosed'] or not capture['passed'] or capture['error']
            or any(stats[key] for key in ('dropped', 'interfaceDropped', 'networkDropped'))
            or not task['captureHealth']['continuous']):
        raise ValueError('活动或采集证据未通过')
    if event['kind'] == 'attack':
        expected = task['profile']['connections']
        if (task['mode'] not in ('slowloris', 'slowhttptest')
                or task['attackResult']['connected'] != expected
                or task['attackResult']['closedConnections'] != expected
                or len(task['serverRecords']) != expected
                or any(record['peer'] != '127.0.0.2' for record in task['serverRecords'])):
            raise ValueError('攻击任务成功/数量/端点不符')
        return 'dos_slow', expected, None
    records = task['records']
    server = {(record['path'], record['peerPort']) for record in task['serverRecords'] if record['success']}
    pairs = {(record['path'], record['peerPort']) for record in records if record['success']}
    if len(records) != 6 or len(pairs) != 6 or pairs != server:
        raise ValueError('困难良性客户端与服务器记录不符')
    return 'normal', 6, {record['peerPort'] for record in records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    root = controlled_root(args.run)
    if os.name != 'nt':
        raise ValueError('A6 必须在 Windows 目标运行时执行')
    ledger_paths = [args.source / folder / 'activity-ledger.jsonl'
                    for folder in ('health', 'health-supplement-01')]
    events = {}
    health_sources, health_evidence = {}, {}
    for path in ledger_paths:
        binding, states, evidence = verified_health(path.parent)
        health_evidence[path.parent.name] = evidence
        for event in rows(path):
            if event['activityId'] in events:
                raise ValueError('活动账本重复')
            events[event['activityId']] = event
            health_sources[event['activityId']] = (binding, states)
    pcaps = sorted(args.source.glob('**/native.pcap'))
    if len(pcaps) != 19 or len(events) != 19:
        raise ValueError('原件/账本不是已登记的 19 个活动')
    configs = controlled_root(root / 'configs')
    key_path = configs / 'peer-key.bin'
    with key_path.open('xb') as stream:
        stream.write(os.urandom(32))
    test = controlled_root(root / 'sealed-test')
    summaries = []
    counts, snapshots, exclusions = (collections.Counter() for _ in range(3))
    with create(test / 'dataset.jsonl') as dataset:
        for pcap in pcaps:
            source = pcap.parent
            task_path = source / ('activity.json' if (source / 'activity.json').exists() else 'task.json')
            task = json.loads(task_path.read_text(encoding='utf-8-sig'))
            event = events[task['activityId']]
            label, expected, ports = verified_task(task, event)
            output = controlled_root(root / 'extract' / (source.parent.name + '-' + source.name))
            config = configs / (output.name + '.json')
            write_json(config, {**{key: str(uuid.uuid4()) for key in
                ('assetId', 'sensorId', 'bootId', 'captureScopeId')},
                'localAddresses': ['127.0.0.1'], 'secretFile': str(key_path), 'keyEpoch': 1})
            subprocess.run([str(root / 'bin/guardextract.exe'), '-config', str(config),
                '-pcap', str(pcap), '-out', str(output / 'observations.jsonl'),
                '-ledger', str(output / 'ledger.jsonl'), '-report', str(output / 'extraction.json')], check=True)
            report = json.loads((output / 'extraction.json').read_text())
            source_hash = digest(pcap)['sha256']
            if report['status'] != 'completed' or report['pcapSha256'] != source_hash:
                raise ValueError('重提取原件不符')
            parents, eligible = {}, []
            for obs, entry in zip(rows(output / 'observations.jsonl'), rows(output / 'ledger.jsonl'), strict=True):
                if obs['observationId'] != entry['observationId']:
                    raise ValueError('旁路账本错位')
                if not applicable(obs):
                    exclusions['non_inbound_tcp_ipv4_snapshot'] += 1
                    continue
                local, peer = endpoint(entry['Endpoints']['Local']), endpoint(entry['Endpoints']['Peer'])
                if local != ('127.0.0.1', 80) or peer[0] != '127.0.0.2' or (ports and peer[1] not in ports):
                    exclusions['unregistered_endpoint_snapshot'] += 1
                    continue
                item = parents.setdefault(obs['parentConnectionId'], {'startUs': micros(entry['First']),
                    'endUs': micros(entry['Last']), 'peerPort': peer[1], 'cleanSnapshots': 0})
                item['startUs'] = min(item['startUs'], micros(entry['First']))
                item['endUs'] = max(item['endUs'], micros(entry['Last']))
                if defective(obs):
                    exclusions['quality_defective_snapshot'] += 1
                    continue
                item['cleanSnapshots'] += 1
                eligible.append(obs)
            if len(parents) != expected or (ports and {p['peerPort'] for p in parents.values()} != ports):
                raise ValueError('受控端点匹配连接数不符: ' + output.name + str(len(parents)))
            start = int((event['endedAt'] - task['elapsedSeconds'] - 3) * 1000000)
            end = int((event['endedAt'] + 3) * 1000000)
            health = task['captureHealth']
            binding, states = health_sources[task['activityId']]
            for item in parents.values():
                if item['startUs'] < start or item['endUs'] > end:
                    raise ValueError('连接不在任务窗口: ' + output.name)
                item['healthCoverage'] = health_coverage(health, binding, states, item['startUs'], item['endUs'])
            counts[label] += sum(bool(item['cleanSnapshots']) for item in parents.values())
            exclusions['all_snapshots_quality_defective_parent'] += sum(not item['cleanSnapshots'] for item in parents.values())
            with create(output / 'labels.jsonl') as labels:
                for parent, item in parents.items():
                    line(labels, {'parentConnectionId': parent, **item, 'label': label,
                        'activityId': task['activityId'], 'evidenceTier': 'controlled_task',
                        'labelRuleVersion': LABEL_VERSION, 'split': 'test', 'trainingAllowed': False})
            for obs in eligible:
                line(dataset, {'parentConnectionId': obs['parentConnectionId'], 'observationId': obs['observationId'],
                    'profile': obs['profile'], 'label': label, 'activityId': task['activityId'],
                    'evidenceTier': 'controlled_task', 'input': model_input(obs)})
                snapshots[label] += 1
            summaries.append({'activityId': task['activityId'], 'relativeSource': str(source.relative_to(args.source)),
                'originalRoleIgnored': task.get('plannedRole'), 'split': 'test', 'label': label,
                'connections': len(parents), 'cleanConnections': sum(bool(p['cleanSnapshots']) for p in parents.values()),
                'pcapBytes': pcap.stat().st_size, 'pcapSha256': source_hash,
                'taskSha256': digest(task_path)['sha256'], 'captureSha256': digest(source / 'capture.json')['sha256'],
                'configSha256': digest(config)['sha256'], 'extractionSha256': digest(output / 'extraction.json')['sha256'],
                'labelsSha256': digest(output / 'labels.jsonl')['sha256']})
            print(json.dumps({'completedActivity': output.name, 'connections': len(parents), 'label': label}), flush=True)
    manifest = {'plan': PLAN, 'stage': 'P3-A/A6', 'datasetRole': 'L3_test_only',
        'contractVersion': 'host-guard/5.0.0-rc.2', 'labelRuleVersion': LABEL_VERSION,
        'classMappingVersion': CLASS_VERSION, 'candidateOnly': True, 'modelFits': 0,
        'trainingAllowed': False, 'finalTestRead': False, 'activities': summaries,
        'connectionCounts': dict(counts), 'snapshotCounts': dict(snapshots), 'exclusions': dict(exclusions),
        'binarySha256': digest(root / 'bin/guardextract.exe')['sha256'],
        'datasetSha256': digest(test / 'dataset.jsonl')['sha256'],
        'ledgerSha256': {str(path.relative_to(args.source)): digest(path)['sha256'] for path in ledger_paths},
        'healthEvidence': health_evidence,
        'preparationSourceSha256': {path.name: digest(path)['sha256'] for path in (Path(__file__),
            Path(__file__).with_name('multiclass_common.py'), Path(__file__).with_name('capture_health.py'))},
        'limitations': ['Previously inspected controlled source; no novel holdout claim',
            'Loopback controlled tasks only, not real network effectiveness',
            'Windows read-only attribute prevents accidental writes, not privileged reading']}
    write_json(root / 'manifest.json', manifest)
    with create(root / 'test-access.jsonl') as stream:
        line(stream, {'event': 'sealed_after_preparation', 'stage': 'P3-A', 'testRead': False})
    os.chmod(test / 'dataset.jsonl', 0o400)
    print(json.dumps({'completed': 'A6', 'connections': dict(counts), 'snapshots': dict(snapshots)}), flush=True)


if __name__ == '__main__':
    main()
