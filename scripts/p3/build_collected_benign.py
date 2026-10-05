#!/usr/bin/env python3
"""核验本轮真实正常任务PCAP后接入Go因果提取器；任务和标签只走旁路。

实际SYN、完整响应、内容哈希、时长、并发和捕获计数全部核验，失败不输出
合格样本。同一资产/对端预算稳定，捕获域每批重置；独立性仍交由整组冻结审查。
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'p1'))
from pcap_reference import tcp
from verify_benign_long import reassemble
from verify_prefix_corpus import lines, read, sha, time_ms
from build_qualified_prefix import target_key


def audit(batch):
    """只接受新登记任务的六个真实业务连接，重传可重组，截短/序号缺口拒绝。"""
    task = read(batch / 'task.json')
    if not task['success'] or not task['listenerClosed'] or not task['capture']['passed']:
        raise ValueError('业务或采集未通过')
    conns = {}; quality = Counter(); count = 0
    with (batch / 'native.pcap').open('rb') as stream:
        head = stream.read(24)
        if head[:4] != b'\xd4\xc3\xb2\xa1' or struct.unpack_from('<I', head, 20)[0] != 0:
            raise ValueError('非登记原生NULL链路')
        while header := stream.read(16):
            if len(header) != 16: raise ValueError('截短记录头')
            sec, micro, cap, wire = struct.unpack('<IIII', header); frame = stream.read(cap)
            if len(frame) != cap or cap != wire or frame[:4] != struct.pack('<I', 2) or micro >= 1000000:
                raise ValueError('截短或非IPv4记录')
            at = sec * 1000000 + micro; ip = frame[4:]
            packet = tcp(at, ip, wire - 4, 101, quality); count += 1
            if packet is None or {packet['src'][0], packet['dst'][0]} != {0x7f000001, 0x7f000002}:
                raise ValueError('包超出授权回环范围')
            forward = packet['dst'] == (0x7f000001, 80)
            if not forward and packet['src'] != (0x7f000001, 80): raise ValueError('包超出登记服务')
            key = packet['key']; c = conns.get(key)
            if packet['flags'] & 2 and not packet['flags'] & 16:
                if not forward or c is not None: raise ValueError('异常SYN epoch')
                c = dict(firstUs=at, lastUs=at, base=(packet['seq'] + 1) % 2**32,
                         reverseBase=None, closeUs=None, request=[], response=[], peerPort=packet['src'][1])
                conns[key] = c
            if c is None: raise ValueError('缺少完整SYN')
            c['lastUs'] = max(c['lastUs'], at)
            if packet['flags'] & 5 and c['closeUs'] is None: c['closeUs'] = at
            if not forward and packet['flags'] & 2: c['reverseBase'] = (packet['seq'] + 1) % 2**32
            body = ip[packet['payloadOffset']:packet['payloadOffset'] + packet['payloadBytes']]
            if body: c['request' if forward else 'response'].append(((packet['seq'] + bool(packet['flags'] & 2)) % 2**32, body))
    expected = {r['peerPort']: r for r in task['records']}
    if len(conns) != len(expected) or count != task['capture']['frames'] or quality:
        raise ValueError('连接/捕获分母或质量不符')
    results = []
    for c in conns.values():
        if c['reverseBase'] is None or c['closeUs'] is None: raise ValueError('握手或关闭不完整')
        req = reassemble(c['request'], c['base']); resp = reassemble(c['response'], c['reverseBase'])
        head, body = resp.split(b'\r\n\r\n', 1); record = expected[c['peerPort']]
        method, path, protocol = req.split(b'\r\n', 1)[0].decode('ascii').split(' ')
        lengths = [v.split(b':', 1)[1].strip() for v in head.split(b'\r\n') if v.lower().startswith(b'content-length:')]
        if path != record['path'] or int(head.split(b' ')[1]) != record['status'] or lengths != [str(len(body)).encode()] or len(body) != record['bodyBytes'] or hashlib.sha256(body).hexdigest() != record['bodySha256']:
            raise ValueError('真实业务路径/状态/内容不符')
        duration = (c['lastUs'] - c['firstUs']) / 1e6
        profile = task['profile']
        if path == '/stream' and not profile['durationSeconds'] - .03 <= duration <= profile['durationSeconds'] + 3:
            raise ValueError('真实长期下载时长不符')
        if path == '/poll' and not profile['pollSeconds'] - .03 <= duration <= profile['pollSeconds'] + 3:
            raise ValueError('真实长轮询时长不符')
        if path == '/upload':
            from collect_benign_prefix import content
            if method != 'POST' or req.split(b'\r\n\r\n', 1)[1] != content(profile['uploadChunkBytes']) * profile['uploadChunks']:
                raise ValueError('正常上传未完整完成')
        results.append(dict(peerPort=c['peerPort'], firstUs=c['firstUs'], lastUs=c['lastUs'],
                            closeUs=c['closeUs'], kind=path[1:], durationSeconds=duration))
    active = maximum = 0
    for _, change in sorted([(c['firstUs'], 1) for c in results] + [(c['closeUs'], -1) for c in results]):
        active += change; maximum = max(maximum, active)
    if maximum > 4: raise ValueError('实际并发超过授权')
    return task, results, maximum


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'extractor', 'output'): p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args(); registration = read(args.root / 'registration.json')
    if read(args.root / 'complete.json')['status'] != 'completed': raise ValueError('整轮任务未完成')
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    secret = args.output / 'peer-key.bin'; secret.write_bytes(os.urandom(32)); secret.chmod(0o600)
    identity = dict(assetId=str(uuid.uuid4()), sensorId=str(uuid.uuid4()), secretFile=str(secret.resolve()), keyEpoch=1)
    rows = []; observations = []; timelines = []; audits = []; previous_end = None
    for profile in registration['profiles']:
        batch = args.root / f"batch-{profile['batch']:02}"
        task, connections, maximum = audit(batch)
        if task['profile'] != profile or task['role'] != profile['role']: raise ValueError('任务预登记不符')
        start = min(c['firstUs'] for c in connections); end = max(c['lastUs'] for c in connections)
        if previous_end is not None and start - previous_end < 150000000: raise ValueError('批次上下文隔离不足')
        previous_end = end
        work = args.output / batch.name; work.mkdir()
        config = dict(identity, bootId=str(uuid.uuid4()), captureScopeId=str(uuid.uuid4()), localAddresses=['127.0.0.1'])
        (work / 'config.json').write_text(json.dumps(config) + '\n')
        result = subprocess.run([str(args.extractor.resolve()), '-config', str(work / 'config.json'), '-pcap', str(batch / 'native.pcap'), '-out', str(work / 'observations.jsonl'), '-ledger', str(work / 'ledger.jsonl'), '-report', str(work / 'extraction.json')], capture_output=True, text=True, timeout=120)
        if result.returncode: raise RuntimeError('GO_EXTRACTION_FAILED:' + result.stderr[-200:])
        ex = read(work / 'extraction.json')
        for key, path in [('pcapSha256', batch / 'native.pcap'), ('observationsSha256', work / 'observations.jsonl'), ('localLedgerSha256', work / 'ledger.jsonl')]:
            if ex[key] != sha(path): raise ValueError('Go原件身份不符')
        if ex['status'] != 'completed' or ex['version'] != 'host-guard/5.0.0-rc.2': raise ValueError('Go契约不符')
        parents = {}; target = target_key(identity['assetId'], '127.0.0.1:80', '127.0.0.2:0'); kept = Counter()
        for obs, ledger in zip(lines(work / 'observations.jsonl'), lines(work / 'ledger.jsonl'), strict=True):
            if obs['observationId'] != ledger['observationId']: raise ValueError('观察旁路错配')
            ep = ledger['Endpoints']; parent = obs['parentConnectionId']
            if ep['Local'] != '127.0.0.1:80': continue
            if parent not in parents:
                matches = [c for c in connections if c['peerPort'] == int(ep['Peer'].rsplit(':', 1)[1]) and abs(c['firstUs'] - time_ms(obs['firstSeenAt']) * 1000) <= 1]
                if len(matches) != 1: raise ValueError('正常parent未唯一绑定SYN')
                parents[parent] = matches[0]
            c = parents[parent]
            if any(obs['quality'][k] for k in ('captureGap', 'latePacket', 'truncated', 'offloadSuspected', 'capacityDrop')) or obs['profile'] != 'flow-prefix-v1': continue
            rows.append(dict(observationId=obs['observationId'], parentConnectionId=parent,
                 activityId=task['activityId'], associationGroup=task['activityId'], sourceId='controlled_windows_http_cde',
                 scenario='controlled_benign', split=task['role'], label=0, family='benign',
                 evidenceTier='controlled_task', taskKind=c['kind'], labelRuleVersion='p3-cde-verified-complete-task-v1',
                 captureSha256=ex['pcapSha256'], firstSeenAt=obs['firstSeenAt'], asOf=obs['asOf'], budgetTargetId=target))
            observations.append(obs); kept[c['kind']] += 1
        for parent, c in parents.items():
            timelines.append(dict(episodeId=hashlib.sha256((task['activityId'] + parent).encode()).hexdigest(),
                 parentConnectionId=parent, activityId=task['activityId'], scenario='controlled_benign', label=0,
                 targetId=target, startMs=c['firstUs'] / 1000, endMs=c['lastUs'] / 1000,
                 hasObservation=any(r['parentConnectionId'] == parent for r in rows), basis='pre_registered_controlled_task_and_verified_content'))
        audits.append(dict(batch=batch.name, activityId=task['activityId'], role=task['role'],
            actualConnectionSeconds=[c['durationSeconds'] for c in connections], connections=len(connections),
            maxConcurrent=maximum, captureDrops=task['capture']['stats']['dropped'], keptByKind=dict(kept),
            captureSha256=ex['pcapSha256'], taskSha256=sha(batch / 'task.json'), extractionSha256=sha(work / 'extraction.json')))
    for name, values in [('index.jsonl', rows), ('observations.jsonl', observations), ('label-timeline.jsonl', timelines)]:
        with (args.output / name).open('x', encoding='utf-8') as stream:
            for value in values: stream.write(json.dumps(value) + '\n')
    report = dict(version='p3-cde-qualified-benign-v1', observations=len(rows), parents=len({r['parentConnectionId'] for r in rows}),
         activities=len(audits), sourceDomainCount=1, taskAudits=audits, finalRead=False, modelFits=0,
         rolesFrozen=False, trainingAllowed=False, registrationSha256=sha(args.root / 'registration.json'),
         extractorSha256=sha(args.extractor), outputHashes={n: sha(args.output / n) for n in ('index.jsonl', 'observations.jsonl', 'label-timeline.jsonl')})
    (args.output / 'readiness.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('observations', 'parents', 'activities', 'sourceDomainCount')}))


if __name__ == '__main__': main()
