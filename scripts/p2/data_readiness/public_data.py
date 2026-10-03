#!/usr/bin/env python3
"""准备公开捕获的同服务标签及逐主机切片；不改地址/端口，不合并主机上下文。

仅 CSV 的身份、标签、时间、包数和载荷数用于关联旁路；CSV 特征不能作为
模型输入。各主机切片完整保留所观测双向流量和时间，原件哈希在整次读取后核验。
"""
import argparse
import collections
import csv
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/p2'))
sys.path.insert(0, str(ROOT / 'scripts/p1'))
from prepare_labels import timestamp, sha
from pcap_reference import frames


def write(path, obj):
    with path.open('x', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write('\n')


def normalize(source, anchor, source_id, output):
    """规范整份来源中触及登记主机的 TCP 标签，保留失败/重叠而非先挑成功记录。"""
    rows, groups, census = [], collections.defaultdict(list), collections.Counter()
    total = 0
    with source.open(encoding='utf-8') as f:
        for raw in csv.DictReader(f):
            total += 1
            if raw['Protocol'] != '6' or anchor not in (raw['Src IP'], raw['Dst IP']):
                continue
            start = timestamp(raw['Timestamp'])
            row = dict(id=hashlib.sha256((source_id + '\0' + raw['id']).encode()).hexdigest(),
                       origin=f"{raw['Src IP']}:{raw['Src Port']}", responder=f"{raw['Dst IP']}:{raw['Dst Port']}",
                       protocol=6, start=start, end=start + int(raw['Flow Duration']), label=raw['Label'],
                       fwdPackets=int(raw['Total Fwd Packet']), bwdPackets=int(raw['Total Bwd packets']),
                       fwdPayload=int(raw['Total Length of Fwd Packet']), bwdPayload=int(raw['Total Length of Bwd Packet']),
                       overlaps=False)
            rows.append(row)
            groups[tuple(sorted((row['origin'], row['responder'])))].append(row)
            census[row['label']] += 1
    for group in groups.values():
        active = []
        for row in sorted(group, key=lambda r: r['start']):
            active = [v for v in active if v['end'] + 2 >= row['start']]
            if active:
                row['overlaps'] = True
                for previous in active:
                    previous['overlaps'] = True
            active.append(row)
    with output.open('x') as f:
        os.chmod(output, 0o600)
        for row in rows:
            f.write(json.dumps(row, separators=(',', ':')) + '\n')
    report = dict(sourceId=source_id, sourceSha256=sha(source), normalizedSha256=sha(output),
                  tableRows=total, selectedRows=len(rows), labels=dict(census),
                  overlappingRows=sum(r['overlaps'] for r in rows), numericFeaturesImported=False)
    write(output.with_suffix('.normalization.json'), report)
    return report


def prepare_benign(source, run):
    """按同服务 BENIGN 数量确定八个来源主机，完整主机分组在四比四角色间隔离。"""
    census = collections.Counter()
    with source.open() as f:
        for r in csv.DictReader(f):
            if r['Protocol'] == '6' and r['Dst Port'] == '80' and r['Label'] == 'BENIGN':
                census[r['Dst IP']] += 1
    selected = sorted(census, key=lambda ip: (-census[ip], hashlib.sha256(ip.encode()).hexdigest()))[:8]
    registrations = []
    for i, anchor in enumerate(selected):
        name = f'public-web-{i:02d}'
        root = run / name
        root.mkdir()
        role = 'train' if i % 2 == 0 else 'validation_selection'
        config = dict(assetId=str(uuid.uuid4()), sensorId=str(uuid.uuid4()), bootId=str(uuid.uuid4()),
                      captureScopeId=str(uuid.uuid4()), localAddresses=[anchor],
                      secretFile=str((run / 'peer-key.bin').resolve()), keyEpoch=1)
        write(root / 'config.json', config)
        result = normalize(source, anchor, 'cic2017-wednesday', root / 'labels.jsonl')
        registrations.append(dict(name=name, role=role, sourceId='cic2017-wednesday',
             activityId=hashlib.sha256(('cic2017-wednesday-server-' + anchor).encode()).hexdigest(),
             selectedBenignServiceRows=census[anchor], normalizedRows=result['selectedRows'],
             sourceView='observed server endpoints within benchmark client-network capture; not complete server-side visibility'))
    write(run / 'public-benign-registration.json', dict(selection='top 8 BENIGN TCP/80 destination counts; ties SHA256; all rows normalized; fixed before extraction',
          sourceSha256=sha(source), registrations=registrations))
    print(json.dumps({'registeredHosts': len(registrations), 'selectedSameServiceBenignRows': sum(r['selectedBenignServiceRows'] for r in registrations)}))


def carve(pcap, run, expected):
    """按原始 IP 归属复制帧；不可定位的头部缺陷复制到所有捕获域供提取器拒绝。"""
    reg = json.loads((run / 'public-benign-registration.json').read_text())['registrations']
    output, by_address, counts = {}, {}, collections.Counter()
    for row in reg:
        root = run / row['name']
        config = json.loads((root / 'config.json').read_text())
        by_address[ipaddress.IPv4Address(config['localAddresses'][0]).packed] = row['name']
        out = (root / 'capture.pcap').open('xb')
        out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        output[row['name']] = out
    audit = {}
    try:
        for ts, data, wire, link in frames(pcap, audit):
            if link != 1:
                raise ValueError('仅支持此来源的 Ethernet 捕获')
            offset = 14
            eth = data[12:14]
            if eth == b'\x81\x00' and len(data) >= 18:
                eth, offset = data[16:18], 18
            if len(data) < 14 or eth == b'\x08\x00' and len(data) < offset + 20:
                names = set(output)
            elif eth == b'\x08\x00':
                names = {by_address[x] for x in (data[offset + 12:offset + 16], data[offset + 16:offset + 20]) if x in by_address}
            else:
                continue
            for name in names:
                output[name].write(struct.pack('<IIII', ts // 1000000, ts % 1000000, len(data), wire) + data)
                counts[name] += 1
    finally:
        for f in output.values():
            f.close()
    if audit['sha256'] != expected or not audit['completeContainer'] or audit.get('subMicrosecondTimestamps', 0):
        raise ValueError('原件哈希、完整性或时间精度不符')
    write(run / 'public-benign-carving.json', dict(sourceAudit=audit, framesByHost=dict(counts),
          derivativeHashes={row['name']: sha(run / row['name'] / 'capture.pcap') for row in reg},
          referenceCodeSha256=sha(ROOT / 'scripts/p1/pcap_reference.py'),
          addressPortOrTimeModified=False, hostContextsMerged=False))
    print(json.dumps({'status': 'passed', 'frames': dict(counts)}))


def extract_benign(run):
    registrations = json.loads((run / 'public-benign-registration.json').read_text())['registrations']
    for row in registrations:
        root = run / row['name']
        limits = ['--end', '2017-07-05T13:10:30Z'] if row['role'] == 'train' else ['--start', '2017-07-05T13:15:30Z']
        subprocess.run([str(ROOT / 'sensor/bin/guardextract'), '--config', str(root / 'config.json'),
             '--pcap', str(root / 'capture.pcap'), '--out', str(root / 'observations.jsonl'),
             '--ledger', str(root / 'ledger.jsonl'), '--report', str(root / 'extraction.json')] + limits, check=True)
        if not (root / 'joins.jsonl').exists():
            subprocess.run([str(ROOT / 'sensor/bin/guardjoin'), '--labels', str(root / 'labels.jsonl'),
                 '--pcap', str(root / 'capture.pcap'), '--out', str(root / 'joins.jsonl')], check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('normalize', 'prepare-benign', 'carve', 'extract-benign'))
    p.add_argument('--source', type=Path)
    p.add_argument('--anchor')
    p.add_argument('--source-id')
    p.add_argument('--output', type=Path)
    p.add_argument('--run', type=Path)
    p.add_argument('--expected-sha256')
    a = p.parse_args()
    if a.action == 'normalize':
        print(json.dumps(normalize(a.source, a.anchor, a.source_id, a.output)))
    elif a.action == 'prepare-benign':
        prepare_benign(a.source, a.run)
    elif a.action == 'carve':
        carve(a.source, a.run, a.expected_sha256)
    else:
        extract_benign(a.run)


if __name__ == '__main__':
    main()
