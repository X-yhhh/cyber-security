#!/usr/bin/env python3
"""将已登记目标主机的所有 TCP 修正标签规范化；原始端点只写受控输出，绝不打印。"""
import argparse
import collections
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path


def timestamp(text):
    value = dt.datetime.fromisoformat(text)
    delta = value - dt.datetime(1970, 1, 1)
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def prepare(source, config, output, report):
    anchors = set(json.loads(config.read_text())['localAddresses'])
    rows, groups, census = [], collections.defaultdict(list), collections.Counter()
    with source.open() as f:
        for row in csv.DictReader(f):
            if not anchors.intersection((row['Src IP'], row['Dst IP'])):
                census['outside_anchor'] += 1
                continue
            if row['Protocol'] != '6':
                census['non_tcp_diagnostic_only'] += 1
                continue
            start = timestamp(row['Timestamp'])
            item = dict(id=hashlib.sha256(('wednesday\0' + row['id']).encode()).hexdigest(),
                        origin=f"{row['Src IP']}:{row['Src Port']}",
                        responder=f"{row['Dst IP']}:{row['Dst Port']}", protocol=6,
                        start=start, end=start + int(row['Flow Duration']), label=row['Label'],
                        fwdPackets=int(row['Total Fwd Packet']), bwdPackets=int(row['Total Bwd packets']),
                        fwdPayload=int(row['Total Length of Fwd Packet']), bwdPayload=int(row['Total Length of Bwd Packet']),
                        overlaps=False)
            rows.append(item)
            groups[tuple(sorted((item['origin'], item['responder'])))].append(item)
            census['selected/' + item['label']] += 1
    for group in groups.values():
        group.sort(key=lambda r: r['start'])
        active = []
        for row in group:
            active = [v for v in active if v['end'] + 2 >= row['start']]
            if active:
                row['overlaps'] = True
                for other in active:
                    other['overlaps'] = True
            active.append(row)
    with output.open('x') as f:
        output.chmod(0o600)
        for row in rows:
            f.write(json.dumps(row, separators=(',', ':')) + '\n')
    result = dict(version='p2-label-normalization-v1', sourceSha256=sha(source),
                  configSha256=sha(config), normalizedSha256=sha(output), rows=len(rows),
                  overlappingRows=sum(r['overlaps'] for r in rows), census=dict(census),
                  scope='all TCP rows touching the registered development host; other protocols diagnostic only')
    with report.open('x') as f:
        json.dump(result, f, indent=2)
    print(json.dumps(dict(rows=len(rows), overlappingRows=result['overlappingRows'])))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'config', 'output', 'report'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    prepare(a.source, a.config, a.output, a.report)
