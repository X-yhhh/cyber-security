#!/usr/bin/env python3
"""保留来源不完整 PCAP 的最大完整记录前缀；原件不改，缺损显式记录。

仅接受 classic Ethernet PCAP 的末尾缺损，拒绝异常头部/长度。派生件不是
完整捕获证明；下游必须排除 EOF 和触及缺损边界的连接，不延长时间真值。
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import struct


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def derive(source, output):
    if output.exists():
        raise FileExistsError('保留已存在的派生件')
    records = 0
    first = last = None
    reason = None
    tail_time = None
    with source.open('rb') as f, output.open('xb') as target:
        header = f.read(24)
        if len(header) != 24 or header[:4] != bytes.fromhex('d4c3b2a1'):
            raise ValueError('仅支持已登记的 little-endian classic PCAP')
        _, major, minor, zone, precision, snaplen, link = struct.unpack('<IHHIIII', header)
        if (major, minor, zone, precision, link) != (2, 4, 0, 0, 1):
            raise ValueError('PCAP 布局不符')
        target.write(header)
        while True:
            boundary = f.tell()
            h = f.read(16)
            if not h:
                break
            if len(h) != 16:
                reason = 'incomplete_final_record_header'
                break
            seconds, micros, cap, wire = struct.unpack('<IIII', h)
            if micros >= 1000000 or not 0 < cap <= snaplen or cap > wire:
                raise ValueError('内部记录非法，不能通过裁尾修复')
            data = f.read(cap)
            if len(data) != cap:
                reason = 'incomplete_final_packet'
                tail_time = seconds * 1000000 + micros
                break
            target.write(h + data)
            records += 1
            now = seconds * 1000000 + micros
            first = now if first is None else min(first, now)
            last = now if last is None else max(last, now)
    return dict(version='p2-complete-record-prefix-v1', sourceSha256=sha(source),
                sourceBytes=source.stat().st_size, derivativeSha256=sha(output),
                derivativeBytes=output.stat().st_size, completeRecords=records,
                discardedTailBytes=source.stat().st_size - boundary,
                truncationReason=reason, incompleteRecordTimeUs=tail_time,
                firstTimestampUs=first, lastCompleteTimestampUs=last,
                sourceContainerComplete=reason is None,
                limitation='retained bytes are unchanged; EOF parents and labels crossing retained boundary are excluded; not full original capture qualification')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    report = derive(a.source, a.output)
    with a.output.with_suffix(a.output.suffix + '.derivation.json').open('x') as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report))
