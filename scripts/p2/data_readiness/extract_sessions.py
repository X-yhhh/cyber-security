#!/usr/bin/env python3
"""用冻结提取器处理已结束的授权良性批次；每批独立 boot，身份/密钥不进入模型。

在 Windows 训练目录运行；不采集新流量、不训练。已存在输出立即拒绝，
避免重跑覆盖旁路、连接记录或可复算证据。
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--extractor', type=Path, required=True)
    p.add_argument('--expected-extractor-sha256', required=True)
    a = p.parse_args()
    digest = hashlib.sha256(a.extractor.read_bytes()).hexdigest()
    if digest != a.expected_extractor_sha256:
        raise ValueError('提取器与登记冻结制品不符')
    report = json.loads((a.root / 'run.json').read_text(encoding='utf-8'))
    if not report['passed'] or not report['listenerClosed']:
        raise ValueError('任务未结束或验收失败')
    secret = a.root / 'peer-key.bin'
    with secret.open('xb') as f:
        f.write(os.urandom(32))
    os.chmod(secret, 0o600)
    asset, sensor = str(uuid.uuid4()), str(uuid.uuid4())
    for session in report['sessions']:
        root = a.root / f"session-{session['ordinal']:02d}"
        config = dict(assetId=asset, sensorId=sensor, bootId=str(uuid.uuid4()),
                      captureScopeId=str(uuid.uuid4()), localAddresses=['127.0.0.1'],
                      secretFile=str(secret.resolve()), keyEpoch=1)
        with (root / 'config.json').open('x', encoding='utf-8') as f:
            json.dump(config, f)
        command = [str(a.extractor.resolve()), '--config', str(root / 'config.json'),
                   '--pcap', str(root / 'raw.pcap'), '--out', str(root / 'observations.jsonl'),
                   '--ledger', str(root / 'ledger.jsonl'), '--report', str(root / 'extraction.json')]
        subprocess.run(command, check=True)
    with (a.root / 'extraction-complete.json').open('x') as f:
        json.dump(dict(status='passed', sessions=len(report['sessions']), extractorSha256=digest,
                       trainingExecuted=False, newCaptureStarted=False), f, indent=2)


if __name__ == '__main__':
    main()
