#!/usr/bin/env python3
"""r6 零能力执行器：只报告存活，不领取命令、不加载防火墙适配器、不签发清理证明。"""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import signal
import ssl
import sys
import time
import urllib.request
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.toolkit import load, private_dir, private_file, require, safe_main, write
from executor.contract import capability_set_sha256


def configuration(path):
    c = load(path)
    require(c['mode'] == 'alert_only' and c['capabilityIds'] == [], 'OBSERVER_MUST_HAVE_ZERO_CAPABILITIES')
    require(c['baseUrl'].startswith('https://127.0.0.1:'), 'LOCAL_TLS_ENDPOINT_REQUIRED')
    require(datetime.fromisoformat(c['validUntil'].replace('Z', '+00:00')) > datetime.now(timezone.utc), 'AUTHORIZATION_EXPIRED')
    return c


def serve(path, role, once=False):
    c = configuration(path)
    state = private_dir(Path(c['stateDir']) / 'observer')
    # 观察入口与历史 PF SQLite 账本绝不混用，避免把未恢复动作当作零规则。
    require(not list(Path(c['stateDir']).glob('*.sqlite*')), 'LEGACY_EXECUTOR_LEDGER_PRESENT')
    context = ssl.create_default_context(cafile=str(private_file(c['caFile'])))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(private_file(c['certificateFile'])), str(private_file(c['keyFile'])))
    token = private_file(c['credentialFile']).read_text().strip()
    boot = str(uuid.uuid4())
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopped:
        configuration(path)
        if role == 'run':
            recovery = state / 'recovery.json'
            require(recovery.exists() and 0 <= time.time() - load(recovery)['at'] < 5, 'OBSERVER_RECOVERY_UNAVAILABLE')
            body = {'bootId': boot, 'adapterVersion': 'hostguard-observer/1', 'capabilityHash': capability_set_sha256({'capabilityIds': []}),
                    'pendingRecovery': False, 'activeRuleCount': 0, 'clockSkewMs': 0}
            request = urllib.request.Request(c['baseUrl'] + '/api/v2/machine/executors/' + c['executorId'] + '/heartbeats',
                data=json.dumps(body).encode(), headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Idempotency-Key': str(uuid.uuid4())})
            with urllib.request.urlopen(request, context=context, timeout=3) as response:
                result = json.load(response)['data']
            server = datetime.fromisoformat(result['serverTime'].replace('Z', '+00:00')).timestamp()
            require(abs(server - time.time()) <= 1, 'CLOCK_UNTRUSTED')
        write(state / (role + '.json'), {'at': time.time(), 'mode': 'alert_only', 'pfInspected': False}, replace=(state / (role + '.json')).exists())
        if once:
            return
        time.sleep(1)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('role', choices=('run', 'recovery'))
    p.add_argument('--config', required=True)
    args = p.parse_args()
    serve(args.config, args.role)


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
