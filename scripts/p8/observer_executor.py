#!/usr/bin/env python3
"""r6 零能力执行器：只报告存活，不领取命令、不加载防火墙适配器、不签发清理证明。"""
from datetime import datetime, timezone
import argparse
import json
import math
import os
from pathlib import Path
import signal
import ssl
import sys
import time
import urllib.request
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.toolkit import absolute, load, private_dir, private_file, require, safe_main, write
from executor.contract import capability_set_sha256

RECOVERY_WAIT_SECONDS = 30
PULSE_MAX_AGE_SECONDS = 5


def configuration(path):
    """仅接受尚在有效期内的本机零能力配置；身份和状态路径不能由脉冲自行声明。"""
    c = load(path)
    require(c['mode'] == 'alert_only' and c['capabilityIds'] == [], 'OBSERVER_MUST_HAVE_ZERO_CAPABILITIES')
    require(c['baseUrl'].startswith('https://127.0.0.1:'), 'LOCAL_TLS_ENDPOINT_REQUIRED')
    require(datetime.fromisoformat(c['validUntil'].replace('Z', '+00:00')) > datetime.now(timezone.utc), 'AUTHORIZATION_EXPIRED')
    for key in ('assetId', 'executorId'):
        require(str(uuid.UUID(c[key])) == c[key], 'OBSERVER_IDENTITY_INVALID')
    return c


def observer_state(config):
    """观察入口与历史 PF SQLite 账本绝不混用，避免把未恢复动作当作零规则。"""
    root = absolute(config['stateDir'])
    require(not list(root.glob('*.sqlite*')), 'LEGACY_EXECUTOR_LEDGER_PRESENT')
    return root / 'observer'


def read_pulse(config, role, *, not_before=None):
    """私有脉冲只证明指定角色存活；缺失、旧格式、陈旧或未来时间均不能证明就绪。"""
    require(role in ('recovery', 'run'), 'OBSERVER_ROLE_INVALID')
    pulse = load(observer_state(config) / (role + '.json'))
    require(pulse.get('mode') == 'alert_only' and pulse.get('pfInspected') is False
            and pulse.get('role') == role and pulse.get('executorId') == config['executorId'], 'OBSERVER_PULSE_IDENTITY_INVALID')
    require(type(pulse.get('pid')) is int and pulse['pid'] > 0, 'OBSERVER_PULSE_PID_INVALID')
    require(isinstance(pulse.get('bootId'), str) and str(uuid.UUID(pulse['bootId'])) == pulse['bootId'], 'OBSERVER_PULSE_BOOT_INVALID')
    at = pulse.get('at')
    require(type(at) in (int, float) and math.isfinite(at) and 0 <= time.time() - at < PULSE_MAX_AGE_SECONDS
            and (not_before is None or at >= not_before), 'OBSERVER_PULSE_STALE')
    return pulse


def wait_observer_recovery(path, *, not_before=None, stopped=lambda: False):
    """安装与启动共享最多 30 秒的就绪等待；未就绪不发心跳，过期/配置变化立即失败，停止信号正常返回。"""
    config = configuration(path)
    deadline = time.monotonic() + RECOVERY_WAIT_SECONDS
    while not stopped() and time.monotonic() < deadline:
        require(configuration(path) == config, 'OBSERVER_CONFIGURATION_CHANGED')
        observer_state(config)
        try:
            return read_pulse(config, 'recovery', not_before=not_before)
        except (OSError, ValueError):
            # recovery 可能尚未调度或仍为旧格式；有界等候下一次原子脉冲，不放行首轮心跳。
            time.sleep(.2)
    if not stopped():
        raise ValueError('OBSERVER_RECOVERY_UNAVAILABLE')


def serve(path, role, once=False):
    """recovery 仅写存活脉冲；run 就绪后只发送心跳，恢复失联即停止，不产生任何 PF 证明。"""
    c = configuration(path)
    require(role in ('run', 'recovery'), 'OBSERVER_ROLE_INVALID')
    state = private_dir(observer_state(c))
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
    if role == 'run':
        wait_observer_recovery(path, stopped=lambda: stopped)
    while not stopped:
        require(configuration(path) == c, 'OBSERVER_CONFIGURATION_CHANGED')
        observer_state(c)
        if role == 'run':
            read_pulse(c, 'recovery')
            body = {'bootId': boot, 'adapterVersion': 'hostguard-observer/1', 'capabilityHash': capability_set_sha256({'capabilityIds': []}),
                    'pendingRecovery': False, 'activeRuleCount': 0, 'clockSkewMs': 0}
            request = urllib.request.Request(c['baseUrl'] + '/api/v2/machine/executors/' + c['executorId'] + '/heartbeats',
                data=json.dumps(body).encode(), headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Idempotency-Key': str(uuid.uuid4())})
            with urllib.request.urlopen(request, context=context, timeout=3) as response:
                result = json.load(response)['data']
            server = datetime.fromisoformat(result['serverTime'].replace('Z', '+00:00')).timestamp()
            require(abs(server - time.time()) <= 1, 'CLOCK_UNTRUSTED')
        write(state / (role + '.json'), {'at': time.time(), 'mode': 'alert_only', 'pfInspected': False,
              'role': role, 'executorId': c['executorId'], 'pid': os.getpid(), 'bootId': boot}, replace=(state / (role + '.json')).exists())
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
