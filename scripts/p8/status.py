#!/usr/bin/env python3
"""只读巡检五服务、采集健康及磁盘；零能力 observer 只证明存活，PF 模式另查专属规则。"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import urllib.request
from urllib.parse import urlencode
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.toolkit import absolute, load, require, safe_main
from scripts.p8.launchd import ORDER, PREFIX, DAEMONS, readiness_settings
from scripts.p8.observer_executor import configuration, observer_state, read_pulse
from executor.contract import capability_set_sha256
from executor.platform import PF


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    return result.returncode, result.stdout


def inspect_backend(root, *, execute=command):
    """P1.2 分段巡检只证明后端与 TLS 就绪，显式保留五服务、采集和 PF 的未验证状态。"""
    root = absolute(root)
    base, context = readiness_settings(root)
    code, output = execute(['launchctl', 'print', 'gui/' + str(os.getuid()) + '/' + PREFIX + 'backend'])
    pid = re.search(r'(?m)^\s*pid = (\d+)\s*$', output)
    running = code == 0 and bool(pid) and re.search(r'(?m)^\s*state = running\s*$', output) is not None
    with urllib.request.urlopen(base + '/health/ready', context=context, timeout=5) as response:
        ready = json.load(response)['data']['status']
    return dict(ok=running and ready == 'UP', mode='backend-only', fullDeploymentReady=False,
                checks=dict(backend=dict(ok=running, pid=int(pid[1]) if pid else None), ready=dict(ok=ready == 'UP', status=ready)),
                deferred=['targets', 'recovery', 'executor', 'sensor', 'host-reboot', 'pf-recovery'],
                note='仅后端分段巡检；P1.5 机器登记和独立授权完成后才能进行完整五服务与 D2 验收。')


def inspect_rehearsal(client, process, runtime, replay):
    """R1 只核对真实临时后端和已结束文件回放；不把未安装五服务、未知采集健康或 PF 写成正常。"""
    ready = client.call('GET', '/health/ready')['data']['status']
    checks = dict(backend=process.poll() is None and process.pid == runtime['pid'],
                  ready=ready == 'UP', deployProfile=runtime['profile'] == 'deploy' and not runtime['automation'],
                  hostedWeb=runtime.get('webHosted') is True,
                  fileReplay=replay['passed'] and replay['fileReplay'] and not replay['liveCapture'],
                  observationAndAlert=replay['observations'] > 0 and replay['alerts'] > 0)
    return dict(ok=all(checks.values()), mode='clone-rehearsal', checks=checks,
                captureHealth=replay['healthState'], launchd='not_installed', pf='not_applicable',
                note='文件回放不证明现场内核丢包计数或五服务重启；这些项目保留在 A23。')


def machine_rows(client, endpoint, asset):
    """完整读取资产的机器状态投影；游标重复或超过保护上限时拒绝宣称覆盖完整。"""
    rows, seen = [], set()
    query = {'assetId': asset, 'limit': 200}
    for _ in range(100):
        data = client.request('GET', '/' + endpoint + '?' + urlencode(query))
        rows.extend(data['items'])
        cursor = data.get('nextCursor')
        if not cursor:
            return rows
        require(isinstance(cursor, str) and cursor not in seen, 'PAGINATION_CURSOR_INVALID')
        seen.add(cursor)
        query['cursor'] = cursor
    raise ValueError('MACHINE_PAGE_LIMIT_EXCEEDED')


def inspect(plan, client, *, execute=command):
    """只告警按配置、PID、bootId 与新鲜心跳核验存活；采集健康门槛和 PF 模式检查保持独立。"""
    root = absolute(plan['root'])
    require(root.is_dir(), 'SERVICE_ROOT_MISSING')
    asset = str(uuid.UUID(plan['assetId']))
    mode = plan.get('mode', 'pf')
    require(mode in ('pf', 'alert-only'), 'STATUS_MODE_INVALID')
    result = {'ok': True, 'checks': {}, 'assetId': asset}
    def check(name, operation):
        try:
            value, ok = operation()
            result['checks'][name] = {'ok': bool(ok), **value}
        except Exception:
            result['checks'][name] = {'ok': False, 'state': 'unknown'}
        result['ok'] = result['ok'] and result['checks'][name]['ok']
    for role in ORDER:
        def service(role=role):
            domain = 'system' if role in DAEMONS and mode == 'pf' else 'gui/' + str(os.getuid())
            code, output = execute(['launchctl', 'print', domain + '/' + PREFIX + role])
            running = code == 0 and re.search(r'(?m)^\s*state = running\s*$', output) is not None
            pid = re.search(r'(?m)^\s*pid = (\d+)\s*$', output)
            return {'state': 'running' if running else 'not_running', 'pid': int(pid[1]) if pid else None}, running
        check(role, service)
    if mode == 'alert-only':
        def observer():
            config = configuration(root / 'config/executor-observer.json')
            require(config['assetId'] == asset and config['executorId'] == str(uuid.UUID(plan['executorId']))
                    and observer_state(config) == root / 'ledger/executor/observer', 'OBSERVER_CONFIGURATION_MISMATCH')
            pulses = {}
            for role, operation in (('recovery', 'recovery'), ('executor', 'run')):
                pulses[role] = read_pulse(config, operation)
                service = result['checks'][role]
                require(service['ok'] and service['pid'] == pulses[role]['pid'], 'OBSERVER_PROCESS_MISMATCH')
            return {'mode': 'alert_only', 'pfInspected': False, 'pulses': pulses}, True
        check('observer', observer)
    def ready():
        data = client.call('GET', '/health/ready')['data']
        return {'status': data['status']}, data['status'] == 'UP'
    check('ready', ready)
    sensors = []
    for endpoint in ('ops/status', 'sensor-heartbeats', 'executor-heartbeats'):
        def api(endpoint=endpoint):
            rows = machine_rows(client, endpoint, asset)
            if endpoint == 'ops/status':
                return {'items': rows}, bool(rows) and all(r['status'] == 'active' for r in rows)
            if endpoint == 'sensor-heartbeats':
                sensors.extend(rows)
            if endpoint == 'executor-heartbeats' and mode == 'alert-only':
                # pending 的 unknown 是后端原始健康结论；这里只追加存活结果，不修改或推导 PF 健康。
                local = result['checks']['observer']
                alive = local['ok'] and len(rows) == 1
                if alive:
                    row = rows[0]
                    reported = row.get('reported') or {}
                    skew = reported.get('clockSkewMs')
                    alive = (row.get('id') == plan['executorId'] and row.get('assetId') == asset
                             and row.get('status') in ('pending', 'active') and row.get('freshness') == 'fresh'
                             and row.get('healthState') == ('unknown' if row['status'] == 'pending' else 'healthy')
                             and row.get('adapterVersion') == 'hostguard-observer/1'
                             and row.get('capabilityHash') == capability_set_sha256({'capabilityIds': []})
                             and row.get('bootId') == local['pulses']['executor']['bootId']
                             and reported.get('pendingRecovery') is False
                             and type(reported.get('activeRuleCount')) is int and reported['activeRuleCount'] == 0
                             and type(skew) in (int, float) and math.isfinite(skew) and abs(skew) <= 1000)
                return {'items': rows, 'observerLiveness': 'alive' if alive else 'unknown',
                        'healthBasis': 'zero_capability_observer_liveness', 'pfInspected': False}, alive
            return {'items': rows}, bool(rows) and all(r['healthState'] == 'healthy' and r['freshness'] == 'fresh' for r in rows)
        check(endpoint, api)
    def health():
        # API 按 receivedAt 倒序；逐个传感器读取最新接收窗口，历史分页不代表当前异常。
        # 身份来自完整心跳投影，避免繁忙传感器挤满首页后漏查另一个传感器。
        rows = []
        for sensor in sensors:
            sensor_id = str(uuid.UUID(sensor['id']))
            query = urlencode({'assetId': asset, 'sensorId': sensor_id, 'limit': 1})
            data = client.request('GET', '/health-windows?' + query)
            require(len(data['items']) == 1 and data['items'][0]['sensorId'] == sensor_id,
                    'SENSOR_HEALTH_WINDOW_MISSING_OR_MISMATCHED')
            rows.extend(data['items'])
        return {'items': rows}, bool(rows) and all(r['healthState'] == 'healthy' and r['freshness'] == 'fresh' for r in rows)
    check('health-windows', health)
    def pf():
        if mode == 'alert-only':
            applicable = result['checks']['observer']['ok'] and result['checks']['executor-heartbeats']['ok']
            return {'state': 'not_applicable' if applicable else 'unknown', 'pfInspected': False,
                    'ruleCount': None, 'readOnly': True}, applicable
        anchor = PF.anchor_root(str(uuid.UUID(plan['executorId'])))
        code, output = execute(['/sbin/pfctl', '-a', anchor + '/*', '-s', 'rules'])
        count = len([line for line in output.splitlines() if line.strip() and not line.lstrip().startswith('#')]) if code == 0 else None
        return {'anchor': anchor, 'ruleCount': count, 'pfInspected': code == 0, 'readOnly': True}, code == 0
    check('pf', pf)
    def disk():
        usage = shutil.disk_usage(root)
        size = sum(p.stat().st_size for p in (root / 'logs').glob('*') if p.is_file() and not p.is_symlink())
        return {'freeBytes': usage.free, 'logBytes': size}, usage.free >= plan.get('minFreeBytes', 1024**3) and size <= plan.get('maxLogBytes', 1024**3)
    check('disk', disk)
    return result


def check_summary(name, value):
    """文本巡检也区分存活与 PF 健康，避免把成功的零能力核验显示为防火墙正常。"""
    if name == 'executor-heartbeats' and 'observerLiveness' in value:
        return ('observer 存活' if value['ok'] else 'observer 存活未确认') + '（不代表 PF 健康）'
    if name == 'pf' and value.get('pfInspected') is False:
        return ('不适用' if value.get('state') == 'not_applicable' else '未知') + '（未检查 PF）'
    return '正常' if value['ok'] else '异常/未知'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument('--plan')
    source.add_argument('--backend-root', help='仅核对登记机器前的后端阶段，不证明五服务或 PF 健康')
    p.add_argument('--format', choices=('json', 'text'), default='json')
    args = p.parse_args()
    if args.backend_root:
        result = inspect_backend(args.backend_root)
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.format == 'json'
              else ('后端阶段正常；完整部署仍待验收' if result['ok'] else '后端阶段异常'))
        return 0 if result['ok'] else 1
    plan = load(args.plan)
    # 巡检只需单独的只读人工账号，不要求申请人/审核人登录两次。
    from scripts.p8.toolkit import Human, private_file
    import ssl
    from urllib.parse import urlsplit
    u = urlsplit(plan['baseUrl'])
    require(u.scheme == 'https' and u.hostname in ('127.0.0.1', '::1') and not u.username and not u.query, 'LOCAL_TLS_ENDPOINT_REQUIRED')
    context = ssl.create_default_context(cafile=str(private_file(plan['backendCA'])))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    result = inspect(plan, Human(plan['baseUrl'], context).login_keychain(plan['reader']))
    if args.format == 'json':
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print('巡检通过' if result['ok'] else '巡检发现异常或未验证项')
        for name, value in result['checks'].items():
            print(name + ': ' + check_summary(name, value))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
