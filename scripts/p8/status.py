#!/usr/bin/env python3
"""只读巡检：五服务、就绪、按资产的心跳与健康、专属 PF 规则和磁盘；未知同异常退出。"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
from urllib.parse import urlencode
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.toolkit import absolute, load, require, safe_main, sessions
from scripts.p8.launchd import ORDER, PREFIX, DAEMONS
from executor.platform import PF


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    return result.returncode, result.stdout


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
    root = absolute(plan['root'])
    require(root.is_dir(), 'SERVICE_ROOT_MISSING')
    asset = str(uuid.UUID(plan['assetId']))
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
            domain = 'system' if role in DAEMONS and plan.get('mode', 'pf') == 'pf' else 'gui/' + str(os.getuid())
            code, output = execute(['launchctl', 'print', domain + '/' + PREFIX + role])
            running = code == 0 and re.search(r'(?m)^\s*state = running\s*$', output) is not None
            pid = re.search(r'(?m)^\s*pid = (\d+)\s*$', output)
            return {'state': 'running' if running else 'not_running', 'pid': int(pid[1]) if pid else None}, running
        check(role, service)
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
        anchor = PF.anchor_root(str(uuid.UUID(plan['executorId'])))
        code, output = execute(['/sbin/pfctl', '-a', anchor + '/*', '-s', 'rules'])
        count = len([line for line in output.splitlines() if line.strip() and not line.lstrip().startswith('#')]) if code == 0 else None
        return {'anchor': anchor, 'ruleCount': count, 'readOnly': True}, code == 0 and (plan.get('mode') != 'alert-only' or count == 0)
    check('pf', pf)
    def disk():
        usage = shutil.disk_usage(root)
        size = sum(p.stat().st_size for p in (root / 'logs').glob('*') if p.is_file() and not p.is_symlink())
        return {'freeBytes': usage.free, 'logBytes': size}, usage.free >= plan.get('minFreeBytes', 1024**3) and size <= plan.get('maxLogBytes', 1024**3)
    check('disk', disk)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', required=True)
    p.add_argument('--format', choices=('json', 'text'), default='json')
    args = p.parse_args()
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
            print(name + ': ' + ('正常' if value['ok'] else '异常/未知'))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
