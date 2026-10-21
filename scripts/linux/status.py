#!/usr/bin/env python3
"""A3：仅经 v2 API 巡检远端只告警资产及 Mac 基准绑定，不探测主机或进程。

巡检计划使用登记结果中的 assetId/sensorId/executorId/authorizationId/captureScopeId/
bundleId/bindingId/guardliveSha256，另加 baseUrl/backendCA/reader（可选 backendTls）。
Mac 绑定 ID 必须由 --mac-binding-id 传入；R0 基准为 active、revision 1，可显式
传入其他已审核 revision。可选 expectedSensorBootId 指定当次运行的预期 boot，
不会把配置包里的初始 bootId 当成重启后不变的基准。
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import math
from pathlib import Path
import re
import ssl
import sys
import uuid
from urllib.parse import urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from executor.contract import capability_set_sha256
from scripts.linux.enroll import HEALTH_VERSION, R6_PRIME, is_sha
from scripts.p8.toolkit import Human, load, private_file, require, safe_main


def identifier(value, code):
    try:
        valid = isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        valid = False
    require(valid, code)
    return value


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(parsed.tzinfo is not None, 'BACKEND_TIME_INVALID')
        return parsed
    except (ValueError, TypeError, AttributeError):
        raise ValueError('BACKEND_TIME_INVALID') from None


def clock_ok(value):
    return type(value) in (int, float) and math.isfinite(value) and abs(value) <= 1000


def failure_code(error):
    """异常只携带固定代码；后端正文、地址、凭据不进入巡检报告。"""
    value = str(error)
    if isinstance(error, ValueError) and re.fullmatch(r'[A-Z][A-Z0-9_]+', value):
        return value
    match = re.search(r'HTTP ([0-9]{3}) ([A-Z][A-Z0-9_]+)$', value)
    if match:
        return 'HTTP_' + match[1] + '_' + match[2]
    return 'BACKEND_RESPONSE_INVALID' if isinstance(error, (KeyError, TypeError)) else 'BACKEND_REQUEST_FAILED'


def rows(client, endpoint, query, *, sample=None):
    """机器列表完整分页；健康窗口仅取有界近期样本，仍拒绝重复游标及重复记录。"""
    result, cursors, ids = [], set(), set()
    query = dict(query)
    for _ in range(100):
        query['limit'] = min(200, sample - len(result)) if sample else 200
        data = client.request('GET', endpoint + '?' + urlencode(query))
        items = data['items']
        require(isinstance(items, list) and len(items) <= query['limit'], 'BACKEND_PAGE_INVALID')
        for row in items:
            require(isinstance(row, dict) and row.get('id') and row['id'] not in ids, 'BACKEND_ROW_DUPLICATED_OR_INVALID')
            ids.add(row['id'])
        result.extend(items)
        cursor = data.get('nextCursor')
        if cursor:
            require(isinstance(cursor, str) and cursor not in cursors, 'PAGINATION_CURSOR_INVALID')
            cursors.add(cursor)
        if not cursor or (sample and len(result) >= sample):
            return result
        query['cursor'] = cursor
    raise ValueError('BACKEND_PAGE_LIMIT_EXCEEDED')


def one_machine(client, endpoint, plan, kind):
    records = rows(client, '/' + endpoint, {'assetId': plan['assetId']})
    require(records, kind + '_HEARTBEAT_NO_RECORD')
    require(len(records) == 1, kind + '_IDENTITY_AMBIGUOUS')
    row = records[0]
    require(row['id'] == plan['sensorId' if kind == 'SENSOR' else 'executorId']
            and row.get('assetId') == plan['assetId'], kind + '_IDENTITY_MISMATCH')
    require(row.get('projection') == 'latest', kind + '_PROJECTION_INVALID')
    require(row.get('freshness') == 'fresh', kind + '_HEARTBEAT_NOT_FRESH')
    identifier(row.get('bootId'), kind + '_BOOT_ID_INVALID')
    timestamp(row.get('receivedAt'))
    return row


def sensor_heartbeat(client, plan):
    row = one_machine(client, 'sensor-heartbeats', plan, 'SENSOR')
    require(row.get('status') == 'active' and row.get('healthState') == 'healthy', 'SENSOR_HEARTBEAT_UNHEALTHY')
    config = row.get('currentConfig') or {}
    identifier(config.get('id'), 'SENSOR_CONFIG_INVALID')
    require(is_sha(config.get('contentSha256')) and config.get('buildSha256') == plan['guardliveSha256'],
            'SENSOR_CONFIG_OR_BUILD_MISMATCH')
    if plan.get('expectedSensorBootId') is not None:
        require(row['bootId'] == plan['expectedSensorBootId'], 'SENSOR_BOOT_ID_MISMATCH')
    return row


def health_windows(client, plan, sensor):
    """分别校验当前健康与近期同会话连续性，历史 stale 不等于当前异常。

    API 未投影 previousSha256 或 bootId：哈希链依赖服务端 healthy 判定，不能
    声称本脚本重算了哈希链、证明了整个运行期，或证明会话与 boot 一一对应。
    """
    limit = plan.get('healthWindowCount', 20)
    require(type(limit) is int and 2 <= limit <= 2000, 'HEALTH_WINDOW_LIMIT_INVALID')
    records = rows(client, '/health-windows', dict(
        assetId=plan['assetId'], sensorId=plan['sensorId'], captureScopeId=plan['captureScopeId']), sample=limit)
    require(records, 'HEALTH_WINDOW_NO_RECORD')
    for row in records:
        require(all(row.get(k) == plan[k] for k in ('assetId', 'sensorId', 'captureScopeId')), 'HEALTH_IDENTITY_MISMATCH')
        identifier(row.get('observerSessionId'), 'HEALTH_SESSION_INVALID')
    latest = max(records, key=lambda row: timestamp(row.get('intervalEnd')))
    require(latest.get('freshness') == 'fresh' and latest.get('healthState') == 'healthy', 'HEALTH_WINDOW_NOT_CURRENT')
    current = [r for r in records if r['observerSessionId'] == latest['observerSessionId']]
    for row in current:
        require(type(row.get('sequence')) is int and row['sequence'] > 0, 'HEALTH_SEQUENCE_INVALID')
    current.sort(key=lambda row: row['sequence'])
    require(len(current) >= 2, 'HEALTH_CONTINUITY_INSUFFICIENT')
    previous = None
    for row in current:
        require(row.get('verificationStatus') == 'healthy' and row.get('serverVerifiedHealthy') is True,
                'HEALTH_SERVER_VERIFICATION_FAILED')
        require(row.get('healthVersion') == HEALTH_VERSION and row.get('captureSource') in (None, ''), 'HEALTH_LIVE_CAPTURE_REQUIRED')
        require(row.get('configSha256') == sensor['currentConfig']['contentSha256']
                and row.get('buildSha256') == plan['guardliveSha256'], 'HEALTH_CONFIG_OR_BUILD_MISMATCH')
        start, end, received = (timestamp(row.get(k)) for k in ('intervalStart', 'intervalEnd', 'receivedAt'))
        require(0 < (end - start).total_seconds() <= 5 and 0 <= (received - end).total_seconds() <= 10,
                'HEALTH_INTERVAL_INVALID')
        require(row.get('captureGap') is False and clock_ok(row.get('clockSkewMs')), 'HEALTH_GAP_OR_CLOCK_UNTRUSTED')
        for key in ('counterStart', 'counterEnd'):
            counters = row.get(key) or {}
            require(all(type(counters.get(k)) is int and 0 <= counters[k] <= 9_007_199_254_740_991
                        for k in ('packetsSeen', 'kernelDrops', 'capacityDrops')), 'HEALTH_COUNTER_UNKNOWN')
        require(all(row['counterEnd'][k] >= row['counterStart'][k]
                    and (k == 'packetsSeen' or row['counterEnd'][k] == row['counterStart'][k])
                    for k in ('packetsSeen', 'kernelDrops', 'capacityDrops')), 'HEALTH_CAPTURE_DROPS')
        if previous:
            require(row['sequence'] == previous['sequence'] + 1
                    and timestamp(previous['intervalEnd']) == start
                    and previous['counterEnd'] == row['counterStart'], 'HEALTH_CHAIN_DISCONTINUOUS')
        previous = row
    return dict(observerSessionId=latest['observerSessionId'], windowCount=len(current), sampleLimit=limit,
                firstSequence=current[0]['sequence'], lastSequence=current[-1]['sequence'],
                historicalSessionWindows=len(records) - len(current),
                hashChainBasis='server_verification', bootHealthLink='not_exposed_by_api')


def inspect(plan, client, *, mac_binding_id, mac_binding_revision=1, mac_asset_id=None):
    """所有状态证据来自后端；失败项给具体原因，其余独立项继续核对。"""
    for key in ('assetId', 'sensorId', 'executorId', 'authorizationId', 'captureScopeId', 'bindingId'):
        identifier(plan.get(key), 'STATUS_IDENTITY_REQUIRED')
    require(plan.get('bundleId') == R6_PRIME and is_sha(plan.get('guardliveSha256')), 'STATUS_BUNDLE_OR_BUILD_INVALID')
    identifier(mac_binding_id, 'MAC_BASELINE_ID_REQUIRED')
    require(type(mac_binding_revision) is int and mac_binding_revision > 0, 'MAC_BASELINE_REVISION_INVALID')
    if mac_asset_id is not None:
        identifier(mac_asset_id, 'MAC_BASELINE_ASSET_INVALID')
        require(mac_asset_id != plan['assetId'], 'MAC_BASELINE_ASSET_INVALID')
    if plan.get('expectedSensorBootId') is not None:
        identifier(plan['expectedSensorBootId'], 'EXPECTED_BOOT_ID_INVALID')
    result = dict(ok=True, readOnly=True, assetId=plan['assetId'], checks={},
                  note='仅后端状态投影；零能力心跳只证明存活，健康连续性限近期样本；不证明主机进程或防火墙健康。')

    def check(name, operation):
        try:
            value = operation()
            result['checks'][name] = dict(ok=True, **value)
            return value
        except Exception as error:
            result['checks'][name] = dict(ok=False, reason=failure_code(error))
            result['ok'] = False
            return None

    def asset():
        records = rows(client, '/ops/status', {'assetId': plan['assetId']})
        require(records and len(records) == 1 and records[0]['id'] == plan['assetId'], 'ASSET_MISSING_OR_AMBIGUOUS')
        row = records[0]
        require(row.get('status') == 'active', 'ASSET_NOT_ACTIVE')
        require(type(row.get('sensorCount')) is int and row['sensorCount'] == 1
                and type(row.get('executorCount')) is int and row['executorCount'] == 1, 'ASSET_MACHINE_COUNT_MISMATCH')
        return dict(status=row['status'])

    check('asset', asset)
    sensor = check('sensor-heartbeat', lambda: sensor_heartbeat(client, plan))

    def executor():
        row = one_machine(client, 'executor-heartbeats', plan, 'EXECUTOR')
        require(row.get('status') in ('pending', 'active')
                and row.get('healthState') == ('unknown' if row['status'] == 'pending' else 'healthy'), 'EXECUTOR_NOT_ALIVE')
        require(row.get('adapterVersion') == 'hostguard-observer/1'
                and row.get('capabilityHash') == capability_set_sha256({'capabilityIds': []}), 'EXECUTOR_NOT_ZERO_CAPABILITY')
        reported = row.get('reported') or {}
        require(reported.get('pendingRecovery') is False
                and type(reported.get('activeRuleCount')) is int and reported['activeRuleCount'] == 0,
                'EXECUTOR_RECOVERY_OR_ACTIVE_RULES')
        require(clock_ok(reported.get('clockSkewMs')), 'EXECUTOR_CLOCK_UNTRUSTED')
        return dict(bootId=row['bootId'], status=row['status'], backendHealthState=row['healthState'],
                    observerLiveness='alive', healthBasis='zero_capability_observer_liveness')

    check('executor-heartbeat', executor)

    def health():
        require(sensor is not None, 'SENSOR_HEARTBEAT_REQUIRED_FOR_HEALTH')
        return health_windows(client, plan, sensor)

    check('health-windows', health)

    def boot_stable():
        require(sensor is not None, 'SENSOR_HEARTBEAT_REQUIRED_FOR_BOOT_CHECK')
        current = sensor_heartbeat(client, plan)
        require(current['bootId'] == sensor['bootId'], 'SENSOR_BOOT_CHANGED_DURING_INSPECTION')
        require(current['currentConfig'] == sensor['currentConfig'], 'SENSOR_CONFIG_CHANGED_DURING_INSPECTION')
        return dict(bootId=current['bootId'], basis='latest_heartbeat_before_and_after_health')

    check('sensor-boot', boot_stable)
    # child API 没有游标且最多返回 200 条；达到上限不能声称绑定覆盖完整。
    def bindings():
        data = client.request('GET', '/release-bundles/' + plan['bundleId'] + '/bindings')
        records = data['items']
        require(isinstance(records, list) and len(records) < 200 and not data.get('nextCursor'), 'BINDING_COVERAGE_INCOMPLETE')
        require(len({r['id'] for r in records}) == len(records), 'BINDING_DUPLICATED')
        return dict(items=records)

    binding_data = check('bindings', bindings)

    def remote_binding():
        require(binding_data is not None, 'BINDING_LIST_REQUIRED')
        records = [r for r in binding_data['items'] if r.get('assetId') == plan['assetId'] and r.get('status') == 'active']
        require(len(records) == 1, 'REMOTE_ACTIVE_BINDING_MISSING_OR_AMBIGUOUS')
        row = records[0]
        require(row.get('id') == plan['bindingId'] and row.get('bundleId') == plan['bundleId']
                and row.get('authorizationId') == plan['authorizationId'], 'REMOTE_BINDING_MISMATCH')
        return dict(bindingId=row['id'], status=row['status'])

    check('remote-binding', remote_binding)

    def mac_binding():
        require(binding_data is not None, 'BINDING_LIST_REQUIRED')
        records = [r for r in binding_data['items'] if r.get('id') == mac_binding_id]
        require(len(records) == 1, 'MAC_BASELINE_BINDING_MISSING')
        row = records[0]
        identifier(row.get('assetId'), 'MAC_BASELINE_ASSET_INVALID')
        require(row['assetId'] != plan['assetId'] and (mac_asset_id is None or row['assetId'] == mac_asset_id), 'MAC_BASELINE_ASSET_CHANGED')
        require(row.get('bundleId') == plan['bundleId'] and row.get('status') == 'active'
                and type(row.get('revision')) is int and row['revision'] == mac_binding_revision, 'MAC_BASELINE_BINDING_CHANGED')
        return dict(bindingId=row['id'], assetId=row['assetId'], status=row['status'], revision=row['revision'])

    check('mac-binding', mac_binding)
    return result


def reader(plan):
    """沿用 Mac 的 Keychain 登录；单独只读会话，可使用业务后端要求的 mTLS。"""
    u = urlsplit(plan['baseUrl'])
    require(u.scheme == 'https' and u.hostname in ('127.0.0.1', '::1') and u.port
            and not u.username and not u.password and u.path in ('', '/')
            and not u.query and not u.fragment, 'LOCAL_TLS_ENDPOINT_REQUIRED')
    context = ssl.create_default_context(cafile=str(private_file(plan['backendCA'])))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if 'backendTls' in plan:
        tls = plan['backendTls']
        context.load_cert_chain(str(private_file(tls['certificateFile'])), str(private_file(tls['keyFile'])))
    return Human(plan['baseUrl'], context).login_keychain(plan['reader'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--mac-binding-id', required=True)
    parser.add_argument('--mac-binding-revision', type=int, default=1)
    parser.add_argument('--mac-asset-id')
    parser.add_argument('--expected-sensor-boot-id')
    parser.add_argument('--format', choices=('json', 'text'), default='json')
    args = parser.parse_args(argv)
    plan = load(args.plan)
    if args.expected_sensor_boot_id:
        plan['expectedSensorBootId'] = args.expected_sensor_boot_id
    result = inspect(plan, reader(plan), mac_binding_id=args.mac_binding_id,
                     mac_binding_revision=args.mac_binding_revision, mac_asset_id=args.mac_asset_id)
    if args.format == 'json':
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print('巡检通过' if result['ok'] else '巡检发现异常或未验证项')
        for name, value in result['checks'].items():
            print(name + ': ' + ('通过' if value['ok'] else value['reason']))
        print(result['note'])
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
