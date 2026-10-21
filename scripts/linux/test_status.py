"""A3 只读巡检验收：进程内 API 投影替身，不运行服务、SSH 或主机命令。"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import uuid

import pytest

from executor import pki
from executor.contract import capability_set_sha256
from scripts.linux import status
from scripts.p8.toolkit import private_dir, write

MAC_BINDING = '54dd1707-d7f9-4ce7-8a9d-8f4955f4546a'


def uid(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'a3-status-fixture/' + name))


def iso(value):
    return value.isoformat().replace('+00:00', 'Z')


class FakeBackend:
    """严格拒绝写请求；模拟后端 latest 心跳、分页和健康窗口投影。"""
    def __init__(self, plan):
        self.calls = []
        self.page_size = 200
        self.errors = {}
        self.sensor_reads = 0
        self.next_sensor = None
        now = datetime(2026, 10, 21, 10, tzinfo=timezone.utc)
        self.asset = dict(id=plan['assetId'], status='active', sensorCount=1, executorCount=1)
        common = dict(assetId=plan['assetId'], receivedAt=iso(now), projection='latest', freshness='fresh')
        self.sensor = dict(common, id=plan['sensorId'], status='active', healthState='healthy',
                           bootId=uid('current-heartbeat-boot'), currentConfig=dict(
                               id=uid('config'), configVersion=1, contentSha256='c' * 64,
                               buildSha256=plan['guardliveSha256']))
        self.executor = dict(common, id=plan['executorId'], status='pending', healthState='unknown',
                             bootId=uid('executor-boot'), adapterVersion='hostguard-observer/1',
                             capabilityHash=capability_set_sha256({'capabilityIds': []}),
                             reported=dict(pendingRecovery=False, activeRuleCount=0, clockSkewMs=0))
        self.windows = []
        for sequence in (2, 1):
            start = now + timedelta(seconds=sequence - 3)
            self.windows.append(dict(
                id=uid('window-' + str(sequence)), assetId=plan['assetId'], sensorId=plan['sensorId'],
                captureScopeId=plan['captureScopeId'], observerSessionId=uid('health-session-independent-of-boot'),
                sequence=sequence, intervalStart=iso(start), intervalEnd=iso(start + timedelta(seconds=1)),
                receivedAt=iso(start + timedelta(seconds=1, milliseconds=50)),
                verificationStatus='healthy', serverVerifiedHealthy=True, failureReason=None,
                freshness='fresh' if sequence == 2 else 'stale',
                healthState='healthy' if sequence == 2 else 'stale',
                healthVersion=status.HEALTH_VERSION, captureSource=None, configSha256='c' * 64,
                buildSha256=plan['guardliveSha256'], captureGap=False, clockSkewMs=0,
                counterStart=dict(packetsSeen=(sequence - 1) * 10, kernelDrops=0, capacityDrops=0),
                counterEnd=dict(packetsSeen=sequence * 10, kernelDrops=0, capacityDrops=0)))
        self.bindings = [
            dict(id=plan['bindingId'], assetId=plan['assetId'], bundleId=plan['bundleId'],
                 authorizationId=plan['authorizationId'], status='active', revision=1),
            dict(id=MAC_BINDING, assetId=uid('mac-asset'), bundleId=plan['bundleId'],
                 authorizationId=uid('mac-authorization'), status='active', revision=1),
        ]

    def request(self, method, path, *args, **kwargs):
        assert method == 'GET' and not args and not kwargs, 'status must use read-only business APIs'
        self.calls.append((method, path))
        url = urlsplit(path)
        query = parse_qs(url.query)
        if url.path in self.errors:
            raise self.errors[url.path]
        if url.path == '/release-bundles/' + status.R6_PRIME + '/bindings':
            assert not query
            return {'items': deepcopy(self.bindings)}
        if url.path == '/sensor-heartbeats':
            self.sensor_reads += 1
            items = [self.next_sensor if self.sensor_reads > 1 and self.next_sensor is not None else self.sensor]
        elif url.path == '/executor-heartbeats':
            items = [self.executor]
        elif url.path == '/ops/status':
            items = [self.asset]
        elif url.path == '/health-windows':
            items = self.windows
            assert query['sensorId'] == [self.sensor['id']]
            assert query['captureScopeId'] == [uid('captureScopeId')]
        else:
            raise AssertionError('unexpected API: ' + path)
        assert query['assetId'] == [uid('assetId')]
        offset = int(query.get('cursor', ['0'])[0])
        size = min(self.page_size, int(query['limit'][0]))
        end = offset + size
        return {'items': deepcopy(items[offset:end]), 'nextCursor': str(end) if end < len(items) else None}


@pytest.fixture
def scenario():
    plan = {key: uid(key) for key in ('assetId', 'sensorId', 'executorId', 'authorizationId', 'captureScopeId', 'bindingId')}
    # 登记配置的初始 boot 已过时；GuardIngest.heartbeat 投影中的 boot 才是巡检基准。
    plan.update(bundleId=status.R6_PRIME, guardliveSha256='b' * 64, bootId=uid('initial-enrollment-boot'))
    return SimpleNamespace(plan=plan, backend=FakeBackend(plan))


def inspect(scenario, **kwargs):
    return status.inspect(scenario.plan, scenario.backend, mac_binding_id=MAC_BINDING, **kwargs)


def test_all_evidence_is_api_only_and_observer_pending_is_alive(scenario):
    result = inspect(scenario, mac_asset_id=uid('mac-asset'))
    assert result['ok'] is True and result['readOnly'] is True
    assert all(v['ok'] for v in result['checks'].values())
    assert [urlsplit(p).path for _, p in scenario.backend.calls] == [
        '/ops/status', '/sensor-heartbeats', '/executor-heartbeats', '/health-windows',
        '/sensor-heartbeats', '/release-bundles/' + status.R6_PRIME + '/bindings']
    executor = result['checks']['executor-heartbeat']
    assert executor['observerLiveness'] == 'alive' and executor['backendHealthState'] == 'unknown'
    assert executor['healthBasis'] == 'zero_capability_observer_liveness'
    assert result['checks']['sensor-boot']['bootId'] == scenario.backend.sensor['bootId']
    assert result['checks']['sensor-boot']['bootId'] != scenario.plan['bootId']
    health = result['checks']['health-windows']
    assert health['windowCount'] == 2 and health['firstSequence'] == 1 and health['lastSequence'] == 2
    assert health['observerSessionId'] != scenario.backend.sensor['bootId']
    assert health['hashChainBasis'] == 'server_verification' and health['bootHealthLink'] == 'not_exposed_by_api'
    assert result['checks']['mac-binding']['bindingId'] == MAC_BINDING
    assert result['checks']['mac-binding']['revision'] == 1


def test_active_observer_and_fully_paginated_recent_windows(scenario):
    scenario.backend.executor.update(status='active', healthState='healthy')
    scenario.backend.page_size = 1
    result = inspect(scenario)
    assert result['ok'] is True
    assert result['checks']['health-windows']['windowCount'] == 2
    assert sum(urlsplit(p).path == '/health-windows' for _, p in scenario.backend.calls) == 2


def test_restart_can_leave_stale_older_session_and_initial_boot(scenario):
    old = deepcopy(scenario.backend.windows[-1])
    old.update(id=uid('old-window'), observerSessionId=uid('previous-session'),
               intervalStart='2026-10-21T09:59:00Z', intervalEnd='2026-10-21T09:59:01Z',
               receivedAt='2026-10-21T09:59:01.050Z', configSha256='d' * 64,
               freshness='stale', healthState='stale')
    scenario.backend.windows.append(old)
    scenario.plan['expectedSensorBootId'] = scenario.backend.sensor['bootId']
    result = inspect(scenario)
    assert result['ok'] is True
    assert result['checks']['health-windows']['historicalSessionWindows'] == 1


def change(backend, path, value):
    target = getattr(backend, path[0])
    for key in path[1:-1]:
        target = target[key]
    target[path[-1]] = value


@pytest.mark.parametrize('path,value,check,reason', [
    (('asset', 'status'), 'suspended', 'asset', 'ASSET_NOT_ACTIVE'),
    (('asset', 'sensorCount'), 2, 'asset', 'ASSET_MACHINE_COUNT_MISMATCH'),
    (('asset', 'executorCount'), True, 'asset', 'ASSET_MACHINE_COUNT_MISMATCH'),
    (('sensor', 'id'), uid('wrong-sensor'), 'sensor-heartbeat', 'SENSOR_IDENTITY_MISMATCH'),
    (('sensor', 'assetId'), uid('wrong-asset'), 'sensor-heartbeat', 'SENSOR_IDENTITY_MISMATCH'),
    (('sensor', 'projection'), 'history', 'sensor-heartbeat', 'SENSOR_PROJECTION_INVALID'),
    (('sensor', 'freshness'), 'stale', 'sensor-heartbeat', 'SENSOR_HEARTBEAT_NOT_FRESH'),
    (('sensor', 'bootId'), 'invalid', 'sensor-heartbeat', 'SENSOR_BOOT_ID_INVALID'),
    (('sensor', 'bootId'), None, 'sensor-heartbeat', 'SENSOR_BOOT_ID_INVALID'),
    (('sensor', 'receivedAt'), '2026-10-21T10:00:00', 'sensor-heartbeat', 'BACKEND_TIME_INVALID'),
    (('sensor', 'status'), 'pending', 'sensor-heartbeat', 'SENSOR_HEARTBEAT_UNHEALTHY'),
    (('sensor', 'healthState'), 'unhealthy', 'sensor-heartbeat', 'SENSOR_HEARTBEAT_UNHEALTHY'),
    (('sensor', 'currentConfig', 'id'), 'invalid', 'sensor-heartbeat', 'SENSOR_CONFIG_INVALID'),
    (('sensor', 'currentConfig', 'contentSha256'), None, 'sensor-heartbeat', 'SENSOR_CONFIG_OR_BUILD_MISMATCH'),
    (('sensor', 'currentConfig', 'buildSha256'), 'd' * 64, 'sensor-heartbeat', 'SENSOR_CONFIG_OR_BUILD_MISMATCH'),
    (('executor', 'freshness'), 'no_record', 'executor-heartbeat', 'EXECUTOR_HEARTBEAT_NOT_FRESH'),
    (('executor', 'status'), 'revoked', 'executor-heartbeat', 'EXECUTOR_NOT_ALIVE'),
    (('executor', 'healthState'), 'healthy', 'executor-heartbeat', 'EXECUTOR_NOT_ALIVE'),
    (('executor', 'bootId'), '', 'executor-heartbeat', 'EXECUTOR_BOOT_ID_INVALID'),
    (('executor', 'capabilityHash'), 'd' * 64, 'executor-heartbeat', 'EXECUTOR_NOT_ZERO_CAPABILITY'),
    (('executor', 'adapterVersion'), 'pf/1', 'executor-heartbeat', 'EXECUTOR_NOT_ZERO_CAPABILITY'),
    (('executor', 'reported', 'pendingRecovery'), True, 'executor-heartbeat', 'EXECUTOR_RECOVERY_OR_ACTIVE_RULES'),
    (('executor', 'reported', 'activeRuleCount'), 1, 'executor-heartbeat', 'EXECUTOR_RECOVERY_OR_ACTIVE_RULES'),
    (('executor', 'reported', 'activeRuleCount'), False, 'executor-heartbeat', 'EXECUTOR_RECOVERY_OR_ACTIVE_RULES'),
    (('executor', 'reported', 'clockSkewMs'), None, 'executor-heartbeat', 'EXECUTOR_CLOCK_UNTRUSTED'),
    (('executor', 'reported', 'clockSkewMs'), float('nan'), 'executor-heartbeat', 'EXECUTOR_CLOCK_UNTRUSTED'),
    (('executor', 'reported', 'clockSkewMs'), 1001, 'executor-heartbeat', 'EXECUTOR_CLOCK_UNTRUSTED'),
    (('windows', 0, 'assetId'), uid('wrong-asset'), 'health-windows', 'HEALTH_IDENTITY_MISMATCH'),
    (('windows', 0, 'observerSessionId'), 'invalid', 'health-windows', 'HEALTH_SESSION_INVALID'),
    (('windows', 0, 'freshness'), 'stale', 'health-windows', 'HEALTH_WINDOW_NOT_CURRENT'),
    (('windows', 0, 'healthState'), 'unhealthy', 'health-windows', 'HEALTH_WINDOW_NOT_CURRENT'),
    (('windows', 0, 'verificationStatus'), 'broken_chain', 'health-windows', 'HEALTH_SERVER_VERIFICATION_FAILED'),
    (('windows', 0, 'serverVerifiedHealthy'), False, 'health-windows', 'HEALTH_SERVER_VERIFICATION_FAILED'),
    (('windows', 0, 'healthVersion'), 'old-version', 'health-windows', 'HEALTH_LIVE_CAPTURE_REQUIRED'),
    (('windows', 0, 'captureSource'), 'pcap_replay', 'health-windows', 'HEALTH_LIVE_CAPTURE_REQUIRED'),
    (('windows', 0, 'configSha256'), 'd' * 64, 'health-windows', 'HEALTH_CONFIG_OR_BUILD_MISMATCH'),
    (('windows', 0, 'buildSha256'), 'd' * 64, 'health-windows', 'HEALTH_CONFIG_OR_BUILD_MISMATCH'),
    (('windows', 0, 'sequence'), True, 'health-windows', 'HEALTH_SEQUENCE_INVALID'),
    (('windows', 0, 'sequence'), 0, 'health-windows', 'HEALTH_SEQUENCE_INVALID'),
    (('windows', 0, 'sequence'), 4, 'health-windows', 'HEALTH_CHAIN_DISCONTINUOUS'),
    (('windows', 0, 'intervalStart'), '2026-10-21T09:59:53Z', 'health-windows', 'HEALTH_INTERVAL_INVALID'),
    (('windows', 0, 'receivedAt'), '2026-10-21T09:59:59Z', 'health-windows', 'HEALTH_INTERVAL_INVALID'),
    (('windows', 0, 'receivedAt'), '2026-10-21T10:00:11Z', 'health-windows', 'HEALTH_INTERVAL_INVALID'),
    (('windows', 0, 'captureGap'), True, 'health-windows', 'HEALTH_GAP_OR_CLOCK_UNTRUSTED'),
    (('windows', 0, 'clockSkewMs'), None, 'health-windows', 'HEALTH_GAP_OR_CLOCK_UNTRUSTED'),
    (('windows', 0, 'clockSkewMs'), True, 'health-windows', 'HEALTH_GAP_OR_CLOCK_UNTRUSTED'),
    (('windows', 0, 'counterEnd', 'packetsSeen'), None, 'health-windows', 'HEALTH_COUNTER_UNKNOWN'),
    (('windows', 0, 'counterEnd', 'capacityDrops'), -1, 'health-windows', 'HEALTH_COUNTER_UNKNOWN'),
    (('windows', 0, 'counterEnd', 'kernelDrops'), 0.0, 'health-windows', 'HEALTH_COUNTER_UNKNOWN'),
    (('windows', 0, 'counterEnd', 'packetsSeen'), 9007199254740992, 'health-windows', 'HEALTH_COUNTER_UNKNOWN'),
    (('windows', 0, 'counterEnd', 'kernelDrops'), 1, 'health-windows', 'HEALTH_CAPTURE_DROPS'),
    (('windows', 0, 'counterEnd', 'capacityDrops'), 1, 'health-windows', 'HEALTH_CAPTURE_DROPS'),
    (('windows', 0, 'counterEnd', 'packetsSeen'), 9, 'health-windows', 'HEALTH_CAPTURE_DROPS'),
    (('windows', 0, 'counterStart', 'packetsSeen'), 11, 'health-windows', 'HEALTH_CHAIN_DISCONTINUOUS'),
    (('bindings', 0, 'status'), 'suspended', 'remote-binding', 'REMOTE_ACTIVE_BINDING_MISSING_OR_AMBIGUOUS'),
    (('bindings', 0, 'id'), uid('wrong-binding'), 'remote-binding', 'REMOTE_BINDING_MISMATCH'),
    (('bindings', 0, 'authorizationId'), uid('wrong-auth'), 'remote-binding', 'REMOTE_BINDING_MISMATCH'),
    (('bindings', 0, 'bundleId'), uid('wrong-bundle'), 'remote-binding', 'REMOTE_BINDING_MISMATCH'),
    (('bindings', 1, 'status'), 'suspended', 'mac-binding', 'MAC_BASELINE_BINDING_CHANGED'),
    (('bindings', 1, 'revision'), 2, 'mac-binding', 'MAC_BASELINE_BINDING_CHANGED'),
    (('bindings', 1, 'revision'), True, 'mac-binding', 'MAC_BASELINE_BINDING_CHANGED'),
    (('bindings', 1, 'bundleId'), uid('old-bundle'), 'mac-binding', 'MAC_BASELINE_BINDING_CHANGED'),
    (('bindings', 1, 'assetId'), uid('assetId'), 'mac-binding', 'MAC_BASELINE_ASSET_CHANGED'),
])
def test_backend_anomalies_are_false_with_specific_reason(scenario, path, value, check, reason):
    change(scenario.backend, path, value)
    result = inspect(scenario)
    assert result['ok'] is False
    assert result['checks'][check] == {'ok': False, 'reason': reason}
    # 即使传感器失败，仍独立读取并核对 Mac 基准绑定。
    assert 'mac-binding' in result['checks']


def test_health_requires_two_contiguous_windows(scenario):
    scenario.backend.windows = scenario.backend.windows[:1]
    result = inspect(scenario)
    assert result['checks']['health-windows']['reason'] == 'HEALTH_CONTINUITY_INSUFFICIENT'
    scenario.backend.windows = []
    result = inspect(scenario)
    assert result['ok'] is False
    assert result['checks']['health-windows']['reason'] == 'HEALTH_WINDOW_NO_RECORD'


def test_health_time_gap_and_duplicate_sequence_are_rejected(scenario):
    scenario.backend.windows[0]['intervalStart'] = '2026-10-21T09:59:59.100Z'
    result = inspect(scenario)
    assert result['checks']['health-windows']['reason'] == 'HEALTH_CHAIN_DISCONTINUOUS'
    scenario.backend.windows[0]['intervalStart'] = '2026-10-21T09:59:59Z'
    scenario.backend.windows[0]['sequence'] = 1
    assert inspect(scenario)['checks']['health-windows']['reason'] == 'HEALTH_CHAIN_DISCONTINUOUS'


@pytest.mark.parametrize('value', [1, True, 2001])
def test_invalid_health_sample_limit(scenario, value):
    scenario.plan['healthWindowCount'] = value
    assert inspect(scenario)['checks']['health-windows']['reason'] == 'HEALTH_WINDOW_LIMIT_INVALID'


def test_boot_and_config_changes_during_read_are_explicit_failures(scenario):
    scenario.backend.next_sensor = deepcopy(scenario.backend.sensor)
    scenario.backend.next_sensor['bootId'] = uid('new-heartbeat-boot')
    result = inspect(scenario)
    assert result['ok'] is False
    assert result['checks']['sensor-boot']['reason'] == 'SENSOR_BOOT_CHANGED_DURING_INSPECTION'
    scenario.backend.sensor_reads = 0
    scenario.backend.next_sensor = deepcopy(scenario.backend.sensor)
    scenario.backend.next_sensor['currentConfig']['contentSha256'] = 'd' * 64
    assert inspect(scenario)['checks']['sensor-boot']['reason'] == 'SENSOR_CONFIG_CHANGED_DURING_INSPECTION'


def test_explicit_boot_and_mac_asset_baselines_are_checked(scenario):
    scenario.plan['expectedSensorBootId'] = uid('different-boot')
    assert inspect(scenario)['checks']['sensor-heartbeat']['reason'] == 'SENSOR_BOOT_ID_MISMATCH'
    del scenario.plan['expectedSensorBootId']
    assert inspect(scenario, mac_asset_id=uid('other-mac'))['checks']['mac-binding']['reason'] == 'MAC_BASELINE_ASSET_CHANGED'


def test_missing_ambiguous_or_incomplete_bindings(scenario):
    initial = deepcopy(scenario.backend.bindings)
    scenario.backend.bindings = initial[:1]
    assert inspect(scenario)['checks']['mac-binding']['reason'] == 'MAC_BASELINE_BINDING_MISSING'
    extra = dict(initial[0], id=uid('second-active-binding'))
    scenario.backend.bindings = [*initial, extra]
    assert inspect(scenario)['checks']['remote-binding']['reason'] == 'REMOTE_ACTIVE_BINDING_MISSING_OR_AMBIGUOUS'
    scenario.backend.bindings = [*initial, initial[0]]
    assert inspect(scenario)['checks']['bindings']['reason'] == 'BINDING_DUPLICATED'
    scenario.backend.bindings = [dict(initial[0], id=uid('binding-' + str(n))) for n in range(200)]
    result = inspect(scenario)
    assert result['ok'] is False and result['checks']['bindings']['reason'] == 'BINDING_COVERAGE_INCOMPLETE'


@pytest.mark.parametrize('endpoint,check', [('/sensor-heartbeats', 'sensor-heartbeat'),
                                           ('/executor-heartbeats', 'executor-heartbeat')])
def test_machine_missing_or_multiple_is_not_healthy(scenario, endpoint, check):
    original = scenario.backend.request

    def response(method, path):
        if urlsplit(path).path == endpoint:
            return {'items': []}
        return original(method, path)
    scenario.backend.request = response
    result = inspect(scenario)
    assert result['ok'] is False and result['checks'][check]['reason'].endswith('_HEARTBEAT_NO_RECORD')

    def multiple(method, path):
        if urlsplit(path).path == endpoint:
            row = scenario.backend.sensor if check == 'sensor-heartbeat' else scenario.backend.executor
            if 'cursor=' in path:
                return {'items': [dict(row, id=uid('second-machine'))]}
            return {'items': [row], 'nextCursor': 'more'}
        return original(method, path)
    scenario.backend.request = multiple
    result = inspect(scenario)
    assert result['checks'][check]['reason'].endswith('_IDENTITY_AMBIGUOUS')


@pytest.mark.parametrize('pages,reason', [
    ([{'items': 'invalid'}], 'BACKEND_PAGE_INVALID'),
    ([{'items': [{'id': 'a'}, {'id': 'a'}]}], 'BACKEND_ROW_DUPLICATED_OR_INVALID'),
    ([{'items': [{}]}], 'BACKEND_ROW_DUPLICATED_OR_INVALID'),
    ([{'items': [], 'nextCursor': 1}], 'PAGINATION_CURSOR_INVALID'),
    ([{'items': [{'id': 'a'}], 'nextCursor': 'same'},
      {'items': [{'id': 'b'}], 'nextCursor': 'same'}], 'PAGINATION_CURSOR_INVALID'),
    ([{'items': [{'id': 'a'}], 'nextCursor': 'more'}, {'items': [{'id': 'a'}]}], 'BACKEND_ROW_DUPLICATED_OR_INVALID'),
])
def test_pagination_anomalies_are_not_silently_truncated(pages, reason):
    iterator = iter(pages)
    fake = SimpleNamespace(request=lambda *args: next(iterator))
    with pytest.raises(ValueError, match='^' + reason + '$'):
        status.rows(fake, '/sensor-heartbeats', {'assetId': uid('assetId')})


@pytest.mark.parametrize('error,reason', [
    (RuntimeError('HTTP 503 SERVICE_UNAVAILABLE'), 'HTTP_503_SERVICE_UNAVAILABLE'),
    (RuntimeError('fixture secret text must not appear'), 'BACKEND_REQUEST_FAILED'),
    (KeyError('fixture private data'), 'BACKEND_RESPONSE_INVALID'),
])
def test_backend_failure_is_sanitized_and_independent_checks_continue(scenario, error, reason):
    scenario.backend.errors['/sensor-heartbeats'] = error
    result = inspect(scenario)
    assert result['ok'] is False
    assert result['checks']['sensor-heartbeat']['reason'] == reason
    assert result['checks']['mac-binding']['ok'] is True
    assert 'fixture secret' not in json.dumps(result) and 'fixture private' not in json.dumps(result)


@pytest.mark.parametrize('field,value,reason', [
    ('assetId', 'invalid', 'STATUS_IDENTITY_REQUIRED'),
    ('bundleId', uid('old-r6'), 'STATUS_BUNDLE_OR_BUILD_INVALID'),
    ('guardliveSha256', 'invalid', 'STATUS_BUNDLE_OR_BUILD_INVALID'),
    ('expectedSensorBootId', 'invalid', 'EXPECTED_BOOT_ID_INVALID'),
])
def test_invalid_plan_rejected_before_api(scenario, field, value, reason):
    scenario.plan[field] = value
    with pytest.raises(ValueError, match='^' + reason + '$'):
        inspect(scenario)
    assert not scenario.backend.calls


def test_mac_baseline_id_and_positive_revision_required_before_api(scenario):
    with pytest.raises(ValueError, match='^MAC_BASELINE_ID_REQUIRED$'):
        status.inspect(scenario.plan, scenario.backend, mac_binding_id='invalid')
    with pytest.raises(ValueError, match='^MAC_BASELINE_REVISION_INVALID$'):
        inspect(scenario, mac_binding_revision=0)
    assert not scenario.backend.calls


@pytest.mark.parametrize('url', ['http://127.0.0.1:18082', 'https://example.invalid:18082',
                                 'https://127.0.0.1:18082/path', 'https://127.0.0.1:18082?q=1',
                                 'https://user:fixture@127.0.0.1:18082', 'https://127.0.0.1'])
def test_reader_rejects_nonlocal_or_ambiguous_urls_without_login(url):
    with pytest.raises(ValueError, match='^LOCAL_TLS_ENDPOINT_REQUIRED$'):
        status.reader({'baseUrl': url})


def test_reader_uses_private_tls_and_separate_read_session(tmp_path, monkeypatch):
    directory = private_dir(tmp_path.resolve())
    tls = directory / 'tls'
    pki.create(tls)
    logins = []

    class Human:
        def __init__(self, base, context):
            assert base == 'https://127.0.0.1:18082'
            assert context.minimum_version == status.ssl.TLSVersion.TLSv1_3

        def login_keychain(self, identity):
            logins.append(identity)
            return 'fixture reader session'

    monkeypatch.setattr(status, 'Human', Human)
    reader = {'username': 'fixture-reader', 'keychainService': 'fixture-reader-service'}
    assert status.reader(dict(baseUrl='https://127.0.0.1:18082', backendCA=str(tls / 'ca.pem'), reader=reader,
                              backendTls=dict(certificateFile=str(tls / 'collector.pem'), keyFile=str(tls / 'collector.key')))) == 'fixture reader session'
    assert logins == [reader]


def test_cli_requires_mac_id_and_returns_json_or_text_failures(scenario, tmp_path, monkeypatch, capsys):
    plan = tmp_path.resolve() / 'status-plan.json'
    write(plan, scenario.plan)
    monkeypatch.setattr(status, 'reader', lambda p: scenario.backend)
    with pytest.raises(SystemExit) as error:
        status.main(['--plan', str(plan)])
    assert error.value.code == 2 and not scenario.backend.calls
    capsys.readouterr()
    args = ['--plan', str(plan), '--mac-binding-id', MAC_BINDING, '--mac-asset-id', uid('mac-asset')]
    assert status.main(args) == 0
    assert json.loads(capsys.readouterr().out)['ok'] is True
    assert status.main([*args, '--expected-sensor-boot-id', uid('another-boot'), '--format', 'text']) == 1
    text = capsys.readouterr().out
    assert 'SENSOR_BOOT_ID_MISMATCH' in text and '巡检发现异常' in text
