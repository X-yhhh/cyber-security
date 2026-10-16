"""P1R-3：延迟恢复、失败封闭及零能力巡检；仅用私有临时目录和回环 mTLS 替身。"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import uuid

import pytest

from executor.contract import capability_set_sha256
from executor.pki import create
from scripts.p8 import launchd, observer_executor, status
from scripts.p8.toolkit import load, private_dir, write


@pytest.fixture
def observer(tmp_path):
    root = private_dir(tmp_path / 'service')
    config = dict(mode='alert_only', capabilityIds=[], assetId=str(uuid.uuid4()), executorId=str(uuid.uuid4()),
                  validUntil=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                  stateDir=str(root / 'ledger/executor'), baseUrl='https://127.0.0.1:18082')
    for key in ('caFile', 'certificateFile', 'keyFile', 'credentialFile'):
        config[key] = str(root / 'config' / key)
        write(config[key], b'synthetic-observer-only')
    path = root / 'config/executor-observer.json'
    write(path, config)
    return root, path, config


def pulse(config, role, **updates):
    data = dict(at=time.time(), mode='alert_only', pfInspected=False, executorId=config['executorId'],
                role=role, pid=71 if role == 'recovery' else 72, bootId=str(uuid.uuid4()))
    data.update(updates)
    path = Path(config['stateDir']) / 'observer' / (role + '.json')
    write(path, data, replace=path.exists())
    return data


class Clock:
    def __init__(self, hook=lambda: None):
        self.elapsed, self.wall, self.hook = 0, time.time(), hook

    def time(self): return self.wall + self.elapsed
    def monotonic(self): return self.elapsed
    def sleep(self, seconds):
        self.elapsed += seconds
        self.hook()


def fake_transport(monkeypatch, clock):
    calls, handlers = [], {}
    monkeypatch.setattr(observer_executor, 'time', clock)
    monkeypatch.setattr(observer_executor.signal, 'signal', lambda sig, handler: handlers.setdefault(sig, handler))
    monkeypatch.setattr(observer_executor.ssl, 'create_default_context', lambda **_: SimpleNamespace(load_cert_chain=lambda *a: None))
    def post(request, **kwargs):
        calls.append(request)
        return io.BytesIO(json.dumps({'data': {'serverTime': datetime.fromtimestamp(clock.time(), timezone.utc).isoformat()}}).encode())
    monkeypatch.setattr(observer_executor.urllib.request, 'urlopen', post)
    return calls, handlers


def test_run_waits_for_delayed_recovery_before_first_heartbeat(observer, monkeypatch):
    _, path, config = observer
    clock = Clock()
    calls, _ = fake_transport(monkeypatch, clock)
    def delayed_recovery():
        assert not calls
        pulse(config, 'recovery', at=clock.time())
    clock.hook = delayed_recovery
    observer_executor.serve(path, 'run', once=True)
    assert clock.elapsed > 0 and len(calls) == 1
    body = json.loads(calls[0].data)
    assert body['pendingRecovery'] is False and body['activeRuleCount'] == 0
    state = load(Path(config['stateDir']) / 'observer/run.json')
    assert state['bootId'] == body['bootId'] and state['pid'] == os.getpid()


def test_install_readiness_rejects_pulse_from_before_bootstrap(observer, monkeypatch):
    """即使旧脉冲还没超过五秒，也必须等到本次 bootstrap 之后的脉冲。"""
    _, path, config = observer
    clock = Clock()
    monkeypatch.setattr(observer_executor, 'time', clock)
    pulse(config, 'recovery', at=clock.time() - .1)
    clock.hook = lambda: pulse(config, 'recovery', at=clock.time())
    current = observer_executor.wait_observer_recovery(path, not_before=clock.time())
    assert clock.elapsed > 0 and current['at'] == clock.time()


def test_running_observer_stops_heartbeats_when_recovery_becomes_stale(observer, monkeypatch):
    _, path, config = observer
    clock = Clock()
    calls, _ = fake_transport(monkeypatch, clock)
    pulse(config, 'recovery', at=clock.time())
    clock.hook = lambda: setattr(clock, 'elapsed', clock.elapsed + 6)
    with pytest.raises(ValueError, match='OBSERVER_PULSE_STALE'):
        observer_executor.serve(path, 'run')
    assert len(calls) == 1


@pytest.mark.parametrize('stop', ['timeout', 'signal', 'expiry'])
def test_wait_timeout_signal_and_expiry_never_send_a_heartbeat(observer, monkeypatch, stop):
    _, path, config = observer
    clock = Clock()
    calls, handlers = fake_transport(monkeypatch, clock)
    if stop == 'signal':
        clock.hook = lambda: handlers[signal.SIGTERM](signal.SIGTERM, None)
        observer_executor.serve(path, 'run', once=True)
    else:
        if stop == 'expiry':
            def expire():
                changed = dict(config, validUntil=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
                write(path, changed, replace=True)
            clock.hook = expire
        with pytest.raises(ValueError, match='AUTHORIZATION_EXPIRED' if stop == 'expiry' else 'OBSERVER_RECOVERY_UNAVAILABLE'):
            observer_executor.serve(path, 'run', once=True)
        if stop == 'timeout':
            assert 30 <= clock.elapsed < 31
    assert calls == [] and not (Path(config['stateDir']) / 'observer/run.json').exists()


@pytest.mark.parametrize('timeout', [False, True])
def test_install_waits_after_recovery_and_stops_before_executor_on_failure(tmp_path, monkeypatch, timeout):
    args = SimpleNamespace(root=str(tmp_path / 'service'), release=str(tmp_path / 'service/program/releases/fixture'),
                           java='/approved/jdk25/bin/java', python='/approved/python/bin/python',
                           mode='alert-only', dry_run=False, authorization_reference='P1R-3-fixture')
    home = tmp_path / 'home'
    agents = home / 'Library/LaunchAgents'
    agents.mkdir(parents=True)
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))
    launchd.render(args)
    events = []
    monkeypatch.setattr(launchd, 'verify_release', lambda _: None)
    monkeypatch.setattr(launchd, 'readiness_settings', lambda _: (None, None))
    monkeypatch.setattr(launchd, 'wait_ready', lambda _: events.append('backend-ready'))
    monkeypatch.setattr(launchd, 'run', lambda command: events.append(Path(command[-1]).stem.removeprefix(launchd.PREFIX)))
    def ready(path, **kwargs):
        assert Path(path) == Path(args.root) / 'config/executor-observer.json'
        assert kwargs['not_before'] <= time.time()
        events.append('recovery-ready')
        if timeout:
            raise ValueError('OBSERVER_RECOVERY_UNAVAILABLE')
    monkeypatch.setattr(launchd, 'wait_observer_recovery', ready, raising=False)
    if timeout:
        with pytest.raises(ValueError, match='OBSERVER_RECOVERY_UNAVAILABLE'):
            launchd.install(args)
        assert events == ['backend', 'backend-ready', 'targets', 'recovery', 'recovery-ready']
        assert not (agents / (launchd.PREFIX + 'executor.plist')).exists()
        assert not (agents / (launchd.PREFIX + 'sensor.plist')).exists()
        assert all((agents / (launchd.PREFIX + role + '.plist')).exists() for role in ('backend', 'targets', 'recovery'))
    else:
        launchd.install(args)
        assert events == ['backend', 'backend-ready', 'targets', 'recovery', 'recovery-ready', 'executor', 'sensor']


@pytest.fixture
def inspection(observer):
    root, path, config = observer
    pulse(config, 'recovery')
    current = pulse(config, 'run')
    plan = dict(root=str(root), assetId=config['assetId'], executorId=config['executorId'], mode='alert-only', minFreeBytes=0)
    row = dict(id=config['executorId'], assetId=config['assetId'], status='pending', bootId=current['bootId'],
               adapterVersion='hostguard-observer/1', capabilityHash=capability_set_sha256({'capabilityIds': []}),
               healthState='unknown', freshness='fresh', serverVerifiedHealthy=None,
               reported=dict(pendingRecovery=False, activeRuleCount=0, clockSkewMs=0))
    sensor = str(uuid.uuid4())
    class Reader:
        def call(self, *args): return {'data': {'status': 'UP'}}
        def request(self, method, route):
            if route.startswith('/ops/status'): return {'items': [{'id': config['assetId'], 'status': 'active'}]}
            if route.startswith('/executor-heartbeats'): return {'items': [row]}
            return {'items': [{'id': sensor, 'sensorId': sensor, 'healthState': 'healthy', 'freshness': 'fresh'}]}
    calls = []
    def execute(command):
        calls.append(command)
        assert command[0] == 'launchctl', 'alert-only must not invoke pfctl'
        role = command[-1].split('.')[-1]
        pid = {'recovery': 71, 'executor': 72}.get(role, 42)
        return 0, f' state = running\n pid = {pid}\n'
    return plan, Reader(), row, execute, calls


def test_zero_capability_observer_liveness_preserves_unknown_and_does_not_inspect_pf(inspection):
    plan, reader, row, execute, _ = inspection
    original = deepcopy(row)
    result = status.inspect(plan, reader, execute=execute)
    assert result['ok']
    check = result['checks']['executor-heartbeats']
    assert check['observerLiveness'] == 'alive'
    assert check['items'][0]['healthState'] == 'unknown' and row == original
    assert check['items'][0]['serverVerifiedHealthy'] is None
    assert result['checks']['pf']['state'] == 'not_applicable'
    assert result['checks']['pf']['pfInspected'] is False and result['checks']['pf']['ruleCount'] is None
    assert status.check_summary('executor-heartbeats', check) == 'observer 存活（不代表 PF 健康）'
    assert status.check_summary('pf', result['checks']['pf']) == '不适用（未检查 PF）'


def test_active_observer_keeps_backend_health_projection(inspection):
    plan, reader, row, execute, _ = inspection
    row.update(status='active', healthState='healthy')
    result = status.inspect(plan, reader, execute=execute)
    assert result['ok'] and result['checks']['executor-heartbeats']['observerLiveness'] == 'alive'
    assert result['checks']['executor-heartbeats']['items'][0]['serverVerifiedHealthy'] is None
    assert result['checks']['pf']['state'] == 'not_applicable'


def test_multiple_executor_rows_cannot_share_observer_exemption(inspection):
    plan, reader, row, execute, _ = inspection
    original = reader.request
    reader.request = lambda method, route: {'items': [row, deepcopy(row)]} if route.startswith('/executor-heartbeats') else original(method, route)
    result = status.inspect(plan, reader, execute=execute)
    assert not result['ok'] and not result['checks']['executor-heartbeats']['ok']
    assert result['checks']['pf']['ruleCount'] is None


@pytest.mark.parametrize('changes', [
    {'id': str(uuid.uuid4())}, {'assetId': str(uuid.uuid4())}, {'status': 'disabled'},
    {'freshness': 'stale'}, {'healthState': 'unhealthy'}, {'adapterVersion': 'other-adapter'}, {'capabilityHash': 'f' * 64},
    {'bootId': str(uuid.uuid4())}, {'reported': {}}, {'reported': {'pendingRecovery': True, 'activeRuleCount': 0, 'clockSkewMs': 0}},
    {'reported': {'pendingRecovery': False, 'activeRuleCount': 1, 'clockSkewMs': 0}},
    {'reported': {'pendingRecovery': False, 'activeRuleCount': False, 'clockSkewMs': 0}},
    {'reported': {'pendingRecovery': False, 'activeRuleCount': 0, 'clockSkewMs': 1001}},
    {'reported': {'pendingRecovery': False, 'activeRuleCount': 0, 'clockSkewMs': float('nan')}},
])
def test_observer_exemption_requires_identity_freshness_and_zero_capability_report(inspection, changes):
    plan, reader, row, execute, calls = inspection
    row.update(changes)
    result = status.inspect(plan, reader, execute=execute)
    assert not result['ok'] and not result['checks']['executor-heartbeats']['ok']
    assert not result['checks']['pf']['ok'] and result['checks']['pf']['ruleCount'] is None
    assert all(command[0] == 'launchctl' for command in calls)
    assert status.check_summary('pf', result['checks']['pf']) == '未知（未检查 PF）'


@pytest.mark.parametrize('failure', ['stale', 'future', 'pid', 'identity', 'old-format', 'legacy-ledger', 'nonzero-config'])
def test_untrusted_local_observer_state_cannot_make_inspection_pass(observer, inspection, failure):
    _, path, config = observer
    plan, reader, _, execute, _ = inspection
    if failure == 'legacy-ledger':
        write(Path(config['stateDir']) / 'legacy.sqlite', b'fixture')
    elif failure == 'nonzero-config':
        write(path, dict(config, capabilityIds=['forbidden']), replace=True)
    elif failure == 'old-format':
        write(Path(config['stateDir']) / 'observer/recovery.json', dict(at=time.time(), mode='alert_only', pfInspected=False), replace=True)
    else:
        changes = {'stale': {'at': time.time() - 6}, 'future': {'at': time.time() + 60},
                   'pid': {'pid': 99}, 'identity': {'executorId': str(uuid.uuid4())}}[failure]
        pulse(config, 'recovery', **changes)
    result = status.inspect(plan, reader, execute=execute)
    assert not result['ok'] and not result['checks']['observer']['ok']
    assert not result['checks']['pf']['ok']


def test_stopped_sensor_is_still_a_failure_when_observer_is_alive(inspection):
    plan, reader, _, execute, _ = inspection
    def stopped(command):
        return (0, ' state = waiting\n') if command[-1].endswith('.sensor') else execute(command)
    result = status.inspect(plan, reader, execute=stopped)
    assert not result['ok'] and not result['checks']['sensor']['ok']
    assert result['checks']['executor-heartbeats']['observerLiveness'] == 'alive'


@pytest.mark.parametrize('health_state', ['unknown', 'stale', 'replay_healthy'])
def test_observer_liveness_cannot_replace_live_capture_health(inspection, health_state):
    plan, reader, _, execute, _ = inspection
    original = reader.request
    def read(method, route):
        data = original(method, route)
        if route.startswith('/health-windows'):
            data['items'][0]['healthState'] = health_state
        return data
    reader.request = read
    result = status.inspect(plan, reader, execute=execute)
    assert not result['ok'] and not result['checks']['health-windows']['ok']
    assert result['checks']['executor-heartbeats']['observerLiveness'] == 'alive'


def test_pf_mode_still_requires_successful_pf_query(inspection):
    plan, reader, _, execute, _ = inspection
    plan['mode'] = 'pf'
    result = status.inspect(plan, reader, execute=lambda command: (1, '') if command[0] == '/sbin/pfctl' else execute(command))
    assert not result['ok'] and not result['checks']['pf']['ok']
    assert result['checks']['pf']['ruleCount'] is None


def test_real_observer_process_waits_then_sends_only_heartbeat_over_mtls(observer):
    """实际 CLI 先于 recovery 启动，延迟恢复后首轮成功，SIGTERM 正常退出；无 launchctl/数据库/PF。"""
    root, path, config = observer
    tls = root / 'tls'
    create(tls)
    received, requests = threading.Event(), []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            assert self.path == '/api/v2/machine/executors/' + config['executorId'] + '/heartbeats'
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert self.connection.version() == 'TLSv1.3' and self.connection.getpeercert()
            assert body['capabilityHash'] == capability_set_sha256({'capabilityIds': []}) and body['activeRuleCount'] == 0
            requests.append(body)
            response = json.dumps({'data': {'serverTime': datetime.now(timezone.utc).isoformat()}}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            received.set()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version, context.verify_mode = ssl.TLSVersion.TLSv1_3, ssl.CERT_REQUIRED
    context.load_cert_chain(tls / 'server.pem', tls / 'server.key')
    context.load_verify_locations(tls / 'ca.pem')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config.update(baseUrl=f'https://127.0.0.1:{server.server_port}', caFile=str(tls / 'ca.pem'),
                  certificateFile=str(tls / 'executor.pem'), keyFile=str(tls / 'executor.key'))
    write(path, config, replace=True)
    processes = []
    try:
        command = [sys.executable, '-B', str(Path(observer_executor.__file__).resolve())]
        processes.append(subprocess.Popen([*command, 'run', '--config', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        time.sleep(.3)
        assert processes[0].poll() is None and not requests
        processes.append(subprocess.Popen([*command, 'recovery', '--config', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        assert received.wait(5)
        deadline = time.monotonic() + 2
        while not (Path(config['stateDir']) / 'observer/run.json').exists() and time.monotonic() < deadline:
            time.sleep(.02)
        for process in processes:
            process.terminate()
        for process in processes:
            output, error = process.communicate(timeout=5)
            assert process.returncode == 0, (output, error)
        state = load(Path(config['stateDir']) / 'observer/run.json')
        assert state['bootId'] == requests[0]['bootId'] and state['pid'] == processes[0].pid
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(2)
