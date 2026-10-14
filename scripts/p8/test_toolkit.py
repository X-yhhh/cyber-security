"""部署文件、幂等恢复、真实契约配置及失败封闭；只用临时目录和替身，不访问系统服务。"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import os
import plistlib
import subprocess
import uuid
import pytest
from scripts.p8 import enroll, launchd, lab_demo, sensor_service, status, observer_executor
from scripts.p8.toolkit import Journal, load, private_dir, write


def args(tmp_path, **overrides):
    return SimpleNamespace(root=str(tmp_path/'service'), release=str(tmp_path/'service/program/releases/abc'),
        java='/approved/jdk25/bin/java', python='/approved/python/bin/python', dry_run=True,
        authorization_reference=None, mode='pf', **overrides)


def test_dry_run_no_writes_and_plists_lint(tmp_path):
    a = args(tmp_path)
    out = launchd.render(a)
    assert not (tmp_path/'service').exists()
    assert list(out['plists']) == list(launchd.ORDER)
    for role, xml in out['plists'].items():
        value = plistlib.loads(xml.encode())
        assert Path(value['ProgramArguments'][0]).is_absolute()
        assert value['Umask'] == 0o077
        assert all('password' not in str(v).lower() for v in value.values())
        path = tmp_path/(role+'.plist')
        path.write_text(xml)
        subprocess.run(['plutil', '-lint', str(path)], check=True, capture_output=True)
    assert plistlib.loads(out['plists']['sensor'].encode())['KeepAlive'] is False
    assert launchd.install(a)['manualRootOrder'] == ['recovery', 'executor']
    assert launchd.uninstall(a)['order'] == list(reversed(launchd.ORDER))
    assert not (tmp_path/'service').exists()


def test_render_permissions_and_no_overwrite(tmp_path):
    a = args(tmp_path)
    a.dry_run = False
    launchd.render(a)
    root = Path(a.root)
    for path in root.rglob('*'):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
    assert (root/'generated/newsyslog.conf').read_text().count('10240') == 10
    with pytest.raises(ValueError, match='FILE_ALREADY_EXISTS'):
        launchd.render(a)
    with pytest.raises(ValueError, match='INSTALL_AUTHORIZATION_REQUIRED'):
        launchd.install(a)


def test_paths_and_symlinks_rejected(tmp_path):
    a = args(tmp_path)
    a.release = '../outside'
    with pytest.raises(ValueError, match='ABSOLUTE_PATH'):
        launchd.render(a)
    outside = tmp_path/'outside'
    outside.mkdir()
    (tmp_path/'service').symlink_to(outside)
    a = args(tmp_path)
    with pytest.raises(ValueError, match='SYMLINK'):
        launchd.render(a)


class Client:
    def __init__(self, identity=1, shared=None):
        self.identity = identity
        self.calls = []
        self.shared = shared if shared is not None else {}
        self.lose = None
    def request(self, method, path, body=None, *, key=None, revision=None):
        self.calls.append((method, path, deepcopy(body), key, revision))
        if method == 'GET':
            if path.startswith('/release-bundles/'):
                return {'id': enroll.R6, 'subjectSha256': 'a'*64, 'environment': 'authorized', 'status': 'approved', 'policyId': 'policy', 'revision': 3}
            if path.startswith('/decision-policies/'):
                return {'definition': {'mode': 'alert_only'}}
            if path.startswith('/sensors?'):
                return {'items': [{'id': self.machine_id, 'assetId': self.asset_id}], 'nextCursor': None}
        if key not in self.shared:
            self.shared[key] = {'id': str(uuid.uuid4()), 'revision': 1, 'status': 'active'}
            if path in ('/sensors', '/executors') or path.endswith('credential-rotations'):
                self.shared[key]['credential'] = 'fixture-only-token'
        if self.lose == path:
            self.lose = None
            raise OSError('connection lost after commit')
        return self.shared[key]


def test_interruption_reuses_exact_key_and_request(tmp_path):
    client = Client()
    journal = Journal(tmp_path, {'scope': 'test'})
    client.lose = '/assets'
    with pytest.raises(OSError):
        journal.step('asset', client, '/assets', {'name': 'owned'})
    first = client.calls[-1]
    result = Journal(tmp_path, {'scope': 'test'}).step('asset', client, '/assets', {'name': 'owned'})
    assert result['id']
    assert client.calls[-1] == first
    with pytest.raises(ValueError, match='RESUME_PLAN_CHANGED'):
        Journal(tmp_path, {'scope': 'other'})
    with pytest.raises(ValueError, match='RESUME_REQUEST_CHANGED'):
        journal.step('asset', client, '/assets', {'name': 'changed'})


def test_machine_lost_response_rotates_only_owned_identity(tmp_path):
    client = Client()
    client.asset_id, client.machine_id = str(uuid.uuid4()), str(uuid.uuid4())
    original = client.request
    def request(method, path, body=None, **kwargs):
        if path == '/sensors':
            raise RuntimeError('HTTP 409 CREDENTIAL_ALREADY_ISSUED')
        return original(method, path, body, **kwargs)
    client.request = request
    journal = Journal(tmp_path, {})
    value = journal.machine('sensor', client, 'sensors', {'assetId': client.asset_id})
    assert value['id'] == client.machine_id and value['credential']
    assert any('credential-rotations' in c[1] for c in client.calls)
    assert journal.machine('sensor', client, 'sensors', {'assetId': client.asset_id}) == value


def plan(tmp_path):
    binary = tmp_path/'guardlive'
    binary.write_bytes(b'fixture binary')
    return {'bundleId': enroll.R6, 'subjectSha256': 'a'*64, 'profileSha256': 'b'*64,
        'assetKey': 'b3-fixture', 'owner': 'test', 'applicant': {'username': 'one'}, 'reviewer': {'username': 'two'},
        'root': str(tmp_path/'service'), 'interface': 'en0', 'localAddresses': ['192.0.2.10'],
        'validFrom': (datetime.now(timezone.utc)-timedelta(seconds=10)).isoformat(),
        'validUntil': (datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat(),
        'approvalReason': 'isolated fixture', 'evidenceRef': 'clone-fixture', 'guardliveBinary': str(binary)}


def test_enrollment_complete_and_resume_without_duplicate_writes(tmp_path):
    p = plan(tmp_path)
    applicant, reviewer = Client(1), Client(2)
    tls = {'caFile': '/private/ca', 'certificateFile': '/private/cert', 'keyFile': '/private/key'}
    result = enroll.enroll(p, tmp_path/'journal', applicant, reviewer, base='https://127.0.0.1:18082', backend_tls=tls)
    assert result['captureStarted'] is False and result['executorMode'] == 'alert_only'
    count = len([r for r in applicant.calls+reviewer.calls if r[0] == 'POST'])
    enroll.enroll(p, tmp_path/'journal', applicant, reviewer, base='https://127.0.0.1:18082', backend_tls=tls)
    assert len([r for r in applicant.calls+reviewer.calls if r[0] == 'POST']) == count
    config = load(Path(p['root'])/'config/sensor.json')
    assert config['captureScope'] == 'all_inbound_tcp' and config['allowedInterfaces'] == ['en0']
    assert load(Path(p['root'])/'config/executor-observer.json')['capabilityIds'] == []
    authorizations = [r[2] for r in applicant.calls if r[1].endswith('/authorizations')]
    assert authorizations[0]['executionScopes'] == []
    for path in (tmp_path/'service').rglob('*'):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
    one = sensor_service.prepare(p['root'], tmp_path/'release')
    two = sensor_service.prepare(p['root'], tmp_path/'release')
    assert one != two and int(one[-1][:-1]) <= 1800


def test_enrollment_rejects_self_approval_expiry_and_wrong_bundle(tmp_path):
    p = plan(tmp_path)
    with pytest.raises(ValueError, match='INDEPENDENT_REVIEWER'):
        enroll.enroll(p, tmp_path/'journal', Client(), Client(), base='', backend_tls={})
    p['bundleId'] = str(uuid.uuid4())
    with pytest.raises(ValueError, match='R6_BINDING'):
        enroll.validate(p)
    p['bundleId'] = enroll.R6
    p['validUntil'] = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    with pytest.raises(ValueError, match='AUTHORIZATION_EXPIRED'):
        enroll.validate(p)


def test_observer_rejects_capabilities_before_network(tmp_path):
    write(tmp_path/'observer.json', {'mode': 'alert_only', 'capabilityIds': ['forbidden']})
    with pytest.raises(ValueError, match='ZERO_CAPABILITIES'):
        observer_executor.configuration(tmp_path/'observer.json')


def test_status_unknown_pf_and_stale_heartbeat_fail(tmp_path):
    (tmp_path/'logs').mkdir()
    p = {'root': str(tmp_path), 'assetId': str(uuid.uuid4()), 'executorId': str(uuid.uuid4()), 'mode': 'alert-only', 'minFreeBytes': 0}
    class Reader:
        def call(self, *a): return {'data': {'status': 'UP'}}
        def request(self, method, path):
            if path.startswith('/ops/status'): return {'items': [{'status': 'active'}]}
            return {'items': [{'healthState': 'stale', 'freshness': 'stale', 'sensorId': 's', 'intervalEnd': 'now'}], 'nextCursor': None}
    result = status.inspect(p, Reader(), execute=lambda c: (1, '') if c[0] == '/sbin/pfctl' else (0, ' state = running\n pid = 12\n'))
    assert not result['ok'] and result['checks']['pf']['ruleCount'] is None
    assert not result['checks']['sensor-heartbeats']['ok']


def test_lab_dry_run_and_schedule_no_side_effect(tmp_path):
    import sys
    root = Path(__file__).resolve().parents[2]
    for script, option in [('lab_demo.py', '--dry-run'), ('backup_restore.py', '--schedule')]:
        proc = subprocess.run([sys.executable, str(root/'scripts/p8'/script), option], capture_output=True, text=True, cwd=tmp_path)
        assert proc.returncode == 0, proc.stdout
    assert not list(tmp_path.iterdir())
    assert lab_demo.Demo.authorization_minutes == 30
    assert lab_demo.Demo.session_timeout_seconds == 1800


def test_alert_only_install_uninstall_order_and_wrong_plist_guard(tmp_path, monkeypatch):
    a = args(tmp_path)
    a.mode, a.dry_run, a.authorization_reference = 'alert-only', False, 'fixture-scope'
    agents = tmp_path/'Library/LaunchAgents'
    agents.mkdir(parents=True)
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    launchd.render(a)
    calls = []
    monkeypatch.setattr(launchd, 'run', lambda command, **kwargs: calls.append(command) or '')
    monkeypatch.setattr(launchd, 'wait_ready', lambda root: calls.append(['ready']))
    monkeypatch.setattr(launchd, 'verify_release', lambda root: None)
    launchd.install(a)
    assert calls[1] == ['ready']
    assert [Path(c[-1]).stem for c in calls if c[0] == 'launchctl'] == [launchd.PREFIX+r for r in launchd.ORDER]
    calls.clear()
    sensor = agents/(launchd.PREFIX+'sensor.plist')
    original = sensor.read_bytes()
    sensor.write_bytes(plistlib.dumps({'Label': 'someone-else'}))
    with pytest.raises(ValueError, match='PLIST_MISMATCH'):
        launchd.uninstall(a)
    assert not calls
    sensor.write_bytes(original)
    launchd.uninstall(a)
    assert [c[-1].split('/')[-1] for c in calls] == [launchd.PREFIX+r for r in reversed(launchd.ORDER)]
    assert not list(agents.iterdir())
    assert (Path(a.root)/'ledger').exists()


def test_build_rejects_wrong_jdk_before_maven(tmp_path, monkeypatch):
    a = args(tmp_path)
    a.release = str(tmp_path/'release')
    monkeypatch.setattr(launchd, 'run', lambda *a, **kw: 'abc')
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: SimpleNamespace(stderr='openjdk version "17"'))
    with pytest.raises(ValueError, match='JDK25_REQUIRED'):
        launchd.build(a)
    assert not (tmp_path/'release').exists()


def test_release_extra_file_and_modified_binary_refused(tmp_path):
    from scripts.p8.toolkit import sha
    for name in ('backend.jar', 'guardlive', 'guardtargets', 'web/index.html', 'release.json'):
        file = tmp_path/name
        file.parent.mkdir(exist_ok=True)
        file.write_bytes(b'fixture')
    manifest = ''.join(sha(p)+'  '+str(p.relative_to(tmp_path))+'\n' for p in sorted(tmp_path.rglob('*')) if p.is_file())
    (tmp_path/'SHA256SUMS').write_text(manifest)
    launchd.verify_release(tmp_path)
    (tmp_path/'untracked-secret').write_bytes(b'fixture')
    with pytest.raises(ValueError, match='FILE_SET'):
        launchd.verify_release(tmp_path)
    (tmp_path/'untracked-secret').unlink()
    (tmp_path/'guardlive').write_bytes(b'changed')
    with pytest.raises(ValueError, match='HASH_MISMATCH'):
        launchd.verify_release(tmp_path)


def test_demo_requires_same_command_ttl_and_verified_cleanup(tmp_path):
    demo = object.__new__(lab_demo.Demo)
    demo.work = tmp_path
    demo.state = {'drain': {'status': {'activeRuleCount': 0, 'pendingReceipts': 0}}, 'rootResult': {'passed': True}}
    demo.asset_rows = lambda sql: [{'commandId': 'c', 'status': 'applied', 'projected': True},
                                   {'commandId': 'c', 'status': 'expired', 'projected': True}]
    calls = []
    demo.lab_op = lambda operation, body: calls.append(operation)
    demo.collect()
    assert calls == ['completions']
    assert json.loads((tmp_path/'demo-result.json').read_bytes())['sourceEligibilityRegistered'] is False
    assert demo.state['formalG3Eligible'] is False
    assert demo.authorization_minutes*60+demo.authorization_backdate_seconds == 1800


def test_demo_expiry_for_other_command_is_not_pass(tmp_path):
    demo = object.__new__(lab_demo.Demo)
    demo.work = tmp_path
    demo.state = {'drain': {'status': {'activeRuleCount': 0, 'pendingReceipts': 0}}, 'rootResult': {'passed': True}}
    demo.asset_rows = lambda sql: [{'commandId': 'a', 'status': 'applied', 'projected': True},
                                   {'commandId': 'b', 'status': 'expired', 'projected': True}]
    with pytest.raises(ValueError, match='NOT_VERIFIED'):
        demo.collect()


def test_root_plan_mismatch_never_launches(tmp_path):
    with pytest.raises(ValueError, match='ROOT_PLAN_MISMATCH'):
        lab_demo.root_command({'manifestSha256': 'wrong'}, SimpleNamespace(stage_manifest='expected', authorization_reference='fixture'))
