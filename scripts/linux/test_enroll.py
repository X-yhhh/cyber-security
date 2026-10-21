"""A3 登记验收：仅使用进程内后端替身和临时私有文件，不绑定端口。"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from executor import pki
from scripts.linux import enroll
from scripts.linux.supervisor import Supervisor
from scripts.p8.toolkit import load, private_dir, sha, write


def uid(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'a3-enroll-fixture/' + name))


class FakeBackend:
    """模拟一次性凭据、幂等重试与按资产激活；任何未登记接口立即失败。"""
    def __init__(self, plan):
        self.calls = []
        self.cache = {}
        self.created = []
        self.lost = None
        self.bundle = dict(id=enroll.R6_PRIME, environment='authorized', status='active', revision=4,
                           subjectSha256=plan['subjectSha256'], policyId=uid('policy'),
                           subject={'featureProfileSha256': 'c' * 64})
        self.policy = {'definition': {'mode': 'alert_only'}}
        self.mac_binding = dict(id='54dd1707-d7f9-4ce7-8a9d-8f4955f4546a', assetId=uid('mac'),
                                status='active', revision=1)
        self.activated = []

    def session(self, role):
        return SimpleNamespace(identity=uid(role), request=lambda *a, **kw: self.request(role, *a, **kw))

    def request(self, actor, method, path, body=None, *, key=None, revision=None):
        self.calls.append(dict(actor=actor, method=method, path=path, body=deepcopy(body), key=key, revision=revision))
        if method == 'GET':
            if path == '/release-bundles/' + enroll.R6_PRIME:
                return deepcopy(self.bundle)
            if path == '/decision-policies/' + self.bundle['policyId']:
                return deepcopy(self.policy)
            for collection in ('sensors', 'executors'):
                if path == '/' + collection + '?assetId=' + uid('asset') + '&limit=2':
                    return {'items': [{'id': uid(collection), 'assetId': uid('asset')}], 'nextCursor': None}
            raise AssertionError('unexpected read: ' + path)
        assert method == 'POST'
        assert str(uuid.UUID(key)) == key
        if key in self.cache:
            if path in ('/sensors', '/executors'):
                raise RuntimeError('HTTP 409 CREDENTIAL_ALREADY_ISSUED')
            return deepcopy(self.cache[key])
        self.created.append(path)
        if path == '/assets':
            result = {'id': uid('asset'), 'revision': 1}
        elif path == '/assets/' + uid('asset') + '/authorizations':
            result = {'id': uid('authorization'), 'revision': 1}
        elif path == '/authorizations/' + uid('authorization') + '/decisions':
            result = {'id': uid('authorization'), 'revision': 2, 'status': 'active'}
        elif path in ('/sensors', '/executors'):
            result = {'id': uid(path[1:]), 'revision': 1, 'credential': 'fixture-only-' + path[1:]}
        elif path.endswith('/credential-rotations'):
            assert path in ('/sensors/' + uid('sensors') + '/credential-rotations',
                            '/executors/' + uid('executors') + '/credential-rotations')
            result = {'credential': 'fixture-only-rotated', 'revision': 2}
        elif path == '/sensors/' + uid('sensors') + '/configs':
            result = {'id': uid('config'), 'revision': 1}
        elif path == '/sensor-configs/' + uid('config') + '/decisions':
            result = {'id': uid('config'), 'revision': 2, 'status': 'active'}
        elif path == '/release-bundles/' + enroll.R6_PRIME + '/activations':
            assert body['assetIds'] == [uid('asset')]
            self.activated.extend(body['assetIds'])
            self.bundle['revision'] += 1
            result = {'id': enroll.R6_PRIME, 'bindingIds': [uid('binding')],
                      'status': 'active', 'revision': self.bundle['revision']}
        else:
            raise AssertionError('unexpected write: ' + path)
        self.cache[key] = deepcopy(result)
        if path == self.lost:
            self.lost = None
            raise OSError('fixture interrupted response delivery')
        return deepcopy(result)


@pytest.fixture
def scenario(tmp_path):
    directory = private_dir(tmp_path.resolve())
    binary = directory / 'guardlive'
    write(binary, b'fixture linux binary; never executed')
    pki.create(directory / 'backend-tls')
    ca = directory / 'backend-tls/ca.pem'
    plan = dict(bundleId=enroll.R6_PRIME, subjectSha256='b' * 64, assetKey='a3-fixture-linux',
                interface='ens17', localAddresses=['192.0.2.42'],
                validFrom=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                validUntil='9999-12-31T00:00:00Z', remoteRoot='/srv/cyber-sensor',
                guardliveSha256=sha(binary), tunnelPort=18082, root=str(directory / 'package'),
                guardliveBinary=str(binary), owner='fixture owner', evidenceRef='fixture authorization',
                approvalReason='仅批准观测，不授予执行权限',
                applicant={'username': 'fixture-applicant', 'keychainService': 'fixture-a'},
                reviewer={'username': 'fixture-reviewer', 'keychainService': 'fixture-b'},
                baseUrl='https://127.0.0.1:18082', backendCA=str(ca),
                backendTls=dict(caFile=str(ca), certificateFile=str(directory / 'backend-tls/collector.pem'),
                                keyFile=str(directory / 'backend-tls/collector.key')))
    backend = FakeBackend(plan)
    return SimpleNamespace(directory=directory, plan=plan, backend=backend, tls=plan['backendTls'],
                           work=directory / 'work', applicant=backend.session('applicant'),
                           reviewer=backend.session('reviewer'))


def register(scenario, **kwargs):
    return enroll.enroll(scenario.plan, scenario.work, scenario.applicant, scenario.reviewer,
                         backend_tls=scenario.tls, **kwargs)


def test_registration_order_actors_revisions_and_only_new_linux_asset(scenario):
    baseline = deepcopy(scenario.backend.mac_binding)
    result = register(scenario)
    calls = scenario.backend.calls
    assert [(c['method'], c['path'], c['actor'], c['revision']) for c in calls] == [
        ('GET', '/release-bundles/' + enroll.R6_PRIME, 'applicant', None),
        ('GET', '/decision-policies/' + uid('policy'), 'applicant', None),
        ('POST', '/assets', 'applicant', None),
        ('POST', '/assets/' + uid('asset') + '/authorizations', 'applicant', None),
        ('POST', '/authorizations/' + uid('authorization') + '/decisions', 'reviewer', 1),
        ('POST', '/sensors', 'applicant', None),
        ('POST', '/executors', 'applicant', None),
        ('POST', '/sensors/' + uid('sensors') + '/configs', 'applicant', None),
        ('POST', '/sensor-configs/' + uid('config') + '/decisions', 'reviewer', 1),
        ('POST', '/release-bundles/' + enroll.R6_PRIME + '/activations', 'reviewer', 4),
    ]
    writes = {c['path']: c['body'] for c in calls if c['method'] == 'POST'}
    assert len({c['key'] for c in calls if c['method'] == 'POST'}) == 8
    assert writes['/assets']['platform'] == writes['/sensors']['platform'] == writes['/executors']['platform'] == 'linux'
    assert writes['/assets']['environment'] == 'authorized'
    auth = writes['/assets/' + uid('asset') + '/authorizations']
    assert auth['executionScopes'] == [] and auth['observationAllowed'] is True
    assert auth['interfaces'] == ['ens17']
    assert auth['validUntil'] == '9999-12-31T00:00:00.000000Z'
    config = writes['/sensors/' + uid('sensors') + '/configs']
    assert config['buildSha256'] == scenario.plan['guardliveSha256']
    assert config['profileSha256'] == 'c' * 64 and config['captureHealthVersion'] == enroll.HEALTH_VERSION
    assert config['captureScopeId'] == result['captureScopeId'] and config['addressFamily'] == 'ipv4'
    assert writes['/release-bundles/' + enroll.R6_PRIME + '/activations'] == {
        'assetIds': [uid('asset')], 'authorizationIds': [uid('authorization')]}
    assert scenario.backend.activated == [uid('asset')]
    assert scenario.backend.mac_binding == baseline
    assert result['bindingId'] == uid('binding') and result['authorizationId'] == uid('authorization')
    assert result['captureStarted'] is False and result['executorMode'] == 'alert_only'


def test_portable_package_permissions_pki_and_a2_scope(scenario):
    result = register(scenario)
    root = Path(result['root'])
    config = root / 'config'
    sensor, observer = load(config / 'sensor.json'), load(config / 'executor-observer.json')
    Supervisor.validate_scope(sensor)
    assert sensor['allowedInterfaces'] == ['ens17'] and 'localAddressSource' not in sensor
    assert sensor['localAddresses'] == ['192.0.2.42']
    assert sensor['upload']['baseUrl'] == observer['baseUrl'] == 'https://127.0.0.1:18082'
    assert observer['capabilityIds'] == [] and observer['mode'] == 'alert_only'
    assert observer['bundleIds'] == [enroll.R6_PRIME]
    paths = [sensor['secretFile'], *[v for k, v in sensor['upload'].items() if k.endswith(('File', 'Dir'))],
             *[v for k, v in observer.items() if k.endswith(('File', 'Dir'))]]
    assert paths and all(v.startswith(scenario.plan['remoteRoot'] + '/') for v in paths)
    # 后端侧配置：指向 Mac 本机包内 CA，而非远端路径。
    assert (config / 'machine-tls.properties').read_text() == 'DEPLOY_TLS_CLIENT_CA=' + str(config / 'ipc/ca.pem') + '\n'
    assert str(scenario.directory) not in json.dumps([sensor, observer])
    assert (config / 'backend-ca.pem').read_bytes() == Path(scenario.tls['caFile']).read_bytes()
    assert (config / 'ipc/ca.pem').read_bytes() != Path(scenario.tls['caFile']).read_bytes()
    assert set(load(config / 'ipc/fingerprints.json')) == {'collector', 'executor', 'server'}
    assert len((config / 'peer.key').read_bytes()) == 32
    assert not list(root.rglob('targets.json'))
    assert 'targets.json' not in result['generated']
    for directory in (root, scenario.work):
        assert directory.stat().st_mode & 0o777 == 0o700
        for entry in directory.rglob('*'):
            assert entry.stat().st_mode & 0o777 == (0o700 if entry.is_dir() else 0o600)


@pytest.mark.parametrize('field,value,code', [
    ('id', uid('other-bundle'), 'R6_PRIME_BINDING_MISMATCH'),
    ('environment', 'lab', 'R6_PRIME_BINDING_MISMATCH'),
    ('status', 'draft', 'R6_PRIME_BINDING_MISMATCH'),
    ('subjectSha256', 'a' * 64, 'R6_PRIME_BINDING_MISMATCH'),
    ('subject', {'featureProfileSha256': 'invalid'}, 'FEATURE_PROFILE_MISMATCH'),
])
def test_bundle_checks_before_any_write(scenario, field, value, code):
    scenario.backend.bundle[field] = value
    with pytest.raises(ValueError, match='^' + code + '$'):
        register(scenario)
    assert all(c['method'] == 'GET' for c in scenario.backend.calls)
    assert not scenario.work.exists() and not Path(scenario.plan['root']).exists()


@pytest.mark.parametrize('mode', ['auto', 'manual', None])
def test_alert_only_policy_required_before_writes(scenario, mode):
    scenario.backend.policy['definition']['mode'] = mode
    with pytest.raises(ValueError, match='^ALERT_ONLY_REQUIRED$'):
        register(scenario)
    assert not scenario.backend.created


def test_approved_bundle_and_ipv6_are_supported(scenario):
    scenario.backend.bundle['status'] = 'approved'
    scenario.plan['localAddresses'] = ['2001:db8::42']
    register(scenario)
    config = next(c['body'] for c in scenario.backend.calls if c['path'].endswith('/configs'))
    assert config['addressFamily'] == 'ipv6'


@pytest.mark.parametrize('field,value,code', [
    ('bundleId', uid('old-r6'), 'R6_PRIME_REQUIRED'),
    ('subjectSha256', 'bad', 'R6_PRIME_REQUIRED'),
    ('platform', 'macos', 'LINUX_REQUIRED'),
    ('assetKey', '', 'AUTHORIZATION_PLAN_REQUIRED'),
    ('interface', '-ens17', 'INTERFACE_INVALID'),
    ('interface', 'ens17\n', 'INTERFACE_INVALID'),
    ('localAddresses', [], 'LOCAL_ADDRESSES_REQUIRED'),
    ('localAddresses', ['192.0.2.42', '2001:db8::42'], 'LOCAL_ADDRESSES_INVALID'),
    ('localAddresses', ['192.0.2.42', '192.0.2.42'], 'LOCAL_ADDRESSES_INVALID'),
    ('localAddresses', ['127.0.0.1'], 'LOCAL_ADDRESSES_INVALID'),
    ('localAddresses', ['fe80::1%ens17'], 'LOCAL_ADDRESSES_INVALID'),
    ('localAddresses', ['not-an-ip'], 'LOCAL_ADDRESSES_INVALID'),
    ('validUntil', '2000-01-01T00:00:00Z', 'AUTHORIZATION_NOT_CURRENT'),
    ('validFrom', '9999-01-01T00:00:00Z', 'AUTHORIZATION_NOT_CURRENT'),
    ('validFrom', '2026-01-01T00:00:00', 'AUTHORIZATION_NOT_CURRENT'),
    ('validUntil', None, 'AUTHORIZATION_NOT_CURRENT'),
    ('remoteRoot', 'relative', 'REMOTE_ROOT_INVALID'),
    ('remoteRoot', '/', 'REMOTE_ROOT_INVALID'),
    ('remoteRoot', '/srv/../root', 'REMOTE_ROOT_INVALID'),
    ('remoteRoot', '/srv//sensor', 'REMOTE_ROOT_INVALID'),
    ('remoteRoot', '/srv/sensor\n', 'REMOTE_ROOT_INVALID'),
    ('tunnelPort', True, 'TUNNEL_PORT_INVALID'),
    ('tunnelPort', 0, 'TUNNEL_PORT_INVALID'),
    ('tunnelPort', 65536, 'TUNNEL_PORT_INVALID'),
    ('guardliveSha256', '0' * 64, 'GUARDLIVE_SHA256_MISMATCH'),
    ('guardliveSha256', 'malformed', 'GUARDLIVE_SHA256_MISMATCH'),
    ('profileSha256', '0' * 64, 'FEATURE_PROFILE_MISMATCH'),
])
def test_invalid_plan_or_binary_rejected_before_writes(scenario, field, value, code):
    scenario.plan[field] = value
    with pytest.raises(ValueError, match='^' + code + '$'):
        register(scenario)
    assert not scenario.backend.created
    assert not scenario.work.exists()


@pytest.mark.parametrize('field', ['bundleId', 'subjectSha256', 'assetKey', 'interface', 'localAddresses',
                                  'validFrom', 'validUntil', 'remoteRoot', 'guardliveSha256', 'tunnelPort'])
def test_missing_card_field_rejected_without_api(scenario, field):
    del scenario.plan[field]
    with pytest.raises(ValueError, match='^ENROLLMENT_PLAN_REQUIRED$'):
        register(scenario)
    assert not scenario.backend.calls


def test_independent_username_and_authenticated_identity_required(scenario):
    scenario.reviewer.identity = scenario.applicant.identity
    with pytest.raises(ValueError, match='^INDEPENDENT_REVIEWER_REQUIRED$'):
        register(scenario)
    scenario.plan['reviewer']['username'] = scenario.plan['applicant']['username']
    with pytest.raises(ValueError, match='^INDEPENDENT_REVIEWER_REQUIRED$'):
        register(scenario)
    assert not scenario.backend.calls


def test_unsafe_output_or_existing_targets_rejected_without_api(scenario):
    root = Path(scenario.plan['root'])
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(ValueError, match='^PRIVATE_DIRECTORY_REQUIRED$'):
        register(scenario)
    root.chmod(0o700)
    private_dir(root / 'config')
    write(root / 'config/targets.json', {})
    with pytest.raises(ValueError, match='^TARGETS_CONFIGURATION_FORBIDDEN$'):
        register(scenario)
    assert not scenario.backend.calls


def test_missing_or_symlink_binary_rejected_without_api(scenario):
    binary = Path(scenario.plan['guardliveBinary'])
    scenario.plan['guardliveBinary'] = str(scenario.directory / 'absent')
    with pytest.raises(ValueError, match='^GUARDLIVE_BUILD_REQUIRED$'):
        register(scenario)
    link = scenario.directory / 'binary-link'
    link.symlink_to(binary)
    scenario.plan['guardliveBinary'] = str(link)
    with pytest.raises(ValueError, match='^SYMLINK_FORBIDDEN$'):
        register(scenario)
    assert not scenario.backend.calls


def test_resume_keeps_identity_secrets_and_original_activation_revision(scenario):
    first = register(scenario)
    files = {str(p): p.read_bytes() for p in Path(first['root']).rglob('*') if p.is_file()}
    mutation_count = len(scenario.backend.created)
    calls = len(scenario.backend.calls)
    assert scenario.backend.bundle['revision'] == 5
    assert register(scenario) == first
    assert len(scenario.backend.created) == mutation_count
    assert all(c['method'] == 'GET' for c in scenario.backend.calls[calls:])
    assert all(Path(name).read_bytes() == content for name, content in files.items())
    journal = load(scenario.work / 'state.json')
    assert journal['steps']['activation']['request']['revision'] == 4
    scenario.plan['owner'] = 'another owner'
    with pytest.raises(ValueError, match='^RESUME_PLAN_CHANGED$'):
        register(scenario)
    assert len(scenario.backend.created) == mutation_count


@pytest.mark.parametrize('collection', ['sensors', 'executors'])
def test_lost_credential_response_rotates_only_the_existing_identity(scenario, collection):
    scenario.backend.lost = '/' + collection
    with pytest.raises(OSError, match='interrupted'):
        register(scenario)
    result = register(scenario)
    assert scenario.backend.created.count('/assets') == 1
    assert scenario.backend.created.count('/' + collection) == 1
    rotation = '/' + collection + '/' + uid(collection) + '/credential-rotations'
    assert scenario.backend.created.count(rotation) == 1
    assert result['sensorId' if collection == 'sensors' else 'executorId'] == uid(collection)
    credential = Path(result['root']) / 'config' / ('sensor.credential' if collection == 'sensors' else 'executor.credential')
    assert credential.read_text() == 'fixture-only-rotated'


def test_clone_resume_refreshes_only_ephemeral_backend_ca(scenario):
    result = register(scenario, refresh_clone_ca=True)
    root = Path(result['root'])
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    pki.create(scenario.directory / 'next-clone-tls')
    scenario.tls = {'caFile': str(scenario.directory / 'next-clone-tls/ca.pem')}
    register(scenario, refresh_clone_ca=True)
    changed = [p.relative_to(root).as_posix() for p, data in before.items() if p.read_bytes() != data]
    assert changed == ['config/backend-ca.pem']
    assert scenario.backend.created.count('/assets') == 1
    assert scenario.backend.created.count('/release-bundles/' + enroll.R6_PRIME + '/activations') == 1


def test_business_resume_does_not_overwrite_changed_configuration(scenario):
    result = register(scenario)
    path = Path(result['root']) / 'config/sensor.json'
    changed = load(path)
    changed['interface'] = 'another-interface'
    write(path, changed, replace=True)
    with pytest.raises(ValueError, match='^GENERATED_FILE_CHANGED$'):
        register(scenario)
    assert load(path) == changed


def cli_plan(scenario):
    path = scenario.directory / 'plan.json'
    write(path, scenario.plan)
    return ['--plan', str(path), '--work', str(scenario.work)]


def test_dry_run_has_no_sessions_files_or_network(scenario, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError('no session or clone permitted')
    monkeypatch.setattr(enroll, 'sessions', forbidden)
    monkeypatch.setattr(enroll, 'clone_backend', forbidden)
    args = cli_plan(scenario)
    assert enroll.main(['--target', 'business', '--dry-run', *args]) == 0
    assert json.loads(capsys.readouterr().out)['captureStarted'] is False
    assert not scenario.work.exists() and not Path(scenario.plan['root']).exists()


@pytest.mark.parametrize('reference', [None, 'another authorization'])
def test_business_requires_exact_explicit_reference(scenario, monkeypatch, reference):
    monkeypatch.setattr(enroll, 'sessions', lambda _: pytest.fail('must not log in'))
    args = ['--target', 'business', *cli_plan(scenario)]
    if reference:
        args += ['--authorization-reference', reference]
    with pytest.raises(ValueError, match='^AUTHORIZED_TARGET_APPROVAL_REQUIRED$'):
        enroll.main(args)
    assert not scenario.work.exists()


def test_clone_requires_runtime_and_target_is_mandatory(scenario):
    args = cli_plan(scenario)
    with pytest.raises(SystemExit) as error:
        enroll.main(args)
    assert error.value.code == 2
    with pytest.raises(ValueError, match='^CLONE_RUNTIME_REQUIRED$'):
        enroll.main(['--target', 'clone', *args])
    assert not scenario.work.exists()


def test_clone_cli_uses_two_sessions_and_tunnel_url_not_clone_port(scenario, monkeypatch, capsys):
    entries, logins = [], []

    @contextmanager
    def clone(args, work):
        entries.append((args.source_schema, work))
        yield 'https://127.0.0.1:49152', 'fixture-context', scenario.tls

    class Human:
        def __init__(self, base, context):
            assert base == 'https://127.0.0.1:49152' and context == 'fixture-context'

        def login_keychain(self, identity):
            role = 'applicant' if identity == scenario.plan['applicant'] else 'reviewer'
            logins.append((id(self), role))
            return scenario.backend.session(role)

    monkeypatch.setattr(enroll, 'clone_backend', clone)
    monkeypatch.setattr(enroll, 'Human', Human)
    args = ['--target', 'clone', *cli_plan(scenario)]
    for option in ('mysql-service', 'java', 'jar', 'report-trust', 'artifacts'):
        args += ['--' + option, '/fixture/' + option]
    assert enroll.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert [role for _, role in logins] == ['applicant', 'reviewer']
    assert entries == [('cyber_security', scenario.work)]
    assert load(scenario.work / 'target.json') == {'target': 'clone'}
    assert load(Path(result['root']) / 'config/sensor.json')['upload']['baseUrl'] == 'https://127.0.0.1:18082'
    assert load(scenario.work / 'result.json') == result


def test_business_cli_reuses_mac_sessions_and_accepts_equal_ca_files(scenario, monkeypatch, capsys):
    duplicate = scenario.directory / 'same-backend-ca.pem'
    write(duplicate, Path(scenario.tls['caFile']).read_bytes())
    scenario.plan['backendCA'] = str(duplicate)
    monkeypatch.setattr(enroll, 'sessions', lambda p: (scenario.applicant, scenario.reviewer))
    assert enroll.main(['--target', 'business', *cli_plan(scenario),
                        '--authorization-reference', scenario.plan['evidenceRef']]) == 0
    assert json.loads(capsys.readouterr().out)['ok'] is True


def test_business_cli_rejects_different_ca_before_login(scenario, monkeypatch):
    different = scenario.directory / 'different-backend-ca.pem'
    write(different, b'fixture incorrect trust material')
    scenario.plan['backendCA'] = str(different)
    monkeypatch.setattr(enroll, 'sessions', lambda p: pytest.fail('must not log in'))
    with pytest.raises(ValueError, match='^BACKEND_CA_MISMATCH$'):
        enroll.main(['--target', 'business', *cli_plan(scenario),
                     '--authorization-reference', scenario.plan['evidenceRef']])
    assert not scenario.backend.calls


def test_clone_journal_cannot_be_reused_for_business(scenario, monkeypatch):
    private_dir(scenario.work)
    write(scenario.work / 'target.json', {'target': 'clone'})
    monkeypatch.setattr(enroll, 'sessions', lambda p: pytest.fail('must not log in to another backend'))
    with pytest.raises(ValueError, match='^ENROLLMENT_TARGET_CHANGED$'):
        enroll.main(['--target', 'business', *cli_plan(scenario),
                     '--authorization-reference', scenario.plan['evidenceRef']])
    assert not scenario.backend.calls
