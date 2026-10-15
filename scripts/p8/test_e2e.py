"""T1 破坏性边界与诊断脱敏回归；不依赖 MySQL，不创建真实服务。"""
import importlib.util
import json
from pathlib import Path
import sys
import zipfile

import pytest

MODULES = Path(__file__).parent
# 脚本入口以同目录导入；测试显式装载同一模块，避免依赖 pytest 的 import mode。
def module(name):
    spec = importlib.util.spec_from_file_location(name, MODULES / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


env = module('e2e_env')
redact = module('e2e_redact')


@pytest.mark.parametrize('name', ['cyber_security', 'mysql', 'cyber_it_e2e_', 'cyber_it_e2e_' + 'a'*32 + '`;DROP DATABASE cyber_security;'])
def test_refuses_unowned_schema_before_any_sql(monkeypatch, name):
    db = object.__new__(env.Database)
    called = []
    monkeypatch.setattr(env.subprocess, 'run', lambda *a, **k: called.append(a))
    with pytest.raises(RuntimeError, match='REFUSE_OTHER_SCHEMA'):
        db.drop(name)
    assert called == []


@pytest.mark.parametrize('url', ['jdbc:mysql://example.com:3306', 'jdbc:mysql://127.0.0.1/cyber_security',
    'jdbc:mysql://user:password@127.0.0.1/', 'jdbc:mysql://127.0.0.1/?allowMultiQueries=true', ''])
def test_refuses_remote_or_schema_scoped_database(monkeypatch, url):
    monkeypatch.setenv('DB_TEST_BASE_URL', url)
    with pytest.raises(RuntimeError, match='LOOPBACK_DB_TEST_BASE_URL_REQUIRED'):
        env.Database()


def test_backend_cannot_inherit_external_spring_or_java_options(monkeypatch):
    monkeypatch.setenv('SPRING_APPLICATION_JSON', '{"spring":{"datasource":{"url":"business"}}}')
    monkeypatch.setenv('JAVA_TOOL_OPTIONS', '-Dspring.datasource.url=business')
    monkeypatch.setenv('JDK_JAVA_OPTIONS', '-Dserver.address=0.0.0.0')
    monkeypatch.setenv('DB_URL', 'business')
    actual = env.backend_environment()
    assert not {'SPRING_APPLICATION_JSON', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'DB_URL'} & actual.keys()


def test_remote_broker_refused_and_unowned_vhost_cannot_be_deleted(monkeypatch):
    monkeypatch.setenv('RABBITMQ_IT_USERNAME', 'fixture')
    monkeypatch.setenv('RABBITMQ_IT_PASSWORD', 'synthetic-test-secret')
    monkeypatch.setenv('E2E_BROKER_MANAGEMENT_URL', 'https://example.com')
    with pytest.raises(RuntimeError, match='LOOPBACK_BROKER_REQUIRED'):
        env.Broker()
    broker = object.__new__(env.Broker)
    broker.name = '/'
    with pytest.raises(RuntimeError, match='REFUSE_OTHER_VHOST'):
        broker.drop()


def test_failure_trace_stays_valid_and_nested_secrets_are_removed(tmp_path):
    private = tmp_path / 'private'
    private.mkdir()
    secret = 'synthetic-one-time-credential'
    env.private_json(private / 'secrets.json', [secret])
    assert (private / 'secrets.json').stat().st_mode & 0o777 == 0o600
    (private / 'browser-secrets.jsonl').write_text(json.dumps('synthetic-session-cookie') + '\n')
    trace = tmp_path / 'trace.zip'
    network = {'request': {'headers': [{'name': 'Cookie', 'value': 'unknown-cookie'}],
        'postData': {'text': json.dumps({'password': 'unregistered-password', 'message': 'useful failure'})}},
        'response': {'headers': [{'name': 'Set-Cookie', 'value': 'another-session'}]}}
    with zipfile.ZipFile(trace, 'w') as archive:
        archive.writestr('test.network', json.dumps(network) + '\n')
        archive.writestr('test.trace', json.dumps({'event': 'snapshot', 'value': secret, 'status': 'failed'}) + '\n')
        archive.writestr('resources/body', json.dumps({'data': {'credential': 'unknown-machine-secret', 'count': 1}}))
    (tmp_path / 'error-context.md').write_text('button: '+secret+'\nexpected pending, actual rejected\nsynthetic-session-cookie')
    redact.redact_artifacts(tmp_path)
    with zipfile.ZipFile(trace) as archive:
        assert archive.testzip() is None
        all_bytes = b''.join(archive.read(name) for name in archive.namelist())
        for value in [secret, 'unknown-cookie', 'another-session', 'unregistered-password', 'unknown-machine-secret']:
            assert value.encode() not in all_bytes
        result = json.loads(archive.read('test.network'))
        assert json.loads(result['request']['postData']['text'])['message'] == 'useful failure'
        assert json.loads(archive.read('test.trace'))['status'] == 'failed'
    assert secret not in (tmp_path / 'error-context.md').read_text()
    assert 'synthetic-session-cookie' not in (tmp_path / 'error-context.md').read_text()
    assert 'expected pending' in (tmp_path / 'error-context.md').read_text()


@pytest.mark.parametrize('redaction_fails', [False, True])
def test_failed_build_cleans_private_material_and_writes_cleanup(tmp_path, monkeypatch, redaction_fails):
    monkeypatch.setattr(env, 'ROOT', tmp_path)
    monkeypatch.setenv('JAVA_HOME', str(tmp_path / 'jdk'))
    monkeypatch.setenv('DB_TEST_PASSWORD', 'synthetic-db-secret')
    monkeypatch.setenv('RABBITMQ_IT_PASSWORD', 'synthetic-broker-secret')
    (tmp_path / 'jdk/bin').mkdir(parents=True)
    (tmp_path / 'jdk/bin/java').touch()
    monkeypatch.setattr(env.subprocess, 'run', lambda *a, **k: type('Version', (), {'stdout': 'version "25.0.2"', 'stderr': ''})())
    monkeypatch.setattr(env, 'Database', lambda: object())
    monkeypatch.setattr(env, 'Broker', lambda: type('Broker', (), {'drop': lambda self: None})())
    def fail(*_):
        raise RuntimeError('E2E_BUILD_FAILED_JAR')
    monkeypatch.setattr(env, 'build', fail)
    monkeypatch.setitem(sys.modules, 'e2e_fixtures', type('Fixtures', (), {'catalog': None}))
    if redaction_fails:
        def fail_redaction(*_):
            raise RuntimeError('SYNTHETIC_REDACTION_FAILURE')
        monkeypatch.setitem(sys.modules, 'e2e_redact', type('Redaction', (), {'redact_artifacts': fail_redaction}))
    else:
        monkeypatch.setitem(sys.modules, 'e2e_redact', redact)
    args = type('Args', (), {'skip_build': False})()
    with pytest.raises(RuntimeError, match='E2E_CLEANUP_INCOMPLETE' if redaction_fails else 'E2E_BUILD_FAILED_JAR'):
        env.run(args)
    run = next((tmp_path / '.cache/t1-e2e').iterdir())
    assert not (run / 'private').exists()
    cleanup = json.loads((run / 'cleanup.json').read_text())
    assert cleanup['redaction'] == (not redaction_fails)
    assert all(value for key, value in cleanup.items() if key != 'redaction')
    if redaction_fails:
        assert [path.name for path in run.iterdir()] == ['cleanup.json']
