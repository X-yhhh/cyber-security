"""整库超时贯穿查询/转储/在线快照/恢复；仅成功核验的恢复库可交给调用方。"""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts.p7 import j1_run
from scripts.p8 import backup_restore as cli
from scripts.p8.register_alert_only import Database
from scripts.demo import backup


@pytest.mark.parametrize('value', ['0', '-1', 'nan', '1.5', '', True, '１８００'])
def test_invalid_timeout_rejected_before_secret(monkeypatch, value):
    credential_lookup = Mock()
    monkeypatch.setattr(j1_run, 'secret', credential_lookup)
    with pytest.raises(ValueError, match='INVALID_DATABASE_TIMEOUT'):
        Database(Path('/fixture'), timeout_seconds=value)
    credential_lookup.assert_not_called()


def test_default_environment_and_explicit_precedence(monkeypatch):
    monkeypatch.delenv('CYBER_DB_TIMEOUT_SECONDS', raising=False)
    assert j1_run.database_timeout() == 300
    monkeypatch.setenv('CYBER_DB_TIMEOUT_SECONDS', '1800')
    monkeypatch.setattr(j1_run, 'secret', lambda _: 'fixture')
    db = Database(Path('/fixture'))
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout=b'1'))
    monkeypatch.setattr(j1_run.subprocess, 'run', run)
    assert db.query('SELECT 1') == b'1'
    assert run.call_args.kwargs['timeout'] == 1800
    assert Database(Path('/fixture'), 900).timeout_seconds == 900
    monkeypatch.setenv('CYBER_DB_TIMEOUT_SECONDS', 'invalid')
    with pytest.raises(ValueError):
        Database(Path('/fixture'))


@pytest.mark.parametrize('online', [False, True])
def test_dump_and_both_restore_files_use_configured_timeout(monkeypatch, tmp_path, online):
    monkeypatch.setattr(j1_run, 'secret', lambda _: 'fixture')
    db = Database(Path('/fixture'), 1800)
    db.query = Mock(return_value=b'')
    snapshot = {'contentSha256': 'fixture', 'tables': {}}
    db.snapshot = Mock(return_value=snapshot)
    def fidelity(_, file):
        file.write_text('fixture')
        return 0
    db.json_fidelity = fidelity
    run = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(j1_run.subprocess, 'run', run)
    if online:
        dump, patch = tmp_path / 'database.sql', tmp_path / 'json-double-fidelity.sql'
        dump.write_text('fixture'); patch.write_text('fixture')
        monkeypatch.setattr(backup, 'capture', lambda *_: (snapshot, dump, patch, 0))
        backup.backup_restore(db, 'source', 'cyber_r6_restore_' + 'a'*16, tmp_path)
    else:
        db.backup_restore('source', 'cyber_r6_restore_' + 'a'*16, tmp_path)
    assert len(run.call_args_list) == (2 if online else 3)
    assert all(c.kwargs['timeout'] == 1800 for c in run.call_args_list)
    assert json.loads((tmp_path / 'restore-proof.json').read_text())['passed']


def test_online_connection_read_timeout(monkeypatch, tmp_path):
    import pymysql
    connect = Mock(side_effect=RuntimeError('connection-sentinel'))
    monkeypatch.setattr(pymysql, 'connect', connect)
    with pytest.raises(RuntimeError, match='connection-sentinel'):
        backup.capture(SimpleNamespace(env={'MYSQL_PWD': 'fixture'}, timeout_seconds=1800), 'source', tmp_path)
    assert connect.call_args.kwargs['read_timeout'] == 1800


@pytest.mark.parametrize('keep,fail,deleted', [(False, False, True), (True, False, False), (True, True, True)])
def test_keep_restored_only_preserves_verified_schema(monkeypatch, tmp_path, keep, fail, deleted):
    class Fake:
        timeout_seconds = 1800
        owned_schema = None
        def query(self, _): return b'0'
        def backup_restore(self, source, target, folder):
            self.owned_schema = target
            if fail: raise RuntimeError('PARITY_FAILED')
            return {'contentSha256': 'fixture', 'tables': {}}, folder / 'database.sql'
        def drop_owned(self): self.owned_schema = None
    db = Fake()
    monkeypatch.setattr(cli, 'Database', lambda *a, **kw: db)
    args = SimpleNamespace(schedule=False, mysql_service=tmp_path, timeout_seconds=1800, keep_restored=keep)
    if fail:
        with pytest.raises(RuntimeError, match='PARITY_FAILED'): cli.main(args)
    else:
        cli.main(args)
    result = json.loads(next(tmp_path.rglob('result.json')).read_text())
    assert result['temporarySchemaDeleted'] is deleted
    assert result['passed'] is (not fail)
    assert result['restoredSchema'].startswith('cyber_r6_restore_')
    assert result['elapsedSeconds'] >= 0
    assert db.owned_schema == (None if deleted else result['restoredSchema'])


def test_cleanup_failure_still_records_owned_schema_and_failed_result(monkeypatch, tmp_path):
    db = SimpleNamespace(timeout_seconds=300, query=lambda _: b'0')
    def restore(source, target, folder):
        db.owned_schema = target
        return {'contentSha256': 'fixture', 'tables': {}}, folder / 'database.sql'
    db.backup_restore = restore
    db.drop_owned = Mock(side_effect=RuntimeError('CLEANUP_FAILED'))
    monkeypatch.setattr(cli, 'Database', lambda *a, **kw: db)
    with pytest.raises(RuntimeError, match='CLEANUP_FAILED'):
        cli.main(SimpleNamespace(schedule=False, mysql_service=tmp_path, timeout_seconds=None, keep_restored=False))
    result = json.loads(next(tmp_path.rglob('result.json')).read_text())
    assert result['passed'] is False
    assert result['temporarySchemaDeleted'] is False
    assert result['restoredSchema'] == db.owned_schema
    assert result['cleanupErrorType'] == 'RuntimeError'
