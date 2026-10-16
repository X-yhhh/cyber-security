"""R1 破坏性操作与迁移判断回归；使用替身，绝不连接业务库或运行防火墙。"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.p8 import rehearsal_runtime as runtime, status


@pytest.mark.parametrize('name', ['cyber_security', 'mysql', 'cyber_r1_clone_', 'cyber_r1_clone_'+'a'*32+';DROP DATABASE mysql'])
def test_rejects_non_owned_clone_before_database_call(name):
    with pytest.raises(ValueError, match='R1_CLONE_REQUIRED'):
        runtime.Clone(object(),name)


def test_existing_or_uncreated_schema_cannot_be_dropped():
    calls=[]
    clone=runtime.Clone(SimpleNamespace(query=lambda *a:calls.append(a)),'cyber_r1_clone_'+'a'*32)
    with pytest.raises(ValueError,match='R1_UNOWNED_SCHEMA'):
        clone.drop()
    assert calls==[]


def test_partial_clone_acquires_cleanup_only_after_owned_create(tmp_path):
    class DB:
        def backup_restore(self,source,target,folder):
            self.owned_schema=target
            raise RuntimeError('RESTORE_FAILED')
    clone=runtime.Clone(DB(),'cyber_r1_clone_'+'a'*32)
    with pytest.raises(RuntimeError,match='RESTORE_FAILED'):
        clone.create(tmp_path)
    assert clone.created


def test_modified_backup_refused_before_drop(tmp_path):
    calls=[]
    clone=runtime.Clone(SimpleNamespace(query=lambda *a:calls.append(a)),'cyber_r1_clone_'+'a'*32)
    clone.created=True
    (tmp_path/'restore-proof.json').write_text(json.dumps(dict(backupSha256='0'*64)))
    (tmp_path/'database.sql').write_text('changed')
    with pytest.raises(ValueError,match='R1_BACKUP_HASH_MISMATCH'):
        clone.restore(tmp_path)
    assert calls==[] and clone.created


def test_permission_baseline_is_loaded_from_current_design():
    roles=runtime.matrix(Path('docs/权限设计.md'))
    assert {key:len(value) for key,value in roles.items()}==dict(platform_admin=7,security_analyst=6,security_reviewer=10,
        model_operator=8,evidence_reviewer=4,auditor=6)
    assert 'authorization.approve' not in roles['platform_admin']
    assert 'feedback.review' not in roles['security_analyst']


def test_status_does_not_present_unknown_health_as_healthy():
    client=SimpleNamespace(call=lambda *a:dict(data=dict(status='UP')))
    process=SimpleNamespace(pid=123,poll=lambda:None)
    proof=dict(pid=123,profile='deploy',automation=False,webHosted=True)
    replay=dict(passed=True,fileReplay=True,liveCapture=False,observations=10,alerts=2,healthState='unknown')
    result=status.inspect_rehearsal(client,process,proof,replay)
    assert result['ok'] and result['captureHealth']=='unknown'
    assert result['launchd']=='not_installed' and result['pf']=='not_applicable'
    process.poll=lambda:1
    assert not status.inspect_rehearsal(client,process,proof,replay)['ok']


def test_cross_schema_queries_are_rejected():
    calls=[]
    clone=runtime.Clone(SimpleNamespace(query=lambda *a:calls.append(a)),'cyber_r1_clone_'+'a'*32)
    clone.created=True
    with pytest.raises(ValueError,match='R1_UNOWNED_SCHEMA'):
        clone.query('UPDATE sys_user SET status=0','cyber_security')
    assert calls==[]
