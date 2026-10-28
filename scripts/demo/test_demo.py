"""纯配置、协议替身、编排、证据与恢复序列回归；不启动靶服务、SSH、抓包或 PF。"""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import asyncio
import json
import sys
from unittest.mock import Mock, patch
import pytest
from scripts.demo import common, run, report, worker, remote, targets, backup, runtime, root_executor

BASE = Path(__file__).parent

def config():
    return common.load(BASE / 'demo.example.json', secret=False)


def rows():
    return common.scenes(BASE / 'scenes.json')


def ts(n):
    return datetime.fromtimestamp(n, timezone.utc).isoformat().replace('+00:00', 'Z')


def approval(c, selected, now=1000):
    return dict(runId='demo-20261017-1200-01', reference='test-approval', purpose='离线测试', operator='tester',
                validFrom=ts(now), validUntil=ts(now+1800), macAddress=c['macAddress'], peerAddress=c['peerAddress'],
                ports=c['ports'], scenes=[r['id'] for r in selected], scenesSha256=common.sha(BASE/'scenes.json'), mode='pf')


def test_dry_run_cannot_touch_network_secrets_or_files(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['run', '--config', str(BASE/'demo.example.json'), '--dry-run', '--pf'])
    with patch('subprocess.run', side_effect=AssertionError('subprocess')), patch('subprocess.Popen', side_effect=AssertionError('spawn')), patch.object(common, 'write', side_effect=AssertionError('write')), patch.object(run, 'write', side_effect=AssertionError('write')), patch.object(run, 'private', side_effect=AssertionError('private')):
        run.main()
    result=json.loads(capsys.readouterr().out)
    assert result['scenes']==['S0','S1','S2','S3','S4']
    assert result['writes'] is result['network'] is result['rootStarted'] is False


@pytest.mark.parametrize('mutate', [lambda c: c.update(peerAddress='8.8.8.8'),lambda c: c.update(peerAddress=c['macAddress']),
    lambda c: c['protection'].update(protectedServicePorts=[]), lambda c: c.update(ttlSeconds=61),
    lambda c: c.update(protectedPeers=['100.64.0.0/10']),lambda c:c['ports'].update(http=22)])
def test_scope_fail_closed(mutate):
    c=config();mutate(c)
    with pytest.raises(ValueError):common.validate(c,rows())


def test_grant_binds_exact_run_mode_scope_hash_and_window():
    c=config();r=rows();g=approval(c,r)
    assert common.grant(c,r,g,g['scenesSha256'],g['runId'],'pf',1000)==g
    for key,value in [('runId','demo-20261017-1200-02'),('mode','alert-only'),('scenesSha256','0'*64),('validUntil',ts(3000)),('validUntil',ts(1010)),('scenes',['S1']),('peerAddress','100.64.0.21')]:
        changed=deepcopy(g);changed[key]=value
        with pytest.raises(ValueError):common.grant(c,r,changed,g['scenesSha256'],g['runId'],'pf',1000)


def test_worker_reuses_scene_semantics(tmp_path):
    c=config();r=rows();r[0]['ports'].reverse()
    with pytest.raises(ValueError,match='NORMAL_LOGIN_SCOPE'):common.scene_ports(c['ports'],r)
    r=rows();r[1]['ports']=[c['ports']['ftp']]
    with pytest.raises(ValueError,match='SCENE_OUTSIDE'):common.scene_ports(c['ports'],r)


def test_private_json_rejects_duplicates_and_does_not_overwrite(tmp_path):
    f=tmp_path/'input.json';common.write(f,b'{"a":1,"a":2}')
    with pytest.raises(ValueError,match='DUPLICATE'):common.load(f)
    with pytest.raises(FileExistsError):common.write(f,{})
    common.write(f,{},replace=True);assert common.load(f)=={}
    f.chmod(0o644)
    with pytest.raises(ValueError,match='PRIVATE_MODE'):common.load(f)


def test_s0_has_exactly_one_synthetic_login_then_http():
    ftp=Mock();ftp.__enter__=Mock(return_value=ftp);ftp.__exit__=Mock(return_value=False)
    sock=Mock();sock.__enter__=Mock(return_value=sock);sock.__exit__=Mock(return_value=False)
    with patch.object(worker.Limiter,'acquire',side_effect=[True,True,False]),patch.object(worker.ftplib,'FTP',return_value=ftp):
        counts=worker.traffic('100.64.0.10',rows()[0],lambda:False,connector=Mock(return_value=sock))
    ftp.login.assert_called_once_with('demo','demo-test-only');ftp.connect.assert_called_once_with('100.64.0.10',55221,timeout=1)
    assert counts['completed']==2;sock.sendall.assert_called_once()


def test_nmap_has_fixed_bounded_arguments():
    command=worker.nmap_command('/approved/nmap','100.64.0.10',rows()[1])
    assert command[1:4]==['-sS','-n','-Pn'] and command[-1]=='100.64.0.10'
    assert '--max-rate' in command and '--host-timeout' in command and '--script' not in command


class Writer:
    def __init__(self):self.output=b'';self.closed=False
    def write(self,b):self.output+=b
    async def drain(self):pass
    def close(self):self.closed=True
    async def wait_closed(self):pass


def test_target_ftp_denies_file_access_and_http_bounds():
    async def exercise():
        reader=asyncio.StreamReader();reader.feed_data(b'USER demo\r\nPASS demo-test-only\r\nRETR private.txt\r\nQUIT\r\n');reader.feed_eof()
        w=Writer();await targets.ftp(reader,w)
        assert b'230 ' in w.output and b'502 ' in w.output and w.closed
        r=asyncio.StreamReader();r.feed_data(b'POST / HTTP/1.1\r\n\r\n');r.feed_eof()
        w=Writer();await targets.http(r,w);assert w.output==b'' and w.closed
    asyncio.run(exercise())


def test_backup_preserves_binary_text_json_and_null():
    sql=backup.insert_statement('test',[('text','varchar'),('payload','json'),('data','blob'),('optional','int')],['E4B8AD','7B7D','00FF',None])
    assert "CONVERT(UNHEX('E4B8AD') USING utf8mb4)" in sql
    assert "CONVERT(UNHEX('7B7D') USING utf8mb4)" in sql
    assert "UNHEX('00FF'),NULL" in sql
    with pytest.raises(ValueError):backup.insert_statement('test',[('a','text')],["');DROP TABLE test;"])
    with pytest.raises(ValueError):backup.insert_statement('test',[('a','text')],[])


def fixture_record():
    s=rows()[1]; state=dict(runId='demo-test',mode='pf',scenes=[s],completed=True,cleanup={k:True for k in common.CLEANUP},endedAt=ts(1250),baseline={'commit':'test'})
    facts=dict(decisions=[dict(id='d1',at=ts(1001),source='model',family='port_scan',decision='block_candidate')],
        commands=[dict(id='c1',decisionId='d1',at=ts(1001),blockUntil=ts(1061),scope='peer_inbound',state='expired',budgetTargetId='b1')],
        receipts=[dict(commandId='c1',status='applied',projected=True,at=ts(1002)),dict(commandId='c1',status='expired',projected=True,at=ts(1061))],
        budgetEvents=[dict(id='e1',targetId='b1',at=ts(1181),kind='reset')])
    w=dict(scenes=[dict(id='S1',startedAt=ts(1000),endedAt=ts(1015),finished=True)],finished=True,stopped=True)
    return state,facts,w


def test_report_requires_per_command_ttl_projected_receipts_and_reset():
    s,f,w=fixture_record();assert report.summarize(s,f,w)['passed']
    mutations=[lambda f:f['receipts'][0].update(projected=False),lambda f:f['commands'][0].update(blockUntil=ts(1062)),
        lambda f:f['budgetEvents'].clear(),lambda f:f['decisions'][0].update(source='rule'),lambda f:f['receipts'][1].update(at=ts(1200)),
        lambda f:f['commands'].append(dict(f['commands'][0],id='other',decisionId='absent'))]
    for mutate in mutations:
        bad=deepcopy(f);mutate(bad);assert not report.summarize(s,bad,w)['passed']
    bad=deepcopy(f);bad['commands'].append(dict(f['commands'][0],id='c2',budgetTargetId='b2'))
    bad['receipts'] += [dict(r,commandId='c2') for r in f['receipts']]
    assert not report.summarize(s,bad,w)['passed']


def test_s4_never_issues_commands_s3_degrades_and_compare_is_strict():
    s,f,w=fixture_record();a=report.summarize(s,f,w);b=deepcopy(a);b['runId']='demo-other'
    assert report.compare(a,b)['consistent'];b['baseline']={'commit':'changed'};assert not report.compare(a,b)['consistent']
    s['scenes']=[rows()[4]];w['scenes'][0]['id']='S4';f['decisions'][0]['family']='dos_flood'
    assert not report.summarize(s,f,w)['passed']
    s['scenes']=[rows()[3]];w['scenes'][0]['id']='S3';f={k:[] for k in f}
    assert report.summarize(s,f,w)['scenes'][0]['conclusion']=='降级'


def test_abnormal_teardown_revokes_first_and_continues_after_stop_failure(tmp_path):
    events=[];state=dict(runId='demo-test',startedAt=ts(1000),scenes=[],mode='pf',cleanup={},remoteRequested=True,en0={'same':True})
    def record(name,value=True):
        def op(*a):events.append(name);return value
        return op
    control=SimpleNamespace(revoke=record('revoke'),reset_state=lambda:dict(bindingSuspended=True,bundleActive=True,authorizationRevoked=True),recovered=lambda:False,facts=lambda *a:{k:[] for k in ('decisions','commands','receipts','budgetEvents')},applicant=None)
    rem=SimpleNamespace(marker=record('STOP'),stopped=lambda _:True,state=lambda _:None,close=record('close'))
    def stop(name):
        events.append(name)
        if name=='sensor':raise OSError('synthetic failure')
        return True
    runner=run.Runner({},tmp_path,state,control,rem,SimpleNamespace(stop=stop))
    with patch('scripts.demo.preflight.en0',return_value={'same':True}):result=runner.teardown(True)
    assert events[:3]==['revoke','STOP','sensor'] and 'targets' in events and 'observer-run' in events
    assert events.index('sensor') < events.index('close')
    assert result['cleanup']['captureStopped'] is False and not result['passed']
    assert 'bundle' not in events
    # 同一目录第二次清理，不覆盖事实，不跳过失败项。
    with patch('scripts.demo.preflight.en0',return_value={'same':True}):runner.teardown(True)
    assert events.count('revoke')==2


def test_teardown_only_closes_control_master_and_records_cleanup(tmp_path, monkeypatch, capsys):
    c=config();root=tmp_path/'demo-root';root.mkdir(mode=0o700);root.chmod(0o700)
    c['root']=str(root.resolve())
    common.write(tmp_path/'config.json',c)
    run_id='demo-20261028-1200-01';runs=root/'runs';runs.mkdir(mode=0o700)
    run_dir=runs/run_id;run_dir.mkdir(mode=0o700)
    locks=root/'locks';locks.mkdir(mode=0o700)
    common.write(root/'enrollment.json',{})
    state=dict(runId=run_id,config=c,enrollment={},mode='alert-only',scenes=[rows()[0]],
               cleanup={name:False for name in common.CLEANUP},completed=False,startedAt=ts(1000),en0={'same':True})
    common.write(run_dir/'state.json',state)
    events=[]

    class Control:
        def __init__(self,*_):self.applicant=None
        def revoke(self):events.append('revoke');return True
        def reset_state(self):return dict(bindingSuspended=True,bundleActive=True,authorizationRevoked=True)
        def recovered(self):return True
        def facts(self,*_):return {key:[] for key in ('decisions','commands','receipts','budgetEvents')}

    class Remote:
        def __init__(self,config,*,root):assert config==c['remote'] and root==c['root']
        def close(self):events.append('close');return True

    class Processes:
        def __init__(self,*_):pass
        def stop(self,name):events.append(name);return True

    monkeypatch.setattr(sys,'argv',['run','--config',str(tmp_path/'config.json'),'--teardown-only',run_id])
    monkeypatch.setattr(run.signal,'signal',lambda *_:None)
    with patch('scripts.demo.control.Control',Control),patch('scripts.demo.remote.Remote',Remote),\
         patch('scripts.demo.runtime.Processes',Processes),patch('scripts.demo.preflight.en0',return_value={'same':True}),\
         patch('scripts.demo.report.generate',return_value={'passed':True}):
        assert run.main()==0

    saved=common.load(run_dir/'state.json')
    assert events.index('sensor') < events.index('close')
    assert events.count('close')==1
    assert saved['cleanup']['controlMasterClosed'] is True
    assert json.loads(capsys.readouterr().out)['runId']==run_id


def test_cooling_requires_continuous_healthy_before_stopping_capture(tmp_path):
    clock=[0];seen=[]
    control=SimpleNamespace(healthy=lambda:clock[0]!=60,reset_state=lambda:{'noActiveActions':True},recovered=lambda:True)
    s=dict(grant={'validUntil':ts(9999999999)},cleanup={})
    proc=SimpleNamespace(alive=lambda:True)
    runner=run.Runner({},tmp_path,s,control,None,proc,clock=lambda:clock[0],sleep=lambda n:clock.__setitem__(0,clock[0]+n))
    runner.cool(240)
    assert clock[0]==181 and s['cleanup']['budgetRecovered']


def test_remote_transport_uses_private_control_master_options_for_every_ssh_call(tmp_path, monkeypatch):
    calls=[];control_envs=[]
    def execute(argv,**kwargs):
        calls.append(argv)
        if '-O' in argv:
            control_envs.append(kwargs.get('env'))
            return SimpleNamespace(returncode=1 if argv[argv.index('-O')+1]=='check' else 0,
                                   stdout=b'',stderr=b'')
        code=__import__('base64').b64decode(argv[-1]).decode('utf-16-le')
        return SimpleNamespace(returncode=0,stdout=b'1234567' if 'ToUnixTimeMilliseconds' in code else b'true')
    # 只放宽此测试中的路径长度约束，以便测试系统临时目录本身较长时仍能
    # 检查传输参数；独立测试覆盖生产限制。
    monkeypatch.setattr(remote.Remote,'CONTROL_PATH_LIMIT',512)
    r=remote.Remote(config()['remote'],execute=execute,root=tmp_path)
    opened_at=r.open()
    assert r.stopped('demo-20261017-1200-01')
    assert isinstance(opened_at,str) and opened_at.endswith('Z')
    lock_dir=tmp_path/'locks'
    assert lock_dir.stat().st_mode & 0o777 == 0o700
    code=__import__('base64').b64decode(calls[-1][-1]).decode('utf-16-le')
    assert '/runs/demo-20261017-1200-01/plan.json' in code and 'StartTime' in code and 'Stop-Process' not in code
    assert r.close() is True
    closed_calls=len(calls)
    assert r.close() is True and len(calls)==closed_calls
    required={'BatchMode=yes','ConnectTimeout=5','ControlMaster=auto','ControlPath='+r.control_path,
              'ControlPersist=yes','ServerAliveInterval=5','ServerAliveCountMax=3'}
    for argv in calls:
        options={argv[i+1] for i,value in enumerate(argv[:-1]) if value=='-o'}
        assert required <= options
    expected_env={**remote.os.environ,'LC_ALL':'C'}
    assert control_envs and all(env==expected_env for env in control_envs)
    with pytest.raises(ValueError):r.directory('../other')
    with pytest.raises(ValueError):r.marker('demo-20261017-1200-01','GO-UNKNOWN')


def test_remote_control_path_longer_than_one_hundred_bytes_is_rejected(tmp_path):
    long_root=tmp_path/('r'*80);long_root.mkdir(mode=0o700)
    calls=[]
    def execute(argv,**kwargs):
        calls.append(argv);return SimpleNamespace(returncode=0,stdout=b'1')
    with pytest.raises(ValueError,match='CONTROL_PATH_TOO_LONG'):
        remote.Remote(config()['remote'],execute=execute,root=long_root)
    assert calls==[]


@pytest.mark.parametrize('fail', [False,True], ids=['success','failure'])
def test_prepare_install_worker_configures_control_path_and_closes(tmp_path, monkeypatch, capsys, fail):
    from scripts.demo import prepare

    c=config();root=tmp_path/'private-root';root.mkdir(mode=0o700);root.chmod(0o700);c['root']=str(root.resolve())
    actual_remote=remote.Remote;constructed=[];installed=[];calls=[]
    def execute(argv,**kwargs):
        calls.append((argv,kwargs))
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
    def construct(remote_config,*args,**kwargs):
        constructed.append((remote_config,args,kwargs))
        return actual_remote(remote_config,execute=execute,*args,**kwargs)
    def install(self,config):
        installed.append((self.control_path,config['root']))
        if fail:raise RuntimeError('synthetic install failure')
        return 'allowlist-sha256'

    monkeypatch.setattr(actual_remote,'CONTROL_PATH_LIMIT',512)
    monkeypatch.setattr(actual_remote,'_install',install)
    monkeypatch.setattr(remote,'Remote',construct)
    monkeypatch.setattr(prepare,'validate',lambda value,_:value)
    monkeypatch.setattr(prepare,'load',Mock(side_effect=[c,{}]))
    monkeypatch.setattr(prepare,'approve',lambda *_:None)
    monkeypatch.setattr(sys,'argv',['prepare','--config',str(tmp_path/'config.json'),'--operation','install-worker',
                                   '--approval',str(tmp_path/'approval.json'),'--execute'])

    if fail:
        with pytest.raises(RuntimeError,match='synthetic install failure'):
            prepare.main()
    else:
        prepare.main()
        assert json.loads(capsys.readouterr().out)['allowlistSha256']=='allowlist-sha256'

    assert constructed==[(c['remote'],(),{})]
    assert installed==[(str(root/'locks'/'ssh-%C'),c['root'])]
    exits=[(argv,kwargs) for argv,kwargs in calls if '-O' in argv and argv[argv.index('-O')+1]=='exit']
    assert len(exits)==1 and exits[0][1]['env']=={**remote.os.environ,'LC_ALL':'C'}


def test_root_boundary_rejects_management_ports_and_changed_identity():
    c=config();b={k:c[k] for k in ('macAddress','peerAddress','ports','protection','protectedPeers','bundleId')}
    b.update({k:'00000000-0000-4000-8000-000000000001' for k in ('assetId','executorId','sensorId','captureScopeId')})
    b.update(budgetKeySha256='a'*64,subjectSha256='b'*64)
    assert root_executor.validate_boundary(b)==b
    b=deepcopy(b);b['ports']['http']=18082
    with pytest.raises(ValueError):root_executor.validate_boundary(b)


def test_generated_runtime_configs_retain_stable_identity_and_real_schemas(tmp_path):
    from scripts.p8.observer_executor import configuration
    from executor.pki import create
    import uuid
    c=config();c['root']=str(tmp_path.resolve());stable=tmp_path/'config';stable.mkdir(mode=0o700)
    create(stable/'ipc')
    for name,content in [('peer.key',b'p'*32),('budget.key',b'b'*32),('sensor.credential',b'synthetic-test'),('executor.credential',b'synthetic-test')]:common.write(stable/name,content)
    c['backendCA']=str(stable/'ipc/ca.pem');c['commandTrust']=str(tmp_path/'command-trust.json');common.write(c['commandTrust'],{'test':{'status':'active'}})
    ids={k:str(uuid.uuid4()) for k in ('assetId','sensorId','executorId','captureScopeId')}
    now=__import__('time').time();g=approval(c,rows(),now);auth=dict(id=str(uuid.uuid4()),revision=2,status='active',validFrom=g['validFrom'],validUntil=g['validUntil'])
    c['capabilities']=[{'id':str(uuid.uuid4()),'payload':{'scope':'peer_inbound'}}]
    generated=[]
    for n in (1,2):
        d=tmp_path/str(n);d.mkdir(mode=0o700)
        data,resolver=runtime.configurations(c,ids,g,auth,'utun9',d,{'subject':{'policySha256':'a'*64}},rows())
        assert data['budgetKey']==__import__('base64').b64encode(b'b'*32).decode()
        assert configuration(d/'observer.json')['capabilityIds']==[]
        assert common.load(d/'sensor.json')['environment']=='lab'
        assert common.load(d/'target-service.json')['ssh'] is False
        assert resolver['scope']['ExecutorCertSHA256']!=resolver['scope']['CollectorCertSHA256']
        generated.append((data,resolver,common.load(d/'sensor.json')))
    assert generated[0][1]['registration']['allowed']==generated[1][1]['registration']['allowed']
    assert generated[0][2]['bootId']!=generated[1][2]['bootId']
    assert generated[0][2]['secretFile']==generated[1][2]['secretFile']


def test_execute_orders_preflight_backup_authorization_capture_then_traffic(tmp_path):
    events=[];c=config();g=approval(c,[rows()[0]],__import__('time').time());state=dict(runId=g['runId'],enrollment={},grant=g,mode='alert-only',scenes=[rows()[0]],cleanup={})
    (tmp_path/'root').mkdir(mode=0o700);common.write(tmp_path/'scenes.json',{'test':True})
    def call(name,result):
        def op(*args):events.append(name);return result
        return op
    class Processes:
        def start(self,name,argv):
            events.append(name)
            if name=='targets':common.write(tmp_path/'targets-ready.json',{})
        def alive(self):return True
    def start_root(*a):
        events.append('root');common.write(tmp_path/'root/ready.json',{'passed':True});return Mock(poll=lambda:None)
    control=SimpleNamespace(backup=call('backup',{'passed':True}),authorize=call('authorize',{'id':'test'}),bundle=lambda:{},healthy=lambda:True,recovered=lambda:True)
    w=dict(scenes=[dict(id='S0',finished=True,endedAt=ts(1000))],finished=True,stopped=True)
    rem=SimpleNamespace(open=call('open',ts(999)),start=call('traffic',{}),state=lambda _:w)
    runner=run.Runner(c,tmp_path,state,control,rem,Processes());runner.cool=call('cool',True)
    with patch('scripts.demo.preflight.inspect',side_effect=call('preflight',{'interface':'utun9','allowlistSha256':'a'})),patch('scripts.demo.runtime.start_root',side_effect=start_root),patch('scripts.demo.runtime.configurations',return_value=({},{})):
        runner.execute()
    assert events==['open','preflight','root','backup','authorize','targets','observer-recovery','observer-run','sensor','traffic','cool']
    assert state['controlMaster']['openedAt']==ts(999)
    assert state['completed']


def test_revoke_reuses_exact_journal_without_suspending_bundle(tmp_path):
    from scripts.demo.control import Control
    control=Control.__new__(Control);control.asset='00000000-0000-4000-8000-000000000001'
    aid='00000000-0000-4000-8000-000000000002'
    control.journal=SimpleNamespace(data={'steps':{'authorization':{'result':{'id':aid}}}},step=Mock())
    control.reviewer=Mock();control.reviewer.request.side_effect=[{'assetId':control.asset,'status':'active','revision':2},{'status':'revoked'}]
    assert control.revoke()
    args=control.journal.step.call_args.args
    assert args[2]=='/authorizations/'+aid+'/revocations'
    assert all('release-bundles' not in str(c) for c in control.reviewer.mock_calls)


@pytest.mark.parametrize('version', ['host-guard-decision/2026-10-08.1', 'host-guard-decision/2026-10-08.1+demo-budget-20261017'])
def test_bundle_requires_explicit_versioned_demo_recovery(version):
    from scripts.demo.control import Control
    from executor.common import digest
    control=Control.__new__(Control);control.c=config()
    subject={'policyId':control.c['bundleId'],'capabilityIds':[cap['id'] for cap in control.c['capabilities']]}
    control.c['subjectSha256']=digest(subject);control.rows=Mock(return_value=[subject])
    control.applicant=Mock();control.applicant.request.side_effect=[
        {'subjectSha256':digest(subject),'environment':'lab','status':'approved'},
        {'definition':{'policyVersion':version,'mode':'auto','maxTtlSeconds':60,'maxContinuousBlockSeconds':120,
                       'familyPolicies':[{'family':'dos_flood','autoEligible':False,'modelAutoEligible':False}]}}]
    with patch('scripts.p7.import_bundle.verify_capability'):
        if version.endswith('+demo-budget-20261017'):
            assert control.bundle()['subject']==subject
        else:
            with pytest.raises(ValueError,match='DEMO_RECOVERY_POLICY_REQUIRED'):control.bundle()


def test_backup_float_uses_exact_wkb_instead_of_rounded_decimal():
    sql=backup.insert_statement('t',[('f','float'),('d','double'),('b','bit')],['00AB','01CD','FF'])
    assert sql.count('ST_X(ST_GeomFromWKB(')==2
    assert "CAST(CONV('FF',16,10) AS UNSIGNED)" in sql


def test_snapshot_query_stays_in_outer_readonly_transaction():
    cursor=Mock();cursor.__enter__=Mock(return_value=cursor);cursor.__exit__=Mock(return_value=False)
    cursor.description=True;cursor.fetchall.return_value=[('t',123,None)];cursor.nextset.return_value=False
    connection=Mock();connection.cursor.return_value=cursor
    view=backup.TransactionView(connection,'test')
    raw=view.query("SET time_zone='+00:00';SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;START TRANSACTION WITH CONSISTENT SNAPSHOT;SELECT 1;COMMIT;",'test')
    assert cursor.execute.call_args.args[0]=='SELECT 1;'
    assert raw==b't\t123\tNULL\n';connection.commit.assert_not_called()
    with pytest.raises(ValueError):view.query('SELECT 1','other')


def test_preparation_plan_is_standalone_and_side_effect_free(monkeypatch,capsys):
    from scripts.demo import prepare
    monkeypatch.setattr(sys,'argv',['prepare','--config',str(BASE/'demo.example.json'),'--operation','enroll'])
    with patch('subprocess.run',side_effect=AssertionError('network')),patch.object(prepare,'enroll',side_effect=AssertionError('write')):
        prepare.main()
    assert json.loads(capsys.readouterr().out)['writes'] is False
