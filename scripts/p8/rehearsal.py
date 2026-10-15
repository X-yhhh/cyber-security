#!/usr/bin/env python3
"""W3-R1：业务库只读快照 → deploy 克隆 → 文件回放 → T1 子克隆 → 整库回退。

只允许本机 MySQL 与独立 vhost；不会安装 launchd、打开抓包接口、领取命令或调用 PF。
两轮 T1 保持原来的合成模式，绝不在 deploy 中打开自动化。报告通过不代表 A23 部署。
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(Path(__file__).parent)]
from scripts.p8 import e2e_env, enroll, launchd, status
from scripts.p8.register_alert_only import Database
from scripts.p8.rehearsal_runtime import Clone, deploy, migration_check, migration_version, permissions
from scripts.p8.toolkit import Human, absolute, private_dir, require, safe_main, sha, write
from executor import pki


def progress(step):
    print(json.dumps(dict(stage=step), ensure_ascii=False), flush=True)


def account_fingerprint(db, schema):
    return hashlib.sha256(db.query('SELECT id,user_key,username,password_hash,status FROM sys_user ORDER BY id', schema)).hexdigest()


def enrollment(args, clone, work, base, context, accounts, service):
    """复用 B3 只告警登记原函数；R1 编排器是克隆的唯一所有者，不接收任意服务 URL。"""
    applicant = Human(base, context).login(accounts['admin'])
    reviewer = Human(base, context).login(accounts['reviewer'])
    bundle = applicant.request('GET', '/release-bundles/' + enroll.R6)
    now = datetime.now(timezone.utc)
    plan = dict(root=str(service), bundleId=enroll.R6, subjectSha256=bundle['subjectSha256'],
        profileSha256=bundle['subject']['featureProfileSha256'], guardliveBinary=str(args.release / 'guardlive'),
        applicant=dict(username=accounts['admin']['username']), reviewer=dict(username=accounts['reviewer']['username']),
        interface='lo0', localAddresses=['127.0.0.1'], validFrom=(now-timedelta(minutes=1)).isoformat(),
        validUntil=(now+timedelta(hours=2)).isoformat(), evidenceRef='R1:clone-only:' + work.name,
        assetKey='r1-enroll-'+uuid.uuid4().hex, owner='R1 clone rehearsal', approvalReason='R1 克隆登记，只告警，无执行范围',
        targetPort=e2e_env.free_port())
    tls = dict(caFile=str(work / 'tls/ca.pem'), certificateFile=str(work / 'tls/collector.pem'), keyFile=str(work / 'tls/collector.key'))
    result = enroll.enroll(plan, work / 'enrollment', applicant, reviewer, base=base, backend_tls=tls)
    require(result['captureStarted'] is False and result['executorMode'] == 'alert_only', 'R1_ENROLLMENT_BOUNDARY')
    write(work / 'enrollment.json', dict(target='clone', **result))
    return applicant, reviewer, result


def pcap(path):
    """生成仅供文件读取的回环 SYN 场景；没有 socket send、驱动或真实攻击流量。"""
    with path.open('xb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        for i in range(200):
            packet = bytearray(40)
            packet[0], packet[8], packet[9] = 0x45, 64, 6
            struct.pack_into('!H', packet, 2, 40)
            packet[12:16] = socket.inet_aton('127.0.0.2')
            packet[16:20] = socket.inet_aton('127.0.0.1')
            struct.pack_into('!HHII', packet, 20, 40000+i, 10000+i, i+1, 0)
            packet[32], packet[33] = 0x50, 0x02
            struct.pack_into('!H', packet, 34, 65535)
            micros = i * 100000
            stream.write(struct.pack('<IIII', 1600000000+micros//1000000, micros%1000000, 40, 40))
            stream.write(packet)


def replay(args, clone, work, base, context, applicant, reviewer, accounts, service):
    """研究资产绑定既有获批只告警组合，使用真实 Go/模型/队列；不改 r6 的 authorized 环境。"""
    def post(client, path, body, *, revision=None):
        # 每个写请求都有独立幂等键；失败即整轮停止，不在未知结果下重复创建资源。
        return client.request('POST', path, body, key=str(uuid.uuid4()), revision=revision)
    records = clone.query("SELECT public_id FROM guard_release_bundle WHERE environment='research' AND status='approved' ORDER BY id DESC").splitlines()
    require(records, 'R1_APPROVED_RESEARCH_BUNDLE_REQUIRED')
    bundle = applicant.request('GET', '/release-bundles/' + records[0])
    asset = post(applicant, '/assets', dict(assetKey='r1-replay-'+uuid.uuid4().hex, platform='macos', environment='research', owner='R1 file-only replay'))
    at = datetime.now(timezone.utc)
    until = (at+timedelta(hours=1)).isoformat().replace('+00:00', 'Z')
    auth = post(applicant, '/assets/'+asset['id']+'/authorizations', dict(interfaces=['lo0'], observationAllowed=True, executionScopes=[],
        validFrom=(at-timedelta(minutes=1)).isoformat().replace('+00:00', 'Z'), validUntil=until, evidenceRef='R1:generated-loopback-pcap'))
    post(reviewer, '/authorizations/'+auth['id']+'/decisions', dict(decision='approve', reason='R1 只读文件回放'), revision=auth['revision'])
    scope, boot = str(uuid.uuid4()), str(uuid.uuid4())
    sensor = post(applicant, '/sensors', dict(assetId=asset['id'],platform='macos',captureScopeId=scope))
    cfg = dict(contractVersion='host-guard/5.0.0-rc.2', profileSha256=bundle['subject']['featureProfileSha256'],
        captureHealthVersion='host-guard-capture-health/1.0.0', interfaceIds=['lo0'], limits=dict(maxBatchSize=100),
        captureScopeId=scope, addressFamily='ipv4', buildSha256=sha(args.release / 'guardlive'))
    remote = post(applicant, '/sensors/'+sensor['id']+'/configs', cfg)
    post(reviewer, '/sensor-configs/'+remote['id']+'/decisions', dict(decision='approve',reason='R1 Go 制品与捕获域校验'), revision=remote['revision'])
    post(reviewer, '/release-bundles/'+bundle['id']+'/activations', dict(assetIds=[asset['id']],authorizationIds=[auth['id']]), revision=bundle['revision'])
    folder = private_dir(work / 'replay')
    write(folder / 'credential', sensor['credential'].encode())
    write(folder / 'peer.key', secrets.token_bytes(32))
    ipc = service / 'config/ipc'
    config = dict(assetId=asset['id'],sensorId=sensor['id'],bootId=boot,captureScopeId=scope,environment='research',
        captureScope='all_inbound_tcp',localAddresses=['127.0.0.1'],secretFile=str(folder / 'peer.key'),keyEpoch=1,
        interface='lo0',allowedInterfaces=['lo0'],authorizedUntil=until,
        upload=dict(baseUrl=base,caFile=str(work / 'tls/ca.pem'),certificateFile=str(ipc / 'collector.pem'),keyFile=str(ipc / 'collector.key'),
            credentialFile=str(folder / 'credential'),spoolDir=str(folder / 'spool'),healthWindowMs=1000))
    write(folder / 'sensor.json', config)
    pcap(folder / 'loopback.pcap')
    analyst = Human(base, context).login(accounts['analyst'])
    before = analyst.request('GET','/stats/live?range=15m&step=10')
    command = [str(args.release / 'guardlive'), '-config',str(folder / 'sensor.json'), '-pcap',str(folder / 'loopback.pcap'),
        '-out',str(folder / 'observations.jsonl'), '-report',str(folder / 'sensor-report.json'), '-duration','40s']
    with (folder / 'sensor.log').open('xb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=130)
    require(result.returncode == 0, 'R1_REPLAY_FAILED')
    for _ in range(60):
        count = int(clone.query("SELECT COUNT(*) FROM guard_observation o JOIN asset a ON a.id=o.asset_id WHERE a.public_id='"+asset['id']+"'"))
        alerts = int(clone.query("SELECT COUNT(*) FROM guard_decision d JOIN asset a ON a.id=d.asset_id WHERE a.public_id='"+asset['id']+"' AND d.decision IN ('alert','block_candidate')"))
        if count and alerts:
            break
        time.sleep(.5)
    require(count > 0 and alerts > 0, 'R1_OBSERVATION_OR_ALERT_MISSING')
    inference = {}
    for row in clone.query("SELECT i.status,COUNT(*) FROM guard_inference i JOIN asset a ON a.id=i.asset_id WHERE a.public_id='"+asset['id']+"' GROUP BY i.status").splitlines():
        state, number = row.split('\t')
        inference[state] = int(number)
    require(inference.get('succeeded', 0) > 0, 'R1_MODEL_INFERENCE_MISSING')
    after = analyst.request('GET','/stats/live?range=15m&step=10')
    require(after['today']['inbound'] > before['today']['inbound'] and after['today']['alerts'] > before['today']['alerts'], 'R1_LIVE_STATS_UNCHANGED')
    require(any(v and v>0 for v in after['inbound']), 'R1_LIVE_SERIES_EMPTY')
    windows = applicant.request('GET','/health-windows?assetId='+asset['id']+'&limit=1')['items']
    require(windows, 'R1_HEALTH_WINDOW_MISSING')
    proof = dict(passed=True,assetId=asset['id'],sensorId=sensor['id'],observations=count,alerts=alerts,
        bundleId=bundle['id'],subjectSha256=bundle['subjectSha256'],inference=inference,
        pcapSha256=sha(folder / 'loopback.pcap'),sensorSha256=sha(args.release / 'guardlive'),fileReplay=True,
        liveCapture=False,packetsInjected=0,healthState=windows[0]['healthState'],
        liveStatsBefore=before['today'],liveStatsAfter=after['today'],inboundSeries=after['inbound'])
    write(work / 'replay.json',proof)
    return proof


def run(args):
    os.umask(0o077)
    # 在读取大体积快照前检查已声明依赖；缺少依赖不得留下半轮预演。
    import bcrypt
    import cryptography
    import rfc8785
    for key in ('release','previous_jar','java','artifacts','trust','mysql_service','work'):
        setattr(args,key,absolute(getattr(args,key)))
    require(not args.work.exists(),'R1_NEW_WORK_REQUIRED')
    launchd.verify_release(args.release)
    require(migration_version(args.release / 'backend.jar')==27 and migration_version(args.previous_jar)==25,'R1_JAR_VERSION_MISMATCH')
    version=subprocess.run([str(args.java),'-version'],capture_output=True,text=True,check=True)
    require('version "25.' in version.stderr,'R1_JDK25_REQUIRED')
    os.environ['JAVA_HOME']=str(args.java.parent.parent)
    db=Database(args.mysql_service)
    require(int(db.query("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE DB='cyber_security' AND ID<>CONNECTION_ID()"))==0,'R1_SOURCE_IN_USE')
    require(db.query('SELECT MAX(CAST(version AS UNSIGNED)) FROM flyway_schema_history WHERE success=1','cyber_security').strip()==b'25','R1_SOURCE_V25_REQUIRED')
    work=private_dir(args.work)
    clone=Clone(db,'cyber_r1_clone_'+uuid.uuid4().hex)
    broker=e2e_env.Broker()
    before=None
    broker_created=False
    report=dict(passed=False,source='cyber_security',schema=clone.name,vhost=broker.name,releaseCommit=json.loads((args.release/'release.json').read_bytes())['commit'],
        jarSha256=sha(args.release/'backend.jar'),previousJarSha256=sha(args.previous_jar),realCapture=False,pfExecuted=False,serviceInstalled=False)
    try:
        progress('snapshot')
        backup=private_dir(work/'backup')
        before,_=clone.create(backup)
        report['sourceBeforeSha256']=before['contentSha256']
        original_accounts=account_fingerprint(db,clone.name)
        runtime_permissions=permissions(db,clone.name,args.runtime_user)
        artifacts=private_dir(work/'artifacts')
        for folder in ('packages','reports'):
            shutil.copytree(args.artifacts/folder,artifacts/folder)
        for p in artifacts.rglob('*'):
            p.chmod(0o700 if p.is_dir() else 0o600)
        pki.create(work/'tls')
        service=private_dir(work/'service')
        private_dir(service/'config')
        pki.create(service/'config/ipc')
        broker_created=True
        broker.create()
        progress('deploy-migration')
        with deploy(args,clone,work/'deploy',artifacts,broker,work/'tls',service/'config/ipc') as (base,context,process,proof):
            report['migration']=migration_check(clone,runtime_permissions,args.runtime_user)
            require(account_fingerprint(db,clone.name)==original_accounts,'R1_ACCOUNT_IDENTITY_CHANGED')
            require(int(clone.query("SELECT COUNT(*) FROM audit_log WHERE action='guard.deploy.startup'"))>0,'R1_STARTUP_AUDIT_MISSING')
            command_baseline=int(clone.query('SELECT COALESCE(MAX(id),0) FROM guard_command'))
            accounts=e2e_env.seed_accounts(clone,clone.name,prefix='r1-')
            progress('enrollment-and-replay')
            applicant,reviewer,enrolled=enrollment(args,clone,work,base,context,accounts,service)
            report['enrollment']=dict(passed=True,assetId=enrolled['assetId'],executorMode='alert_only')
            report['replay']=replay(args,clone,work,base,context,applicant,reviewer,accounts,service)
            report['status']=status.inspect_rehearsal(applicant,process,proof,report['replay'])
            write(work/'status.json',report['status'])
            require(report['status']['ok'],'R1_STATUS_FAILED')
            require(clone.query('SELECT COUNT(*) FROM guard_command WHERE id>'+str(command_baseline))=='0','R1_UNEXPECTED_COMMAND')
            report['issuedCommands']=0
        report['deploy']=proof
        # deploy 的自动化门保持关闭；T1 在同版 JAR/dist 的子克隆验证合成 UI 流程。
        progress('t1-clone-regression')
        report['t1']=[]
        for number in (1,2):
            context=dict(schema=clone.name,mysql_service=str(args.mysql_service),artifacts=str(artifacts),release=str(args.release),work=str(work/f't1-{number}'))
            require(e2e_env.run(argparse.Namespace(skip_build=True,playwright=[]),rehearsal=context)==0,'R1_T1_FAILED')
            results=json.loads((work/f't1-{number}'/'results.json').read_bytes())
            report['t1'].append(results['stats'])
            require(results['stats']['expected']==16 and results['stats']['unexpected']==0 and results['stats']['skipped']==0 and results['stats']['flaky']==0,'R1_T1_INCOMPLETE')
        progress('restore-and-previous-jar')
        restored=clone.restore(backup)
        report['rollback']=dict(restoredSha256=restored['contentSha256'],exactBeforeStartup=True)
        with deploy(args,clone,work/'rollback',artifacts,broker,work/'tls',service/'config/ipc',jar=args.previous_jar) as (_,_,_,old):
            require(clone.query('SELECT MAX(CAST(version AS UNSIGNED)) FROM flyway_schema_history WHERE success=1')=='25','R1_ROLLBACK_VERSION_CHANGED')
            require(account_fingerprint(db,clone.name)==original_accounts,'R1_ROLLBACK_ACCOUNTS_CHANGED')
            report['rollback'].update(health=old['health'],version=25)
        report['rollback']['process']=old
        launchd.verify_release(args.release)
        require(sha(args.previous_jar)==report['previousJarSha256'],'R1_PREVIOUS_JAR_CHANGED')
        report['releaseUnchanged']=True
        report['passed']=True
    except Exception as error:
        # 错误正文可能包含 HTTP/SQL 数据，报告只记录稳定短错误码。
        report['error']=str(error) if re.fullmatch('[A-Z0-9_]+',str(error)) else type(error).__name__
        raise
    finally:
        cleanup={}
        for key,operation in [('schema',lambda: clone.drop() if clone.created else None),('vhost',lambda: broker.drop() if broker_created else None)]:
            try:
                operation();cleanup[key]=True
            except Exception:
                cleanup[key]=False
        cleanup['businessUnchanged']=False
        if before:
            try:
                current=db.snapshot('cyber_security')
                report['sourceAfterSha256']=current['contentSha256']
                cleanup['businessUnchanged']=current==before
            except Exception:
                # 数据库不可读时仍保留本轮失败与清理报告，不把未核验的源库写成未变。
                report['sourceVerificationError']='R1_SOURCE_SNAPSHOT_FAILED'
        report['cleanup']=cleanup
        report['passed']=report['passed'] and all(cleanup.values())
        write(work/'result.json',report)
        # 清单仅包含本轮已有输出；它自身不循环进入摘要，秘密材料只保留私有目录。
        files=[p for p in work.rglob('*') if p.is_file()]
        write(work/'SHA256SUMS',''.join(f'{sha(p)}  {p.relative_to(work)}\n' for p in sorted(files)).encode())
        print(json.dumps(dict(passed=report['passed'],report=str(work/'result.json'),cleanup=cleanup)),flush=True)
    require(report['passed'],'R1_FAILED')


def main():
    def cancelled(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,cancelled)
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('release','previous-jar','java','artifacts','trust','mysql-service','work'):
        parser.add_argument('--'+key,required=True,type=Path)
    parser.add_argument('--runtime-user',action='append',required=True,help='三个已有运行账号，逐个传入；只核对，不改绑')
    run(parser.parse_args())


if __name__=='__main__':
    raise SystemExit(safe_main(main))
