#!/usr/bin/env python3
"""按 v2 接口登记只告警真实主机；默认仅对本进程启动的隔离克隆验证，不打开采集接口。"""
from contextlib import contextmanager
from datetime import datetime, timezone
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.toolkit import Journal, Human, absolute, load, private_dir, private_file, require, safe_main, sha, write
from executor import pki

R6 = 'aa35ae6e-3b41-461d-8b54-cb4bb4726349'


def validate(plan):
    require(plan['bundleId'] == R6 and re.fullmatch('[0-9a-f]{64}', plan['subjectSha256']), 'R6_BINDING_REQUIRED')
    require(plan['applicant']['username'] != plan['reviewer']['username'], 'INDEPENDENT_REVIEWER_REQUIRED')
    require(re.fullmatch('[A-Za-z0-9_.:-]{1,96}', plan['interface']), 'INTERFACE_REQUIRED')
    addresses = [ipaddress.ip_address(v) for v in plan['localAddresses']]
    require(addresses and len({v.version for v in addresses}) == 1 and all(not (v.is_unspecified or v.is_multicast) for v in addresses), 'LOCAL_ADDRESSES_REQUIRED')
    start, end = (datetime.fromisoformat(plan[k].replace('Z', '+00:00')) for k in ('validFrom', 'validUntil'))
    require(start.tzinfo and end.tzinfo and start < end and end > datetime.now(timezone.utc), 'AUTHORIZATION_EXPIRED')
    plan['validFrom'] = start.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    plan['validUntil'] = end.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    require(plan.get('evidenceRef') and re.fullmatch('[0-9a-f]{64}', plan['profileSha256']), 'AUTHORIZATION_PLAN_REQUIRED')
    absolute(plan['root'])
    require(absolute(plan['guardliveBinary']).is_file(), 'GUARDLIVE_BUILD_REQUIRED')


def same_file(path, value):
    if path.exists():
        require(private_file(path).read_bytes() == value, 'GENERATED_FILE_CHANGED')
    else:
        write(path, value)


def configs(plan, journal, bundle, authorization, base, backend_tls):
    """配置引用一次性凭据和独立 mTLS 身份；真实接入不登记任何执行许可。"""
    root = private_dir(plan['root'])
    config = private_dir(root / 'config')
    for folder in ('ledger', 'logs', 'ledger/executor', 'ledger/sensor'):
        private_dir(root / folder)
    steps = journal.data['steps']
    asset, sensor, executor = [steps[k]['result']['id'] for k in ('asset', 'sensor', 'executor')]
    for name in ('sensor', 'executor'):
        same_file(config / (name + '.credential'), steps[name]['result']['credential'].encode())
    ipc = config / 'ipc'
    if not ipc.exists():
        # 原子发布整个 PKI 目录，中断只留下可辨别的未完成目录，不能混用新旧证书。
        temporary = config / ('ipc-' + uuid.uuid4().hex)
        pki.create(temporary)
        temporary.rename(ipc)
    fingerprints = load(ipc / 'fingerprints.json')
    for name in ('peer.key', 'budget.key'):
        if not (config / name).exists():
            write(config / name, os.urandom(32))
    sensor_config = dict(assetId=asset, sensorId=sensor, bootId=journal.data['bootId'], captureScopeId=journal.data['scopeId'],
        environment='authorized', captureScope='all_inbound_tcp', localAddresses=plan['localAddresses'],
        secretFile=str(config / 'peer.key'), keyEpoch=1, interface=plan['interface'], allowedInterfaces=[plan['interface']],
        authorizedUntil=plan['validUntil'], upload=dict(baseUrl=base, caFile=backend_tls['caFile'],
            certificateFile=str(ipc / 'collector.pem'), keyFile=str(ipc / 'collector.key'),
            credentialFile=str(config / 'sensor.credential'), spoolDir=str(root / 'ledger/sensor' / journal.data['bootId']), healthWindowMs=1000))
    write(config / 'sensor.json', sensor_config, replace=(config / 'sensor.json').exists())
    # 登记身份不授予 PF 能力。观察模式配置由 p8/observer_executor.py 消费，只发心跳，不加载 PF 适配器。
    observer = dict(mode='alert_only', assetId=asset, executorId=executor, authorizationId=authorization['id'],
        validUntil=plan['validUntil'], baseUrl=base, credentialFile=str(config / 'executor.credential'),
        caFile=backend_tls['caFile'], certificateFile=str(ipc / 'executor.pem'), keyFile=str(ipc / 'executor.key'),
        stateDir=str(root / 'ledger/executor'), capabilityIds=[], bundleIds=[bundle['id']])
    write(config / 'executor-observer.json', observer, replace=(config / 'executor-observer.json').exists())
    same_file(config / 'machine-tls.properties', ('DEPLOY_TLS_CLIENT_CA=' + str(ipc / 'ca.pem') + '\n').encode())
    targets = dict(listen='127.0.0.1:' + str(plan.get('targetPort', 18083)), certificateFile=str(ipc / 'server.pem'),
        keyFile=str(ipc / 'server.key'), caFile=str(ipc / 'ca.pem'), authorizedUntil=plan['validUntil'],
        scope=dict(AssetID=asset, SensorID=sensor, BootID=journal.data['bootId'], CaptureScopeID=journal.data['scopeId'],
            Environment='authorized', ExecutorBootID=journal.data['executorBootId'], KeyEpoch=1, LocalAddresses=plan['localAddresses'],
            CollectorCertSHA256=fingerprints['collector'], ExecutorCertSHA256=fingerprints['executor'], MaxReferences=10000))
    write(config / 'targets.json', targets, replace=(config / 'targets.json').exists())
    return {'ok': True, 'assetId': asset, 'sensorId': sensor, 'executorId': executor, 'root': str(root), 'captureStarted': False,
            'executorMode': 'alert_only', 'generated': ['sensor.json', 'executor-observer.json', 'targets.json']}


def enroll(plan, work, applicant, reviewer, *, base, backend_tls):
    validate(plan)
    require(applicant.identity != reviewer.identity, 'INDEPENDENT_REVIEWER_REQUIRED')
    journal = Journal(work, plan)
    for field in ('scopeId', 'bootId', 'executorBootId'):
        journal.data.setdefault(field, str(uuid.uuid4()))
    journal.save()
    bundle = applicant.request('GET', '/release-bundles/' + plan['bundleId'])
    require(bundle['subjectSha256'] == plan['subjectSha256'] and bundle['environment'] == 'authorized'
            and bundle['status'] in ('approved', 'active'), 'R6_BINDING_MISMATCH')
    policy = applicant.request('GET', '/decision-policies/' + bundle['policyId'])
    require(policy['definition']['mode'] == 'alert_only', 'ALERT_ONLY_REQUIRED')
    step = journal.step
    asset = step('asset', applicant, '/assets', dict(assetKey=plan['assetKey'], platform='macos', environment='authorized', owner=plan['owner']))
    authorization = step('authorization', applicant, '/assets/' + asset['id'] + '/authorizations',
        dict(interfaces=[plan['interface']], observationAllowed=True, executionScopes=[], validFrom=plan['validFrom'],
             validUntil=plan['validUntil'], evidenceRef=plan['evidenceRef']))
    approved = step('authorizationApproval', reviewer, '/authorizations/' + authorization['id'] + '/decisions',
        dict(decision='approve', reason=plan['approvalReason']), authorization['revision'])
    sensor = journal.machine('sensor', applicant, 'sensors', dict(assetId=asset['id'], platform='macos', captureScopeId=journal.data['scopeId']))
    journal.machine('executor', applicant, 'executors', dict(assetId=asset['id'], platform='macos', capabilityProbeRef='p8-alert-only-no-pf'))
    draft = step('config', applicant, '/sensors/' + sensor['id'] + '/configs',
        dict(contractVersion='host-guard/5.0.0-rc.2', profileSha256=plan['profileSha256'], captureHealthVersion='host-guard-capture-health/1.0.0',
             interfaceIds=[plan['interface']], limits={'maxBatchSize': 100}, captureScopeId=journal.data['scopeId'],
             addressFamily='ipv4' if ipaddress.ip_address(plan['localAddresses'][0]).version == 4 else 'ipv6', buildSha256=sha(plan['guardliveBinary'])))
    step('configApproval', reviewer, '/sensor-configs/' + draft['id'] + '/decisions', dict(decision='approve', reason=plan['approvalReason']), draft['revision'])
    # 保留首次发起时 revision，避免重入因本次 activation 已推进 revision 而改变请求。
    prior = journal.data['steps'].get('activation')
    revision = prior['request']['revision'] if prior else bundle['revision']
    step('activation', reviewer, '/release-bundles/' + bundle['id'] + '/activations',
        dict(assetIds=[asset['id']], authorizationIds=[authorization['id']]), revision)
    return configs(plan, journal, bundle, approved, base, backend_tls)


@contextmanager
def clone_backend(args, work):
    """只在随机 cyber_b3_clone schema 启动本次 JAR；绝不复用用户提供 URL 指向未知业务服务。"""
    from scripts.p8.register_alert_only import Database, backend
    from types import SimpleNamespace
    db = Database(absolute(args.mysql_service))
    state_path = work / 'clone.json'
    if state_path.exists():
        state = load(state_path)
        require(state['sourceSchema'] == args.source_schema, 'CLONE_SOURCE_CHANGED')
    else:
        require(re.fullmatch('[A-Za-z0-9_]+', args.source_schema), 'SOURCE_SCHEMA_INVALID')
        state = {'sourceSchema': args.source_schema, 'schema': 'cyber_b3_clone_' + uuid.uuid4().hex[:16]}
        write(state_path, state)
        backup = private_dir(work / 'backup')
        db.backup_restore(args.source_schema, state['schema'], backup)
        state['restored'] = True
        write(state_path, state, replace=True)
    require(state.get('restored') and re.fullmatch('cyber_b3_clone_[0-9a-f]{16}', state['schema']), 'CLONE_NOT_RESTORED')
    session = private_dir(work / ('backend-' + uuid.uuid4().hex))
    cfg = SimpleNamespace(java_home=absolute(args.java).parent.parent, jar=absolute(args.jar), trust=absolute(args.report_trust))
    record = {}
    try:
        with backend(cfg, db, state['schema'], session, absolute(args.artifacts), record) as (base, context):
            yield base, context, {'caFile': str(session / 'tls/ca.pem'), 'certificateFile': str(session / 'tls/client.pem'), 'keyFile': str(session / 'tls/client.key')}
    finally:
        write(session / 'process.json', record)
    # 保留克隆与幂等事实以供中断重入；删除必须使用显式 cleanup-clone，并严格核对前缀。


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=['clone', 'authorized'], required=True)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--work', required=True)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--authorization-reference')
    for option in ('mysql-service', 'java', 'jar', 'report-trust', 'artifacts'):
        parser.add_argument('--' + option)
    parser.add_argument('--source-schema', default='cyber_security')
    args = parser.parse_args()
    plan = load(args.plan)
    validate(plan)
    if args.dry_run:
        print(json.dumps({'target': args.target, 'steps': ['asset', 'authorization', 'independent approval', 'sensor', 'executor', 'mTLS',
              'config', 'independent config approval', 'r6 activation', 'generate configs'], 'captureStarted': False}))
        return
    work = private_dir(args.work)
    if args.target == 'clone':
        require(all(getattr(args, p) for p in ('mysql_service', 'java', 'jar', 'report_trust', 'artifacts')), 'CLONE_RUNTIME_REQUIRED')
        with clone_backend(args, work) as (base, context, tls):
            applicant = Human(base, context).login_keychain(plan['applicant'])
            reviewer = Human(base, context).login_keychain(plan['reviewer'])
            result = enroll(plan, work / 'journal', applicant, reviewer, base=base, backend_tls=tls)
    else:
        require(args.authorization_reference == plan['evidenceRef'], 'AUTHORIZED_TARGET_APPROVAL_REQUIRED')
        from scripts.p8.toolkit import sessions
        applicant, reviewer = sessions(plan)
        result = enroll(plan, work / 'journal', applicant, reviewer, base=plan['baseUrl'], backend_tls=plan['backendTls'])
    write(work / 'result.json', result, replace=(work / 'result.json').exists())
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
