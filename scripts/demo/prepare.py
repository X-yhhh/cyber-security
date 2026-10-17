#!/usr/bin/env python3
"""一次性准备入口：私有密钥/PKI、独立 lab 机器登记及远端 worker 安装；默认只输出计划。"""
import argparse
import json
import os
from pathlib import Path
import sys
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.demo.common import load, path, private, require, safe_main, scenes, sha, validate, write


def approve(c, approval, operation):
    from scripts.demo.common import digest
    require(approval['operation'] == operation and approval['configSha256'] == digest(c) and approval['reference'], 'SETUP_APPROVAL_MISMATCH')


def initialize(c):
    """只创建仓库外私有材料；已有身份不覆盖，半成品保留供核对。"""
    from scripts.p8.toolkit import private_dir
    from executor import pki
    root = private_dir(c['root'])
    config = private_dir(root / 'config')
    for folder in ('runs', 'ledger', 'locks'):
        private_dir(root / folder)
    for name in ('peer.key', 'budget.key'):
        if not (config / name).exists():
            write(config / name, os.urandom(32))
        require(len(private(config / name).read_bytes()) == 32, 'EXISTING_KEY_INVALID')
    if not (config / 'ipc').exists():
        temp = config / ('ipc-' + uuid.uuid4().hex)
        pki.create(temp)
        temp.rename(config / 'ipc')
    return {'initialized': True, 'backendClientCA': str(config / 'ipc/ca.pem'), 'backendTrustNeedsSetup': True}


def enroll(c, approval):
    """备份恢复成功后才创建资产/机器；各步有幂等日志，不创建运行授权或启动采集。"""
    from scripts.p8.toolkit import Journal, sessions, private_dir
    from scripts.demo.preflight import command, interface_for
    from scripts.p8.register_alert_only import Database
    from scripts.demo.root_executor import validate_boundary
    approve(c, approval, 'enroll')
    root = private(c['root'], True)
    applicant, reviewer = sessions(c)
    bundle = applicant.request('GET', '/release-bundles/' + c['bundleId'])
    require(bundle['subjectSha256'] == c['subjectSha256'] and bundle['environment'] == 'lab' and bundle['status'] in ('approved', 'active'), 'APPROVED_LAB_BUNDLE_REQUIRED')
    interface = interface_for(command(['/sbin/ifconfig']), c['macAddress'])
    work = private_dir(root / 'enrollment')
    journal = Journal(work / 'api', {'config': c, 'approval': approval, 'interface': interface})
    if not journal.data.get('backup'):
        db = Database(path(c['mysqlService']))
        backup = private_dir(work / ('backup-' + uuid.uuid4().hex))
        try:
            from scripts.demo.backup import backup_restore
            before, filename = backup_restore(db, c['schema'], 'cyber_r6_restore_' + uuid.uuid4().hex[:16], backup)
            journal.data['backup'] = {'file': str(filename), 'sha256': sha(filename), 'restoreVerified': True}
            journal.save()
        finally:
            db.drop_owned()
    journal.data.setdefault('scopeId', str(uuid.uuid4()))
    journal.save()
    step = journal.step
    asset = step('asset', applicant, '/assets', dict(assetKey=c['assetKey'], platform='macos', environment='lab', owner=c['owner']))
    sensor = journal.machine('sensor', applicant, 'sensors', dict(assetId=asset['id'], platform='macos', captureScopeId=journal.data['scopeId']))
    executor = journal.machine('executor', applicant, 'executors', dict(assetId=asset['id'], platform='macos', capabilityProbeRef=approval['platformEvidenceRef']))
    for name, result in (('sensor', sensor), ('executor', executor)):
        f = root / 'config' / (name + '.credential')
        if f.exists():
            require(private(f).read_text() == result['credential'], 'ENROLLMENT_CREDENTIAL_CHANGED')
        else:
            write(f, result['credential'].encode())
    definition = dict(contractVersion='host-guard/5.0.0-rc.2', profileSha256=c['profileSha256'],
                      captureHealthVersion='host-guard-capture-health/1.0.0', interfaceIds=[interface],
                      limits={'maxBatchSize': 100}, captureScopeId=journal.data['scopeId'], addressFamily='ipv4', buildSha256=sha(c['guardlive']))
    draft = step('config', applicant, '/sensors/' + sensor['id'] + '/configs', definition)
    step('configApproval', reviewer, '/sensor-configs/' + draft['id'] + '/decisions',
         {'decision': 'approve', 'reason': approval['reference']}, draft['revision'])
    ids = dict(assetId=asset['id'], sensorId=sensor['id'], executorId=executor['id'], captureScopeId=journal.data['scopeId'],
               interface=interface, guardliveSha256=sha(c['guardlive']))
    boundary = validate_boundary({**{k: ids[k] for k in ('assetId', 'sensorId', 'executorId', 'captureScopeId')},
                                 **{k: c[k] for k in ('macAddress', 'peerAddress', 'ports', 'protection', 'protectedPeers', 'bundleId', 'subjectSha256')},
                                 'budgetKeySha256': sha(root / 'config/budget.key')})
    for filename, value in (('enrollment.json', ids), ('root-boundary.json', boundary)):
        f = root / filename
        if f.exists():
            require(load(f) == value, 'ENROLLMENT_CHANGED')
        else:
            write(f, value)
    return {'enrolled': True, **ids, 'captureStarted': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--scenes-file', default=str(Path(__file__).with_name('scenes.json')))
    p.add_argument('--operation', choices=('init', 'enroll', 'install-worker'), required=True)
    p.add_argument('--approval')
    p.add_argument('--execute', action='store_true')
    a = p.parse_args()
    c = validate(load(a.config, secret=a.execute), scenes(a.scenes_file))
    if not a.execute:
        print(json.dumps({'operation': a.operation, 'writes': False, 'network': False, 'captureStarted': False}))
        return
    if a.operation == 'init':
        result = initialize(c)
    else:
        require(a.approval, 'SETUP_APPROVAL_REQUIRED')
        g = load(a.approval)
        approve(c, g, a.operation)
        if a.operation == 'enroll':
            result = enroll(c, g)
        else:
            from scripts.demo.remote import Remote
            result = {'allowlistSha256': Remote(c['remote']).install(c), 'toolsInstalled': False}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
