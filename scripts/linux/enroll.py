#!/usr/bin/env python3
"""A3：登记 Linux 只告警身份并生成远端配置包，不启动采集或下发文件。

计划除任务单的业务字段外，还需 root（本机输出目录）、guardliveBinary（B2
拷回的本机文件）、owner、evidenceRef、approvalReason 和 applicant/reviewer。
business 另需 p8 会话约定的 baseUrl、backendCA、backendTls；显式授权引用必须
等于 evidenceRef。clone/business 必须使用不同的工作及输出目录，避免复用克隆
身份。B4 的业务库备份及随机库恢复核验由现场编排负责。
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from executor import pki
from scripts.p8.enroll import clone_backend
from scripts.p8.toolkit import (
    Human, Journal, absolute, load, private_dir, private_file, require,
    safe_main, sessions, sha, write,
)

R6_PRIME = 'd89e7b99-ea61-40b1-b376-dbb90f004ef6'
CONTRACT = 'host-guard/5.0.0-rc.2'
HEALTH_VERSION = 'host-guard-capture-health/1.0.0'


def is_sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def remote_root(value):
    """只做 Linux 路径语法检查；不在 Mac 上解析、创建或探测远端目录。"""
    require(isinstance(value, str) and not any(ord(c) < 32 for c in value)
            and '\\' not in value, 'REMOTE_ROOT_INVALID')
    path = PurePosixPath(value)
    require(path.is_absolute() and path.root == '/' and '..' not in path.parts
            and str(path) == value and value != '/', 'REMOTE_ROOT_INVALID')
    return path


def validate(plan):
    """在任何写 API 前校验静态范围、有效期和待下发二进制，不接受隐式执行权限。"""
    fields = ('bundleId subjectSha256 assetKey interface localAddresses validFrom validUntil '
              'remoteRoot guardliveSha256 tunnelPort root guardliveBinary owner evidenceRef '
              'approvalReason applicant reviewer').split()
    require(isinstance(plan, dict) and all(k in plan for k in fields), 'ENROLLMENT_PLAN_REQUIRED')
    require(plan['bundleId'] == R6_PRIME and is_sha(plan['subjectSha256']), 'R6_PRIME_REQUIRED')
    require(plan.get('platform', 'linux') == 'linux', 'LINUX_REQUIRED')
    for key in ('assetKey', 'owner', 'evidenceRef', 'approvalReason'):
        require(isinstance(plan[key], str) and plan[key].strip()
                and not any(ord(c) < 32 for c in plan[key]), 'AUTHORIZATION_PLAN_REQUIRED')
    require(all(isinstance(plan[k], dict) and plan[k].get('username') for k in ('applicant', 'reviewer')),
            'INDEPENDENT_REVIEWER_REQUIRED')
    require(plan['applicant']['username'] != plan['reviewer']['username'], 'INDEPENDENT_REVIEWER_REQUIRED')
    require(isinstance(plan['interface'], str)
            and re.fullmatch(r'[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,95}', plan['interface']), 'INTERFACE_INVALID')
    values = plan['localAddresses']
    require(isinstance(values, list) and values and all(isinstance(v, str) for v in values),
            'LOCAL_ADDRESSES_REQUIRED')
    try:
        addresses = {ipaddress.ip_address(v) for v in values}
    except ValueError:
        raise ValueError('LOCAL_ADDRESSES_INVALID') from None
    require(len(addresses) == len(values) and len({v.version for v in addresses}) == 1
            and all(not (v.is_loopback or v.is_link_local or v.is_unspecified or v.is_multicast
                         or getattr(v, 'scope_id', None)) for v in addresses), 'LOCAL_ADDRESSES_INVALID')
    try:
        start, end = (datetime.fromisoformat(plan[k].replace('Z', '+00:00'))
                      for k in ('validFrom', 'validUntil'))
        require(start.tzinfo and end.tzinfo and start <= datetime.now(timezone.utc) < end,
                'AUTHORIZATION_NOT_CURRENT')
    except (TypeError, AttributeError, ValueError):
        raise ValueError('AUTHORIZATION_NOT_CURRENT') from None
    for key, value in (('validFrom', start), ('validUntil', end)):
        plan[key] = value.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    remote_root(plan['remoteRoot'])
    require(type(plan['tunnelPort']) is int and 1 <= plan['tunnelPort'] <= 65535, 'TUNNEL_PORT_INVALID')
    root = absolute(plan['root'])
    if root.exists():
        private_dir(root)
    require(not (root / 'config/targets.json').exists(), 'TARGETS_CONFIGURATION_FORBIDDEN')
    binary = absolute(plan['guardliveBinary'])
    require(binary.is_file(), 'GUARDLIVE_BUILD_REQUIRED')
    require(is_sha(plan['guardliveSha256']) and sha(binary) == plan['guardliveSha256'], 'GUARDLIVE_SHA256_MISMATCH')


def same_file(path, content):
    """重入只复用相同的私有文件；不覆盖另一资产的配置、凭据或信任材料。"""
    if path.exists():
        require(private_file(path).read_bytes() == content, 'GENERATED_FILE_CHANGED')
    else:
        write(path, content)


def same_json(path, value):
    if path.exists():
        require(load(path) == value, 'GENERATED_FILE_CHANGED')
    else:
        write(path, value)


def configs(plan, journal, bundle, authorization, backend_tls, *, refresh_clone_ca=False):
    """本机私有包与远端路径分离；包内 CA 可搬运，机器只经回环隧道上传。"""
    root = private_dir(plan['root'])
    config = private_dir(root / 'config')
    for folder in ('ledger', 'logs', 'ledger/executor', 'ledger/sensor'):
        private_dir(root / folder)
    steps = journal.data['steps']
    asset, sensor, executor = (steps[k]['result']['id'] for k in ('asset', 'sensor', 'executor'))
    # 先绑定输出目录，防止重用其他登记的凭据或 IPC CA。
    same_json(config / 'enrollment.json', dict(assetId=asset, sensorId=sensor, executorId=executor,
              captureScopeId=journal.data['scopeId'], bundleId=bundle['id']))
    for name in ('sensor', 'executor'):
        same_file(config / (name + '.credential'), steps[name]['result']['credential'].encode())
    backend_ca = private_file(backend_tls['caFile']).read_bytes()
    # 隔离克隆每次启动生成新后端 CA；同一登记重入只更新该临时信任材料。
    if refresh_clone_ca:
        write(config / 'backend-ca.pem', backend_ca, replace=(config / 'backend-ca.pem').exists())
    else:
        same_file(config / 'backend-ca.pem', backend_ca)
    ipc = config / 'ipc'
    if not ipc.exists():
        temporary = config / ('ipc-' + uuid.uuid4().hex)
        pki.create(temporary)
        temporary.rename(ipc)
    private_dir(ipc)
    for name in ('ca.pem', 'server.pem', 'server.key', 'collector.pem', 'collector.key',
                 'executor.pem', 'executor.key', 'fingerprints.json'):
        private_file(ipc / name)
    if not (config / 'peer.key').exists():
        write(config / 'peer.key', os.urandom(32))
    private_file(config / 'peer.key')
    remote = remote_root(plan['remoteRoot'])
    rc = remote / 'config'
    base = 'https://127.0.0.1:' + str(plan['tunnelPort'])
    sensor_config = dict(
        assetId=asset, sensorId=sensor, bootId=journal.data['bootId'], captureScopeId=journal.data['scopeId'],
        environment='authorized', captureScope='all_inbound_tcp', localAddresses=plan['localAddresses'],
        secretFile=str(rc / 'peer.key'), keyEpoch=1, interface=plan['interface'], allowedInterfaces=[plan['interface']],
        authorizedUntil=plan['validUntil'], upload=dict(
            baseUrl=base, caFile=str(rc / 'backend-ca.pem'), certificateFile=str(rc / 'ipc/collector.pem'),
            keyFile=str(rc / 'ipc/collector.key'), credentialFile=str(rc / 'sensor.credential'),
            spoolDir=str(remote / 'ledger/sensor' / journal.data['bootId']), healthWindowMs=1000))
    same_json(config / 'sensor.json', sensor_config)
    observer = dict(
        mode='alert_only', assetId=asset, executorId=executor, authorizationId=authorization['id'],
        validUntil=plan['validUntil'], baseUrl=base, credentialFile=str(rc / 'executor.credential'),
        caFile=str(rc / 'backend-ca.pem'), certificateFile=str(rc / 'ipc/executor.pem'),
        keyFile=str(rc / 'ipc/executor.key'), stateDir=str(remote / 'ledger/executor'),
        capabilityIds=[], bundleIds=[bundle['id']])
    same_json(config / 'executor-observer.json', observer)
    # 该文件给 Mac 后端用（B3 合入 DEPLOY_TLS_CLIENT_CA），指向本机包内的 CA，不下发到远端。
    same_file(config / 'machine-tls.properties', ('DEPLOY_TLS_CLIENT_CA=' + str(ipc / 'ca.pem') + '\n').encode())
    activation = steps['activation']['result']
    require(len(activation['bindingIds']) == 1, 'SINGLE_ASSET_BINDING_REQUIRED')
    return dict(ok=True, assetId=asset, sensorId=sensor, executorId=executor,
                authorizationId=authorization['id'], captureScopeId=journal.data['scopeId'],
                bundleId=bundle['id'], bindingId=activation['bindingIds'][0],
                guardliveSha256=plan['guardliveSha256'], root=str(root), remoteRoot=str(remote),
                captureStarted=False, executorMode='alert_only',
                generated=['sensor.json', 'executor-observer.json', 'sensor.credential', 'executor.credential',
                           'backend-ca.pem', 'peer.key', 'ipc/', 'machine-tls.properties', 'enrollment.json'])


def enroll(plan, work, applicant, reviewer, *, backend_tls, refresh_clone_ca=False):
    """按 Mac 的幂等日志和独立批准流程，仅为本次新建的 Linux 资产激活 r6′。"""
    validate(plan)
    require(applicant.identity != reviewer.identity, 'INDEPENDENT_REVIEWER_REQUIRED')
    private_file(backend_tls['caFile'])
    bundle = applicant.request('GET', '/release-bundles/' + plan['bundleId'])
    require(bundle['id'] == plan['bundleId'] and bundle['environment'] == 'authorized'
            and bundle['status'] in ('approved', 'active')
            and bundle['subjectSha256'] == plan['subjectSha256'], 'R6_PRIME_BINDING_MISMATCH')
    policy = applicant.request('GET', '/decision-policies/' + bundle['policyId'])
    require(policy['definition']['mode'] == 'alert_only', 'ALERT_ONLY_REQUIRED')
    profile = bundle['subject']['featureProfileSha256']
    require(is_sha(profile) and plan.get('profileSha256', profile) == profile, 'FEATURE_PROFILE_MISMATCH')
    journal = Journal(work, plan)
    for field in ('scopeId', 'bootId'):
        journal.data.setdefault(field, str(uuid.uuid4()))
    journal.save()
    step = journal.step
    asset = step('asset', applicant, '/assets', dict(
        assetKey=plan['assetKey'], platform='linux', environment='authorized', owner=plan['owner']))
    authorization = step('authorization', applicant, '/assets/' + asset['id'] + '/authorizations', dict(
        interfaces=[plan['interface']], observationAllowed=True, executionScopes=[],
        validFrom=plan['validFrom'], validUntil=plan['validUntil'], evidenceRef=plan['evidenceRef']))
    approved = step('authorizationApproval', reviewer, '/authorizations/' + authorization['id'] + '/decisions',
                    dict(decision='approve', reason=plan['approvalReason']), authorization['revision'])
    sensor = journal.machine('sensor', applicant, 'sensors', dict(
        assetId=asset['id'], platform='linux', captureScopeId=journal.data['scopeId']))
    journal.machine('executor', applicant, 'executors', dict(
        assetId=asset['id'], platform='linux', capabilityProbeRef='linux-alert-only-zero-capabilities'))
    draft = step('config', applicant, '/sensors/' + sensor['id'] + '/configs', dict(
        contractVersion=CONTRACT, profileSha256=profile, captureHealthVersion=HEALTH_VERSION,
        interfaceIds=[plan['interface']], limits={'maxBatchSize': 100}, captureScopeId=journal.data['scopeId'],
        addressFamily='ipv4' if ipaddress.ip_address(plan['localAddresses'][0]).version == 4 else 'ipv6',
        buildSha256=plan['guardliveSha256']))
    step('configApproval', reviewer, '/sensor-configs/' + draft['id'] + '/decisions',
         dict(decision='approve', reason=plan['approvalReason']), draft['revision'])
    prior = journal.data['steps'].get('activation')
    revision = prior['request']['revision'] if prior else bundle['revision']
    step('activation', reviewer, '/release-bundles/' + bundle['id'] + '/activations',
         dict(assetIds=[asset['id']], authorizationIds=[authorization['id']]), revision)
    return configs(plan, journal, bundle, approved, backend_tls, refresh_clone_ca=refresh_clone_ca)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=('clone', 'business'), required=True)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--work', required=True)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--authorization-reference')
    for option in ('mysql-service', 'java', 'jar', 'report-trust', 'artifacts'):
        parser.add_argument('--' + option)
    parser.add_argument('--source-schema', default='cyber_security')
    args = parser.parse_args(argv)
    plan = load(args.plan)
    validate(plan)
    if args.dry_run:
        print(json.dumps(dict(target=args.target, platform='linux', captureStarted=False,
              steps=['asset', 'authorization', 'independent approval', 'sensor', 'zero-capability executor',
                     'config', 'independent config approval', 'r6-prime activation', 'generate remote configs'])))
        return 0
    if args.target == 'business':
        require(args.authorization_reference == plan['evidenceRef'], 'AUTHORIZED_TARGET_APPROVAL_REQUIRED')
        tls = plan['backendTls']
        require(private_file(tls['caFile']).read_bytes() == private_file(plan['backendCA']).read_bytes(),
                'BACKEND_CA_MISMATCH')
    else:
        require(all(getattr(args, k) for k in ('mysql_service', 'java', 'jar', 'report_trust', 'artifacts')),
                'CLONE_RUNTIME_REQUIRED')
    work = private_dir(args.work)
    # 幂等日志不能跨后端复用，否则克隆结果可能被误当作已完成的业务登记。
    target_path = work / 'target.json'
    target = dict(target=args.target)
    if target_path.exists():
        require(load(target_path) == target, 'ENROLLMENT_TARGET_CHANGED')
    else:
        write(target_path, target)
    if args.target == 'clone':
        with clone_backend(args, work) as (base, context, tls):
            applicant = Human(base, context).login_keychain(plan['applicant'])
            reviewer = Human(base, context).login_keychain(plan['reviewer'])
            result = enroll(plan, work / 'journal', applicant, reviewer, backend_tls=tls, refresh_clone_ca=True)
    else:
        applicant, reviewer = sessions(plan)
        result = enroll(plan, work / 'journal', applicant, reviewer, backend_tls=plan['backendTls'])
    write(work / 'result.json', result, replace=(work / 'result.json').exists())
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
