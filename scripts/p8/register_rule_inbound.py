#!/usr/bin/env python3
"""Q12/C1a：r6′ 登记演练与业务登记。

先在业务库快照的随机克隆中完整演练：登记派生策略 → 独立审查 → 建组合 → 导入重签 final → 封存 → 独立批准 →
激活到原真实资产与现有授权（原 r6 绑定由后端自动挂起）。业务模式必须引用同输入的成功演练，且不在本脚本中激活。
只通过真实鉴权 API 写入；失败保留受控备份与逐步记录，绝不自动覆盖业务库；只删除本次创建的随机库。
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.p7 import j1_run
from scripts.p7.compose_policy import validate_rule_inbound_derivation, RULE_INBOUND_TOKEN
from scripts.p5.platform_report import private_key, sign
from scripts.p8.launchd import wait_ready
from scripts.p8.register_alert_only import (Database, backend, digest, load, protected, sha, verify_signature, write,
                                            SIGNER, ANCILLARY, require)

R6 = 'aa35ae6e-3b41-461d-8b54-cb4bb4726349'
R6_POLICY = 'de650e8c-372e-56c7-ba24-2114d5025627'
ASSET = 'cb7e844b-01b1-453f-a6a2-8cf248979b9a'
REGISTER = {'guard_decision_policy': 1, 'guard_release_bundle': 1, 'guard_bundle_capability': 4, 'guard_evaluation_run': 1}
ACTIVATE = {'guard_asset_binding': 2}
SERVICE = Path.home() / 'Workspace/development/services/security/cyber-security'
PLIST = Path.home() / 'Library/LaunchAgents/com.xyh.cyber-security.backend.plist'


def stop_backend(db):
    """常驻后端停写，保证整库备份与源库逐行一致；托管传感器随后端一起停止。"""
    require(subprocess.run(['/usr/sbin/lsof', '-nP', '-iTCP:18080', '-sTCP:LISTEN'], capture_output=True).returncode != 0, 'IDE_BACKEND_STILL_RUNNING')
    subprocess.run(['/bin/launchctl', 'bootout', 'gui/' + str(os.getuid()) + '/com.xyh.cyber-security.backend'], check=True, capture_output=True)
    for _ in range(40):
        if int(db.query("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE DB='cyber_security' AND ID<>CONNECTION_ID()")) == 0:
            return
        time.sleep(.5)
    raise RuntimeError('BUSINESS_DATABASE_IN_USE')


def start_backend():
    for _ in range(10):
        if subprocess.run(['/bin/launchctl', 'bootstrap', 'gui/' + str(os.getuid()), str(PLIST)], capture_output=True).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('BACKEND_BOOTSTRAP_FAILED')
    wait_ready(SERVICE)


def source_material(db, args):
    """读取 r6 的已审查策略、正式 final 与 subject；派生策略只允许改 ID 与版本。"""
    require(args.source == 'cyber_security', 'BUSINESS_SCHEMA_MISMATCH')
    row = db.query("SELECT b.subject_json,p.public_id,p.definition_json,p.status,e.report_ref,e.report_sha256,e.runner_identity,ep.public_id "
                   "FROM guard_release_bundle b JOIN guard_decision_policy p ON p.id=b.policy_id "
                   "JOIN guard_evaluation_run e ON e.bundle_id=b.id JOIN guard_evaluation_plan ep ON ep.id=b.plan_id "
                   f"WHERE b.public_id='{R6}' AND e.run_kind='final' AND e.status='passed'", args.source).decode().splitlines()
    require(len(row) == 1, 'R6_FINAL_NOT_UNIQUE')
    subject, policy_id, original, status, ref, expected, runner, plan_id = row[0].split('\t')
    require(policy_id == R6_POLICY and status == 'reviewed' and runner == SIGNER, 'SOURCE_POLICY_OR_SIGNER_MISMATCH')
    source, policy = json.loads(original), load(args.policy)
    changes = validate_rule_inbound_derivation(source, policy)
    final_path = (args.artifacts / ref).resolve()
    require(final_path.is_relative_to(args.artifacts.resolve()) and sha(final_path) == expected, 'R6_FINAL_HASH_MISMATCH')
    trust = load(protected(args.trust))
    envelope = load(final_path)
    verify_signature(envelope, trust)
    payload, subject = envelope['payload'], json.loads(subject)
    require(payload['subject'] == subject and payload['subjectSha256'] == digest(subject)
            and payload['runKind'] == 'final' and payload['passed'] is True, 'R6_FINAL_SUBJECT_INVALID')
    request = {k: deepcopy(subject[k]) for k in ('modelId', 'featureProfileSha256', 'extractorSha256', 'protocolVersions', 'capabilityIds')}
    request.update(policyId=policy['policyId'], evaluationPlanId=plan_id, environment='authorized')
    evaluation = load(args.offline_eval)
    require(evaluation['policyId'] == policy['policyId'] and evaluation['testRead'] is False
            and evaluation['validation']['ruleHitsOldVsNewIdentical'] is True, 'OFFLINE_EVALUATION_INVALID')
    inputs = {'jarSha256': sha(args.jar), 'scriptSha256': sha(Path(__file__)), 'policySha256': digest(policy),
              'sourcePolicySha256': digest(source), 'sourceReportSha256': expected, 'trustSha256': sha(args.trust),
              'requestSha256': digest(request), 'offlineEvaluationSha256': sha(args.offline_eval)}
    return policy, request, payload, {'reportRef': ref, 'sha256': expected, 'bundleId': R6}, trust, inputs, changes, evaluation


def deltas(before, after, expected):
    require(before['schemaSha256'] == after['schemaSha256'], 'DATABASE_STRUCTURE_CHANGED')
    require(before['tables'].keys() == after['tables'].keys(), 'TABLE_SET_CHANGED')
    changes, modified = {}, set()
    for table, previous in before['tables'].items():
        current = after['tables'][table]
        if previous['sha256'] == current['sha256']:
            continue
        require(table in expected or table in ANCILLARY or table == 'guard_release_bundle', 'UNEXPECTED_TABLE_CHANGED:' + table)
        changes[table] = current['count'] - previous['count']
        if table == 'sys_user':
            require(previous['invariantSha256'] == current['invariantSha256'], 'ACCOUNT_IDENTITY_OR_CREDENTIAL_CHANGED')
        elif table not in {'SPRING_SESSION', 'SPRING_SESSION_ATTRIBUTES', 'auth_login_throttle'}:
            altered = [k for k, v in previous['rows'].items() if current['rows'].get(k) != v]
            if altered:
                modified.add(table)
                # 演练激活与回退只允许挂起原 r6 绑定、更新组合修订号；其余既有行不得改变。
                require(table in ('guard_asset_binding', 'guard_release_bundle') and len(altered) <= 2, 'EXISTING_ROW_CHANGED:' + table)
    require({k: changes.get(k) for k in expected} == expected, 'BUSINESS_DELTA_MISMATCH')
    return changes, sorted(modified)


def register(args, db, schema, work, materials, record):
    policy, request, previous, derived, trust, inputs, changes, evaluation = materials
    artifacts = args.artifacts if args.mode == 'business' else work / 'artifacts'
    if args.mode != 'business':
        # 演练使用独立制品根，复制 r6 原 final 以便导入时按相同相对路径核对。
        source = args.artifacts / derived['reportRef']
        target = artifacts / derived['reportRef']
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    report_folder = artifacts / 'reports' / ('r6-rule-inbound-' + work.name)
    report_folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    require(not db.query(f"SELECT id FROM guard_decision_policy WHERE public_id='{policy['policyId']}'", schema), 'POLICY_ALREADY_REGISTERED')
    with backend(args, db, schema, work, artifacts, record) as (base, context):
        op_credentials, reviewer_credentials = load(protected(args.operator)), load(protected(args.reviewer))
        op = j1_run.Session(base, context).login({k: op_credentials[k] for k in ('username', 'password')})
        reviewer = j1_run.Session(base, context).login({k: reviewer_credentials[k] for k in ('username', 'password')})

        def step(name, session, path, body, revision=None):
            result = session.v2(path, body, revision)
            write(work / (name + '.json'), result)
            record.setdefault('steps', []).append(name)
            return result
        registered = step('01-policy', op, '/decision-policies', policy)
        require(registered['id'] == policy['policyId'] and registered['status'] == 'draft', 'POLICY_REGISTRATION_MISMATCH')
        reviewed = step('02-review', reviewer, '/decision-policies/' + policy['policyId'] + '/reviews',
                        {'decision': 'approve', 'reason': 'Q12/C1a：派生差异仅 policyId 与 policyVersion（追加 rule-inbound-20261018），窗口规则只对 inbound 观察适用；阈值、规则、模式与部署字段不变，仅告警。'},
                        registered['revision'])
        require(reviewed['status'] == 'reviewed', 'POLICY_REVIEW_FAILED')
        bundle = step('03-bundle', op, '/release-bundles', request)
        bid = str(uuid.UUID(bundle['id']))
        subject = json.loads(db.query(f"SELECT subject_json FROM guard_release_bundle WHERE public_id='{bid}'", schema))
        require(digest(subject) == bundle['subjectSha256'] and subject['policySha256'] == inputs['policySha256'], 'SUBJECT_MISMATCH')
        final = deepcopy(previous)
        final.update(subject=subject, subjectSha256=digest(subject), environment='authorized', protocolVersions=subject['protocolVersions'],
                     authorization='Q12/C1a ' + ('克隆演练' if args.mode == 'rehearsal' else '业务登记') + '：r6′ 仅告警，窗口规则 inbound 前置',
                     derivedFrom=derived,
                     policyDerivation={'sourcePolicyId': R6_POLICY, 'sourcePolicySha256': inputs['sourcePolicySha256'],
                                       'frozenSemanticsEqual': True, 'changedFields': [c['path'].lstrip('/') for c in changes],
                                       'ruleSemantics': RULE_INBOUND_TOKEN},
                     offlineEvaluation={'sha256': inputs['offlineEvaluationSha256'], 'testRead': False,
                                        'validationRows': evaluation['validation']['rows'],
                                        'validationRuleHitsIdentical': evaluation['validation']['ruleHitsOldVsNewIdentical'],
                                        'liveRuleHitsAfter': {k: {r: v['new'] for r, v in s['rules'].items()} for k, s in evaluation['live'].items()}},
                     limits='沿用 r6 final 的离线 L1/P6 结论与 provenance；未读取 test、未重算指标。冻结评价集只含 inbound 快照，新口径在其上不改变规则判定（validation 实测一致）。仅告警，无自动执行资格；规则在 inbound 上的既有精度局限不变。')
        require(final['evaluation'] == previous['evaluation'] and final['provenance'] == previous['provenance'], 'P6_CONCLUSIONS_CHANGED')
        envelope = sign(final, private_key(protected(args.evaluator)), SIGNER)
        verify_signature(envelope, trust)
        report = report_folder / 'p6-final.json'
        write(report, envelope)
        imported = step('04-import', op, '/release-bundles/' + bid + '/imports',
                        {'reportRef': report.relative_to(artifacts).as_posix(), 'sha256': sha(report), 'runnerIdentity': SIGNER})
        require(imported['status'] == 'passed', 'FINAL_IMPORT_FAILED')
        sealed = step('05-seal', op, '/release-bundles/' + bid + '/sealings', {'evaluationIds': [imported['id']]}, bundle['revision'])
        approved = step('06-approve', reviewer, '/release-bundles/' + bid + '/decisions',
                        {'decision': 'approve', 'reason': 'Q12/C1a r6′ 独立批准：正式 final 绑定同 subject，冻结结论不变，仅告警。'}, sealed['revision'])
        require(approved['status'] == 'approved', 'BUNDLE_APPROVAL_FAILED')
        independent = db.query(f"SELECT requested_by<>approved_by FROM guard_release_bundle WHERE public_id='{bid}'", schema).strip() == b'1'
        independent &= db.query(f"SELECT created_by<>reviewed_by FROM guard_decision_policy WHERE public_id='{policy['policyId']}'", schema).strip() == b'1'
        require(independent, 'REVIEWER_NOT_INDEPENDENT')
        record.update(bundleId=bid, subjectSha256=bundle['subjectSha256'], policyId=policy['policyId'], policySha256=inputs['policySha256'],
                      sealedManifestSha256=sealed['sealedManifestSha256'], evaluationId=imported['id'], reportSha256=sha(report),
                      status='approved', independentApproval=True)
        if args.mode == 'rehearsal':
            # 演练切换：激活到原资产与当前有效授权；原 r6 绑定由后端挂起。业务激活不在本脚本内进行。
            auth = db.query("SELECT a.public_id FROM guard_asset_binding g JOIN asset_authorization a ON a.id=g.authorization_id "
                            f"JOIN guard_release_bundle b ON b.id=g.bundle_id WHERE b.public_id='{R6}' AND g.status='active'", schema).decode().split()
            require(len(auth) == 1, 'R6_ACTIVE_BINDING_NOT_UNIQUE')
            activated = step('07-activate', reviewer, '/release-bundles/' + bid + '/activations',
                             {'assetIds': [ASSET], 'authorizationIds': [auth[0]]}, approved['revision'])
            require(activated['status'] == 'active' and len(activated['bindingIds']) == 1, 'ACTIVATION_FAILED')
            states = db.query("SELECT b.public_id,g.status FROM guard_asset_binding g JOIN guard_release_bundle b ON b.id=g.bundle_id "
                              f"JOIN asset a ON a.id=g.asset_id WHERE a.public_id='{ASSET}' AND b.public_id IN ('{R6}','{bid}')", schema).decode()
            pairs = dict(line.split('\t') for line in states.splitlines())
            require(pairs.get(bid) == 'active' and pairs.get(R6) == 'suspended', 'BINDING_SWITCH_MISMATCH')
            record.update(activation={'bindingIds': activated['bindingIds'], 'r6Binding': 'suspended', 'authorizationId': auth[0]}, status='active')
            # 演练回退：把同一资产与授权重新激活到原 r6，r6′ 绑定应被挂起，恢复到切换前的检测口径。
            r6_revision = db.query(f"SELECT revision FROM guard_release_bundle WHERE public_id='{R6}'", schema).decode().strip()
            rolled = step('08-rollback', reviewer, '/release-bundles/' + R6 + '/activations',
                          {'assetIds': [ASSET], 'authorizationIds': [auth[0]]}, r6_revision)
            states = db.query("SELECT b.public_id,g.status,g.id FROM guard_asset_binding g JOIN guard_release_bundle b ON b.id=g.bundle_id "
                              f"JOIN asset a ON a.id=g.asset_id WHERE a.public_id='{ASSET}' AND b.public_id IN ('{R6}','{bid}') ORDER BY g.id", schema).decode()
            latest = {}
            for line in states.splitlines():
                public, status, _ = line.split('\t')
                latest[public] = status
            require(rolled['status'] == 'active' and latest.get(R6) == 'active' and latest.get(bid) == 'suspended', 'ROLLBACK_MISMATCH')
            record['rollback'] = {'r6Binding': 'active', 'r6PrimeBinding': 'suspended', 'bindingIds': rolled['bindingIds']}


def main(args):
    os.umask(0o077)
    args.work = args.work.resolve()
    args.work.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ('jar', 'policy', 'artifacts', 'offline_eval'):
        setattr(args, name, getattr(args, name).resolve())
    db = Database(args.mysql_service)
    record = {'task': 'Q12-C1a', 'mode': args.mode, 'passed': False, 'startedAt': j1_run.stamp()}
    try:
        require(db.query("SELECT MAX(CAST(version AS UNSIGNED)) FROM flyway_schema_history WHERE success=1", args.source).strip() == b'28', 'FLYWAY_VERSION_MISMATCH')
        materials = source_material(db, args)
        record['inputs'] = materials[5]
        if args.mode == 'business':
            require(args.rehearsal is not None, 'SUCCESSFUL_REHEARSAL_REQUIRED')
            rehearsal = load(args.rehearsal)
            require(rehearsal.get('passed') and rehearsal['mode'] == 'rehearsal' and rehearsal['inputs'] == record['inputs'], 'REHEARSAL_INPUTS_MISMATCH')
            record['rehearsalSha256'] = sha(args.rehearsal)
        suffix = uuid.uuid4().hex[:16]
        # 沿用 r6 随机库命名，drop_owned 只删除符合该模式的本次库。
        schema = 'cyber_r6_' + ('rehearsal_' if args.mode == 'rehearsal' else 'restore_') + suffix
        backup_dir = args.mysql_service / 'backups' / ('20261018-c1a-' + args.mode + '-' + suffix)
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        record.update(backupDirectory=str(backup_dir), randomSchema=schema)
        stop_backend(db)
        record['backendStoppedAt'] = j1_run.stamp()
        try:
            before, backup = db.backup_restore(args.source, schema, backup_dir)
        finally:
            # 演练只需停写备份；业务模式保持停写直至登记完成（见下方 finally）。
            if args.mode == 'rehearsal':
                start_backend()
                record['backendRestartedAt'] = j1_run.stamp()
        record.update(backupSha256=sha(backup), restoreProofSha256=sha(backup_dir / 'restore-proof.json'), restoreVerified=True,
                      sourceBeforeSha256=before['contentSha256'])
        if args.mode == 'business':
            db.drop_owned()
        target = schema if args.mode == 'rehearsal' else args.source
        register(args, db, target, args.work, materials, record)
        after = db.snapshot(target)
        write(args.work / 'target-after.json', after)
        expected = REGISTER | (ACTIVATE if args.mode == 'rehearsal' else {})
        record['tableDeltas'], record['modifiedTables'] = deltas(before, after, expected)
        if args.mode == 'rehearsal':
            record['businessChangedDuringRehearsal'] = db.snapshot(args.source)['contentSha256'] != before['contentSha256']
        record['passed'] = True
    except Exception as exc:
        record['errorType'] = type(exc).__name__
        record['errorLocation'] = [{'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(exc.__traceback__)]
        if isinstance(exc, RuntimeError) and re.fullmatch(r'[A-Z0-9_:]+', str(exc)):
            record['errorCode'] = str(exc)
        elif isinstance(exc, RuntimeError):
            match = re.search(r'HTTP (\d{3}) ([A-Z_]+|None)$', str(exc))
            if match:
                record['apiError'] = {'status': int(match[1]), 'code': match[2]}
        raise
    finally:
        db.drop_owned()
        if args.mode == 'business' and 'backendStoppedAt' in record:
            start_backend()
            record['backendRestartedAt'] = j1_run.stamp()
        record['temporarySchemaDeleted'] = getattr(db, 'owned_schema', None) is None
        record['finishedAt'] = j1_run.stamp()
        write(args.work / 'result.json', record)
        print(json.dumps({k: record[k] for k in ('mode', 'passed', 'status', 'bundleId', 'errorCode', 'errorType', 'apiError') if k in record}), flush=True)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=('rehearsal', 'business'), required=True)
    p.add_argument('--source', default='cyber_security')
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--jar', type=Path, required=True)
    p.add_argument('--policy', type=Path, required=True)
    p.add_argument('--offline-eval', type=Path, required=True)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--trust', type=Path, required=True)
    p.add_argument('--evaluator', type=Path, required=True)
    p.add_argument('--operator', type=Path, required=True)
    p.add_argument('--reviewer', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    p.add_argument('--mysql-service', type=Path, default=Path.home() / 'Workspace/development/services/databases/mysql-server-8.0.42')
    p.add_argument('--rehearsal', type=Path)
    return p


if __name__ == '__main__':
    main(parser().parse_args())
