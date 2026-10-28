#!/usr/bin/env python3
"""从 r6′ 正式 final 派生 lab 只告警组合；登记到 approved 后停止，不激活。"""
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
from scripts.p5.platform_report import private_key, sign
from scripts.p8.launchd import wait_ready
from scripts.p8.register_alert_only import (ANCILLARY, SIGNER, Database, backend, digest, load,
                                            protected, require, sha, verify_signature, write)

R6_PRIME_BUNDLE_ID = 'd89e7b99-ea61-40b1-b376-dbb90f004ef6'
R6_PRIME_POLICY_ID = '68a57070-df9f-51fe-9837-daa0858f68c1'
R6_PRIME_MODEL_ID = 'f7734c7c-1c9a-52dd-8e89-79f36b2f3815'
R6_PRIME_BINDING_PREFIX = '54dd1707'
R6_ASSET_ID = 'cb7e844b-01b1-453f-a6a2-8cf248979b9a'
SERVICE = Path.home() / 'Workspace/development/services/security/cyber-security'
PLIST = Path.home() / 'Library/LaunchAgents/com.xyh.cyber-security.backend.plist'
DERIVATION_TEXT = '由 r6′ 正式 final 派生，lab 只告警演示，未重新评价'


def stop_backend(db):
    """停写后再做全库快照；调用方负责在失败路径恢复常驻服务。"""
    require(subprocess.run(['/usr/sbin/lsof', '-nP', '-iTCP:18080', '-sTCP:LISTEN'],
                           capture_output=True).returncode != 0, 'IDE_BACKEND_STILL_RUNNING')
    subprocess.run(['/bin/launchctl', 'bootout', 'gui/' + str(os.getuid()) + '/com.xyh.cyber-security.backend'],
                   check=True, capture_output=True)
    for _ in range(40):
        if int(db.query("SELECT COUNT(*) FROM information_schema.PROCESSLIST "
                        "WHERE DB='cyber_security' AND ID<>CONNECTION_ID()")) == 0:
            return
        time.sleep(.5)
    raise RuntimeError('BUSINESS_DATABASE_IN_USE')


def start_backend():
    for _ in range(10):
        if subprocess.run(['/bin/launchctl', 'bootstrap', 'gui/' + str(os.getuid()), str(PLIST)],
                          capture_output=True).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('BACKEND_BOOTSTRAP_FAILED')
    wait_ready(SERVICE)


def validate_r6_prime_ids(bundle_id, policy_id, model_id):
    require(bundle_id == R6_PRIME_BUNDLE_ID, 'R6_PRIME_BUNDLE_ID_MISMATCH')
    require(policy_id == R6_PRIME_POLICY_ID, 'R6_PRIME_POLICY_ID_MISMATCH')
    require(model_id == R6_PRIME_MODEL_ID, 'R6_PRIME_MODEL_ID_MISMATCH')


def source_identity(db, schema):
    row = db.query(
        "SELECT b.public_id,p.public_id,b.subject_json,p.definition_json,p.status "
        "FROM guard_release_bundle b JOIN guard_decision_policy p ON p.id=b.policy_id "
        f"WHERE b.public_id='{R6_PRIME_BUNDLE_ID}'", schema).decode().splitlines()
    require(len(row) == 1, 'R6_PRIME_SOURCE_NOT_UNIQUE')
    bundle_id, policy_id, subject_json, definition_json, status = row[0].split('\t')
    subject, definition = json.loads(subject_json), json.loads(definition_json)
    validate_r6_prime_ids(bundle_id, policy_id, subject.get('modelId'))
    require(subject.get('policyId') == R6_PRIME_POLICY_ID and subject.get('environment') == 'authorized'
            and definition.get('mode') == 'alert_only'
            and status == 'reviewed', 'R6_PRIME_POLICY_INVALID')
    require('rule-inbound-20261018' in definition.get('policyVersion', '').split('+'),
            'R6_PRIME_POLICY_VERSION_INVALID')
    require(subject.get('capabilityIds') and
            set(subject['capabilityIds']) == set(definition.get('supportedCapabilityIds', [])),
            'R6_PRIME_CAPABILITIES_INVALID')
    return subject, definition


def active_r6_prime_binding(db, schema):
    rows = db.query(
        "SELECT g.public_id,g.status FROM guard_asset_binding g "
        "JOIN asset a ON a.id=g.asset_id JOIN guard_release_bundle b ON b.id=g.bundle_id "
        f"WHERE a.public_id='{R6_ASSET_ID}' AND b.public_id='{R6_PRIME_BUNDLE_ID}' "
        f"AND g.public_id LIKE '{R6_PRIME_BINDING_PREFIX}%'", schema).decode().splitlines()
    require(len(rows) == 1, 'R6_PRIME_BINDING_NOT_UNIQUE')
    binding_id, status = rows[0].split('\t')
    require(binding_id.startswith(R6_PRIME_BINDING_PREFIX) and status == 'active', 'R6_PRIME_BINDING_NOT_ACTIVE')
    return binding_id


def source_material(db, args):
    require(args.source == 'cyber_security', 'BUSINESS_SCHEMA_MISMATCH')
    subject, policy = source_identity(db, args.source)
    row = db.query(
        "SELECT e.report_ref,e.report_sha256,e.runner_identity,ep.public_id "
        "FROM guard_release_bundle b JOIN guard_evaluation_run e ON e.bundle_id=b.id "
        "JOIN guard_evaluation_plan ep ON ep.id=b.plan_id "
        f"WHERE b.public_id='{R6_PRIME_BUNDLE_ID}' AND e.run_kind='final' AND e.status='passed'",
        args.source).decode().splitlines()
    require(len(row) == 1, 'R6_PRIME_FINAL_NOT_UNIQUE')
    report_ref, expected_sha, runner, plan_id = row[0].split('\t')
    require(runner == SIGNER, 'R6_PRIME_SIGNER_MISMATCH')
    final_path = (args.artifacts / report_ref).resolve()
    require(final_path.is_relative_to(args.artifacts.resolve()) and sha(final_path) == expected_sha,
            'R6_PRIME_FINAL_HASH_MISMATCH')
    trust = load(protected(args.trust))
    envelope = load(final_path)
    verify_signature(envelope, trust)
    payload = envelope['payload']
    require(payload.get('subject') == subject and payload.get('subjectSha256') == digest(subject)
            and payload.get('runKind') == 'final' and payload.get('passed') is True,
            'R6_PRIME_FINAL_INVALID')
    require(payload.get('environment') == 'authorized', 'R6_PRIME_FINAL_ENVIRONMENT_INVALID')
    binding_id = active_r6_prime_binding(db, args.source)
    request = {key: deepcopy(subject[key]) for key in
               ('modelId', 'featureProfileSha256', 'extractorSha256', 'protocolVersions', 'capabilityIds')}
    request.update(policyId=R6_PRIME_POLICY_ID, evaluationPlanId=plan_id, environment='lab')
    inputs = {
        'jarSha256': sha(args.jar),
        'scriptSha256': sha(Path(__file__)),
        'sourceBundleId': R6_PRIME_BUNDLE_ID,
        'sourceBindingId': binding_id,
        'sourceSubjectSha256': digest(subject),
        'sourcePolicySha256': digest(policy),
        'sourceReportSha256': expected_sha,
        'trustSha256': sha(args.trust),
        'evaluatorSha256': sha(args.evaluator),
        'operatorSha256': sha(args.operator),
        'reviewerSha256': sha(args.reviewer),
        'requestSha256': digest(request),
    }
    return subject, policy, payload, {'reportRef': report_ref, 'sha256': expected_sha,
                                     'bundleId': R6_PRIME_BUNDLE_ID}, trust, request, inputs, binding_id


def validate_rehearsal_inputs(mode, rehearsal_path, inputs):
    if mode != 'business':
        return None
    require(rehearsal_path is not None, 'SUCCESSFUL_REHEARSAL_REQUIRED')
    rehearsal = load(rehearsal_path)
    require(rehearsal.get('passed') is True and rehearsal.get('mode') == 'rehearsal'
            and rehearsal.get('inputs') == inputs, 'REHEARSAL_INPUTS_MISMATCH')
    return rehearsal


def lab_final(source_final, lab_subject):
    final = deepcopy(source_final)
    final.update(subject=lab_subject, subjectSha256=digest(lab_subject), environment='lab')
    prior = final.get('derivation', [])
    if not isinstance(prior, list):
        prior = [prior]
    final['derivation'] = [*prior, {
        'sourceBundleId': R6_PRIME_BUNDLE_ID,
        'sourceSubjectSha256': digest(source_final['subject']),
        'description': DERIVATION_TEXT,
    }]
    require(final['evaluation'] == source_final['evaluation']
            and final['provenance'] == source_final['provenance'], 'R6_PRIME_CONCLUSIONS_CHANGED')
    return final


def expected_deltas(capability_count):
    require(capability_count > 0, 'R6_PRIME_CAPABILITIES_INVALID')
    return {'guard_decision_policy': 0, 'guard_release_bundle': 1,
            'guard_bundle_capability': capability_count, 'guard_evaluation_run': 1}


def validate_snapshot_schema(snapshot):
    actual = len(snapshot['tables'])
    require(actual == 89, f'DATABASE_TABLE_COUNT_MISMATCH:{actual}')


def validate_source_release_unchanged(before, after):
    for table in ('guard_release_bundle', 'guard_decision_policy', 'guard_asset_binding'):
        require(before['tables'].get(table) == after['tables'].get(table),
                'SOURCE_RELEASE_FACT_CHANGED:' + table)


def deltas(before, after, expected):
    require(before['schemaSha256'] == after['schemaSha256'], 'DATABASE_STRUCTURE_CHANGED')
    require(before['tables'].keys() == after['tables'].keys(), 'TABLE_SET_CHANGED')
    changes = {}
    for table, previous in before['tables'].items():
        current = after['tables'][table]
        if previous['sha256'] == current['sha256']:
            continue
        require(table in expected or table in ANCILLARY, 'UNEXPECTED_TABLE_CHANGED:' + table)
        changes[table] = current['count'] - previous['count']
        if table == 'sys_user':
            require(previous['invariantSha256'] == current['invariantSha256'],
                    'ACCOUNT_IDENTITY_OR_CREDENTIAL_CHANGED')
        elif table not in {'SPRING_SESSION', 'SPRING_SESSION_ATTRIBUTES', 'auth_login_throttle'}:
            altered = [key for key, value in previous['rows'].items() if current['rows'].get(key) != value]
            require(not altered, 'EXISTING_ROW_CHANGED:' + table)
    require({key: changes.get(key, 0) for key in expected} == expected, 'BUSINESS_DELTA_MISMATCH')
    changes.update({key: changes.get(key, 0) for key in expected})
    return changes, []


def step(name, session, path, body, revision, work, record):
    require('/activations' not in path, 'ACTIVATION_FORBIDDEN')
    require(path == '/release-bundles' or
            re.fullmatch(r'/release-bundles/[0-9a-f-]+/(imports|sealings|decisions)', path),
            'REGISTER_ENDPOINT_FORBIDDEN')
    result = session.v2(path, body, revision)
    write(work / (name + '.json'), result)
    record.setdefault('steps', []).append(name)
    return result


def register(args, db, schema, work, materials, record):
    source_subject, _, previous, derived, trust, request, inputs, source_binding = materials
    artifacts = args.artifacts if args.mode == 'business' else work / 'artifacts'
    artifacts.mkdir(mode=0o700, exist_ok=True)
    report_folder = artifacts / 'reports' / ('lab-alert-only-' + work.name)
    report_folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    with backend(args, db, schema, work, artifacts, record) as (base, context):
        op_credentials = load(protected(args.operator))
        reviewer_credentials = load(protected(args.reviewer))
        require(op_credentials.get('username') == 'g3-operator'
                and reviewer_credentials.get('username') == 'guard-reviewer'
                and op_credentials['username'] != reviewer_credentials['username'], 'ACTOR_MISMATCH')
        op = j1_run.Session(base, context).login({key: op_credentials[key] for key in ('username', 'password')})
        reviewer = j1_run.Session(base, context).login({key: reviewer_credentials[key]
                                                        for key in ('username', 'password')})
        bundle = step('01-bundle', op, '/release-bundles', request, None, work, record)
        bundle_id = str(uuid.UUID(bundle['id']))
        stored_rows = db.query(
            "SELECT subject_json FROM guard_release_bundle "
            f"WHERE public_id='{bundle_id}'", schema).decode().splitlines()
        require(len(stored_rows) == 1, 'LAB_SUBJECT_NOT_UNIQUE')
        subject = json.loads(stored_rows[0])
        require(subject.get('policyId') == R6_PRIME_POLICY_ID and subject.get('modelId') == R6_PRIME_MODEL_ID
                and subject.get('environment') == 'lab'
                and subject.get('capabilityIds') == source_subject.get('capabilityIds')
                and subject.get('policySha256') == inputs['sourcePolicySha256'], 'LAB_SUBJECT_MISMATCH')
        require(digest(subject) == bundle['subjectSha256'], 'LAB_SUBJECT_HASH_MISMATCH')
        final = lab_final(previous, subject)
        envelope = sign(final, private_key(protected(args.evaluator)), SIGNER)
        verify_signature(envelope, trust)
        report = report_folder / 'p6-final.json'
        write(report, envelope)
        imported = step('02-import', op, '/release-bundles/' + bundle_id + '/imports',
                        {'reportRef': report.relative_to(artifacts).as_posix(), 'sha256': sha(report),
                         'runnerIdentity': SIGNER}, None, work, record)
        require(imported['status'] == 'passed', 'FINAL_IMPORT_FAILED')
        sealed = step('03-seal', op, '/release-bundles/' + bundle_id + '/sealings',
                      {'evaluationIds': [imported['id']]}, bundle['revision'], work, record)
        approved = step('04-approve', reviewer, '/release-bundles/' + bundle_id + '/decisions',
                        {'decision': 'approve',
                         'reason': 'RD A5：由 r6′ 正式 final 派生，lab 只告警演示，未重新评价。'},
                        sealed['revision'], work, record)
        require(approved['status'] == 'approved', 'BUNDLE_APPROVAL_FAILED')
        binding_count = int(db.query(
            "SELECT COUNT(*) FROM guard_asset_binding "
            f"WHERE bundle_id=(SELECT id FROM guard_release_bundle WHERE public_id='{bundle_id}')", schema))
        require(binding_count == 0, 'LAB_BUNDLE_HAS_BINDING')
        require(active_r6_prime_binding(db, schema) == source_binding, 'R6_PRIME_BINDING_CHANGED')
        independent = db.query(
            "SELECT requested_by<>approved_by FROM guard_release_bundle "
            f"WHERE public_id='{bundle_id}'", schema).strip() == b'1'
        require(independent, 'REVIEWER_NOT_INDEPENDENT')
        record.update(bundleId=bundle_id, subjectSha256=bundle['subjectSha256'],
                      policyId=R6_PRIME_POLICY_ID, modelId=R6_PRIME_MODEL_ID,
                      evaluationId=imported['id'], reportSha256=sha(report),
                      reportRef=report.relative_to(artifacts).as_posix(), status='approved',
                      assetBindings=0, independentApproval=True, sourceBindingId=source_binding)


def main(args):
    os.umask(0o077)
    require(args.mode in ('rehearsal', 'business'), 'MODE_INVALID')
    if args.mode == 'business':
        require(args.rehearsal is not None, 'SUCCESSFUL_REHEARSAL_REQUIRED')
    args.work = args.work.resolve()
    args.work.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ('jar', 'artifacts', 'trust', 'evaluator', 'operator', 'reviewer'):
        setattr(args, name, getattr(args, name).resolve())
    db = Database(args.mysql_service)
    record = {'task': 'RD-A5', 'mode': args.mode, 'passed': False, 'startedAt': j1_run.stamp()}
    try:
        require(db.query("SELECT MAX(CAST(version AS UNSIGNED)) FROM flyway_schema_history WHERE success=1",
                         args.source).strip() == b'28', 'FLYWAY_VERSION_MISMATCH')
        materials = source_material(db, args)
        record['inputs'] = materials[6]
        validate_rehearsal_inputs(args.mode, args.rehearsal, record['inputs'])
        if args.mode == 'business':
            record['rehearsalSha256'] = sha(args.rehearsal)
        suffix = uuid.uuid4().hex[:16]
        schema = 'cyber_r6_' + ('rehearsal_' if args.mode == 'rehearsal' else 'restore_') + suffix
        backup_dir = args.mysql_service / 'backups' / ('20261028-rd-a5-' + args.mode + '-' + suffix)
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        record.update(backupDirectory=str(backup_dir), randomSchema=schema)
        stop_backend(db)
        record['backendStoppedAt'] = j1_run.stamp()
        try:
            before, backup = db.backup_restore(args.source, schema, backup_dir)
            validate_snapshot_schema(before)
        finally:
            if args.mode == 'rehearsal':
                start_backend()
                record['backendRestartedAt'] = j1_run.stamp()
        record.update(backupSha256=sha(backup), restoreProofSha256=sha(backup_dir / 'restore-proof.json'),
                      restoreVerified=True, sourceBeforeSha256=before['contentSha256'])
        if args.mode == 'business':
            db.drop_owned()
        target = schema if args.mode == 'rehearsal' else args.source
        register(args, db, target, args.work, materials, record)
        after = db.snapshot(target)
        write(args.work / 'target-after.json', after)
        record['tableDeltas'], record['modifiedTables'] = deltas(
            before, after, expected_deltas(len(materials[0]['capabilityIds'])))
        if args.mode == 'rehearsal':
            source_after = db.snapshot(args.source)
            validate_source_release_unchanged(before, source_after)
            record['businessChangedDuringRehearsal'] = (
                source_after['contentSha256'] != before['contentSha256'])
        active_r6_prime_binding(db, target)
        record['passed'] = True
    except Exception as exc:
        record['errorType'] = type(exc).__name__
        record['errorLocation'] = [{'file': Path(item.filename).name, 'line': item.lineno}
                                   for item in traceback.extract_tb(exc.__traceback__)]
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
        print(json.dumps({key: record[key] for key in
                          ('mode', 'passed', 'status', 'bundleId', 'errorCode', 'errorType', 'apiError')
                          if key in record}), flush=True)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=('rehearsal', 'business'), required=True)
    p.add_argument('--source', default='cyber_security')
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--jar', type=Path, required=True)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--trust', type=Path, required=True)
    p.add_argument('--evaluator', type=Path, required=True)
    p.add_argument('--operator', type=Path, required=True)
    p.add_argument('--reviewer', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    p.add_argument('--mysql-service', type=Path,
                   default=Path.home() / 'Workspace/development/services/databases/mysql-server-8.0.42')
    p.add_argument('--rehearsal', type=Path)
    return p


if __name__ == '__main__':
    main(parser().parse_args())
