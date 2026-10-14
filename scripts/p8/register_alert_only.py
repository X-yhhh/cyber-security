#!/usr/bin/env python3
"""DB-9/A21：先随机库完整演练，再整库备份/恢复后将 r6 登记到 approved。

仅通过真实鉴权 API 登记、审查、导入、封存、批准；不提供激活接口、不建资产。
每次运行绑定 JAR、脚本、策略和正式 r5 final 的哈希；业务执行必须引用相同输入的成功演练。
失败保留受控备份与逐步记录，绝不自动覆盖业务库。只删除本次创建且名称校验通过的随机库。
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import traceback
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.p7 import j1_run
from scripts.p7.compose_policy import frozen_semantics, validate_policy
from scripts.p5.platform_report import private_key, sign
import rfc8785
from cryptography.hazmat.primitives import serialization

HOME = Path.home() / 'Workspace'
KEYS = HOME / 'ai/keys'
R5 = '0ec310fc-776e-48f6-8955-1e4f46ad8de8'
SOURCE_POLICY = '6adcb0d0-d8ff-527b-bb46-6970acbb4eb4'
R6_POLICY = 'de650e8c-372e-56c7-ba24-2114d5025627'
SIGNER = 'p6-evaluator/2026-10-10'
EXPECTED = {'guard_decision_policy': 1, 'guard_release_bundle': 1,
            'guard_bundle_capability': 4, 'guard_evaluation_run': 1}
ANCILLARY = {'guard_idempotency', 'audit_log', 'audit_resource_scope', 'SPRING_SESSION',
             'SPRING_SESSION_ATTRIBUTES', 'auth_login_throttle', 'sys_user'}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def load(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return j1_run.sha(path)


def digest(value):
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def write(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def ident(value):
    require(re.fullmatch(r'[A-Za-z0-9_]+', value), 'SQL_IDENTIFIER_INVALID')
    return '`' + value + '`'


def hex_value(column, kind):
    """HEX(number) 会取整；先转二进制文本，浮点列用 WKB 保存精确 IEEE 位。"""
    name = ident(column)
    return 'HEX(ST_AsWKB(POINT(' + name + ',0)))' if kind in {'float', 'double'} else 'HEX(CAST(' + name + ' AS BINARY))'


def normalized_ddl(value):
    # SHOW CREATE 在转储恢复后可能补全由 COLLATE 已唯一决定的 CHARACTER SET；有效结构不变。
    value = re.sub(r' CHARACTER SET ([a-z0-9]+)(?= COLLATE \1_)', '', value)
    return re.sub(r' AUTO_INCREMENT=\d+', '', value)


class JsonDouble(str):
    """保留 MySQL JSON 输出的 DOUBLE 数字文本，避免 Python 把整数与浮点类型混淆。"""


def double_paths(value, path='$'):
    if isinstance(value, JsonDouble):
        yield path, str(value)
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from double_paths(child, path + '.' + json.dumps(key, ensure_ascii=False))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from double_paths(child, path + '[' + str(index) + ']')


def protected(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file() and path.stat().st_uid == os.geteuid()
            and path.stat().st_mode & 0o7777 == 0o600, 'PRIVATE_FILE_UNSAFE')
    return path


class Database(j1_run.Database):
    """全表、一致读摘要：每列转 HEX 后组成 JSON，服务端逐行 SHA，避免导出秘密到日志。"""
    def snapshot(self, schema):
        ident(schema)
        columns = self.query("SELECT TABLE_NAME,COLUMN_NAME,COLUMN_KEY,DATA_TYPE FROM information_schema.COLUMNS "
                             f"WHERE TABLE_SCHEMA='{schema}' ORDER BY TABLE_NAME,ORDINAL_POSITION").decode().splitlines()
        layout = {}
        for line in columns:
            table, column, key, kind = line.split('\t')
            layout.setdefault(table, []).append((column, key, kind))
        statements = ["SET time_zone='+00:00'", 'SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ',
                      'START TRANSACTION WITH CONSISTENT SNAPSHOT']
        for table, fields in layout.items():
            values = ','.join(hex_value(col, kind) for col, _, kind in fields)
            keys = ','.join(hex_value(col, kind) for col, key, kind in fields if key == 'PRI')
            require(keys, 'SNAPSHOT_PRIMARY_KEY_REQUIRED')
            row = 'SHA2(JSON_ARRAY(' + values + '),256)'
            invariant = row
            if table == 'sys_user':
                stable = ','.join(hex_value(col, kind) for col, _, kind in fields if col not in {'last_login_at', 'updated_at'})
                invariant = "IF(username IN ('g3-operator','guard-reviewer'),SHA2(JSON_ARRAY(" + stable + '),256),' + row + ')'
            statements.append(f"SELECT '{table}',SHA2(JSON_ARRAY({keys}),256),{row},{invariant} FROM {ident(table)}")
        statements.append('COMMIT')
        output = self.query(';\n'.join(statements) + ';', schema).decode().splitlines()
        rows = {table: {} for table in layout}
        invariants = {table: {} for table in layout}
        for line in output:
            table, key, row, invariant = line.split('\t')
            require(key not in rows[table], 'SNAPSHOT_DUPLICATE_KEY')
            rows[table][key], invariants[table][key] = row, invariant
        ddl = []
        for table in layout:
            definition = self.query('SHOW CREATE TABLE ' + ident(table), schema).decode()
            ddl.append(normalized_ddl(definition))
        result = {'tables': {table: {'count': len(items), 'sha256': digest(items), 'rows': items,
                                    'invariantSha256': digest(invariants[table])} for table, items in rows.items()},
                  'schemaSha256': digest(ddl)}
        result['contentSha256'] = digest(result)
        return result

    def json_fidelity(self, source, path):
        """为 MySQL 8 JSON 文本解析的 1 ULP 漂移保存独立恢复 SQL，只在随机恢复库执行。

        SQL CAST AS DOUBLE 使用正常数值解析器，再由 JSON_SET 写入原精度；所有值来自备份时源库。
        不依赖恢复时源库存在。补充文件与 dump 一起绑定 SHA，完整行摘要仍须逐字相同。
        """
        columns = self.query("SELECT TABLE_NAME,COLUMN_NAME,COLUMN_KEY,DATA_TYPE,EXTRA FROM information_schema.COLUMNS "
                             f"WHERE TABLE_SCHEMA='{source}' ORDER BY TABLE_NAME,ORDINAL_POSITION").decode().splitlines()
        layout = {}
        for line in columns:
            table, column, key, kind, extra = line.split('\t')
            layout.setdefault(table, []).append((column, key, kind, extra))
        patched = 0
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
            stream.write("SET time_zone='+00:00';\nSTART TRANSACTION;\n")
            for table, fields in layout.items():
                keys = [(col, kind) for col, key, kind, _ in fields if key == 'PRI']
                for column, _, kind, _ in fields:
                    if kind != 'json':
                        continue
                    values = ','.join(hex_value(col, dtype) for col, dtype in keys)
                    sql = f'SELECT {values},HEX({ident(column)}) FROM {ident(table)} WHERE {ident(column)} IS NOT NULL AND '
                    sql += f'NOT ({ident(column)} <=> CAST(CAST({ident(column)} AS CHAR) AS JSON))'
                    for line in self.query(sql, source).decode().splitlines():
                        row = line.split('\t')
                        document = json.loads(bytes.fromhex(row[-1]), parse_float=JsonDouble)
                        replacements = list(double_paths(document))
                        require(replacements, 'JSON_RESTORE_NON_FLOAT_DIFFERENCE')
                        args = []
                        for pointer, number in replacements:
                            require(re.fullmatch(r'-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', number), 'JSON_NUMBER_INVALID')
                            args.extend(["CONVERT(UNHEX('" + pointer.encode().hex() + "') USING utf8mb4)", "CAST('" + number + "' AS DOUBLE)"])
                        assignment = ident(column) + '=JSON_SET(' + ident(column) + ',' + ','.join(args) + ')'
                        for col, _, _, extra in fields:
                            if 'on update' in extra.lower():
                                assignment += ',' + ident(col) + '=' + ident(col)
                        where = ' AND '.join(hex_value(col, dtype) + "='" + value + "'" for (col, dtype), value in zip(keys, row[:-1]))
                        stream.write('UPDATE ' + ident(table) + ' SET ' + assignment + ' WHERE ' + where + ';\n')
                        patched += 1
            stream.write('COMMIT;\n')
        return patched

    def backup_restore(self, source, target, folder):
        require(not self.query("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + target + "'"), 'RESTORE_SCHEMA_EXISTS')
        before = self.snapshot(source)
        write(folder / 'source-before.json', before)
        backup = folder / 'database.sql'
        command = [str(self.service / 'bin/mysqldump'), '--protocol=TCP', '--host=127.0.0.1', '--port=3306',
                   '--user=root', '--single-transaction', '--routines', '--triggers', '--events', '--hex-blob',
                   '--set-gtid-purged=OFF', '--no-tablespaces', source]
        with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            result = subprocess.run(command, env=self.env, stdout=stream, stderr=subprocess.PIPE, timeout=300)
        require(result.returncode == 0, 'BACKUP_FAILED')
        fidelity = folder / 'json-double-fidelity.sql'
        fidelity_rows = self.json_fidelity(source, fidelity)
        self.query(f'CREATE DATABASE {ident(target)} CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin')
        self.owned_schema = target
        with backup.open('rb') as stream:
            result = subprocess.run(self.client + [target], env=self.env, stdin=stream, capture_output=True, timeout=300)
        require(result.returncode == 0, 'RESTORE_FAILED')
        with fidelity.open('rb') as stream:
            result = subprocess.run(self.client + [target], env=self.env, stdin=stream, capture_output=True, timeout=300)
        require(result.returncode == 0, 'JSON_FIDELITY_RESTORE_FAILED')
        restored, current = self.snapshot(target), self.snapshot(source)
        write(folder / 'restored.json', restored)
        require(before == restored == current, 'RESTORE_OR_SOURCE_PARITY_FAILED')
        write(folder / 'restore-proof.json', {'backupSha256': sha(backup), 'sourceSha256': before['contentSha256'],
              'fidelitySha256': sha(fidelity), 'fidelityUpdates': fidelity_rows,
              'restoredSha256': restored['contentSha256'], 'tableCount': len(before['tables']), 'passed': True})
        return before, backup

    def drop_owned(self):
        schema = getattr(self, 'owned_schema', None)
        if schema:
            require(re.fullmatch(r'cyber_r6_(rehearsal|restore)_[0-9a-f]{16}', schema), 'REFUSE_DROP_SCHEMA')
            self.query('DROP DATABASE ' + ident(schema))
            require(not self.query("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + schema + "'"), 'SCHEMA_CLEANUP_FAILED')
            self.owned_schema = None


def verify_signature(envelope, trust):
    require(set(envelope) == {'payload', 'keyId', 'algorithm', 'signature'}
            and envelope['keyId'] == SIGNER and envelope['algorithm'] == 'Ed25519', 'REPORT_ENVELOPE_INVALID')
    key = serialization.load_der_public_key(base64.b64decode(trust[SIGNER], validate=True))
    value = envelope['signature']
    key.verify(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)), rfc8785.dumps(envelope['payload']))


def source_material(db, args):
    require(args.source == 'cyber_security', 'BUSINESS_SCHEMA_MISMATCH')
    row = db.query("SELECT b.subject_json,p.public_id,p.definition_json,p.status,e.report_ref,e.report_sha256,e.runner_identity,ep.public_id "
                   "FROM guard_release_bundle b JOIN guard_decision_policy p ON p.id=b.policy_id "
                   "JOIN guard_evaluation_run e ON e.bundle_id=b.id JOIN guard_evaluation_plan ep ON ep.id=b.plan_id "
                   f"WHERE b.public_id='{R5}' AND e.run_kind='final' AND e.status='passed'", args.source).decode().splitlines()
    require(len(row) == 1, 'R5_FINAL_NOT_UNIQUE')
    subject, policy_id, original, status, ref, expected, runner, plan_id = row[0].split('\t')
    require(policy_id == SOURCE_POLICY and status == 'reviewed' and runner == SIGNER, 'SOURCE_POLICY_OR_SIGNER_MISMATCH')
    source = json.loads(original)
    policy = load(args.policy)
    validate_policy(policy)
    require(policy['policyId'] == R6_POLICY and policy['mode'] == 'alert_only', 'R6_POLICY_MISMATCH')
    require(frozen_semantics(source) == frozen_semantics(policy), 'FROZEN_SEMANTICS_CHANGED')
    # frozen_semantics 有意略过若干部署字段；Q4 只准改 ID/版本/模式/自动开关，额外逐项证明。
    def only_switches(value):
        if isinstance(value, dict):
            return {k: only_switches(v) for k, v in value.items()
                    if k not in {'policyId', 'policyVersion', 'mode', 'autoEligible', 'modelAutoEligible'}}
        return [only_switches(v) for v in value] if isinstance(value, list) else value
    require(only_switches(source) == only_switches(policy), 'POLICY_OTHER_FIELDS_CHANGED')
    def disabled(value):
        if isinstance(value, dict):
            return all((v is False if k in {'autoEligible', 'modelAutoEligible'} else disabled(v)) for k, v in value.items())
        return all(disabled(v) for v in value) if isinstance(value, list) else True
    require(disabled(policy), 'AUTOMATIC_SOURCE_ENABLED')
    final_path = (args.artifacts / ref).resolve()
    require(final_path.is_relative_to(args.artifacts.resolve()) and sha(final_path) == expected, 'R5_FINAL_HASH_MISMATCH')
    trust = load(protected(args.trust))
    envelope = load(final_path)
    verify_signature(envelope, trust)
    payload, subject = envelope['payload'], json.loads(subject)
    require(payload['subject'] == subject and payload['subjectSha256'] == digest(subject)
            and payload['runKind'] == 'final' and payload['passed'] is True, 'R5_FINAL_SUBJECT_INVALID')
    require(set(subject['capabilityIds']) == set(policy['supportedCapabilityIds']) and len(subject['capabilityIds']) == 4, 'CAPABILITIES_CHANGED')
    request = {k: deepcopy(subject[k]) for k in ('modelId', 'featureProfileSha256', 'extractorSha256', 'protocolVersions', 'capabilityIds')}
    request.update(policyId=R6_POLICY, evaluationPlanId=plan_id, environment='authorized')
    request['protocolVersions']['health'] = 'host-guard-capture-health/1.0.0'
    inputs = {'jarSha256': sha(args.jar), 'scriptSha256': sha(Path(__file__)), 'policySha256': digest(policy),
              'sourcePolicySha256': digest(source), 'sourceReportSha256': expected, 'trustSha256': sha(args.trust),
              'requestSha256': digest(request)}
    return policy, request, payload, {'reportRef': ref, 'sha256': expected, 'bundleId': R5}, trust, inputs


@contextmanager
def backend(args, db, schema, work, artifacts, record):
    """只启动本次 mTLS 回环管理进程，关闭自动化、消息消费和定时会话清理；退出只停止自己的 PID。"""
    java = args.java_home / 'bin/java'
    version = subprocess.run([str(java), '-version'], capture_output=True, text=True, check=True)
    require('version "25.' in version.stdout + version.stderr, 'JDK25_REQUIRED')
    tls = work / 'tls'
    password = j1_run.tls_files(tls)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith(('SPRING_', 'SERVER_', 'CYBER_', 'DEPLOY_'))}
    env.update(DB_URL='jdbc:mysql://127.0.0.1:3306/' + schema, DB_USERNAME='root', DB_PASSWORD=db.env['MYSQL_PWD'],
               DB_POOL_SIZE='4', LOGIN_THROTTLE_HMAC_KEY=j1_run.secret('com.xyh.cyber-security.login-throttle-hmac'),
               SERVER_PORT=str(port), SERVER_ADDRESS='127.0.0.1', SESSION_COOKIE_SECURE='true',
               OUTBOX_RELAY_ENABLED='false', INGEST_CONSUMER_ENABLED='false', CYBER_DRIFT_ENABLED='false',
               SERVER_SSL_ENABLED='true', SERVER_SSL_CLIENT_AUTH='need', SERVER_SSL_ENABLED_PROTOCOLS='TLSv1.3',
               SERVER_SSL_KEY_STORE=str(tls / 'server.p12'), SERVER_SSL_KEY_STORE_TYPE='PKCS12',
               SERVER_SSL_KEY_STORE_PASSWORD=password, SERVER_SSL_TRUST_STORE=str(tls / 'trust.p12'),
               SERVER_SSL_TRUST_STORE_TYPE='PKCS12', SERVER_SSL_TRUST_STORE_PASSWORD=password)
    command = [str(java), '--enable-native-access=ALL-UNNAMED', '-Xmx1g',
               '-Dcyber.guard.automation-enabled=false', '-Dcyber.guard.bootstrap-reports-enabled=false',
               '-Dcyber.guard.lab-rehearsal-enabled=false', '-Dcyber.security.local-admin-bootstrap.enabled=false',
               '-Dcyber.guard.artifact-root=' + str(artifacts), '-Dcyber.guard.report-trust-file=' + str(args.trust),
               '-Dcyber.model-artifact.root=' + str(HOME / 'deliveries'),
               '-Dspring.session.jdbc.cleanup-cron=-', '-jar', str(args.jar)]
    with os.fdopen(os.open(work / 'backend.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    record['backend'] = {'pid': process.pid, 'port': port, 'jarSha256': sha(args.jar), 'javaVersion': version.stderr.splitlines()[0]}
    base, context = 'https://127.0.0.1:' + str(port), j1_run.ssl_context(tls)
    try:
        for _ in range(90):
            require(process.poll() is None, 'BACKEND_EXITED')
            try:
                with urllib.request.urlopen(base + '/actuator/health', context=context, timeout=2) as response:
                    if json.load(response)['status'] == 'UP':
                        break
            except OSError:
                time.sleep(1)
        else:
            raise RuntimeError('BACKEND_HEALTH_TIMEOUT')
        record['backend']['health'] = 'UP'
        yield base, context
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        record['backend']['stopped'] = process.poll() is not None
        with socket.socket() as probe:
            record['backend']['listenerClosed'] = probe.connect_ex(('127.0.0.1', port)) != 0


def deltas(before, after):
    require(before['schemaSha256'] == after['schemaSha256'], 'DATABASE_STRUCTURE_CHANGED')
    require(before['tables'].keys() == after['tables'].keys(), 'TABLE_SET_CHANGED')
    changes = {}
    for table, previous in before['tables'].items():
        current = after['tables'][table]
        if previous['sha256'] == current['sha256']:
            continue
        require(table in EXPECTED or table in ANCILLARY, 'UNEXPECTED_TABLE_CHANGED:' + table)
        changes[table] = current['count'] - previous['count']
        if table == 'sys_user':
            require(previous['invariantSha256'] == current['invariantSha256'], 'ACCOUNT_IDENTITY_OR_CREDENTIAL_CHANGED')
        elif table not in {'SPRING_SESSION', 'SPRING_SESSION_ATTRIBUTES', 'auth_login_throttle'}:
            require(all(current['rows'].get(k) == v for k, v in previous['rows'].items()), 'EXISTING_ROW_CHANGED:' + table)
    require({k: changes.get(k) for k in EXPECTED} == EXPECTED, 'BUSINESS_DELTA_MISMATCH')
    return changes


def register(args, db, schema, work, materials, record):
    policy, request, previous, derived, trust, inputs = materials
    artifacts = args.artifacts if args.mode == 'business' else work / 'artifacts'
    artifacts.mkdir(mode=0o700, exist_ok=True)
    report_folder = artifacts / 'reports' / ('r6-' + work.name)
    report_folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    require(not db.query(f"SELECT id FROM guard_decision_policy WHERE public_id='{R6_POLICY}'", schema), 'R6_POLICY_ALREADY_REGISTERED')
    with backend(args, db, schema, work, artifacts, record) as (base, context):
        op_credentials, reviewer_credentials = load(protected(args.operator)), load(protected(args.reviewer))
        require(op_credentials['username'] == 'g3-operator' and reviewer_credentials['username'] == 'guard-reviewer', 'ACTOR_MISMATCH')
        op = j1_run.Session(base, context).login(op_credentials)
        reviewer = j1_run.Session(base, context).login(reviewer_credentials)
        def step(name, session, path, body, revision=None):
            result = session.v2(path, body, revision)
            write(work / (name + '.json'), result)
            record.setdefault('steps', []).append(name)
            return result
        registered = step('01-policy', op, '/decision-policies', policy)
        require(registered['id'] == R6_POLICY and registered['status'] == 'draft', 'POLICY_REGISTRATION_MISMATCH')
        reviewed = step('02-review', reviewer, '/decision-policies/' + R6_POLICY + '/reviews',
                        {'decision': 'approve', 'reason': 'A21 r6：派生差异仅 ID/版本、模式和自动开关；冻结语义与部署字段一致，仅允许告警。'}, registered['revision'])
        require(reviewed['status'] == 'reviewed', 'POLICY_REVIEW_FAILED')
        bundle = step('03-bundle', op, '/release-bundles', request)
        bid = str(uuid.UUID(bundle['id']))
        subject = json.loads(db.query(f"SELECT subject_json FROM guard_release_bundle WHERE public_id='{bid}'", schema))
        require(digest(subject) == bundle['subjectSha256'] and subject['policySha256'] == inputs['policySha256'], 'R6_SUBJECT_MISMATCH')
        final = deepcopy(previous)
        final.update(subject=subject, subjectSha256=digest(subject), environment='authorized',
                     protocolVersions=subject['protocolVersions'], authorization='A21 2026-10-14 r6 登记至 approved；不激活',
                     sourceEligibility=[], derivedFrom=derived,
                     policyDerivation={'sourcePolicyId': SOURCE_POLICY, 'sourcePolicySha256': inputs['sourcePolicySha256'],
                         'frozenSemanticsEqual': True, 'changedFields': ['policyId', 'policyVersion', 'mode', 'autoEligible', 'modelAutoEligible']},
                     sourceDispositions={source: 'alert_only' for source in
                         [row['family'] + ':model:' for row in policy['familyPolicies']] +
                         [row['family'] + ':rule:' + row['ruleId'] for row in policy['rulePolicies']]},
                     limits='仅复用 r5 final 的离线 L1/P6 结论和 provenance；未读取 test 或重算指标。r6 现场只告警，无自动执行资格；不包含现场健康实测、PF、平台或 canary 证据；L2 未评价与 L3 慢速局限仍保留。')
        require(final['evaluation'] == previous['evaluation'] and final['provenance'] == previous['provenance'], 'P6_CONCLUSIONS_CHANGED')
        envelope = sign(final, private_key(protected(args.evaluator)), SIGNER)
        verify_signature(envelope, trust)
        report = report_folder / 'p6-final.json'
        write(report, envelope)
        evaluation = step('04-import', op, '/release-bundles/' + bid + '/imports',
                          {'reportRef': report.relative_to(artifacts).as_posix(), 'sha256': sha(report), 'runnerIdentity': SIGNER})
        require(evaluation['status'] == 'passed', 'FINAL_IMPORT_FAILED')
        sealed = step('05-seal', op, '/release-bundles/' + bid + '/sealings', {'evaluationIds': [evaluation['id']]}, bundle['revision'])
        approved = step('06-approve', reviewer, '/release-bundles/' + bid + '/decisions',
                        {'decision': 'approve', 'reason': 'A21 r6 独立批准：正式 final 绑定同 subject，冻结结论不变，仅告警；停在 approved，不激活、不建真实资产。'}, sealed['revision'])
        require(approved['status'] == 'approved', 'BUNDLE_APPROVAL_FAILED')
        binding_count = int(db.query(f"SELECT COUNT(*) FROM guard_asset_binding WHERE bundle_id=(SELECT id FROM guard_release_bundle WHERE public_id='{bid}')", schema))
        require(binding_count == 0, 'R6_HAS_ASSET_BINDING')
        independent = db.query(f"SELECT requested_by<>approved_by FROM guard_release_bundle WHERE public_id='{bid}'", schema).strip() == b'1'
        independent &= db.query(f"SELECT created_by<>reviewed_by FROM guard_decision_policy WHERE public_id='{R6_POLICY}'", schema).strip() == b'1'
        require(independent, 'REVIEWER_NOT_INDEPENDENT')
        record.update(bundleId=bid, subjectSha256=bundle['subjectSha256'], policyId=R6_POLICY, policySha256=inputs['policySha256'],
                      sealedManifestSha256=sealed['sealedManifestSha256'], evaluationId=evaluation['id'], reportSha256=sha(report),
                      reportRef=report.relative_to(artifacts).as_posix(), status='approved', assetBindings=0, independentApproval=True)


def main(args):
    os.umask(0o077)
    args.work = args.work.resolve()
    args.work.mkdir(mode=0o700, parents=True, exist_ok=False)
    args.jar, args.policy, args.artifacts = args.jar.resolve(), args.policy.resolve(), args.artifacts.resolve()
    db = Database(args.mysql_service)
    record = {'task': 'DB-9', 'mode': args.mode, 'authorization': 'A21', 'passed': False, 'startedAt': j1_run.stamp()}
    try:
        require(int(db.query("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE DB='cyber_security' AND ID<>CONNECTION_ID()")) == 0, 'BUSINESS_DATABASE_IN_USE')
        require(db.query("SELECT MAX(CAST(version AS UNSIGNED)) FROM flyway_schema_history WHERE success=1", args.source).strip() == b'25', 'FLYWAY_VERSION_MISMATCH')
        materials = source_material(db, args)
        record['inputs'] = materials[-1]
        if args.mode == 'business':
            require(args.rehearsal is not None, 'SUCCESSFUL_REHEARSAL_REQUIRED')
            rehearsal = load(args.rehearsal)
            require(rehearsal.get('passed') and rehearsal['mode'] == 'rehearsal' and rehearsal['inputs'] == record['inputs'], 'REHEARSAL_INPUTS_MISMATCH')
            record['rehearsalSha256'] = sha(args.rehearsal)
        suffix = uuid.uuid4().hex[:16]
        schema = 'cyber_r6_' + ('rehearsal_' if args.mode == 'rehearsal' else 'restore_') + suffix
        backup_dir = args.mysql_service / 'backups' / ('20261014-r6-' + args.mode + '-' + suffix)
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        record.update(backupDirectory=str(backup_dir), randomSchema=schema)
        before, backup = db.backup_restore(args.source, schema, backup_dir)
        record.update(backupSha256=sha(backup), restoreProofSha256=sha(backup_dir / 'restore-proof.json'),
                      restoreVerified=True, sourceBeforeSha256=before['contentSha256'])
        if args.mode == 'business':
            require(before['contentSha256'] == rehearsal['sourceBeforeSha256'], 'BUSINESS_CHANGED_SINCE_REHEARSAL')
            db.drop_owned()
        target = schema if args.mode == 'rehearsal' else args.source
        register(args, db, target, args.work, materials, record)
        after = db.snapshot(target)
        write(args.work / 'target-after.json', after)
        record['tableDeltas'] = deltas(before, after)
        if args.mode == 'rehearsal':
            require(before == db.snapshot(args.source), 'BUSINESS_CHANGED_DURING_REHEARSAL')
            record['businessUnchanged'] = True
        else:
            require(record['tableDeltas'] == rehearsal['tableDeltas'], 'BUSINESS_DELTAS_DIFFER_FROM_REHEARSAL')
        record['passed'] = True
    except Exception as exc:
        # 仅固定代码可打印；数据库和 HTTP 原始报文不回显，备份始终保留。
        record['errorType'] = type(exc).__name__
        record['errorLocation'] = [{'file': Path(frame.filename).name, 'line': frame.lineno}
                                   for frame in traceback.extract_tb(exc.__traceback__)]
        if isinstance(exc, RuntimeError) and re.fullmatch(r'[A-Z0-9_:]+', str(exc)):
            record['errorCode'] = str(exc)
        elif isinstance(exc, RuntimeError):
            match = re.search(r'HTTP (\d{3}) ([A-Z_]+|None)$', str(exc))
            if match:
                record['apiError'] = {'status': int(match[1]), 'code': match[2]}
        raise
    finally:
        db.drop_owned()
        record['temporarySchemaDeleted'] = getattr(db, 'owned_schema', None) is None
        record['finishedAt'] = j1_run.stamp()
        write(args.work / 'result.json', record)
        print(json.dumps({k: record[k] for k in ('mode', 'passed', 'status', 'bundleId', 'errorCode', 'errorType') if k in record}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['rehearsal', 'business'], required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--rehearsal', type=Path)
    parser.add_argument('--source', default='cyber_security')
    parser.add_argument('--artifacts', type=Path, default=HOME / 'ai/artifacts/cyber-guard')
    parser.add_argument('--mysql-service', type=Path, default=HOME / 'development/services/databases/mysql-server-8.0.42')
    parser.add_argument('--java-home', type=Path, default=HOME / 'development/runtimes/java/temurin-25.0.2/Contents/Home')
    parser.add_argument('--operator', type=Path, default=KEYS / 'cyber-guard-g3-operator/credentials.json')
    parser.add_argument('--reviewer', type=Path, default=KEYS / 'cyber-guard-reviewer/credentials.json')
    parser.add_argument('--trust', type=Path, default=KEYS / 'cyber-guard-trust/report-trust.json')
    parser.add_argument('--evaluator', type=Path, default=KEYS / 'cyber-guard-evaluator/evaluator.der')
    try:
        main(parser.parse_args())
    except Exception:
        raise SystemExit(1) from None
