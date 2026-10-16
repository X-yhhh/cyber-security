"""R1 的克隆、deploy 进程和迁移核对；所有写入只针对本次登记的随机克隆。

复用精确保真备份，不允许业务库恢复、任意 JDBC 地址或外部 Spring 配置覆盖。
进程、配置与材料使用本次私有目录，退出核对 PID 与监听关闭，不安装系统服务。
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import time
import urllib.request
import zipfile

from scripts.p8 import e2e_env
from scripts.p8.register_alert_only import ident
from scripts.p8.toolkit import ROOT, private_dir, require, sha, write


def owned_schema(value):
    require(isinstance(value, str) and re.fullmatch(r'cyber_r1_clone_[0-9a-f]{32}', value), 'R1_CLONE_REQUIRED')
    return value


class Clone:
    """创建后才取得清理权；恢复只能作用于同一实例实际创建的 schema。"""
    def __init__(self, db, name):
        self.db, self.name, self.created = db, owned_schema(name), False

    def create(self, backup):
        require(not self.created, 'R1_CLONE_ALREADY_CREATED')
        try:
            return self.db.backup_restore('cyber_security', self.name, backup)
        finally:
            self.created = getattr(self.db, 'owned_schema', None) == self.name

    def query(self, sql, schema=None):
        require(self.created and schema in (None, self.name), 'R1_UNOWNED_SCHEMA')
        return self.db.query(sql, self.name).decode().strip()

    def drop(self):
        require(self.created, 'R1_UNOWNED_SCHEMA')
        self.db.query('DROP DATABASE ' + ident(owned_schema(self.name)))
        require(not self.db.query("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + self.name + "'"), 'R1_CLONE_DROP_FAILED')
        self.created = False

    def restore(self, backup):
        """只能使用先前校验的两份 SQL；drop 前核对全部摘要，备份永久保留。"""
        proof = json.loads((backup / 'restore-proof.json').read_bytes())
        for name, key in [('database.sql', 'backupSha256'), ('json-double-fidelity.sql', 'fidelitySha256')]:
            require(sha(backup / name) == proof[key], 'R1_BACKUP_HASH_MISMATCH')
        self.drop()
        self.db.query('CREATE DATABASE ' + ident(self.name) + ' CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin')
        self.created = True
        for name in ('database.sql', 'json-double-fidelity.sql'):
            with (backup / name).open('rb') as stream:
                result = subprocess.run(self.db.client + [self.name], env=self.db.env, stdin=stream, capture_output=True, timeout=300)
            require(result.returncode == 0, 'R1_ROLLBACK_RESTORE_FAILED')
        snapshot = self.db.snapshot(self.name)
        require(snapshot['contentSha256'] == proof['sourceSha256'], 'R1_ROLLBACK_PARITY_FAILED')
        return snapshot


def matrix(path):
    """直接解析唯一权限基线的第 5 节，不另维护可能漂移的硬编码矩阵。"""
    section = path.read_text().split('## 5. 角色 × 权限矩阵', 1)[1].split('\n## ', 1)[0]
    roles = list(e2e_env.ROLES.values())
    expected = {role: set() for role in roles}
    for line in section.splitlines():
        cells = [v.strip() for v in line.strip('|').split('|')]
        if len(cells) == 7 and re.fullmatch(r'`[a-z.]+`', cells[0]):
            for role, mark in zip(roles, cells[1:]):
                if mark == '●':
                    expected[role].add(cells[0].strip('`'))
    require(all(expected.values()), 'R1_PERMISSION_MATRIX_MISSING')
    return expected


def permissions(db, schema, users):
    require(len(users) == 3 and len(set(users)) == 3 and all(re.fullmatch(r'[A-Za-z0-9_-]+', u) for u in users), 'R1_THREE_RUNTIME_USERS_REQUIRED')
    names = ','.join("'" + u + "'" for u in users)
    sql = ('SELECT u.username,p.permission_key FROM sys_user u JOIN sys_user_role ur ON ur.user_id=u.id '
           'JOIN sys_role r ON r.id=ur.role_id JOIN sys_role_permission rp ON rp.role_id=r.id '
           "JOIN sys_permission p ON p.id=rp.permission_id WHERE u.status='active' AND r.status='active' AND p.status='active' "
           'AND u.username IN (' + names + ') ORDER BY u.username,p.permission_key')
    result = {u: set() for u in users}
    for row in db.query(sql, schema).decode().splitlines():
        user, key = row.split('\t')
        result[user].add(key)
    require(all(result.values()), 'R1_RUNTIME_USER_MISSING')
    return result


def migration_check(clone, before, users):
    expected = matrix(ROOT / 'docs/权限设计.md')
    actual = {role: set() for role in expected}
    for row in clone.query("SELECT r.role_key,p.permission_key FROM sys_role r JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id WHERE r.status='active' AND p.status='active'").splitlines():
        role, key = row.split('\t')
        if role in actual:
            actual[role].add(key)
    require(actual == expected, 'R1_ROLE_MATRIX_MISMATCH')
    require(clone.query('SELECT MAX(CAST(version AS UNSIGNED)) FROM flyway_schema_history WHERE success=1') == '27', 'R1_V27_REQUIRED')
    require(clone.query('SELECT COUNT(*) FROM sys_role WHERE builtin=TRUE') == '9', 'R1_BUILTIN_MISMATCH')
    require(clone.query("SELECT COUNT(*) FROM sys_role WHERE role_key IN ('asset_source_admin','response_approver','model_releaser') AND status<>'disabled'") == '0', 'R1_LEGACY_ROLE_ACTIVE')
    after = permissions(clone.db, clone.name, users)
    v2 = set.union(*expected.values())
    changes = {}
    for user in users:
        lost = (before[user] & v2) - after[user]
        require(not lost, 'R1_RUNTIME_PERMISSION_LOSS')
        changes[user] = dict(v2Before=sorted(before[user] & v2), v2After=sorted(after[user] & v2),
                             retiredV1=sorted(before[user] - v2), v2Lost=sorted(lost))
    return dict(version=27, matrixExact=True, builtinCount=9, runtimeUsers=changes)


def migration_version(jar):
    with zipfile.ZipFile(jar) as archive:
        versions = [int(m[1]) for name in archive.namelist() if (m := re.search(r'/V(\d+)__', name))]
    require(versions, 'R1_JAR_MIGRATIONS_MISSING')
    return max(versions)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    require(process.poll() is not None, 'R1_PROCESS_STOP_FAILED')


@contextmanager
def deploy(args, clone, work, artifacts, broker, tls, ipc, *, jar=None):
    """按正式 deploy 门启动独占回环 TLS 服务；显式关闭自动化和引导报告。"""
    require(clone.created, 'R1_UNOWNED_SCHEMA')
    work = private_dir(work)
    config = private_dir(work / 'config')
    ledger = private_dir(work / 'ledger')
    port = e2e_env.free_port()
    public = json.loads(args.trust.read_bytes())
    write(config / 'report-trust.json', public)
    write(config / 'protection.json', dict(protectedBudgetTargetIds=[], protectedServicePorts=[22, 53, 3389]))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    write(config / 'signing.der', key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write(config / 'client-ca.pem', (tls / 'ca.pem').read_bytes() + (ipc / 'ca.pem').read_bytes())
    prefix = 'r1.' + clone.name.removeprefix('cyber_r1_clone_')
    values = dict(DEPLOY_DB_URL='jdbc:mysql://127.0.0.1:3306/' + clone.name, DEPLOY_DB_USERNAME='root',
        DEPLOY_LOGIN_THROTTLE_HMAC_KEY=secrets.token_hex(32), DEPLOY_SERVER_PORT=port,
        DEPLOY_TLS_CLIENT_CA=config / 'client-ca.pem', DEPLOY_TLS_CERTIFICATE=tls / 'server.pem', DEPLOY_TLS_KEY=tls / 'server.key',
        DEPLOY_SIGNING_KEY_ID='r1-unused-no-automation', DEPLOY_SIGNING_KEY_FILE=config / 'signing.der',
        DEPLOY_REPORT_TRUST_FILE=config / 'report-trust.json', DEPLOY_PROTECTION_FILE=config / 'protection.json',
        DEPLOY_ARTIFACT_ROOT=artifacts, DEPLOY_LEDGER_ROOT=ledger, DEPLOY_WEB_ROOT=args.release / 'web',
        DEPLOY_QUEUE_PREFIX=prefix, DEPLOY_INGEST_QUEUE=prefix+'.ingest', DEPLOY_INGEST_DEAD_LETTER_QUEUE=prefix+'.dead',
        DEPLOY_INGEST_RETRY_QUEUE_PREFIX=prefix+'.retry', DEPLOY_RABBITMQ_VHOST=broker.name,
        DEPLOY_RABBITMQ_USERNAME=os.environ['RABBITMQ_IT_USERNAME'],
        DEPLOY_RABBITMQ_EXCHANGE=prefix+'.exchange', DEPLOY_RABBITMQ_DEAD_LETTER_EXCHANGE=prefix+'.dlx',
        DEPLOY_OUTBOX_RELAY_ENABLED='true', DEPLOY_CONSUMER_ENABLED='true')
    values.update({'DEPLOY_DB_PASSWORD': clone.db.env['MYSQL_PWD'],
                   'DEPLOY_RABBITMQ_PASSWORD': os.environ['RABBITMQ_IT_PASSWORD'],
                   'cyber.model-artifact.root': str(Path.home() / 'Workspace/deliveries'),
                   'spring.session.jdbc.cleanup-cron': '-'})
    # Java properties 的反斜杠必须转义；秘密从不进入命令行或标准输出。
    def escape(v):
        return str(v).replace('\\', '\\\\').replace('\r', '\\r').replace('\n', '\\n').replace(' ', '\\ ')
    write(config / 'deploy.properties', ''.join(k+'='+escape(v)+'\n' for k,v in values.items()).encode())
    java = args.java
    previous = jar is not None
    jar = jar or args.release / 'backend.jar'
    command = [str(java), '--enable-native-access=ALL-UNNAMED', '-Xmx1g', '-jar', str(jar),
               '--spring.config.location=classpath:/application.yml', '--spring.profiles.active=deploy']
    env = dict(e2e_env.backend_environment(), SPRING_PROFILES_ACTIVE='deploy', DEPLOY_CONFIG_FILE=str(config / 'deploy.properties'))
    context = ssl.create_default_context(cafile=str(tls / 'ca.pem'))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    base = 'https://127.0.0.1:' + str(port)
    proof = dict(pid=None, port=port, jarSha256=sha(jar), configSha256=sha(config / 'deploy.properties'), profile='deploy', automation=False)
    process = None
    try:
        with (work / 'backend.log').open('xb') as log:
            process = subprocess.Popen(command, env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        proof['pid'] = process.pid
        for _ in range(180):
            require(process.poll() is None, 'R1_DEPLOY_EXITED')
            try:
                with urllib.request.urlopen(base + '/actuator/health', context=context, timeout=2) as response:
                    if json.load(response)['status'] == 'UP':
                        proof['health'] = 'UP'
                        break
            except OSError:
                time.sleep(.5)
        else:
            raise ValueError('R1_DEPLOY_TIMEOUT')
        ready_path = '/api/v1/health/ready' if previous else '/health/ready'
        with urllib.request.urlopen(base + ready_path, context=context, timeout=5) as response:
            require(json.load(response)['data']['status'] == 'UP', 'R1_READINESS_FAILED')
            proof['ready'] = 'UP'
        if not previous:
            with urllib.request.urlopen(base + '/login', context=context, timeout=5) as response:
                require(response.read() == (args.release / 'web/index.html').read_bytes(), 'R1_WEB_NOT_HOSTED')
                proof['webHosted'] = True
        else:
            # V25 旧包尚无后端托管前端能力；回退只核对其已有健康、迁移与数据契约。
            proof['webHosted'] = 'not_supported_by_previous_jar'
        yield base, context, process, proof
    finally:
        if process:
            stop(process)
            proof['stopped'] = process.poll() is not None
            with socket.socket() as probe:
                proof['listenerClosed'] = probe.connect_ex(('127.0.0.1', port)) != 0
            require(proof['listenerClosed'], 'R1_LISTENER_NOT_CLOSED')
        write(work / 'process.json', proof)
