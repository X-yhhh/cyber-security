#!/usr/bin/env python3
"""T1：真实 JAR + dist 的一次性预览环境，仅创建随机隔离 schema/vhost。

DB_TEST_* 与 RABBITMQ_IT_* 由调用环境注入；不读取业务库，不启动执行器。
失败只输出稳定错误码，秘密仅在内存或本次 0700/0600 目录中；finally 清理拥有的资源。
"""
from __future__ import annotations

import argparse
import base64
import functools
import hashlib
import http.client
import http.cookiejar
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
ROLES = dict(admin='platform_admin', analyst='security_analyst', reviewer='security_reviewer',
             operator='model_operator', evidence='evidence_reviewer', auditor='auditor')


def require(value, code):
    if not value:
        raise RuntimeError(code)


def uid():
    return str(uuid.uuid4())


def private_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(value, stream, ensure_ascii=False)


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def owned_schema(name):
    require(re.fullmatch(r'cyber_it_e2e_[0-9a-f]{32}', name), 'REFUSE_OTHER_SCHEMA')
    return name


class Database:
    """mysql 命令只连显式的本机测试服务，SQL 通过 stdin，错误与连接凭据不打印。"""
    def __init__(self):
        raw = os.environ.get('DB_TEST_BASE_URL', '')
        parsed = urllib.parse.urlsplit(raw.removeprefix('jdbc:'))
        require(parsed.scheme == 'mysql' and parsed.hostname in ('127.0.0.1', 'localhost')
                and parsed.path in ('', '/') and not parsed.query and not parsed.username,
                'LOOPBACK_DB_TEST_BASE_URL_REQUIRED')
        require(os.environ.get('DB_TEST_USERNAME') and 'DB_TEST_PASSWORD' in os.environ, 'DB_TEST_SETTINGS_REQUIRED')
        executable = os.environ.get('E2E_MYSQL') or shutil.which('mysql')
        require(executable, 'MYSQL_CLIENT_REQUIRED')
        self.url = raw.rstrip('/')
        self.env = dict(os.environ, MYSQL_PWD=os.environ['DB_TEST_PASSWORD'])
        self.command = [executable, '--protocol=TCP', '--host=' + parsed.hostname,
                        '--port=' + str(parsed.port or 3306), '--user=' + os.environ['DB_TEST_USERNAME'],
                        '--batch', '--raw', '--skip-column-names', '--connect-timeout=5', '--default-character-set=utf8mb4']

    def query(self, sql, schema=None):
        if schema:
            owned_schema(schema)
        result = subprocess.run(self.command + ([schema] if schema else []), input=sql, text=True,
                                env=self.env, capture_output=True, timeout=45)
        require(result.returncode == 0, 'E2E_SQL_FAILED')
        return result.stdout.strip()

    def drop(self, schema):
        self.query('DROP DATABASE IF EXISTS `' + owned_schema(schema) + '`')
        require(not self.query("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + schema + "'"),
                'E2E_SCHEMA_CLEANUP_FAILED')


class Human:
    """独立真实 v2 会话，不把 Cookie、CSRF 或响应载荷带入诊断信息。"""
    def __init__(self, base):
        self.base = base
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.cookies))
        self.token = None

    def call(self, method, path, body=None, revision=None, credential=None):
        headers = {'Content-Type': 'application/json', 'Idempotency-Key': uid()}
        if self.token:
            headers['X-CSRF-TOKEN'] = self.token
        if revision is not None:
            headers['If-Match'] = str(revision)
        if credential:
            headers['Authorization'] = 'Bearer ' + credential
        request = urllib.request.Request(self.base + path, method=method, headers=headers,
                                         data=None if body is None else json.dumps(body).encode())
        try:
            with self.opener.open(request, timeout=30) as response:
                return json.load(response)['data']
        except urllib.error.HTTPError as error:
            try:
                code = json.load(error).get('error', {}).get('code', 'UNKNOWN')
            except (ValueError, AttributeError):
                code = 'UNKNOWN'
            raise RuntimeError(f'E2E_HTTP_{error.code}_{code}') from None

    def login(self, account):
        self.token = self.call('GET', '/api/v2/auth/csrf')['token']
        self.call('POST', '/api/v2/auth/login', account)
        self.token = self.call('GET', '/api/v2/auth/csrf')['token']
        return self

    def v2(self, path, body=None, revision=None, method=None):
        return self.call(method or ('GET' if body is None else 'POST'), '/api/v2' + path, body, revision)


class Broker:
    def __init__(self):
        require(os.environ.get('RABBITMQ_IT_USERNAME') and 'RABBITMQ_IT_PASSWORD' in os.environ, 'BROKER_TEST_SETTINGS_REQUIRED')
        self.name = 'cyber-security-e2e-' + uuid.uuid4().hex
        self.base = os.environ.get('E2E_BROKER_MANAGEMENT_URL', 'http://127.0.0.1:15672')
        parsed = urllib.parse.urlsplit(self.base)
        require(parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1') and not parsed.username,
                'LOOPBACK_BROKER_REQUIRED')
        self.token = base64.b64encode((os.environ['RABBITMQ_IT_USERNAME'] + ':' + os.environ['RABBITMQ_IT_PASSWORD']).encode()).decode()

    def call(self, method, path, body=None):
        request = urllib.request.Request(self.base + '/api' + path, method=method,
                                         headers={'Authorization': 'Basic ' + self.token, 'Content-Type': 'application/json'},
                                         data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as response:
                return json.loads(response.read() or 'null')
        except urllib.error.HTTPError as error:
            raise RuntimeError(f'E2E_BROKER_HTTP_{error.code}') from None

    def create(self):
        self.call('PUT', '/vhosts/' + self.name)
        self.call('PUT', '/permissions/' + self.name + '/' + urllib.parse.quote(os.environ['RABBITMQ_IT_USERNAME'], safe=''),
                  dict(configure='.*', write='.*', read='.*'))

    def drop(self):
        require(re.fullmatch(r'cyber-security-e2e-[0-9a-f]{32}', self.name), 'REFUSE_OTHER_VHOST')
        if self.name in [v['name'] for v in self.call('GET', '/vhosts')]:
            self.call('DELETE', '/vhosts/' + self.name)
        require(self.name not in [v['name'] for v in self.call('GET', '/vhosts')], 'E2E_VHOST_CLEANUP_FAILED')


class Preview(SimpleHTTPRequestHandler):
    """仅回环监听；dist 的 SPA 回退与 API 同源代理，不拦截或替换业务响应。"""
    backend_port = 0

    def log_message(self, *_):
        pass

    def handle_request(self):
        if self.path.startswith(('/api/', '/health/', '/actuator/')):
            length = int(self.headers.get('Content-Length', '0'))
            if length > 2 * 1024 * 1024:
                self.send_error(413)
                return
            connection = http.client.HTTPConnection('127.0.0.1', self.backend_port, timeout=45)
            try:
                headers = {k: v for k, v in self.headers.items() if k.lower() not in ('host', 'connection', 'transfer-encoding')}
                connection.request(self.command, self.path, self.rfile.read(length) if length else None, headers)
                response = connection.getresponse()
                content = response.read()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in ('content-length', 'transfer-encoding', 'connection'):
                        self.send_header(key, value)
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                if self.command != 'HEAD':
                    self.wfile.write(content)
            finally:
                connection.close()
        else:
            if self.command not in ('GET', 'HEAD'):
                self.send_error(405)
                return
            self.path = self.path if Path(self.translate_path(self.path)).is_file() else '/index.html'
            if self.command == 'HEAD':
                super().do_HEAD()
            else:
                super().do_GET()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = handle_request


class PreviewServer(ThreadingHTTPServer):
    # dist 的动态分块会同时建立多个短连接；避免默认 backlog=5 拒绝正常浏览器请求。
    request_queue_size = 128
    daemon_threads = True


def backend_environment():
    """只继承工具所需环境，阻止外部 Spring/Java 配置覆盖一次性服务的隔离边界。"""
    allowed = ('PATH', 'JAVA_HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TZ', 'HOME')
    return {key: value for key, value in os.environ.items() if key in allowed}


def seed_accounts(db, schema):
    import bcrypt
    accounts = {}
    # 同一次运行共享随机口令以降低 bcrypt 设置成本；每个账号仍只有一个角色。
    password = secrets.token_urlsafe(24)
    encoded = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    for alias, role in ROLES.items():
        name = 'demo-' + alias
        db.query(f"INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES('{uid()}','{name}','T1 {alias}','{encoded}','active');"
                 f"INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT u.id,r.id,'global','*' FROM sys_user u,sys_role r WHERE u.username='{name}' AND r.role_key='{role}';", schema)
        accounts[alias] = dict(username=name, password=password)
    return accounts


def build(java, work):
    # 删除旧 class 后再打包，避免分支整合/接口退役后把已删除代码带进预览 JAR。
    for name, command, cwd in [('jar', ['mvn', '-q', '-DskipTests', 'clean', 'package'], ROOT / 'backend'),
                               ('dist', ['npm', 'run', 'build'], ROOT / 'frontend')]:
        with (work / (name + '-build.log')).open('wb') as log:
            result = subprocess.run(command, cwd=cwd, env=dict(os.environ, JAVA_HOME=str(java.parent.parent)),
                                    stdout=log, stderr=subprocess.STDOUT, timeout=300)
        require(result.returncode == 0, 'E2E_BUILD_FAILED_' + name.upper())


def run(args):
    from e2e_fixtures import catalog
    os.umask(0o077)
    java = Path(os.environ.get('JAVA_HOME', '')) / 'bin/java'
    require(java.is_file(), 'JAVA_HOME_JDK_25_REQUIRED')
    version = subprocess.run([str(java), '-version'], capture_output=True, text=True, check=True)
    require('version "25.' in version.stdout + version.stderr, 'JDK_25_REQUIRED')
    db, broker = Database(), Broker()
    work = ROOT / '.cache/t1-e2e' / uuid.uuid4().hex
    work.mkdir(parents=True, mode=0o700)
    schema = owned_schema('cyber_it_e2e_' + uuid.uuid4().hex)
    process = server = browser = None
    schema_created = broker_created = False
    ready = False
    result_code = 1
    cleanup = dict(schema=False, vhost=False, backend=False, preview=False, redaction=False, secrets=False)
    try:
        artifacts = work / 'private'
        artifacts.mkdir(mode=0o700)
        private_json(artifacts / 'secrets.json', [os.environ['DB_TEST_PASSWORD'], os.environ['RABBITMQ_IT_PASSWORD']])
        if not args.skip_build:
            build(java, work)
        jars = list((ROOT / 'backend/target').glob('*.jar'))
        require(len(jars) == 1 and (ROOT / 'frontend/dist/index.html').is_file(), 'BUILD_OUTPUT_REQUIRED')
        jar = jars[0]
        db.query('CREATE DATABASE `' + schema + '` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin')
        schema_created = True
        broker_created = True
        broker.create()
        port = free_port()
        from e2e_fixtures import signing_files
        signing_files(artifacts)
        env = dict(backend_environment(), DB_URL=db.url + '/' + schema, DB_USERNAME=os.environ['DB_TEST_USERNAME'],
                   DB_PASSWORD=os.environ['DB_TEST_PASSWORD'], SERVER_ADDRESS='127.0.0.1', SERVER_PORT=str(port),
                   SPRING_PROFILES_ACTIVE='', LOGIN_THROTTLE_HMAC_KEY=secrets.token_hex(32), LOCAL_ADMIN_BOOTSTRAP_ENABLED='false',
                   OUTBOX_RELAY_ENABLED='true', INGEST_CONSUMER_ENABLED='true', CYBER_DRIFT_ENABLED='false',
                   RABBITMQ_HOST='127.0.0.1', RABBITMQ_PORT=os.environ.get('RABBITMQ_IT_PORT', '5672'),
                   RABBITMQ_VHOST=broker.name, RABBITMQ_USERNAME=os.environ['RABBITMQ_IT_USERNAME'], RABBITMQ_PASSWORD=os.environ['RABBITMQ_IT_PASSWORD'])
        command = [str(java), '-jar', str(jar), '--spring.config.location=classpath:/application.yml',
                   '--spring.profiles.active=', '--cyber.security.local-admin-bootstrap.enabled=false',
                   '--cyber.guard.automation-enabled=true', '--cyber.guard.bootstrap-reports-enabled=true',
                   '--cyber.guard.signing-key-id=', '--cyber.guard.signing-key-file=',
                   '--cyber.guard.artifact-root=' + str(artifacts), '--cyber.guard.report-trust-file=' + str(artifacts / 'trust.json'),
                   '--cyber.guard.protection-file=' + str(artifacts / 'protection.json'), '--cyber.guard.queue-prefix=q.guard.t1.' + uuid.uuid4().hex]
        with (work / 'backend.log').open('wb') as log:
            process = subprocess.Popen(command, env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        backend = 'http://127.0.0.1:' + str(port)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            require(process.poll() is None, 'E2E_BACKEND_EXITED')
            try:
                Human(backend).call('GET', '/api/v2/auth/csrf')
                break
            except (OSError, RuntimeError):
                time.sleep(.3)
        else:
            raise RuntimeError('E2E_BACKEND_TIMEOUT')
        accounts = seed_accounts(db, schema)
        with (artifacts / 'secrets.json').open('w') as registry:
            json.dump([a['password'] for a in accounts.values()] +
                      [os.environ['DB_TEST_PASSWORD'], os.environ['RABBITMQ_IT_PASSWORD']], registry)
        fixtures = catalog(backend, accounts, artifacts)
        ready = True
        Preview.backend_port = port
        server = PreviewServer(('127.0.0.1', 0), functools.partial(Preview, directory=str(ROOT / 'frontend/dist')))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = 'http://127.0.0.1:' + str(server.server_port)
        private_json(artifacts / 'state.json', dict(baseURL=base, accounts=accounts, fixtures=fixtures))
        private_json(work / 'runtime.json', dict(schema=schema, vhost=broker.name, jarSha256=hashlib.sha256(jar.read_bytes()).hexdigest(),
                                                commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                                                backendPid=process.pid, backendPort=port, previewPort=server.server_port, javaVersion='25', synthetic=True))
        print('T1 isolated environment ready; evidence: ' + str(work.relative_to(ROOT)), flush=True)
        env = dict(os.environ, E2E_STATE_FILE=str(artifacts / 'state.json'), E2E_BASE_URL=base, E2E_WORK=str(work),
                   E2E_SCHEMA=schema, E2E_ARTIFACT_ROOT=str(artifacts))
        # Playwright 的断言可能回显 fill 参数；先写私有权限日志，脱敏成功后才向终端输出。
        with (work / 'playwright.log').open('wb') as log:
            browser = subprocess.Popen([str(ROOT / 'frontend/node_modules/.bin/playwright'), 'test', *args.playwright],
                                       cwd=ROOT / 'frontend', env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            result_code = browser.wait()
    finally:
        if browser and browser.poll() is None:
            os.killpg(browser.pid, signal.SIGTERM)
            try:
                browser.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(browser.pid, signal.SIGKILL)
                browser.wait(timeout=5)
        if server:
            server.shutdown()
            server.server_close()
        cleanup['preview'] = True
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        cleanup['backend'] = process is None or process.poll() is not None
        if ready:
            # 与浏览器结果独立保存零命令证明；即使前半段测试失败也不得漏查。
            try:
                count = int(db.query("SELECT COUNT(*) FROM guard_command WHERE key_id<>'t1-ui-synthetic'", schema))
                private_json(work / 'safety.json', dict(issuedCommands=count, executorStarted=False, synthetic=True))
                if count:
                    result_code = 1
                    print('E2E_UNEXPECTED_COMMAND_ISSUED', file=sys.stderr)
            except Exception:
                result_code = 1
                print('E2E_COMMAND_CHECK_FAILED', file=sys.stderr)
        for key, created, operation in [('schema', schema_created, lambda: db.drop(schema)), ('vhost', broker_created, broker.drop)]:
            try:
                if created:
                    operation()
                cleanup[key] = True
            except Exception:
                print('E2E_CLEANUP_FAILED_' + key.upper(), file=sys.stderr)
        # 日志、失败 trace 和 error-context 在删除凭据前统一脱敏；保留 ZIP 结构可供 trace viewer 使用。
        from e2e_redact import redact_artifacts
        try:
            redact_artifacts(work)
            cleanup['redaction'] = True
        except Exception:
            print('E2E_REDACTION_FAILED', file=sys.stderr)
            # 脱敏失败时 fail-closed：移除本次生成的诊断副本，不留下未经清理的凭据。
            for generated in list(work.iterdir()):
                if generated.name == 'private':
                    continue
                if generated.is_dir():
                    shutil.rmtree(generated)
                else:
                    generated.unlink()
        if (work / 'private').is_dir():
            shutil.rmtree(work / 'private')
        cleanup['secrets'] = not (work / 'private').exists()
        private_json(work / 'cleanup.json', cleanup)
        require(all(cleanup.values()), 'E2E_CLEANUP_INCOMPLETE')
    if (work / 'playwright.log').is_file():
        print((work / 'playwright.log').read_text(), end='')
    return result_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-build', action='store_true', help='复用当前 worktree 已构建的 JAR/dist')
    args, rest = parser.parse_known_args()
    args.playwright = rest[1:] if rest[:1] == ['--'] else rest
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        return run(args)
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, RuntimeError) else 'E2E_ENVIRONMENT_FAILED', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
