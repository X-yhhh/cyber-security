#!/usr/bin/env python3
"""BE-14c：独立 vhost 的真实确认、超时、重试、死信、幂等与完整进程重启证据。

默认在同一已安装 RabbitMQ 的临时独立节点运行，重启只作用于本脚本创建的节点。
--existing 另验本机现有 broker 的独立 vhost；不重启共享节点，该结果不能单独代替完整重启验收。
Java 探针调用生产 publisher/listener/消费者，MySQL 使用随机 schema，结束清空消息并删除本次 vhost。
凭据仅从环境或受控临时文件读取；输出只含结论、摘要和本次对象身份。
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def require(value, code):
    if not value:
        raise RuntimeError(code)


def private_write(path, value):
    raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        stream.write(raw)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


class Management:
    def __init__(self, port, username, password):
        self.port, self.username = port, username
        self.token = base64.b64encode(f'{username}:{password}'.encode()).decode()

    def call(self, method, path, body=None):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}/api{path}', method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={'Authorization': 'Basic ' + self.token, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f'BROKER_MANAGEMENT_FAILED_HTTP_{exc.code}') from None

    def create_vhost(self, name):
        quoted = urllib.parse.quote(name, safe='')
        self.call('PUT', '/vhosts/' + quoted)
        self.call('PUT', '/permissions/' + quoted + '/' + urllib.parse.quote(self.username, safe=''),
                  {'configure': '.*', 'write': '.*', 'read': '.*'})

    def delete_vhost(self, name):
        require(name.startswith('cyber-security-deploy-acceptance-'), 'REFUSE_DELETE_OTHER_VHOST')
        self.call('DELETE', '/vhosts/' + urllib.parse.quote(name, safe=''))

    def other_topology(self, excluded):
        result = {}
        for kind in ('vhosts', 'exchanges', 'queues', 'bindings'):
            rows = self.call('GET', '/' + kind)
            clean = []
            for row in rows:
                if row.get('vhost', row.get('name') if kind == 'vhosts' else None) == excluded:
                    continue
                clean.append({k: row[k] for k in ('name', 'vhost', 'source', 'destination', 'destination_type',
                                                 'routing_key', 'arguments', 'durable', 'auto_delete', 'type') if k in row})
            result[kind] = sorted(clean, key=lambda item: json.dumps(item, sort_keys=True))
        return hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class PrivateNode:
    def __init__(self, args, work):
        self.service = args.rabbit_service.resolve()
        self.sbin = self.service / 'server/sbin'
        require((self.sbin / 'rabbitmq-server').is_file(), 'RABBITMQ_INSTALLATION_MISSING')
        self.name = 'cyber_deploy_' + secrets.token_hex(6) + '@localhost'
        self.directory = self.service / 'instances' / self.name.split('@')[0].replace('_', '-')
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.directory.chmod(0o700)
        for name in ('data', 'logs', 'run', 'config'):
            (self.directory / name).mkdir(mode=0o700)
        self.amqp_port, self.management_port, self.dist_port = free_port(), free_port(), free_port()
        require(len({self.amqp_port, self.management_port, self.dist_port}) == 3, 'PRIVATE_PORT_COLLISION')
        self.username, self.password = 'acceptance', secrets.token_urlsafe(32)
        config = self.directory / 'config'
        private_write(config / 'rabbitmq.conf', f'listeners.tcp.1 = 127.0.0.1:{self.amqp_port}\n'
                      f'management.tcp.ip = 127.0.0.1\nmanagement.tcp.port = {self.management_port}\n'
                      f'default_user = {self.username}\ndefault_pass = {self.password}\n'
                      'default_vhost = /\nloopback_users.guest = true\n')
        private_write(config / 'enabled_plugins', '[rabbitmq_management].\n')
        private_write(config / 'rabbitmq-env.conf', '# Environment provided only for this owned node.\n')
        private_write(config / 'erlang-cookie', secrets.token_hex(32))
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('RABBITMQ_', 'P8_'))}
        self.env.update(PATH=f'{args.erlang_bin}:{self.sbin}:' + os.environ.get('PATH', ''),
                        RABBITMQ_CONF_ENV_FILE=str(config / 'rabbitmq-env.conf'), RABBITMQ_CONFIG_FILE=str(config / 'rabbitmq'),
                        RABBITMQ_ENABLED_PLUGINS_FILE=str(config / 'enabled_plugins'),
                        RABBITMQ_NODENAME=self.name, RABBITMQ_NODE_IP_ADDRESS='127.0.0.1',
                        RABBITMQ_NODE_PORT=str(self.amqp_port), RABBITMQ_DIST_PORT=str(self.dist_port),
                        RABBITMQ_MNESIA_BASE=str(self.directory / 'data'),
                        RABBITMQ_LOG_BASE=str(self.directory / 'logs'),
                        RABBITMQ_PID_FILE=str(self.directory / 'run/node.pid'),
                        RABBITMQ_PLUGINS_EXPAND_DIR=str(self.directory / 'data/plugins'),
                        RABBITMQ_ERLANG_COOKIE=(config / 'erlang-cookie').read_text(),
                        RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS='+S 2:2 +A 4',
                        RABBITMQ_CTL_ERL_ARGS='+S 1:1 +A 1')
        self.management = Management(self.management_port, self.username, self.password)
        self.process = None
        self.generation = 0
        self.work = work

    def start(self):
        self.generation += 1
        log = self.work / f'node-{self.generation}.log'
        with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            self.process = subprocess.Popen([str(self.sbin / 'rabbitmq-server')], cwd=self.directory, env=self.env,
                                            stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            require(self.process.poll() is None, 'PRIVATE_NODE_START_FAILED')
            try:
                overview = self.management.call('GET', '/overview')
                nodes = self.management.call('GET', '/nodes')
                owned = [n for n in nodes if n.get('name') == self.name and n.get('running')]
                if owned:
                    self.version = overview['rabbitmq_version']
                    # management /nodes 不保证提供 os_pid；由本节点专用 PID 文件核对进程组。
                    self.pid = int((self.directory / 'run/node.pid').read_text().strip())
                    require(os.getpgid(self.pid) == self.process.pid, 'PRIVATE_NODE_PROCESS_IDENTITY_MISMATCH')
                    return
            except (OSError, RuntimeError):
                pass
            time.sleep(.5)
        raise RuntimeError('PRIVATE_NODE_START_TIMEOUT')

    def stop(self):
        if self.process is None or self.process.poll() is not None:
            return
        result = subprocess.run([str(self.sbin / 'rabbitmqctl'), '-n', self.name, 'stop'], env=self.env,
                                capture_output=True, timeout=45)
        if result.returncode:
            # 只终止本脚本以新进程组启动的节点，绝不匹配或停止共享 broker。
            os.killpg(self.process.pid, signal.SIGTERM)
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        require(self.process.poll() is not None, 'PRIVATE_NODE_STOP_FAILED')

    def restart(self):
        before = self.pid
        self.stop()
        self.start()
        return {'kind': 'isolated_node', 'pidBefore': before, 'pidAfter': self.pid,
                'node': self.name, 'version': self.version, 'passed': self.pid != before}


@contextmanager
def restart_control(callback, work):
    token = secrets.token_urlsafe(32)
    token_file = work / 'restart-token'
    private_write(token_file, token)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            if self.path != '/restart' or not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + token):
                self.send_error(403)
                return
            try:
                body = json.dumps(callback()).encode()
                self.send_response(200)
            except Exception:
                body = b'{"passed":false,"error":"OWNED_NODE_RESTART_FAILED"}'
                self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/restart', token_file
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main(args):
    os.umask(0o077)
    work = args.work.resolve()
    work.mkdir(parents=True, mode=0o700, exist_ok=False)
    work.chmod(0o700)
    java = args.java_home / 'bin/java'
    version = subprocess.run([str(java), '-version'], capture_output=True, text=True, check=True)
    require('version "25.' in version.stderr + version.stdout, 'JDK_25_REQUIRED')
    require(bool(os.environ.get('DB_TEST_BASE_URL')) and bool(os.environ.get('DB_TEST_USERNAME'))
            and 'DB_TEST_PASSWORD' in os.environ, 'ISOLATED_DB_TEST_SETTINGS_REQUIRED')
    name = 'cyber-security-deploy-acceptance-' + secrets.token_hex(8)
    node = None
    created = False
    record = {'task': 'BE-14c', 'vhost': name, 'runs': [], 'sharedNodeRestarted': False}
    try:
        if args.existing:
            username = os.environ['RABBITMQ_IT_USERNAME']
            password = os.environ['RABBITMQ_IT_PASSWORD']
            amqp_port = int(os.environ.get('RABBITMQ_IT_PORT', '5672'))
            management = Management(args.management_port, username, password)
            overview = management.call('GET', '/overview')
            record.update(mode='existing_vhost', rabbitmqVersion=overview['rabbitmq_version'])
            callback = lambda: {'kind': 'shared_node_unchanged', 'passed': True,
                                'limitation': '共享节点不重启；完整进程重启证据在 isolated_node 运行中提供'}
        else:
            node = PrivateNode(args, work)
            node.start()
            management, username, password, amqp_port = node.management, node.username, node.password, node.amqp_port
            record.update(mode='isolated_node', node=node.name, rabbitmqVersion=node.version, runtimeDirectory=str(node.directory))
            callback = node.restart
        topology_before = management.other_topology(name)
        require(name not in [v['name'] for v in management.call('GET', '/vhosts')], 'VHOST_ALREADY_EXISTS')
        management.create_vhost(name)
        created = True
        with restart_control(callback, work) as (url, token_file):
            for index in range(1, args.runs + 1):
                report = work / f'run-{index}.json'
                log = work / f'maven-{index}.log'
                env = dict(os.environ, JAVA_HOME=str(args.java_home),
                           PATH=str(args.java_home / 'bin') + ':' + os.environ.get('PATH', ''),
                           P8_BROKER_IT_ENABLED='true', P8_RABBIT_HOST='127.0.0.1', P8_RABBIT_PORT=str(amqp_port),
                           P8_RABBIT_VHOST=name, P8_RABBIT_USERNAME=username, P8_RABBIT_PASSWORD=password,
                           P8_QUEUE_PREFIX='q.guard.p8.' + secrets.token_hex(8), P8_BROKER_REPORT_FILE=str(report),
                           P8_RESTART_URL=url, P8_RESTART_TOKEN_FILE=str(token_file))
                with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
                    result = subprocess.run([str(args.maven), '-o', '-B', '-f', str(ROOT / 'backend/pom.xml'),
                                             '-Dtest=GuardIntegrationTest#deploymentBrokerAcceptance', 'test'],
                                            env=env, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
                require(result.returncode == 0 and report.is_file(), f'BROKER_PROBE_FAILED_RUN_{index}')
                value = json.loads(report.read_text())
                require(value.get('passed') is True, 'BROKER_PROBE_CHECK_FAILED')
                record['runs'].append({'index': index, 'report': report.name, 'sha256': sha(report), 'checks': value['checks'],
                                       'schema': value['schema'], 'productionClassesSha256': value['productionClassesSha256']})
                print(json.dumps({'event': 'broker_run_completed', 'run': index, 'passed': True, 'mode': record['mode']}), flush=True)
        record['consistentConclusions'] = all(r['checks'] == record['runs'][0]['checks'] for r in record['runs'])
        record['consistentProductionClasses'] = all(r['productionClassesSha256'] == record['runs'][0]['productionClassesSha256'] for r in record['runs'])
        queues = management.call('GET', '/queues/' + urllib.parse.quote(name, safe=''))
        record['messagesEmpty'] = all(q.get('messages', 0) == 0 for q in queues)
        record['otherTopologyUnchanged'] = topology_before == management.other_topology(name)
        record['passed'] = all(record[k] for k in ('consistentConclusions', 'consistentProductionClasses', 'messagesEmpty', 'otherTopologyUnchanged'))
    except Exception as error:
        record['passed'] = False
        record['errorType'] = type(error).__name__
        if isinstance(error, RuntimeError) and re.fullmatch(r'[A-Z0-9_]+', str(error)):
            record['errorCode'] = str(error)
        raise
    finally:
        cleanup_errors = []
        if created:
            try:
                management.delete_vhost(name)
                record['vhostDeleted'] = name not in [v['name'] for v in management.call('GET', '/vhosts')]
            except Exception:
                cleanup_errors.append('VHOST_CLEANUP_FAILED')
        if node is not None:
            try:
                node.stop()
                record['ownedNodeStopped'] = node.process is None or node.process.poll() is not None
            except Exception:
                cleanup_errors.append('OWNED_NODE_CLEANUP_FAILED')
        if cleanup_errors:
            record.update(passed=False, cleanupErrors=cleanup_errors)
        private_write(work / 'result.json', record)
    require(record.get('passed') and record.get('vhostDeleted'), 'BROKER_ACCEPTANCE_FAILED')
    private_write(work / 'SHA256SUMS', '\n'.join(f'{sha(path)}  {path.name}' for path in sorted(work.glob('*.json'))) + '\n')
    print(json.dumps({'passed': True, 'mode': record['mode'], 'runs': args.runs, 'result': str(work / 'result.json')}, ensure_ascii=False))


if __name__ == '__main__':
    home = Path.home() / 'Workspace/development'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--rabbit-service', type=Path, default=home / 'services/messaging/RabbitMQ-4.2.5')
    parser.add_argument('--erlang-bin', type=Path, default=Path('/opt/homebrew/opt/erlang@27/bin'))
    parser.add_argument('--java-home', type=Path, default=home / 'runtimes/java/temurin-25.0.2/Contents/Home')
    parser.add_argument('--maven', type=Path, default=home / 'toolchains/build/apache-maven-3.9.13/bin/mvn')
    parser.add_argument('--existing', action='store_true')
    parser.add_argument('--management-port', type=int, default=15672)
    parser.add_argument('--runs', type=int, choices=(2,), default=2)
    options = parser.parse_args()
    try:
        main(options)
    except Exception as error:
        # 异常文本/子进程环境可能包含凭据，终端只发固定错误类别；私有证据目录保留。
        print(json.dumps({'passed': False, 'errorType': type(error).__name__, 'resultDirectory': str(options.work)}), flush=True)
        raise SystemExit(1) from None
