"""部署工具的受控文件、命令和会话基础；错误只返回代码，不回显秘密或 HTTP 正文。"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import urllib.parse
import uuid
from scripts.p7.j1_run import Session

ROOT = Path(__file__).resolve().parents[2]


def require(ok, code):
    if not ok:
        raise ValueError(code)


def absolute(value):
    require(isinstance(value, (str, Path)) and not any(ord(c) < 32 for c in str(value)), 'PATH_INVALID')
    p = Path(value).expanduser()
    require(p.is_absolute() and '..' not in p.parts, 'ABSOLUTE_PATH_REQUIRED')
    require(not any(part.is_symlink() for part in [p, *p.parents]), 'SYMLINK_FORBIDDEN')
    return p


def private_dir(path):
    p = absolute(path)
    if not p.exists():
        private_dir(p.parent) if not p.parent.exists() else None
        p.mkdir(mode=0o700)
    require(p.is_dir() and p.stat().st_uid == os.getuid() and p.stat().st_mode & 0o777 == 0o700, 'PRIVATE_DIRECTORY_REQUIRED')
    return p


def private_file(path):
    p = absolute(path)
    require(p.is_file() and p.stat().st_uid == os.getuid() and p.stat().st_mode & 0o777 == 0o600, 'PRIVATE_FILE_REQUIRED')
    return p


def load(path):
    return json.loads(private_file(path).read_bytes())


def write(path, value, *, replace=False):
    """先写 0600 临时文件并 fsync；新增用 link 防止覆盖，状态更新原子替换。"""
    p = absolute(path)
    private_dir(p.parent)
    if p.exists():
        private_file(p)
        require(replace, 'FILE_ALREADY_EXISTS')
    data = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    fd, name = tempfile.mkstemp(prefix='.write-', dir=p.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(name, p)
        else:
            os.link(name, p)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv, *, cwd=None, env=None):
    result = subprocess.run([str(v) for v in argv], cwd=cwd, env=env, capture_output=True, timeout=900)
    require(result.returncode == 0, 'COMMAND_FAILED:' + Path(argv[0]).name)
    return result.stdout.decode().strip()


class Human(Session):
    """两个独立的 v2 人工会话；Keychain 读取口令，只在内存交给 TLS 登录。"""
    def login_keychain(self, identity):
        password = run(['/usr/bin/security', 'find-generic-password', '-s', identity['keychainService'], '-a', identity.get('keychainAccount', identity['username']), '-w'])
        return self.login({'username': identity['username'], 'password': password})

    def login(self, credentials):
        self.csrf = self.call('GET', '/api/v2/auth/csrf')['data']['token']
        self.call('POST', '/api/v2/auth/login', credentials, {'Idempotency-Key': str(uuid.uuid4())})
        self.csrf = self.call('GET', '/api/v2/auth/csrf')['data']['token']
        self.identity = self.call('GET', '/api/v2/auth/me')['data']['id']
        return self

    def request(self, method, path, body=None, *, key=None, revision=None):
        headers = {'Idempotency-Key': key} if key else {}
        if revision is not None:
            headers['If-Match'] = str(revision)
        return self.call(method, '/api/v2' + path, body, headers, (200, 201, 202))['data']


def sessions(plan):
    url = urllib.parse.urlsplit(plan['baseUrl'])
    require(url.scheme == 'https' and url.hostname in ('127.0.0.1', '::1') and not url.username and not url.password
            and not url.query and not url.fragment and url.path in ('', '/'), 'LOCAL_TLS_ENDPOINT_REQUIRED')
    context = ssl.create_default_context(cafile=str(private_file(plan['backendCA'])))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if 'backendTls' in plan:
        context.load_cert_chain(str(private_file(plan['backendTls']['certificateFile'])), str(private_file(plan['backendTls']['keyFile'])))
    a = Human(plan['baseUrl'], context).login_keychain(plan['applicant'])
    b = Human(plan['baseUrl'], context).login_keychain(plan['reviewer'])
    require(a.identity != b.identity, 'INDEPENDENT_REVIEWER_REQUIRED')
    return a, b


class Journal:
    """请求先落盘，响应（含一次性机器凭据）原子保存；重入强制完全相同的计划与请求。"""
    def __init__(self, directory, plan):
        self.directory = private_dir(directory)
        self.path = self.directory / 'state.json'
        self.data = load(self.path) if self.path.exists() else {'planSha256': digest(plan), 'steps': {}}
        require(self.data['planSha256'] == digest(plan), 'RESUME_PLAN_CHANGED')
        self.save()

    def machine(self, name, client, collection, body):
        """签发回包丢失时只查找本次独占资产的唯一机器，再走 B2 轮换；绝不重复创建身份。"""
        try:
            return self.step(name, client, '/' + collection, body)
        except RuntimeError as error:
            if 'CREDENTIAL_ALREADY_ISSUED' not in str(error):
                raise
        rows = client.request('GET', '/' + collection + '?assetId=' + body['assetId'] + '&limit=2')
        require(len(rows['items']) == 1 and not rows.get('nextCursor'), 'CREDENTIAL_RECOVERY_AMBIGUOUS')
        machine = rows['items'][0]
        require(machine['assetId'] == body['assetId'], 'CREDENTIAL_RECOVERY_SCOPE_MISMATCH')
        attempts = self.data.setdefault('credentialRecovery', {}).setdefault(name, [])
        if not attempts:
            attempts.append(str(uuid.uuid4()))
            self.save()
        try:
            result = client.request('POST', '/' + collection + '/' + machine['id'] + '/credential-rotations',
                {'reason': 'P8 enrollment interrupted credential delivery'}, key=attempts[-1])
        except RuntimeError as error:
            if 'CREDENTIAL_ALREADY_ISSUED' in str(error):
                # 本轮新凭据也丢失：保留审计，下一次使用新轮换键撤销未保存凭据。
                attempts.append(str(uuid.uuid4()))
                self.save()
            raise
        require('credential' in result, 'CREDENTIAL_RECOVERY_INVALID')
        result = {**result, 'id': machine['id']}
        self.data['steps'][name]['result'] = result
        self.save()
        return result

    def save(self):
        write(self.path, self.data, replace=self.path.exists())

    def step(self, name, client, path, body, revision=None):
        request = {'path': path, 'body': body, 'revision': revision, 'actor': client.identity}
        steps = self.data['steps']
        if name not in steps:
            steps[name] = {'request': request, 'key': str(uuid.uuid4())}
            self.save()
        row = steps[name]
        require(row['request'] == request, 'RESUME_REQUEST_CHANGED')
        if 'result' not in row:
            row['result'] = client.request('POST', path, body, key=row['key'], revision=revision)
            self.save()
        return row['result']


def safe_main(function):
    try:
        os.umask(0o077)
        return function() or 0
    except (Exception, KeyboardInterrupt) as exc:
        code = str(exc) if isinstance(exc, ValueError) and re.fullmatch(r'[A-Z0-9_:.\-]+', str(exc)) else 'DEPLOY_OPERATION_FAILED'
        http = re.search(r'HTTP ([0-9]{3}) ([A-Z][A-Z0-9_]+)$', str(exc))
        if http:
            code = 'HTTP_' + http[1] + '_' + http[2]
        print(json.dumps({'ok': False, 'error': code, 'errorType': type(exc).__name__}))
        return 1
