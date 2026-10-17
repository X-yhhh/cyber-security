"""演示工具的纯配置边界：离线校验不取密、不登录、不运行子进程。"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
from datetime import datetime, timezone
import uuid

ROOT = Path(__file__).resolve().parents[2]
VERSION = 'hostguard-demo/1'
FAMILIES = {'S0': 'normal', 'S1': 'port_scan', 'S2': 'brute_force', 'S3': 'dos_slow', 'S4': 'dos_flood'}
CLEANUP = ('attackStopped', 'captureStopped', 'targetsStopped', 'pfEmpty', 'aliasesUnchanged',
           'rootVerified', 'authorizationRevoked', 'bindingSuspended', 'bundleActive', 'budgetRecovered', 'en0Unchanged')


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def instant(value):
    t = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(t.tzinfo is not None, 'TIMEZONE_REQUIRED')
    return t.timestamp()


def uid(value):
    require(str(uuid.UUID(value)) == value, 'UUID_INVALID')
    return value


def address(value):
    a = ipaddress.ip_address(value)
    require(a.version == 4 and a in ipaddress.ip_network('100.64.0.0/10') and str(a) == value, 'TAILSCALE_IPV4_REQUIRED')
    return value


def path(value):
    p = Path(value).expanduser()
    require(p.is_absolute() and '..' not in p.parts and not any(v.is_symlink() for v in (p, *p.parents)), 'PATH_UNSAFE')
    require(not any(ord(ch) < 32 for ch in str(p)), 'PATH_UNSAFE')
    return p


def private(pathname, directory=False):
    p = path(pathname)
    require(p.is_dir() if directory else p.is_file(), 'PRIVATE_PATH_MISSING')
    if os.name != 'nt':
        require(p.stat().st_uid == os.getuid() and p.stat().st_mode & 0o777 == (0o700 if directory else 0o600), 'PRIVATE_MODE_REQUIRED')
    return p


def load(pathname, *, secret=True):
    p = private(pathname) if secret else Path(pathname)
    require(p.stat().st_size <= 4 << 20, 'JSON_TOO_LARGE')
    def pairs(rows):
        result = {}
        for k, v in rows:
            require(k not in result, 'DUPLICATE_JSON_KEY')
            result[k] = v
        return result
    return json.loads(p.read_text(encoding='utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'NONFINITE_JSON'))


def write(pathname, value, *, replace=False):
    """原子落盘且不覆盖历史；运行状态唯一例外，使用同目录原子替换。"""
    p = Path(pathname)
    raw = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    tmp = p.with_name('.' + p.name + '.' + uuid.uuid4().hex)
    with os.fdopen(os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    try:
        if replace:
            os.replace(tmp, p)
        else:
            os.link(tmp, p)
    finally:
        if tmp.exists():
            tmp.unlink()


def integer(value, lo, hi, code):
    require(type(value) is int and lo <= value <= hi, code)


def scenes(filename, selected=None):
    raw = load(filename, secret=False)
    require(set(raw) == {'version', 'scenes'} and raw['version'] == VERSION, 'SCENES_VERSION_INVALID')
    rows = raw['scenes']
    require(isinstance(rows, list) and len(rows) == 5 and {r['id'] for r in rows} == set(FAMILIES), 'SCENES_REQUIRED')
    for r in rows:
        require(set(r) == {'id', 'family', 'tool', 'ports', 'rate', 'concurrency', 'durationSeconds', 'cooldownSeconds', 'expected', 'latencyLimitMs'}, 'SCENE_FIELDS_INVALID')
        require(r['family'] == FAMILIES[r['id']], 'SCENE_FAMILY_INVALID')
        tools = {'S0': ('normal',), 'S1': ('nmap', 'connect_scan'), 'S2': ('ftp_login', 'ssh_login'), 'S3': ('slow_http',), 'S4': ('http_burst',)}
        require(r['tool'] in tools[r['id']], 'TOOL_NOT_ALLOWED')
        integer(r['rate'], 1, 50, 'RATE_LIMIT_INVALID')
        integer(r['concurrency'], 1, 16, 'CONCURRENCY_LIMIT_INVALID')
        integer(r['durationSeconds'], 1, 45, 'DURATION_LIMIT_INVALID')
        integer(r['cooldownSeconds'], 180, 240, 'COOLDOWN_LIMIT_INVALID')
        integer(r['latencyLimitMs'], 1, 120000, 'LATENCY_LIMIT_INVALID')
        require(isinstance(r['ports'], list) and 1 <= len(r['ports']) <= 128 and len(set(r['ports'])) == len(r['ports']), 'SCENE_PORTS_INVALID')
        for p in r['ports']:
            integer(p, 1024, 65535, 'SCENE_PORT_INVALID')
        expected = {'S0': 'none', 'S1': 'peer_inbound', 'S2': 'peer_service', 'S3': 'optional', 'S4': 'alert_only'}
        require(r['expected'] == expected[r['id']], 'EXPECTED_INVALID')
    wanted = selected or list(FAMILIES)
    require(wanted and len(wanted) == len(set(wanted)) and set(wanted) <= set(FAMILIES), 'SCENE_SELECTION_INVALID')
    return [next(r for r in rows if r['id'] == k) for k in wanted]


def scene_ports(ports, rows):
    """控制端与 worker 共用端口语义，S0 必须只有一次正常 FTP 登录通道。"""
    for r in rows:
        permitted = [ports['http'], ports['ftp']] if r['id'] == 'S0' else ports['scan'] if r['id'] == 'S1' else [ports['ftp'] if r['tool'] == 'ftp_login' else ports['ssh'] if r['tool'] == 'ssh_login' else ports['http']]
        if r['id'] == 'S0':
            require(r['ports'] == permitted and r['concurrency'] == 1, 'NORMAL_LOGIN_SCOPE_INVALID')
        require(set(r['ports']) <= set(permitted), 'SCENE_OUTSIDE_ALLOWLIST')


def validate(c, rows):
    require(c['version'] == VERSION, 'CONFIG_VERSION_INVALID')
    require(address(c['macAddress']) != address(c['peerAddress']), 'PEER_EQUALS_LOCAL')
    require(c['ttlSeconds'] == 60 and c['budgetSeconds'] == 120, 'FROZEN_LIMITS_REQUIRED')
    integer(c['authorizationSeconds'], 300, 1800, 'AUTHORIZATION_WINDOW_INVALID')
    require(sum(r['durationSeconds'] + r['cooldownSeconds'] for r in rows) + 240 <= c['authorizationSeconds'], 'RUN_EXCEEDS_AUTHORIZATION')
    ports = c['ports']
    require(set(ports) == {'http', 'ftp', 'ssh', 'scan'} and isinstance(ports['scan'], list), 'PORT_MAP_INVALID')
    all_ports = [ports[k] for k in ('http', 'ftp', 'ssh')] + ports['scan']
    require(len(set(all_ports)) == len(all_ports) and len(all_ports) <= 128, 'PORTS_OVERLAP')
    for p in all_ports:
        integer(p, 1024, 65535, 'PORT_INVALID')
    protection = c['protection']
    require({22, 18080, 18082, 41641} <= set(protection['protectedServicePorts']) and not set(all_ports) & set(protection['protectedServicePorts']), 'PROTECTION_INVALID')
    for peer in c.get('protectedPeers', []):
        require(ipaddress.ip_address(c['peerAddress']) not in ipaddress.ip_network(peer), 'PEER_PROTECTED')
    scene_ports(ports, rows)
    require(set(protection) == {'protectedBudgetTargetIds', 'protectedServicePorts'}, 'PROTECTION_FIELDS_INVALID')
    for k in ('root', 'guardlive', 'guardtargets', 'python', 'mysqlService', 'backendCA'):
        path(c[k])
    require(not path(c['root']).is_relative_to(ROOT), 'PRIVATE_ROOT_OUTSIDE_REPOSITORY_REQUIRED')
    require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', c['schema']), 'SCHEMA_INVALID')
    from urllib.parse import urlsplit
    u = urlsplit(c['baseUrl'])
    require(u.scheme == 'https' and u.hostname in ('127.0.0.1', '::1') and not (u.username or u.password or u.query or u.fragment) and u.path in ('', '/'), 'LOOPBACK_TLS_REQUIRED')
    require(c['applicant']['username'] != c['reviewer']['username'], 'INDEPENDENT_REVIEWER_REQUIRED')
    require(c['remote']['host'] == 'win-dev' and re.fullmatch(r'[A-Za-z]:/[A-Za-z0-9_./-]+', c['remote']['root']) and '..' not in c['remote']['root'].split('/'), 'REMOTE_SCOPE_INVALID')
    require(re.fullmatch(r'[A-Za-z]:/[A-Za-z0-9_./-]+', c['remote']['python']), 'REMOTE_PYTHON_INVALID')
    return c


def grant(c, rows, g, scene_sha, run_id, mode, now):
    """一次批准只绑定准确运行号、地址、端口、场景摘要、模式和截止时间；过期不能复用。"""
    require(re.fullmatch(r'demo-\d{8}-\d{4}-\d{2,4}', run_id), 'RUN_ID_INVALID')
    required = {'runId', 'reference', 'purpose', 'operator', 'validFrom', 'validUntil', 'macAddress', 'peerAddress', 'ports', 'scenes', 'scenesSha256', 'mode'}
    require(set(g) == required and g['runId'] == run_id and g['mode'] == mode and mode in ('alert-only', 'pf'), 'RUN_APPROVAL_MISMATCH')
    require(g['reference'] and g['operator'] and g['purpose'], 'APPROVAL_REFERENCE_REQUIRED')
    require(g['macAddress'] == c['macAddress'] and g['peerAddress'] == c['peerAddress'] and g['ports'] == c['ports'] and g['scenes'] == [r['id'] for r in rows] and g['scenesSha256'] == scene_sha, 'APPROVAL_SCOPE_MISMATCH')
    start, end = instant(g['validFrom']), instant(g['validUntil'])
    require(start <= now < end and end - start <= min(1800, c['authorizationSeconds']), 'APPROVAL_EXPIRED')
    require(end - now >= sum(r['durationSeconds'] + r['cooldownSeconds'] for r in rows) + 180, 'APPROVAL_TOO_SHORT')
    return g


def safe_main(fn):
    try:
        os.umask(0o077)
        return fn() or 0
    except (Exception, KeyboardInterrupt) as e:
        code = str(e) if isinstance(e, ValueError) and re.fullmatch('[A-Z0-9_:-]+', str(e)) else 'DEMO_FAILED'
        print(json.dumps({'ok': False, 'error': code, 'errorType': type(e).__name__}))
        return 1
