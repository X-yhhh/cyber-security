#!/usr/bin/env python3
"""本机机器 mTLS 证书的到期检查与整套轮换（BE-30）。

部署目录 `config/` 下有两套由 `executor.pki.create` 生成的证书：
- `tls/`：后端服务端证书；传感器、执行器观察端与巡检用 `tls/ca.pem` 校验后端。
- `ipc/`：传感器（collector）、执行器（executor）的客户端证书与 guardtargets 的服务端证书；
  后端以 `ipc/ca.pem` 或 `ipc/client-trust-with-demo.pem` 校验客户端；`targets.json` 钉住
  collector/executor 叶子证书指纹。

CA 私钥不落盘，无法续签，只能整套重新生成。轮换先在 `config/` 内的私有暂存目录生成并核验，
再备份原文件为 `*.bak-<stamp>`，按原文件名逐个原子替换；替换失败时用备份恢复。
命令只打印证书元数据和指纹，不输出私钥。
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from scripts.p8.toolkit import absolute, require, safe_main
from scripts.p8.launchd import PREFIX

SETS = ('tls', 'ipc')
ROLES = ('server', 'collector', 'executor')
BUNDLE = 'client-trust-with-demo.pem'
TARGETS = 'targets.json'
PEM_BLOCK = re.compile(rb'-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----\r?\n?', re.S)
# targets 先于 backend：执行器经 guardtargets 领取目标；backend 重启会连带重启托管传感器。
RESTART_ORDER = ('targets', 'backend', 'recovery', 'executor')


def _now(now=None):
    return now or datetime.now(timezone.utc)


def certificates(path):
    blocks = PEM_BLOCK.findall(Path(path).read_bytes())
    require(blocks, 'CERTIFICATE_FILE_INVALID')
    return [x509.load_pem_x509_certificate(block) for block in blocks]


def fingerprint(certificate):
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()


def _common_name(certificate):
    names = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return names[0].value if names else ''


def watched_files(config):
    files = []
    for name in SETS:
        for stem in ('ca',) + ROLES:
            files.append(Path(config) / name / (stem + '.pem'))
    bundle = Path(config) / 'ipc' / BUNDLE
    if bundle.exists():
        files.append(bundle)
    return files


def expiry(config, *, now=None):
    """逐个证书报告剩余天数；文件缺失或无法解析记为异常项而不是跳过。"""
    config = absolute(config)
    now = _now(now)
    items = []
    for path in watched_files(config):
        relative = str(path.relative_to(config))
        try:
            for certificate in certificates(path):
                after = certificate.not_valid_after_utc
                items.append({'file': relative, 'subject': _common_name(certificate), 'notAfter': after.isoformat(),
                              'daysRemaining': round((after - now).total_seconds() / 86400, 2)})
        except (OSError, ValueError):
            items.append({'file': relative, 'subject': None, 'notAfter': None, 'daysRemaining': None})
    known = [item['daysRemaining'] for item in items if item['daysRemaining'] is not None]
    earliest = min(known) if known else None
    return {'items': items, 'minDaysRemaining': earliest,
            'unreadable': [item['file'] for item in items if item['daysRemaining'] is None]}


def assess(config, *, warn_days=7, now=None):
    """巡检口径：最早到期证书剩余天数 > warn_days 才算正常；不可读文件一律异常。"""
    require(type(warn_days) is int and 0 <= warn_days <= 365, 'INVALID_WARN_DAYS')
    value = expiry(config, now=now)
    earliest = value['minDaysRemaining']
    if value['unreadable'] or earliest is None:
        state = 'unknown'
    elif earliest <= 0:
        state = 'expired'
    elif earliest <= warn_days:
        state = 'expiring'
    else:
        state = 'ok'
    return {'state': state, 'warnDays': warn_days, **value}, state == 'ok'


def _private(path, *, directory=False):
    stat = path.stat()
    mode = stat.st_mode & 0o777
    require(stat.st_uid == os.getuid() and mode == (0o700 if directory else 0o600), 'PRIVATE_PERMISSION_REQUIRED')


def _current(config):
    """核对现有布局与指纹登记，确认替换对象就是本命令认识的那一套。"""
    state = {}
    for name in SETS:
        directory = config / name
        require(directory.is_dir() and not directory.is_symlink(), 'CERTIFICATE_DIRECTORY_MISSING')
        _private(directory, directory=True)
        files = ['ca.pem', 'fingerprints.json'] + [role + suffix for role in ROLES for suffix in ('.pem', '.key')]
        for file in files:
            path = directory / file
            require(path.is_file() and not path.is_symlink(), 'CERTIFICATE_FILE_MISSING')
            _private(path)
        recorded = json.loads((directory / 'fingerprints.json').read_bytes())
        actual = {role: fingerprint(certificates(directory / (role + '.pem'))[0]) for role in ROLES}
        require(recorded == actual, 'FINGERPRINT_RECORD_MISMATCH')
        state[name] = actual
    return state


def _bundle(config, new_ca):
    """信任包首张必须是当前 ipc CA；其余（如演示 CA）原样保留在新 CA 之后。"""
    path = config / 'ipc' / BUNDLE
    if not path.exists():
        return None
    _private(path)
    blocks = PEM_BLOCK.findall(path.read_bytes())
    current = certificates(config / 'ipc' / 'ca.pem')[0]
    require(blocks and fingerprint(x509.load_pem_x509_certificate(blocks[0])) == fingerprint(current),
            'TRUST_BUNDLE_LAYOUT_UNEXPECTED')
    tail = b''.join(block if block.endswith(b'\n') else block + b'\n' for block in blocks[1:])
    return new_ca + (b'' if new_ca.endswith(b'\n') else b'\n') + tail


def _targets(config, old, new):
    """只替换 scope 中两个指纹的原文，其余字节不变；指纹对不上就拒绝。"""
    path = config / TARGETS
    if not path.exists():
        return None
    _private(path)
    text = path.read_text()
    scope = json.loads(text).get('scope') or {}
    require(scope.get('CollectorCertSHA256') == old['collector'] and scope.get('ExecutorCertSHA256') == old['executor'],
            'TARGETS_FINGERPRINT_MISMATCH')
    for role in ('collector', 'executor'):
        require(text.count(old[role]) == 1, 'TARGETS_FINGERPRINT_NOT_UNIQUE')
        text = text.replace(old[role], new[role])
    parsed = json.loads(text)['scope']
    require(parsed['CollectorCertSHA256'] == new['collector'] and parsed['ExecutorCertSHA256'] == new['executor'],
            'TARGETS_UPDATE_FAILED')
    return text


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def rotate(config, *, leaf_days=180, ca_days=730, stamp=None, dry_run=False, create=None):
    from executor import pki
    from executor.common import Rejected
    create = create or pki.create
    config = absolute(config)
    _private(config, directory=True)
    stamp = stamp or datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    require(re.fullmatch(r'[0-9A-Za-z\-]{1,40}', stamp) is not None, 'INVALID_STAMP')
    try:
        pki.validity(leaf_days, ca_days)
    except Rejected as exc:
        raise ValueError(str(exc)) from None
    old = _current(config)
    backups = {name: config / (name + '.bak-' + stamp) for name in SETS}
    if (config / TARGETS).exists():
        backups[TARGETS] = config / (TARGETS + '.bak-' + stamp)
    require(not any(path.exists() for path in backups.values()), 'BACKUP_ALREADY_EXISTS')
    staging = config / ('.rotate-' + stamp)
    require(not staging.exists(), 'STAGING_ALREADY_EXISTS')
    staging.mkdir(mode=0o700)
    try:
        new = {}
        for name in SETS:
            new[name] = create(staging / name, leaf_days=leaf_days, ca_days=ca_days)
        bundle = _bundle(config, (staging / 'ipc' / 'ca.pem').read_bytes())
        if bundle is not None:
            _write_private(staging / 'ipc' / BUNDLE, bundle)
        targets = _targets(config, old['ipc'], new['ipc'])
        if targets is not None:
            _write_private(staging / TARGETS, targets.encode())
        preview = expiry(staging)
        result = {'ok': True, 'dryRun': dry_run, 'stamp': stamp, 'leafDays': leaf_days, 'caDays': ca_days,
                  'oldFingerprints': old, 'newFingerprints': new, 'newMinDaysRemaining': preview['minDaysRemaining'],
                  'backups': {key: str(path) for key, path in backups.items()},
                  'targetsUpdated': targets is not None, 'trustBundleRebuilt': bundle is not None}
        if dry_run:
            result['backups'] = {}
            return result
        for name in SETS:
            shutil.copytree(config / name, backups[name], copy_function=shutil.copy2)
        if TARGETS in backups:
            shutil.copy2(config / TARGETS, backups[TARGETS])
        installed = []
        try:
            for name in SETS:
                for path in sorted((staging / name).iterdir()):
                    os.replace(path, config / name / path.name)
                    installed.append(config / name / path.name)
            if targets is not None:
                os.replace(staging / TARGETS, config / TARGETS)
                installed.append(config / TARGETS)
        except BaseException:
            for path in installed:
                source = (backups[TARGETS] if path.name == TARGETS and path.parent == config
                          else backups[path.parent.name] / path.name)
                if source.exists():
                    shutil.copy2(source, path)
                else:
                    path.unlink()
            raise
        check = _current(config)
        require(check == new, 'ROTATION_VERIFY_FAILED')
        result['minDaysRemaining'] = expiry(config)['minDaysRemaining']
        return result
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def restart(*, mode='alert-only', sensor_lifecycle='backend', execute=None):
    """只在只告警模式下重启（四个服务均为用户 LaunchAgent）；PF 模式的守护进程需要 root，只给出命令。"""
    roles = RESTART_ORDER + (() if sensor_lifecycle == 'backend' else ('sensor',))
    if mode != 'alert-only':
        return {'restarted': [], 'manual': ['sudo launchctl kickstart -k system/' + PREFIX + role
                                            if role in ('recovery', 'executor') else
                                            'launchctl kickstart -k gui/' + str(os.getuid()) + '/' + PREFIX + role
                                            for role in roles]}
    execute = execute or (lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=30).returncode)
    done = []
    for role in roles:
        code = execute(['launchctl', 'kickstart', '-k', 'gui/' + str(os.getuid()) + '/' + PREFIX + role])
        require(code == 0, 'RESTART_FAILED:' + role)
        done.append(role)
    return {'restarted': done, 'manual': []}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    check = sub.add_parser('check', help='报告证书剩余天数；最早到期 ≤ --warn-days 时退出码 1')
    check.add_argument('--config', required=True)
    check.add_argument('--warn-days', type=int, default=7)
    run = sub.add_parser('rotate', help='整套重新生成两套证书并原子替换（先备份）')
    run.add_argument('--config', required=True)
    run.add_argument('--leaf-days', type=int, default=180)
    run.add_argument('--ca-days', type=int, default=730)
    run.add_argument('--stamp')
    run.add_argument('--dry-run', action='store_true')
    run.add_argument('--restart', action='store_true', help='替换后按 targets、backend、recovery、executor 顺序重启')
    run.add_argument('--mode', choices=('alert-only', 'pf'), default='alert-only')
    run.add_argument('--sensor-lifecycle', choices=('backend', 'launchd'), default='backend')
    args = parser.parse_args()
    if args.command == 'check':
        value, ok = assess(args.config, warn_days=args.warn_days)
        print(json.dumps({'ok': ok, **value}, ensure_ascii=False, indent=2))
        return 0 if ok else 1
    result = rotate(args.config, leaf_days=args.leaf_days, ca_days=args.ca_days, stamp=args.stamp, dry_run=args.dry_run)
    if args.restart and not args.dry_run:
        result['restart'] = restart(mode=args.mode, sensor_lifecycle=args.sensor_lifecycle)
    else:
        result['restartRequired'] = list(RESTART_ORDER)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
