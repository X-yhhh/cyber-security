#!/usr/bin/env python3
"""发布构建及五服务编排。dry-run 零写入；PF 服务只交付管理员安装说明，不调用 sudo。"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import time
import ssl
import urllib.request
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.toolkit import ROOT, absolute, load, private_dir, require, run, safe_main, sha, write
from executor.services import launchd as executor_launchd

ORDER = ('backend', 'targets', 'recovery', 'executor', 'sensor')
PREFIX = 'com.xyh.cyber-security.'
DAEMONS = {'recovery', 'executor'}


def program(value):
    """程序入口允许 Python venv 的正常解释器链接；配置/发布/账本仍使用禁止链接的 absolute。"""
    p = Path(value).expanduser()
    require(p.is_absolute() and '..' not in p.parts and not any(ord(c) < 32 for c in str(p)), 'ABSOLUTE_PROGRAM_REQUIRED')
    return p


def paths(args):
    root, release = absolute(args.root), absolute(args.release)
    require(release.is_relative_to(root / 'program/releases'), 'RELEASE_OUTSIDE_ROOT')
    return root, release


def definitions(args):
    root, release = paths(args)
    java, python = program(args.java), program(args.python)
    # 复用执行器现有生成器，临时目录仅用于非 dry-run；dry-run 用同一纯配置函数（见 render）。
    base = {'WorkingDirectory': str(release), 'RunAtLoad': True, 'KeepAlive': True,
            'ThrottleInterval': 10, 'ExitTimeOut': 30, 'Umask': 0o077}
    commands = {
        'backend': [str(java), '-jar', str(release / 'backend.jar')],
        'targets': [str(release / 'guardtargets'), '-config', str(root / 'config/targets.json')],
        'recovery': [str(python), '-m', 'executor', 'recover', '--config', str(root / 'config/executor.json')],
        'executor': [str(python), '-m', 'executor', 'run', '--config', str(root / 'config/executor.json')],
        'sensor': [str(python), str(release / 'scripts/p8/sensor_service.py'), '--root', str(root), '--release', str(release)]}
    if args.mode == 'alert-only':
        for role, operation in [('recovery', 'recovery'), ('executor', 'run')]:
            commands[role] = [str(python), str(release / 'scripts/p8/observer_executor.py'), operation, '--config', str(root / 'config/executor-observer.json')]
    result = {}
    for role in ORDER:
        result[role] = dict(base, Label=PREFIX + role, ProgramArguments=commands[role],
                            StandardOutPath=str(root / ('logs/' + role + '.stdout.log')),
                            StandardErrorPath=str(root / ('logs/' + role + '.stderr.log')))
    for role in ('recovery', 'executor', 'sensor'):
        result[role]['EnvironmentVariables'] = {
            'DYLD_LIBRARY_PATH': str(Path(sys.base_prefix) / 'lib'),
            'DYLD_FRAMEWORK_PATH': str(Path(sys.base_prefix).parents[2]),
            'PYTHONDONTWRITEBYTECODE': '1'}
    result['backend']['EnvironmentVariables'] = {'SPRING_PROFILES_ACTIVE': 'deploy',
        'DEPLOY_CONFIG_FILE': str(root / 'config/deploy.properties'), 'DEPLOY_WEB_ROOT': str(release / 'web')}
    # 一次授权只启动一次采集，防止 KeepAlive 把 30 分钟扩成无限循环。
    result['sensor']['KeepAlive'] = False
    result['sensor']['RunAtLoad'] = False
    return result


def render(args):
    entries = definitions(args)
    if args.dry_run:
        return {'plists': {r: plistlib.dumps(v).decode() for r, v in entries.items()}, 'order': ORDER,
                'rootServicesManual': sorted(DAEMONS) if args.mode == 'pf' else [], 'sensorStartsManually': True}
    root, release = paths(args)
    for folder in ('config', 'ledger', 'logs', 'generated'):
        private_dir(root / folder)
    with tempfile.TemporaryDirectory() as temporary:
        stage = Path(temporary) / 'executor'
        executor_launchd(stage, program(args.python), release, root / 'config/executor.json',
                         release / 'guardtargets', root / 'config/targets.json')
        for role in (('targets', 'recovery', 'executor') if args.mode == 'pf' else ('targets',)):
            original = plistlib.loads((stage / ('com.xyh.hostguard.' + role + '.plist')).read_bytes())
            require(original['ProgramArguments'] == entries[role]['ProgramArguments'], 'EXECUTOR_LAUNCHD_DRIFT')
    for role, value in entries.items():
        write(root / 'generated' / (value['Label'] + '.plist'), plistlib.dumps(value))
    lines = ['# 仅生成；P1 管理员审核后安装。0600、每日或达到 10 MiB 轮转，保留 7 份。']
    for role in ORDER:
        for stream in ('stdout', 'stderr'):
            lines.append(f'"{root}/logs/{role}.{stream}.log" 600 7 10240 @T00 JN')
    write(root / 'generated/newsyslog.conf', ('\n'.join(lines) + '\n').encode())
    instructions = ('五服务顺序：backend → targets → recovery → executor → sensor。\n'
        'recovery/executor 为 LaunchDaemon，管理员先审核源码/解释器/依赖/helper 的 root 所有权和 0700/0600 权限。\n'
        '本工具不 sudo，不自动安装 /Library 文件。先安装后端及 targets，再由管理员安装 recovery/executor；\n'
        '核验恢复器心跳及清理完成后，显式 kickstart sensor；过期和重启不会自动重新采集。\n'
        '卸载：先停 sensor，停 executor 并 cleanup + status 核验零规则，再停 recovery、targets、backend。\n'
        'PF 只允许本系统 anchor；清理或核验失败必须保留恢复器和账本。日志轮转配置仅生成，不安装。\n')
    if args.mode == 'alert-only':
        instructions = ('只告警模式：五服务均为当前用户 LaunchAgent；executor/recovery 使用 observer_executor，零能力、无 PF 调用。\n'
            '启动顺序：backend → targets → recovery → executor；sensor 不随启动运行，批准窗口内显式 kickstart。\n'
            '卸载按相反顺序；发现旧 PF 账本则拒绝自动卸载，改用原授权恢复流程。账本、日志与配置永久保留。\n')
    write(root / 'generated/INSTALL.txt', instructions.encode())
    return {'ok': True, 'generated': str(root / 'generated'), 'installed': False}


def install(args):
    root, release = paths(args)
    domain = 'gui/' + str(os.getuid())
    agents = Path.home() / 'Library/LaunchAgents'
    # 全计划可审查；自动阶段止于 targets，root 恢复链就绪后才手动启动 sensor。
    roles = ('backend', 'targets', 'sensor') if args.mode == 'pf' else ORDER
    commands = [['launchctl', 'bootstrap', domain, str(agents / (PREFIX + r + '.plist'))] for r in roles]
    if args.dry_run:
        return {'commands': commands, 'manualRootOrder': ['recovery', 'executor'] if args.mode == 'pf' else [], 'sensorRunAtLoad': False}
    require(args.authorization_reference, 'INSTALL_AUTHORIZATION_REQUIRED')
    verify_release(release)
    expected = definitions(args)
    for role in ORDER:
        file = root / 'generated' / (PREFIX + role + '.plist')
        require(plistlib.loads(file.read_bytes()) == expected[role], 'PLIST_MISMATCH')
    require(agents.is_dir() and not agents.is_symlink(), 'LAUNCHAGENTS_DIRECTORY_REQUIRED')
    for role in roles:
        require(not (agents / (PREFIX + role + '.plist')).exists(), 'SERVICE_ALREADY_INSTALLED')
    for role, command in zip(roles, commands):
        destination = agents / (PREFIX + role + '.plist')
        require(not destination.exists(), 'SERVICE_ALREADY_INSTALLED')
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(plistlib.dumps(expected[role]))
        run(command)
        if role == 'backend':
            wait_ready(root)
    return {'ok': True, 'manualRootOrder': ['recovery', 'executor'] if args.mode == 'pf' else [], 'sensorStarted': False}


def uninstall(args):
    root, release = paths(args)
    domain = 'gui/' + str(os.getuid())
    commands = [['launchctl', 'bootout', domain + '/' + PREFIX + 'sensor'],
                [str(program(args.python)), '-m', 'executor', 'cleanup', '--config', str(root / 'config/executor.json')],
                [str(program(args.python)), '-m', 'executor', 'status', '--config', str(root / 'config/executor.json')]]
    if args.mode == 'alert-only':
        commands = [['launchctl', 'bootout', domain + '/' + PREFIX + role] for role in reversed(ORDER)]
    if args.dry_run:
        return {'commands': commands, 'order': list(reversed(ORDER)), 'manualRootStopBeforeCleanup': 'executor' if args.mode == 'pf' else None,
                'manualRootStopAfterZeroRules': 'recovery' if args.mode == 'pf' else None, 'preserve': ['config', 'ledger', 'logs', 'program']}
    require(args.authorization_reference, 'UNINSTALL_AUTHORIZATION_REQUIRED')
    managed = ('sensor', 'targets', 'backend') if args.mode == 'pf' else tuple(reversed(ORDER))
    for role in managed:
        destination = Path.home() / 'Library/LaunchAgents' / (PREFIX + role + '.plist')
        require(not destination.is_symlink() and plistlib.loads(destination.read_bytes()) == definitions(args)[role], 'PLIST_MISMATCH')
    # root 链须由管理员先完成停 executor / cleanup / status；不把用户伪造文件当清理证明。
    for role in DAEMONS if args.mode == 'pf' else ():
        import subprocess
        result = subprocess.run(['launchctl', 'print', 'system/' + PREFIX + role], capture_output=True)
        require(result.returncode != 0, 'ROOT_SERVICES_REQUIRE_MANUAL_CLEANUP')
    run(commands[0])
    if args.mode == 'pf':
        run(commands[1], cwd=release)
        status = json.loads(run(commands[2], cwd=release))
        require(status['activeRuleCount'] == 0 and not status['recoveryErrors'], 'CLEANUP_NOT_VERIFIED')
    else:
        require(not list((root / 'ledger/executor').glob('*.sqlite*')), 'LEGACY_EXECUTOR_LEDGER_PRESENT')
    roles = ('targets', 'backend') if args.mode == 'pf' else ('executor', 'recovery', 'targets', 'backend')
    for role in roles:
        run(['launchctl', 'bootout', domain + '/' + PREFIX + role])
    for role in ('sensor', *roles):
        destination = Path.home() / 'Library/LaunchAgents' / (PREFIX + role + '.plist')
        require(plistlib.loads(destination.read_bytes()) == definitions(args)[role], 'PLIST_MISMATCH')
        destination.unlink()
    return {'ok': True, 'removed': ['sensor', 'targets', 'backend'], 'retained': ['config', 'ledger', 'logs', 'program']}


def wait_ready(root):
    """后端确实就绪才继续安装依赖服务；证书验证失败或超时保留现场并停止。"""
    sensor = load(root / 'config/sensor.json')
    context = ssl.create_default_context(cafile=str(absolute(sensor['upload']['caFile'])))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(sensor['upload']['baseUrl'] + '/api/v1/health/ready', context=context, timeout=2) as response:
                if json.load(response)['data']['status'] == 'UP':
                    return
        except (OSError, KeyError, ValueError):
            pass
        time.sleep(1)
    raise ValueError('BACKEND_NOT_READY')


def verify_release(release):
    release = absolute(release)
    require((release / 'SHA256SUMS').is_file(), 'RELEASE_MANIFEST_REQUIRED')
    seen = set()
    for line in (release / 'SHA256SUMS').read_text().splitlines():
        hashed, name = line.split('  ', 1)
        require(name not in seen, 'RELEASE_DUPLICATE_ENTRY')
        seen.add(name)
        p = absolute(release / name)
        require(p.is_relative_to(release) and sha(p) == hashed, 'RELEASE_HASH_MISMATCH')
    actual = {str(p.relative_to(release)) for p in release.rglob('*') if p.is_file() and p.name != 'SHA256SUMS'}
    require(seen == actual and {'backend.jar', 'guardlive', 'guardtargets', 'web/index.html', 'release.json'} <= seen, 'RELEASE_FILE_SET_MISMATCH')


def build(args):
    root = absolute(args.release)
    commit = run(['git', 'rev-parse', 'HEAD'], cwd=ROOT)
    destination = root / 'program/releases' / commit
    require(not destination.exists(), 'RELEASE_ALREADY_EXISTS')
    java = program(args.java)
    import subprocess
    version = subprocess.run([str(java), '-version'], capture_output=True, text=True, check=True).stderr
    require('version "25' in version, 'JDK25_REQUIRED')
    versions = {'python': sys.version.split()[0], 'java': version.splitlines()[0], 'maven': run(['mvn', '-v'], env=dict(os.environ, JAVA_HOME=str(java.parent.parent))).splitlines()[0],
                'node': run(['node', '--version']), 'npm': run(['npm', '--version']), 'go': run(['go', 'version'])}
    if args.dry_run:
        return {'destination': str(destination), 'commands': ['mvn -q -DskipTests package', 'npm ci', 'npm run build', 'go build guardlive/guardtargets'], 'toolchains': versions}
    require(not run(['git', 'status', '--porcelain'], cwd=ROOT), 'CLEAN_COMMIT_REQUIRED')
    run(['mvn', '-q', '-DskipTests', 'package'], cwd=ROOT / 'backend', env=dict(os.environ, JAVA_HOME=str(java.parent.parent)))
    run(['npm', 'ci'], cwd=ROOT / 'frontend')
    run(['npm', 'run', 'build'], cwd=ROOT / 'frontend')
    private_dir(destination)
    shutil.copyfile(ROOT / 'backend/target/cyber-security-backend-0.1.0-SNAPSHOT.jar', destination / 'backend.jar')
    shutil.copytree(ROOT / 'frontend/dist', destination / 'web')
    for binary in ('guardlive', 'guardtargets'):
        run(['go', 'build', '-o', str(destination / binary), './cmd/' + binary], cwd=ROOT / 'sensor')
    # 只打包已跟踪源文件，避免带入 venv、凭据、缓存或本机训练制品。
    for path in run(['git', 'ls-files', 'executor', 'scripts/p8', 'scripts/p7', 'scripts/p5', 'docs/contracts'], cwd=ROOT).splitlines():
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(ROOT / path, target)
    for p in [destination, *destination.rglob('*')]:
        p.chmod(0o700 if p.is_dir() or p.name in ('guardlive', 'guardtargets') else 0o600)
    write(destination / 'release.json', {'commit': commit, 'builtAt': datetime.now(timezone.utc).isoformat(), 'toolchains': versions})
    write(destination / 'SHA256SUMS', ''.join(f'{sha(p)}  {p.relative_to(destination)}\n' for p in sorted(destination.rglob('*')) if p.is_file()).encode())
    verify_release(destination)
    return {'ok': True, 'release': str(destination), 'commit': commit}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('build', 'render', 'install', 'uninstall'))
    p.add_argument('--release', required=True)
    p.add_argument('--root')
    p.add_argument('--java', required=True)
    p.add_argument('--python', default=sys.executable)
    p.add_argument('--mode', choices=('pf', 'alert-only'), default='alert-only')
    p.add_argument('--authorization-reference')
    p.add_argument('--dry-run', action='store_true')
    return p


def main():
    args = parser().parse_args()
    require(args.command == 'build' or args.root, 'ROOT_REQUIRED')
    print(json.dumps(globals()[args.command](args), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
