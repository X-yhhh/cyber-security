"""A4 离线验收：解析模板、拒绝无效输入，用假 Go/ldd 检查容器命令；不运行 Docker 或服务。"""
import configparser
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parent
BUILDER = ROOT / 'builder/build_guardlive.sh'
UNITS = ('cyber-sensor.service', 'cyber-observer.service', 'cyber-observer-recovery.service')


def unit(name):
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read(ROOT / name)
    return parser


@pytest.mark.parametrize('name', UNITS)
def test_unit_hardening_and_limits(name):
    """每个单元有独立限额与只读文件系统，依赖集合不得触及其他服务。"""
    parsed = unit(name)
    service = parsed['Service']
    expected = dict(User='cybersensor', NoNewPrivileges='yes', ProtectSystem='strict',
                    ProtectHome='yes', ReadWritePaths='@ROOT@/ledger @ROOT@/logs',
                    WorkingDirectory='@RELEASE@', UMask='0077', MemorySwapMax='0',
                    Nice='10', IOSchedulingClass='idle', OOMScoreAdjust='900',
                    Restart='on-failure', RestartSec='30')
    for key, value in expected.items():
        assert service[key] == value
    assert parsed['Install']['WantedBy'] == 'multi-user.target'
    allowed = {'network-online.target', 'cyber-observer-recovery.service'}
    assert 'network-online.target' in parsed['Unit']['After'].split()
    for key in ('After', 'Before', 'Requires', 'Wants', 'Conflicts', 'BindsTo', 'PartOf'):
        assert set(parsed['Unit'].get(key, '').split()) <= allowed
    assert 'ExecStartPre' not in service and 'ExecStartPost' not in service
    if name == 'cyber-sensor.service':
        assert service['AmbientCapabilities'] == service['CapabilityBoundingSet'] == 'CAP_NET_RAW'
        assert service['MemoryHigh'] == '256M'
        assert service['MemoryMax'] == '320M' and service['CPUQuota'] == '30%'
        assert service['RestartPreventExitStatus'] == '2 3 4 5'
        assert service['KillMode'] == 'mixed' and int(service['TimeoutStopSec']) > 8
    else:
        assert service['AmbientCapabilities'] == service['CapabilityBoundingSet'] == ''
        assert service['MemoryMax'] == '96M' and service['CPUQuota'] == '10%'


def test_unit_commands_match_existing_entry_points():
    assert shlex.split(unit(UNITS[0])['Service']['ExecStart']) == [
        '@VENV@/bin/python', '@RELEASE@/scripts/linux/supervisor.py',
        '--root', '@ROOT@', '--release', '@RELEASE@']
    for name, role in zip(UNITS[1:], ('run', 'recovery')):
        assert shlex.split(unit(name)['Service']['ExecStart']) == [
            '@VENV@/bin/python', '@RELEASE@/scripts/p8/observer_executor.py', role,
            '--config', '@ROOT@/config/executor-observer.json']
    observer = unit(UNITS[1])['Unit']
    assert observer['Wants'] == 'cyber-observer-recovery.service'
    assert 'cyber-observer-recovery.service' in observer['After'].split()


def test_tunnel_is_fixed_loopback_and_noninteractive():
    config = plistlib.loads((ROOT / 'com.xyh.cyber-security.remote-tunnel.plist').read_bytes())
    args = config['ProgramArguments']
    assert args[0:2] == ['/usr/bin/ssh', '-N']
    assert args.count('-R') == 1
    assert args[args.index('-R') + 1] == '127.0.0.1:18082:127.0.0.1:18082'
    options = {args[i + 1] for i, value in enumerate(args) if value == '-o'}
    assert options == {'ExitOnForwardFailure=yes', 'ServerAliveInterval=15',
                       'ServerAliveCountMax=3', 'BatchMode=yes', 'IdentitiesOnly=yes',
                       'StrictHostKeyChecking=yes', 'UserKnownHostsFile=@KNOWN_HOSTS@'}
    assert args[args.index('-i') + 1] == '@TUNNEL_PRIVATE_KEY@'
    assert args[-1] == 'cybertunnel@@REMOTE_HOST@'
    assert not {'-g', '-L', '-D', '-A'} & set(args)
    assert config['KeepAlive'] is True and config['RunAtLoad'] is True
    assert config['ThrottleInterval'] == 30 and config['Umask'] == 0o077


def test_placeholders_and_authorized_key_are_documented():
    names = (*UNITS, 'authorized_keys.template', 'com.xyh.cyber-security.remote-tunnel.plist')
    content = '\n'.join((ROOT / name).read_text() for name in names)
    placeholders = set(re.findall(r'@[A-Z][A-Z0-9_]*@', content))
    assert placeholders == {'@ROOT@', '@RELEASE@', '@VENV@', '@TUNNEL_PUBLIC_KEY_BASE64@',
                            '@TUNNEL_PRIVATE_KEY@', '@KNOWN_HOSTS@', '@REMOTE_HOST@', '@MAC_LOG_DIR@'}
    readme = (ROOT / 'README.md').read_text()
    assert all(value in readme for value in placeholders)
    key = [line for line in (ROOT / 'authorized_keys.template').read_text().splitlines()
           if line and not line.startswith('#')]
    assert key == ['restrict,port-forwarding,permitlisten="127.0.0.1:18082" '
                   'ssh-ed25519 @TUNNEL_PUBLIC_KEY_BASE64@ cyber-security-remote-tunnel']
    assert not re.search(r'\b(?!127\.0\.0\.1\b)\d{1,3}(?:\.\d{1,3}){3}\b', content)


def test_builder_has_complete_archive_and_offline_container():
    script = BUILDER.read_text()
    dockerfile = (ROOT / 'builder/Dockerfile').read_text()
    archive = script.split('git -C "$repository" archive', 1)[1].split('> "$output/source.tar"', 1)[0]
    for path in ('sensor', 'docs/contracts', 'backend/src/main/resources/feature-contract',
                 'backend/src/test/resources/feature-contract'):
        assert path in archive.split()
    assert 'FROM ubuntu:24.04' in dockerfile and 'Acquire::Retries=5' in dockerfile
    assert 'gcc libc6-dev libpcap-dev' in dockerfile
    assert 'COPY go.tar.gz' in dockerfile and 'sha256sum -c -' in dockerfile
    for item in ('GOFLAGS=-mod=readonly', 'GOPROXY=off', 'GOTOOLCHAIN=local', 'GOMODCACHE=/modcache'):
        assert item in dockerfile and item in script
    assert 'docker run --rm --platform linux/amd64 --pull=never --network none' in script
    assert 'source=$output/modcache,target=/modcache,readonly' in script
    assert '"$build_go" mod download' in script
    assert not re.search(r'\b(curl|wget)\b', script + dockerfile)


@pytest.mark.parametrize('existing_output', (False, True))
def test_builder_rejects_bad_hash_or_existing_output_before_commands(tmp_path, existing_output):
    """输入失败不能走到 Git/Go/Docker；已有输出中的数据必须原样保留。"""
    archive = tmp_path / 'go.tar.gz'
    archive.write_bytes(b'not a real Go archive')
    output = tmp_path / 'output'
    expected = '0' * 64
    if existing_output:
        output.mkdir()
        (output / 'keep').write_text('existing work')
        expected = hashlib.sha256(archive.read_bytes()).hexdigest()
    result = subprocess.run(['/bin/sh', str(BUILDER), 'a' * 40, str(archive), expected, str(output)],
                            env=dict(os.environ, BUILD_PYTHON=sys.executable, PATH='/nonexistent'),
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert ('NEW_OUTPUT_DIRECTORY_REQUIRED' if existing_output else 'GO_SHA256_MISMATCH') in result.stderr
    if existing_output:
        assert (output / 'keep').read_text() == 'existing work'
        assert list(output.iterdir()) == [output / 'keep']
    else:
        assert not output.exists()


@pytest.mark.parametrize('test_code,missing_library', ((0, False), (17, False), (0, True)))
def test_container_command_stops_on_failed_tests_or_missing_library(tmp_path, test_code, missing_library):
    """仅执行提取的 sh 命令和假工具，验证变量转义、测试闸门及 ldd 失败边界。"""
    tail = BUILDER.read_text().split('"$image_id" sh -eu -c ', 1)[1]
    command = shlex.split(tail)[0]
    for directory in ('src/sensor', 'work', 'out', 'bin'):
        (tmp_path / directory).mkdir(parents=True, exist_ok=True)
    for mount in ('src', 'work', 'out'):
        command = command.replace('/' + mount, str(tmp_path / mount))
    fake_commands = {
        'go': '#!/bin/sh\nset -eu\ncase "$1" in\n'
              'version) echo "go version go1.26.4 linux/amd64" ;;\n'
              'test) echo "fake test output"; exit "$FAKE_TEST_CODE" ;;\n'
              'build) printf "fake binary" > "$4" ;;\nesac\n',
        'dpkg-query': f'#!{sys.executable}\nimport sys\n'
                      'assert sys.argv[2] == r"-f=${Version}\\n"\nprint("1.10.4-test")\n',
        'ldd': '#!/bin/sh\nif [ "$1" = --version ]; then echo "glibc 2.39"; '
               'elif [ "$FAKE_MISSING_LIBRARY" = 1 ]; then echo "libpcap.so.0.8 => not found"; '
               'else echo "libpcap.so.0.8 => /lib/libpcap.so.0.8"; fi\n',
        'sha256sum': '#!/bin/sh\nprintf "fake-hash  %s\\n" "$1"\n',
    }
    for name, content in fake_commands.items():
        path = tmp_path / 'bin' / name
        path.write_text(content)
        path.chmod(0o700)
    result = subprocess.run(['/bin/sh', '-eu', '-c', command], capture_output=True, text=True,
                            env=dict(os.environ, PATH=str(tmp_path / 'bin') + ':/usr/bin:/bin',
                                     FAKE_TEST_CODE=str(test_code),
                                     FAKE_MISSING_LIBRARY=str(int(missing_library))))
    assert result.returncode == (test_code or int(missing_library)), result.stderr
    assert (tmp_path / 'out/test.rc').read_text().strip() == str(test_code)
    assert (tmp_path / 'out/guardlive').exists() is (test_code == 0)
    assert (tmp_path / 'out/libpcap-version.txt').read_text().strip() == '1.10.4-test'
