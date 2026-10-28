#!/bin/sh
# 仅为演示采集临时开放 bpf1；参数由 LaunchDaemon 模板固定，不读取配置文件。
# root 运行时测试钩子全部失效。
set -eu

if [ "${DEMO_CAPTURE_PERMISSION_TEST_MODE-}" != 1 ] || [ "$(/usr/bin/id -u)" -eq 0 ]; then
    /usr/sbin/chown root:wheel /dev/bpf1
    /bin/chmod 600 /dev/bpf1
fi

[ "$#" -eq 4 ] || exit 64
if [ "${DEMO_CAPTURE_PERMISSION_TEST_MODE-}" = 1 ] && [ "$(/usr/bin/id -u)" -ne 0 ]; then
    helper_python=${DEMO_CAPTURE_PERMISSION_TEST_INTERPRETER:-$3}
else
    helper_python=/usr/bin/python3
fi
exec "$helper_python" -B - "$@" <<'PY'
import os
import pwd
import re
import shlex
import signal
import stat
import subprocess
import sys
import time

DEVICE = '/dev/bpf1'
TEST_MODE = os.geteuid() != 0 and os.environ.get('DEMO_CAPTURE_PERMISSION_TEST_MODE') == '1'


def set_device_owner(owner):
    if TEST_MODE:
        with open(os.environ['DEMO_CAPTURE_PERMISSION_TEST_ACTIONS'], 'a', encoding='utf-8') as actions:
            actions.write(owner + ':wheel:600\n')
        return
    subprocess.run(['/usr/sbin/chown', owner + ':wheel', DEVICE], check=True, timeout=5)
    subprocess.run(['/bin/chmod', '600', DEVICE], check=True, timeout=5)


def run_arguments_match(arguments, username, root, python_path, run_path):
    config_path = os.path.join(root, 'config.json')
    if not arguments or arguments[0] != python_path:
        return False
    command = arguments[1:]
    if command[:1] == ['-B']:
        command = command[1:]
    if command[:3] != [run_path, '--config', config_path]:
        return False
    options = {'--grant', '--run-id', '--scenes', '--scenes-file'}
    seen = set()
    grant_path = None
    index = 3
    modes = 0
    while index < len(command):
        option = command[index]
        if option in ('--pf', '--alert-only'):
            modes += 1
            if modes > 1:
                return False
            index += 1
            continue
        if option not in options or option in seen or index + 1 >= len(command):
            return False
        value = command[index + 1]
        if not value or value.startswith('--'):
            return False
        seen.add(option)
        if option == '--grant':
            grant_path = value
        elif option == '--run-id' and not re.fullmatch(r'demo-\d{8}-\d{4}-\d{2,4}', value):
            return False
        elif option == '--scenes' and not re.fullmatch(r'S[0-4](,S[0-4])*', value):
            return False
        elif option == '--scenes-file':
            expected_scenes = os.path.join(os.path.dirname(run_path), 'scenes.json')
            if value != expected_scenes:
                return False
        index += 2
    if grant_path is None or not os.path.isabs(grant_path):
        return False
    grants_root = os.path.join(root, 'grants') + os.sep
    return grant_path.startswith(grants_root) and '..' not in grant_path.split(os.sep)


def authorized_pid(pid_path, username, uid, root, python_path, run_path):
    directory_fd = None
    file_fd = None
    try:
        directory_fd = os.open(os.path.dirname(pid_path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        file_fd = os.open('demo-run.pid', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        metadata = os.fstat(file_fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            return False
        raw = os.read(file_fd, 64)
        if os.read(file_fd, 1) or not re.fullmatch(rb'[1-9][0-9]{0,15}\n?', raw):
            return False
        pid = raw.rstrip(b'\n').decode('ascii')
        ps = os.environ.get('DEMO_CAPTURE_PERMISSION_TEST_PS', '/bin/ps') if TEST_MODE else '/bin/ps'
        result = subprocess.run([ps, '-o', 'user=,command=', '-p', pid], capture_output=True,
                                text=True, check=True, timeout=2)
        rows = result.stdout.splitlines()
        if len(rows) != 1:
            return False
        row = rows[0].strip()
        process_user, command = row.split(None, 1)
        return process_user == username and run_arguments_match(
            shlex.split(command), username, root, python_path, run_path)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def stop(_signum, _frame):
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGHUP, stop)
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGQUIT, stop)
try:
    set_device_owner('root')
    if len(sys.argv) != 5:
        raise SystemExit(64)
    username, root, python_path, run_path = sys.argv[1:]
    if not all(os.path.isabs(value) for value in (root, python_path, run_path)):
        raise SystemExit(64)
    uid = int(os.environ.get('DEMO_CAPTURE_PERMISSION_TEST_UID', pwd.getpwnam(username).pw_uid)) if TEST_MODE else pwd.getpwnam(username).pw_uid
    if uid < 501:
        raise SystemExit(64)
    pid_path = os.path.join(root, 'locks', 'demo-run.pid')
    while True:
        if authorized_pid(pid_path, username, uid, root, python_path, run_path):
            set_device_owner(username)
        else:
            set_device_owner('root')
        if TEST_MODE and os.environ.get('DEMO_CAPTURE_PERMISSION_TEST_ONCE') == '1':
            break
        time.sleep(1)
finally:
    set_device_owner('root')
PY
