#!/usr/bin/env python3
"""传感器启动入口：短窗口兼容原行为；后端托管时持续到父进程退出或授权撤销/到期。"""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import uuid
from urllib.parse import urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.toolkit import absolute, load, private_dir, require, safe_main, write


def prepare(root, release, *, parent_pid=None, backend_url=None):
    root, release = absolute(root), absolute(release)
    c = load(root / 'config/sensor.json')
    remaining = int((datetime.fromisoformat(c['authorizedUntil'].replace('Z', '+00:00')) - datetime.now(timezone.utc)).total_seconds())
    require(remaining >= 1, 'AUTHORIZATION_EXPIRED')
    require(c['environment'] == 'authorized' and c['captureScope'] == 'all_inbound_tcp' and c['allowedInterfaces'] == [c['interface']], 'CAPTURE_SCOPE_INVALID')
    if parent_pid is not None:
        require(parent_pid > 1 and parent_pid == os.getppid(), 'BACKEND_PARENT_INVALID')
    if backend_url is not None:
        u = urlsplit(backend_url)
        require(parent_pid is not None and u.scheme == 'https' and u.hostname in ('127.0.0.1', '::1')
                and u.port and not u.username and not u.password and u.path in ('', '/')
                and not u.query and not u.fragment, 'LOCAL_TLS_ENDPOINT_REQUIRED')
        c['upload']['baseUrl'] = backend_url
    boot = str(uuid.uuid4())
    directory = private_dir(root / 'ledger/sensor' / boot)
    c['bootId'] = boot
    c['upload']['spoolDir'] = str(directory / 'spool')
    write(directory / 'config.json', c)
    command = [str(release / 'guardlive'), '-config', str(directory / 'config.json'), '-out', str(directory / 'observations.jsonl'),
               '-trace', str(directory / 'trace.jsonl'), '-report', str(directory / 'report.json'),
               '-duration', '0' if parent_pid is not None else str(min(1800, remaining)) + 's']
    if parent_pid is not None:
        command += ['-parent-pid', str(parent_pid), '-drain-timeout', '5s']
    return command


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', required=True)
    p.add_argument('--release', required=True)
    p.add_argument('--parent-pid', type=int)
    p.add_argument('--backend-url')
    args = p.parse_args()
    if args.parent_pid is not None:
        # 锁跨 exec 保留：父 JVM 即使被 SIGKILL，旧采集句柄退出前也不能启动第二个捕获进程。
        import fcntl
        fd = os.open(absolute(args.root) / 'ledger/sensor.capture.lock', os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.set_inheritable(fd, True)
    command = prepare(args.root, args.release, parent_pid=args.parent_pid, backend_url=args.backend_url)
    os.execv(command[0], command)


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
