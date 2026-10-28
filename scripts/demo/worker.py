#!/usr/bin/env python3
"""Windows 本地自主执行有界场景。固定目标、硬上限与本地截止时间不依赖演示中的 SSH 链路。"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import ftplib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.demo.common import VERSION, address, digest, grant, instant, load, require, safe_main, scene_ports, scenes, sha, stamp, write


class ProcessTree:
    """Windows Job Object 在父进程结束时杀死整棵外部工具进程树；Unix 使用独立进程组。"""
    def __init__(self):
        self.job = None
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes as w
            class Basic(ctypes.Structure):
                _fields_ = [('user', ctypes.c_int64), ('job', ctypes.c_int64), ('flags', w.DWORD),
                            ('min', ctypes.c_size_t), ('max', ctypes.c_size_t), ('active', w.DWORD),
                            ('affinity', ctypes.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]
            class IO(ctypes.Structure):
                _fields_ = [(n, ctypes.c_uint64) for n in ('readOps', 'writeOps', 'otherOps', 'readBytes', 'writeBytes', 'otherBytes')]
            class Extended(ctypes.Structure):
                _fields_ = [('basic', Basic), ('io', IO), ('processMemory', ctypes.c_size_t),
                            ('jobMemory', ctypes.c_size_t), ('peakProcess', ctypes.c_size_t), ('peakJob', ctypes.c_size_t)]
            k = self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            k.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
            k.CreateJobObjectW.restype = w.HANDLE
            self.resume = ctypes.WinDLL('ntdll').NtResumeProcess
            self.resume.argtypes = [w.HANDLE]
            self.resume.restype = w.LONG
            k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
            k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
            k.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
            k.CloseHandle.argtypes = [w.HANDLE]
            self.job = k.CreateJobObjectW(None, None)
            limit = Extended()
            limit.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            require(self.job and k.SetInformationJobObject(self.job, 9, ctypes.byref(limit), ctypes.sizeof(limit)), 'WINDOWS_JOB_REQUIRED')

    def start(self, argv, log):
        p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             start_new_session=os.name != 'nt', creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004) if os.name == 'nt' else 0)
        # CREATE_SUSPENDED 防止工具在加入 Job 前派生逃逸进程；任何失败均先杀死未运行的子进程。
        if self.job and (not self.kernel.AssignProcessToJobObject(self.job, int(p._handle)) or self.resume(int(p._handle)) != 0):
            p.kill()
            p.wait()
            raise ValueError('WINDOWS_JOB_ASSIGNMENT_FAILED')
        return p

    def stop(self, p):
        if p.poll() is None:
            if self.job:
                self.kernel.TerminateJobObject(self.job, 124)
            else:
                os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill() if self.job else os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=3)

    def close(self):
        if self.job:
            self.kernel.CloseHandle(self.job)
            self.job = None


class Limiter:
    def __init__(self, rate, deadline, stopped):
        self.spacing, self.deadline, self.stopped = 1 / rate, deadline, stopped
        self.next = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            at = max(time.monotonic(), self.next)
            if at >= self.deadline or self.stopped():
                return False
            self.next = at + self.spacing
        while time.monotonic() < at:
            if self.stopped():
                return False
            time.sleep(min(.05, at - time.monotonic()))
        return time.monotonic() < self.deadline and not self.stopped()


def nmap_command(binary, target, row):
    """不接收自由参数；SYN 扫描只包含登记端口，禁 DNS/主机发现/脚本/服务探测。"""
    require(row['tool'] == 'nmap' and Path(binary).is_absolute(), 'NMAP_BINARY_INVALID')
    return [binary, '-sS', '-n', '-Pn', '--disable-arp-ping', '--max-retries', '0',
            '--max-rate', str(row['rate']), '--max-parallelism', str(row['concurrency']),
            '--host-timeout', str(row['durationSeconds']) + 's', '-p', ','.join(map(str, row['ports'])), target]


def _read_http_response(sock):
    """读取一个固定 HTTP 响应及其 Content-Length 指定的完整正文。"""
    response = bytearray()
    while b'\r\n\r\n' not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError('HTTP_RESPONSE_CLOSED')
        response.extend(chunk)
        require(len(response) <= 8192, 'HTTP_RESPONSE_TOO_LARGE')
    headers, _, raw_body = bytes(response).partition(b'\r\n\r\n')
    require(headers.split(b'\r\n', 1)[0] == b'HTTP/1.1 200 OK', 'HTTP_RESPONSE_INVALID')
    content_length = None
    for line in headers.split(b'\r\n')[1:]:
        name, separator, value = line.partition(b':')
        if separator and name.lower() == b'content-length':
            try:
                content_length = int(value.strip())
            except ValueError as exc:
                raise ValueError('HTTP_RESPONSE_INVALID') from exc
    require(content_length is not None and content_length >= 0, 'HTTP_RESPONSE_INVALID')
    body = bytearray(raw_body)
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError('HTTP_RESPONSE_CLOSED')
        body.extend(chunk)
    require(len(body) == content_length, 'HTTP_RESPONSE_INVALID')


def traffic(target, row, stopped, *, connector=socket.create_connection):
    """内置工具只操作无业务数据的测试协议；不尝试系统凭据、不读取文件、不提供任意请求体。"""
    end = time.monotonic() + row['durationSeconds']
    limiter = Limiter(row['rate'], end, stopped)
    counts = {'attempts': 0, 'completed': 0, 'refusedOrBlocked': 0}
    if row['tool'] == 'normal':
        counts['httpReconnectRefused'] = False
    lock = threading.Lock()

    def normal_client():
        if limiter.acquire():
            with lock:
                counts['attempts'] += 1
            try:
                with ftplib.FTP() as ftp:
                    ftp.connect(target, row['ports'][1], timeout=1)
                    try:
                        ftp.login('demo', 'demo-test-only')
                    except ftplib.error_perm:
                        pass
                with lock:
                    counts['completed'] += 1
            except (OSError, EOFError, ftplib.Error):
                with lock:
                    counts['refusedOrBlocked'] += 1

        if not limiter.acquire():
            return
        with lock:
            counts['attempts'] += 1
        connected = False
        try:
            with connector((target, row['ports'][0]), timeout=1) as sock:
                connected = True
                while True:
                    sock.sendall(b'GET / HTTP/1.1\r\nHost: demo.invalid\r\nConnection: keep-alive\r\n\r\n')
                    _read_http_response(sock)
                    with lock:
                        counts['completed'] += 1
                    if not limiter.acquire():
                        break
                    with lock:
                        counts['attempts'] += 1
        except (OSError, EOFError, ValueError, ftplib.Error):
            with lock:
                counts['refusedOrBlocked'] += 1
                if connected:
                    counts['httpReconnectRefused'] = True

    def client(index):
        if row['tool'] == 'normal':
            normal_client()
            return
        sequence = index
        while limiter.acquire():
            with lock:
                counts['attempts'] += 1
            port = row['ports'][sequence % len(row['ports'])]
            sequence += row['concurrency']
            try:
                if row['tool'] == 'ftp_login':
                    with ftplib.FTP() as ftp:
                        ftp.connect(target, port, timeout=1)
                        try:
                            ftp.login('demo', 'invalid-demo-attempt')
                        except ftplib.error_perm:
                            pass  # 预期测试账号拒绝；不采用现场凭据或外部字典。
                elif row['tool'] == 'ssh_login':
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        ssh.connect(target, port=port, username='demo', password='invalid-demo-attempt',
                                    timeout=1, auth_timeout=1, banner_timeout=1, allow_agent=False, look_for_keys=False)
                    except paramiko.AuthenticationException:
                        pass
                    finally:
                        ssh.close()
                else:
                    with connector((target, port), timeout=1) as s:
                        if row['tool'] == 'slow_http':
                            s.sendall(b'GET / HTTP/1.1\r\nHost: demo.invalid\r\n')
                            while time.monotonic() < end and not stopped():
                                time.sleep(.5)
                                s.sendall(b'X-Demo: 1\r\n')
                        elif row['tool'] != 'connect_scan':
                            s.sendall(b'GET / HTTP/1.1\r\nHost: demo.invalid\r\nConnection: close\r\n\r\n')
                            s.recv(4096)
                with lock:
                    counts['completed'] += 1
            except (OSError, EOFError, ftplib.Error):
                with lock:
                    counts['refusedOrBlocked'] += 1
    with ThreadPoolExecutor(max_workers=row['concurrency']) as pool:
        list(pool.map(client, range(row['concurrency'])))
    return counts


def validate_plan(plan, directory):
    """实际执行与 dry-run 使用相同纯校验；运行目录只能引用安装时的固定白名单。"""
    d = Path(directory)
    c = load(plan['allowlist'])
    require(digest(c) == plan['allowlistSha256'] and address(c['macAddress']) == plan['grant']['macAddress'] and address(c['peerAddress']) == plan['grant']['peerAddress'], 'WORKER_ALLOWLIST_MISMATCH')
    rows = scenes(plan['scenesFile'], plan['grant']['scenes'])
    require(sha(plan['scenesFile']) == plan['grant']['scenesSha256'], 'WORKER_SCENES_MISMATCH')
    scene_ports(c['ports'], rows)
    # 远端只保存非秘密 allowlist，不能接受控制端临时扩大目标或端口。
    for r in rows:
        require(set(r['ports']) <= set(c['allowedPorts']), 'WORKER_PORT_NOT_ALLOWED')
    g = plan['grant']
    grant(dict(macAddress=c['macAddress'], peerAddress=c['peerAddress'], ports=c['ports'], authorizationSeconds=1800),
          rows, g, sha(plan['scenesFile']), d.name, g['mode'], time.time())
    require(plan['allowlist'] == str(d.parents[1] / 'allowlist.json').replace('\\', '/'), 'WORKER_ALLOWLIST_PATH_INVALID')
    require(g['runId'] == d.name and instant(g['validFrom']) <= time.time() < instant(g['validUntil']) and instant(g['validUntil']) - instant(g['validFrom']) <= 1800, 'WORKER_AUTHORIZATION_INVALID')
    require(plan['version'] == VERSION and instant(plan['startAt']) >= instant(g['validFrom']), 'WORKER_PLAN_INVALID')
    require(instant(plan['startAt']) + sum(r['durationSeconds'] + r['cooldownSeconds'] for r in rows) < instant(g['validUntil']), 'WORKER_PLAN_TOO_LONG')
    return c, rows, g


def execute(plan, directory, *, stop_event=None):
    """计划包含本地 allowlist 摘要与绝对截止时间；STOP 文件和 Ctrl-C 均立即停止，日志只保留计数。"""
    d = Path(directory)
    c, rows, g = validate_plan(plan, d)
    event = stop_event or threading.Event()
    if stop_event is None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: event.set())
    mono_end = time.monotonic() + instant(g['validUntil']) - time.time()
    stopped = lambda: event.is_set() or (d / 'STOP').exists() or time.monotonic() >= mono_end or time.time() >= instant(g['validUntil'])
    record = {'runId': g['runId'], 'scenesSha256': sha(plan['scenesFile']), 'pid': os.getpid(), 'startedAt': stamp(), 'scenes': [], 'finished': False}
    def save():
        write(d / 'worker-state.json', record, replace=(d / 'worker-state.json').exists())
    save()
    try:
        while time.time() < instant(plan['startAt']) and not stopped():
            time.sleep(.05)
        for row in rows:
            if stopped():
                break
            fact = {'id': row['id'], 'family': row['family'], 'startedAt': stamp(), 'tool': row['tool'], 'finished': False}
            record['scenes'].append(fact)
            save()
            if row['tool'] == 'nmap':
                tree = ProcessTree()
                try:
                    with (d / ('nmap-' + row['id'] + '.log')).open('xb') as log:
                        p = tree.start(nmap_command(c['nmap'], c['macAddress'], row), log)
                        deadline = time.monotonic() + row['durationSeconds']
                        try:
                            while p.poll() is None and time.monotonic() < deadline and not stopped():
                                time.sleep(.05)
                        finally:
                            tree.stop(p)
                        fact['returnCode'] = p.returncode
                        require(p.returncode == 0 or time.monotonic() >= deadline or stopped(), 'NMAP_FAILED')
                finally:
                    tree.close()
            else:
                fact['counts'] = traffic(c['macAddress'], row, stopped)
            fact.update(endedAt=stamp(), finished=not stopped())
            save()
            # 远端自主冷却；下一段还需控制端写入精确 GO 文件，否则不发包。
            until = time.monotonic() + row['cooldownSeconds']
            while time.monotonic() < until and not stopped():
                time.sleep(.1)
            if row != rows[-1]:
                next_id = rows[rows.index(row) + 1]['id']
                while not (d / ('GO-' + next_id)).exists() and not stopped():
                    time.sleep(.1)
        record['finished'] = not stopped() and len(record['scenes']) == len(rows) and all(r['finished'] for r in record['scenes'])
    finally:
        record.update(stopped=True, endedAt=stamp())
        save()
    return record


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', required=True)
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args()
    plan = load(args.plan)
    if args.dry_run:
        _, rows, _ = validate_plan(plan, Path(args.plan).parent)
        print(json.dumps({'writes': False, 'network': False, 'scenes': [r['id'] for r in rows]}))
        return
    execute(plan, Path(args.plan).parent)


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
