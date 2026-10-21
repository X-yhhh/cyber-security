#!/usr/bin/env python3
"""A2：托管 Linux 只告警采集，资源不足时优先于 NewAPI 停止。

退出码：0 为主动停止；2 为自检、地址变化或所有权失败；3 为授权/身份拒绝；
4 为 ledger 超限；5 为主机资源不足。其他采集退出（含 0、报告缺失）等待 30 秒，
重新调用 release 内的 sensor_service.py，由它生成新 bootId 并 exec guardlive。
不调用 shell、网络探针、服务管理器或防火墙；本模块仅依赖 Python 标准库。

AUTH_IDENTITY_FATAL_CODES 的来源与边界：
- SecurityConfiguration：UNAUTHENTICATED、FORBIDDEN；DeployMachineTlsFilter：
  MACHINE_TLS_REQUIRED；GuardAccess：MACHINE_IDENTITY_REQUIRED、SCOPE_DENIED、
  SENSOR_INACTIVE、AUTHORIZATION_INACTIVE。
- GuardIngest / GuardHealth：CONFIG_INACTIVE、BOOT_ID_MISMATCH、
  CAPTURE_SCOPE_INACTIVE；GuardAdministration.observationAuthorization：
  AUTHORIZATION_INACTIVE；guardup.VerifyRemote：BUILD_NOT_APPROVED；
  guardup.OpenSpool：SPOOL_IDENTITY_MISMATCH。
- guardup/client.go 对除 408/429 外的 4xx 不重试，uploader.setFatal 将 Error.Code
  原样写入 upload.fatalCode。协议、容量、幂等冲突和 HEALTH_QUEUE_OVERFLOW 不在
  此集合。启动验证错误未必进入 uploader，也未必产生 report，不能伪造 fatalCode。

实现口径：spool 的实际批次目录为 <boot>/spool/<bootId>；仅有 batch 且没有
同序号 ack 才是未确认，不使用可能过期的 report.pendingBatches。清理要求有有效
报告且整个目录最近修改已超过七天，只留下原 report.json；不清理当前 boot。
内存 MB、磁盘 GB 按十进制字节，ledger 的 GiB 按 1024**3，包含全部 ledger 文件。

补传时机：后端每次心跳都把 sensor_agent.guard_boot_id 改为心跳的 bootId，批次写入
又要求 bootId 与之相等（GuardIngest.heartbeat/batches）。旧 boot 的 -drain 会发心跳，
若与当前采集并行，当前采集的下一批会被拒为 BOOT_ID_MISMATCH 并致命退出（退出码 3）。
因此补传只在没有采集子进程时执行：每次启动和每次重启采集之前；旧 boot 也只在重启
时产生，不会漏补。采集运行期间每个维护周期只做清理。

共享代码的限制留给 A5/后续评审：Go 部分失败路径不落 report.json，因此无法仅靠
报告识别这些拒绝。不放宽后端身份校验，不将离线替身测试表述为现场续传已验证。
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Callable
from urllib.parse import urlsplit


AUTH_IDENTITY_FATAL_CODES = frozenset({
    'UNAUTHENTICATED', 'FORBIDDEN', 'MACHINE_TLS_REQUIRED',
    'MACHINE_IDENTITY_REQUIRED', 'SCOPE_DENIED', 'SENSOR_INACTIVE',
    'AUTHORIZATION_INACTIVE', 'CONFIG_INACTIVE', 'BOOT_ID_MISMATCH',
    'CAPTURE_SCOPE_INACTIVE', 'BUILD_NOT_APPROVED', 'SPOOL_IDENTITY_MISMATCH',
})
RESTART_SECONDS = 30.0
STOP_TIMEOUT_SECONDS = 8.0
DRAIN_INTERVAL_SECONDS = 300.0
RESOURCE_CHECK_SECONDS = 10.0
LEDGER_MAX_BYTES = 5 * 1024**3
MIN_MEMORY_BYTES = 300 * 1000**2
MIN_ROOT_FREE_BYTES = 10 * 1000**3
RETENTION_SECONDS = 7 * 24 * 60 * 60
BOOT_NAME = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
BATCH_NAME = re.compile(r'batch-([0-9]{12}).json')
ACK_NAME = re.compile(r'ack-([0-9]{12}).json')


class StopSupervisor(Exception):
    """受控停止仅携带脱敏固定原因码，不包含配置、地址或子进程输出。"""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def require(condition, reason):
    if not condition:
        raise StopSupervisor(2, reason)


def absolute(value):
    """与 p8 文件工具相同：只接受绝对、无符号链接、无父目录穿越的路径。"""
    p = Path(value).expanduser()
    require(p.is_absolute() and '..' not in p.parts
            and not any(ord(c) < 32 for c in str(p)), 'ABSOLUTE_PATH_REQUIRED')
    require(not any(part.is_symlink() for part in (p, *p.parents)), 'SYMLINK_FORBIDDEN')
    return p


def private_dir(path, *, create=False):
    p = absolute(path)
    if create:
        p.mkdir(mode=0o700, exist_ok=True)
    info = p.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_DIRECTORY_REQUIRED')
    return p


def read_json(path):
    p = absolute(path)
    info = p.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600, 'PRIVATE_FILE_REQUIRED')
    require(info.st_size <= 1024 * 1024, 'JSON_TOO_LARGE')
    value = json.loads(p.read_bytes())
    require(isinstance(value, dict), 'JSON_OBJECT_REQUIRED')
    return value


def open_private(path, flags):
    """锁和日志只创建普通 0600 文件；已有宽权限或符号链接一律拒绝。"""
    p = absolute(path)
    fd = os.open(p, flags | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'PRIVATE_FILE_REQUIRED')
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextmanager
def exclusive_lock(path):
    """独占整个托管生命周期；冲突以自检失败结束，锁不传给采集子进程。"""
    fd = open_private(path, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StopSupervisor(2, 'SUPERVISOR_ALREADY_RUNNING') from None
        yield
    finally:
        os.close(fd)


def loopback_url(value):
    u = urlsplit(value)
    require(u.scheme == 'https' and u.hostname in ('127.0.0.1', '::1')
            and u.port and not u.username and not u.password and u.path in ('', '/')
            and not u.query and not u.fragment, 'LOCAL_TLS_ENDPOINT_REQUIRED')


def local_addresses(values):
    require(isinstance(values, list) and values, 'LOCAL_ADDRESSES_REQUIRED')
    addresses = {ipaddress.ip_address(v) for v in values}
    require(len(addresses) == len(values) and len({a.version for a in addresses}) == 1
            and all(not (a.is_link_local or a.is_loopback or a.is_unspecified
                         or a.is_multicast or getattr(a, 'scope_id', None))
                    for a in addresses), 'LOCAL_ADDRESSES_INVALID')
    return addresses


def interface_addresses(interface, *, ip_command='/usr/sbin/ip', run=subprocess.run):
    """ip 只读取指定接口；忽略链路本地等不可采集地址，新增全局 IPv6 也算变化。"""
    try:
        result = run([str(ip_command), '-o', 'addr', 'show', 'dev', interface],
                     capture_output=True, text=True, check=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        raise StopSupervisor(2, 'IP_ADDRESS_READ_FAILED') from None
    found = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        require(len(parts) >= 4 and parts[2] in ('inet', 'inet6'), 'IP_OUTPUT_INVALID')
        address = ipaddress.ip_interface(parts[3]).ip
        if not (address.is_link_local or address.is_loopback or address.is_unspecified
                or address.is_multicast):
            found.add(address)
    require(found, 'INTERFACE_ADDRESS_UNAVAILABLE')
    return found


def memory_available(path):
    """只使用 MemAvailable 的 kB 值（内核单位 1024 字节），缺失/无效时停止。"""
    for line in Path(path).read_text().splitlines():
        parts = line.split()
        if parts and parts[0] == 'MemAvailable:':
            require(len(parts) == 3 and parts[1].isdigit() and parts[2] == 'kB',
                    'MEMINFO_INVALID')
            return int(parts[1]) * 1024
    raise StopSupervisor(2, 'MEMINFO_UNAVAILABLE')


def tree_entries(directory):
    """逐项 lstat，不跟随链接；计量或删除时也不越过 ledger 的真实目录。"""
    pending = [absolute(directory)]
    while pending:
        p = pending.pop()
        try:
            info = p.lstat()
        except FileNotFoundError:  # 采集轮转可能刚刚替换了一个文件。
            continue
        require(not stat.S_ISLNK(info.st_mode), 'SYMLINK_FORBIDDEN')
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'LEDGER_FILE_INVALID')
        yield p, info
        if stat.S_ISDIR(info.st_mode):
            pending.extend(p.iterdir())


@dataclass(frozen=True)
class Settings:
    """运行阈值可注入；测试不需要真实等待、网卡、/proc 或磁盘统计。"""

    root: Path
    release: Path
    backend_url: str = 'https://127.0.0.1:18082'
    ip_command: str = '/usr/sbin/ip'
    meminfo: Path = Path('/proc/meminfo')
    ledger_max_bytes: int = LEDGER_MAX_BYTES
    min_memory_bytes: int = MIN_MEMORY_BYTES
    min_root_free_bytes: int = MIN_ROOT_FREE_BYTES
    restart_seconds: float = RESTART_SECONDS
    stop_timeout: float = STOP_TIMEOUT_SECONDS
    drain_interval: float = DRAIN_INTERVAL_SECONDS  # 采集期间的清理周期。
    resource_interval: float = RESOURCE_CHECK_SECONDS
    retention_seconds: float = RETENTION_SECONDS
    drain_process_timeout: float = 90.0  # 包含启动时最多 15 秒的配置读取。
    poll_seconds: float = 0.25


@dataclass
class Runtime:
    """仅供离线测试替换 OS 读取与进程/时钟；命令行不提供跳过平台或用户校验。"""

    platform: Callable = lambda: sys.platform
    username: Callable = lambda: pwd.getpwuid(os.getuid()).pw_name
    wall: Callable = time.time
    monotonic: Callable = time.monotonic
    sleep: Callable = time.sleep
    disk_usage: Callable = shutil.disk_usage
    run: Callable = subprocess.run
    popen: Callable = subprocess.Popen
    log: Callable = lambda value: print(json.dumps(value, ensure_ascii=False), flush=True)


class Supervisor:
    """串行补传旧 boot，监测直接采集子进程；任何停止路径都回收自身两个子进程。"""

    def __init__(self, settings: Settings, runtime: Runtime | None = None):
        self.s, self.rt = settings, runtime or Runtime()
        self.root, self.release = Path(settings.root), Path(settings.release)
        self.capture = self.drainer = None
        self.active_boot = None
        self.before_boots = set()
        self.config = None
        self.stopping = False
        self.terminating = {}
        self.next_guard = 0.0

    def event(self, name, **values):
        self.rt.log(dict(event=name, **values))

    def preflight(self):
        """校验实际 OS/用户、静态授权范围与接口地址，成功前不启动任何子进程。"""
        require(self.rt.platform() == 'linux', 'LINUX_REQUIRED')
        require(self.rt.username() == 'cybersensor', 'CYBERSENSOR_REQUIRED')
        for value in (self.s.ledger_max_bytes, self.s.min_memory_bytes,
                      self.s.min_root_free_bytes, self.s.restart_seconds, self.s.stop_timeout,
                      self.s.drain_interval, self.s.resource_interval, self.s.retention_seconds,
                      self.s.drain_process_timeout, self.s.poll_seconds):
            require(math.isfinite(value) and value > 0, 'LIMIT_INVALID')
        self.root = private_dir(self.root)
        self.release = absolute(self.release)
        require(self.release.is_dir(), 'RELEASE_REQUIRED')
        for path in (self.release / 'guardlive', self.release / 'scripts/p8/sensor_service.py'):
            p = absolute(path)
            require(p.is_file(), 'RELEASE_FILE_REQUIRED')
        require(os.access(self.release / 'guardlive', os.X_OK), 'GUARDLIVE_NOT_EXECUTABLE')
        loopback_url(self.s.backend_url)
        self.config = read_json(self.root / 'config/sensor.json')
        self.validate_scope(self.config)
        self.check_authorization()
        self.check_addresses()

    @staticmethod
    def validate_scope(config):
        interface = config['interface']
        require(isinstance(interface, str) and re.fullmatch(r'[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,95}', interface),
                'INTERFACE_INVALID')
        require(config['environment'] == 'authorized' and config['captureScope'] == 'all_inbound_tcp'
                and config['allowedInterfaces'] == [interface], 'CAPTURE_SCOPE_INVALID')
        require('localAddressSource' not in config, 'STATIC_ADDRESS_REQUIRED')
        require(not config.get('peerAddresses') and not config.get('servicePorts')
                and not config.get('servicePort') and not config.get('serviceEndpoint')
                and config.get('liveTargets') is None and config.get('lab') is None, 'CAPTURE_SCOPE_INVALID')
        local_addresses(config['localAddresses'])
        loopback_url(config['upload']['baseUrl'])

    def check_authorization(self):
        until = datetime.fromisoformat(self.config['authorizedUntil'].replace('Z', '+00:00'))
        require(until.tzinfo is not None and (until - datetime.fromtimestamp(
            self.rt.wall(), timezone.utc)).total_seconds() >= 1, 'AUTHORIZATION_EXPIRED')

    def check_addresses(self):
        actual = interface_addresses(self.config['interface'], ip_command=self.s.ip_command, run=self.rt.run)
        require(actual == local_addresses(self.config['localAddresses']), 'INTERFACE_ADDRESS_CHANGED')

    def provision(self):
        for name in ('ledger', 'logs'):
            private_dir(self.root / name, create=True)
        private_dir(self.root / 'ledger/sensor', create=True)

    def guard(self, *, force=False):
        """采集、补传、退避共用资源检查，最多每十秒检测一次；失败交给 finally 停子进程。"""
        now = self.rt.monotonic()
        if not force and now < self.next_guard:
            return
        self.next_guard = now + self.s.resource_interval
        if memory_available(self.s.meminfo) < self.s.min_memory_bytes:
            raise StopSupervisor(5, 'MEMORY_LOW')
        if self.rt.disk_usage('/').free < self.s.min_root_free_bytes:
            raise StopSupervisor(5, 'ROOT_DISK_LOW')
        # 超限时保留全部文件，不先执行清理来掩盖容量超限。
        size = sum(info.st_size for _, info in tree_entries(self.root / 'ledger')
                   if stat.S_ISREG(info.st_mode))
        if size > self.s.ledger_max_bytes:
            raise StopSupervisor(4, 'LEDGER_LIMIT_EXCEEDED')
        self.check_authorization()
        self.check_addresses()

    def boots(self):
        return {p for p in (self.root / 'ledger/sensor').iterdir()
                if BOOT_NAME.fullmatch(p.name) and private_dir(p)}

    def discover_boot(self):
        if self.active_boot is None:
            new = self.boots() - self.before_boots
            require(len(new) <= 1, 'BOOT_OWNERSHIP_AMBIGUOUS')
            if new:
                self.active_boot = new.pop()

    def spool(self, boot):
        """续传只使用该 boot 的原配置，不重写身份、字节或后端地址。"""
        config = read_json(boot / 'config.json')
        self.validate_scope(config)
        require(config['bootId'] == boot.name
                and config['upload']['spoolDir'] == str(boot / 'spool'), 'SPOOL_IDENTITY_MISMATCH')
        for key in ('sensorId', 'assetId', 'captureScopeId', 'interface'):
            require(config[key] == self.config[key], 'SPOOL_IDENTITY_MISMATCH')
        directory = private_dir(boot / 'spool' / boot.name)
        meta = read_json(directory / 'meta.json')
        require(meta['bootId'] == boot.name and meta['sensorId'] == config['sensorId'],
                'SPOOL_IDENTITY_MISMATCH')
        return directory

    def pending_batches(self, boot):
        directory = self.spool(boot)
        batches, acks = set(), set()
        for p in directory.iterdir():
            batch, ack = BATCH_NAME.fullmatch(p.name), ACK_NAME.fullmatch(p.name)
            if batch or ack:
                info = p.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o600, 'SPOOL_FILE_INVALID')
                (batches if batch else acks).add((batch or ack)[1])
        return batches - acks

    def spawn(self, command):
        """直接 Popen 保持真实 PPID；stdout/stderr 追加私有日志，不经过 shell 或内存队列。"""
        stdout = open_private(self.root / 'logs/sensor.stdout.log', os.O_WRONLY | os.O_APPEND)
        try:
            stderr = open_private(self.root / 'logs/sensor.stderr.log', os.O_WRONLY | os.O_APPEND)
            try:
                return self.rt.popen(command, cwd=str(self.release), stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, close_fds=True,
                                     env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            finally:
                os.close(stderr)
        finally:
            os.close(stdout)

    def capture_command(self):
        return [sys.executable, str(self.release / 'scripts/p8/sensor_service.py'),
                '--root', str(self.root), '--release', str(self.release),
                '--parent-pid', str(os.getpid()), '--backend-url', self.s.backend_url]

    def terminate(self, process):
        if process is not None and process.poll() is None and process.pid not in self.terminating:
            self.terminating[process.pid] = self.rt.monotonic()
            try:
                process.terminate()
            except ProcessLookupError:
                pass

    def request_stop(self, signum, frame):
        """信号处理器立即转发；循环中的 finally 负责计时、升级 SIGKILL 与 wait 回收。"""
        self.stopping = True
        self.terminate(self.capture)
        self.terminate(self.drainer)

    def stop_process(self, process):
        if process is None:
            return
        self.terminate(process)
        try:
            remaining = max(0, self.s.stop_timeout - (self.rt.monotonic()
                            - self.terminating.get(process.pid, self.rt.monotonic())))
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            self.event('child_kill', pid=process.pid)
            try:
                process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
        finally:
            self.terminating.pop(process.pid, None)

    def drain_old(self):
        """仅在无采集子进程时顺序补传旧 boot；失败或超时只记日志，下次启动前重试。"""
        require(self.capture is None, 'DRAIN_WHILE_CAPTURING')
        for boot in sorted(self.boots()):
            if self.stopping:
                return
            if boot == self.active_boot:
                continue
            self.guard()
            try:
                if not self.pending_batches(boot):
                    continue
            except (OSError, ValueError, KeyError, TypeError, StopSupervisor):
                self.event('drain_skipped', bootId=boot.name, reason='SPOOL_UNAVAILABLE')
                continue
            self.event('drain_start', bootId=boot.name)
            command = [str(self.release / 'guardlive'), '-config', str(boot / 'config.json'),
                       '-drain', '-drain-timeout', '60s']
            try:
                self.drainer = self.spawn(command)
                deadline = self.rt.monotonic() + self.s.drain_process_timeout
                while self.drainer.poll() is None and not self.stopping:
                    self.guard()
                    if self.rt.monotonic() >= deadline:
                        self.event('drain_failed', bootId=boot.name, reason='DRAIN_TIMEOUT')
                        break
                    self.rt.sleep(self.s.poll_seconds)
                if self.drainer.poll() is not None:
                    self.event('drain_finished' if self.drainer.returncode == 0 else 'drain_failed',
                               bootId=boot.name, exitCode=self.drainer.returncode)
            except StopSupervisor:
                self.terminate(self.drainer)
                raise
            except OSError:
                self.event('drain_failed', bootId=boot.name, reason='DRAIN_START_FAILED')
            finally:
                self.stop_process(self.drainer)
                self.drainer = None

    def cleanup(self):
        """只删超过保留期、可证明全部确认的旧 boot 内容；损坏/缺证据的一律保留。"""
        for boot in sorted(self.boots()):
            if boot == self.active_boot:
                continue
            try:
                read_json(boot / 'report.json')
                if self.pending_batches(boot):
                    continue
                entries = list(tree_entries(boot))
                if not entries or self.rt.wall() - max(info.st_mtime for _, info in entries) <= self.s.retention_seconds:
                    continue
            except (OSError, ValueError, KeyError, TypeError, StopSupervisor):
                continue
            for p in boot.iterdir():
                if p.name != 'report.json':
                    shutil.rmtree(p) if p.is_dir() else p.unlink()
            self.event('boot_cleaned', bootId=boot.name)

    def fatal_code(self):
        if self.active_boot is not None:
            try:
                upload = read_json(self.active_boot / 'report.json').get('upload', {})
                code = upload.get('fatalCode')
                return code if isinstance(code, str) else None
            except (OSError, ValueError, TypeError, AttributeError, StopSupervisor):
                pass
        self.event('report_unavailable')
        return None

    def backoff(self):
        """从退出/启动失败起等待完整 30 秒，期间仍响应停止和主机保护。"""
        deadline = self.rt.monotonic() + self.s.restart_seconds
        self.event('capture_retry', seconds=self.s.restart_seconds)
        while not self.stopping and self.rt.monotonic() < deadline:
            self.guard()
            self.rt.sleep(max(0, min(self.s.poll_seconds, deadline - self.rt.monotonic())))

    def monitor(self):
        """采集期间只做资源检查和周期清理；补传会改写后端 bootId，见模块说明。"""
        next_cleanup = self.rt.monotonic() + self.s.drain_interval
        while not self.stopping:
            self.discover_boot()
            if self.capture.poll() is not None:
                return
            self.guard()
            if self.rt.monotonic() >= next_cleanup:
                self.cleanup()
                next_cleanup = self.rt.monotonic() + self.s.drain_interval
            self.rt.sleep(self.s.poll_seconds)

    def run(self):
        """自检/锁持有至子进程回收完成；所有异常仅输出固定码，不回显异常消息。"""
        handlers = {}
        try:
            for sig in (signal.SIGTERM, signal.SIGINT):
                handlers[sig] = signal.signal(sig, self.request_stop)
            self.preflight()
            self.provision()
            with exclusive_lock(self.root / 'ledger/sensor.supervisor.lock'):
                try:
                    while not self.stopping:
                        self.guard(force=True)
                        self.drain_old()
                        self.cleanup()
                        if self.stopping:
                            break
                        # 补传最长可持续多轮，启动前重读授权配置和主机实际状态。
                        self.preflight()
                        self.guard(force=True)
                        self.before_boots, self.active_boot = self.boots(), None
                        try:
                            self.capture = self.spawn(self.capture_command())
                        except OSError:
                            self.event('capture_start_failed')
                            self.backoff()
                            continue
                        self.event('capture_started', pid=self.capture.pid)
                        self.monitor()
                        if self.stopping:
                            break
                        self.discover_boot()
                        self.capture.wait()
                        code = self.fatal_code()
                        self.event('capture_exited', exitCode=self.capture.returncode,
                                   fatalCode=code if code in AUTH_IDENTITY_FATAL_CODES else None)
                        self.capture = None
                        if code in AUTH_IDENTITY_FATAL_CODES:
                            raise StopSupervisor(3, code)
                        self.guard(force=True)
                        self.active_boot = None
                        self.backoff()
                finally:
                    # 先同时发 TERM，两个进程共享同一八秒截止，不串行各等待八秒。
                    self.terminate(self.capture)
                    self.terminate(self.drainer)
                    self.stop_process(self.capture)
                    self.stop_process(self.drainer)
        except StopSupervisor as exc:
            self.event('supervisor_stopped', exitCode=exc.status, reason=exc.reason)
            return exc.status
        except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError):
            self.event('supervisor_stopped', exitCode=2, reason='SELF_CHECK_FAILED')
            return 2
        finally:
            for sig, previous in handlers.items():
                signal.signal(sig, previous)
        self.event('supervisor_stopped', exitCode=0, reason='STOP_REQUESTED')
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--release', required=True, type=Path)
    parser.add_argument('--backend-url', default='https://127.0.0.1:18082')
    parser.add_argument('--ip-command', default='/usr/sbin/ip')
    parser.add_argument('--ledger-max-bytes', type=int, default=LEDGER_MAX_BYTES)
    parser.add_argument('--min-memory-bytes', type=int, default=MIN_MEMORY_BYTES)
    parser.add_argument('--min-root-free-bytes', type=int, default=MIN_ROOT_FREE_BYTES)
    parser.add_argument('--restart-seconds', type=float, default=RESTART_SECONDS)
    args = parser.parse_args(argv)
    os.umask(0o077)
    return Supervisor(Settings(**vars(args))).run()


if __name__ == '__main__':
    raise SystemExit(main())
