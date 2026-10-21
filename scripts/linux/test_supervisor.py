"""A2 离线验收：标准库替身、临时私有文件、假时钟；不访问网卡或网络。"""
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from scripts.linux import supervisor as s


def write_json(path, value):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.write_text(json.dumps(value))
    path.chmod(0o600)


class Clock:
    def __init__(self):
        self.now = 0.0
        self.epoch = time.time()
        self.sleeps = []
        self.hook = lambda: None

    def monotonic(self):
        return self.now

    def wall(self):
        return self.epoch + self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds
        self.hook()


class Process:
    """wait 的超时由假时钟推进，不真实等待八秒或三十秒。"""

    def __init__(self, pid, clock, *, lifetime=1, code=1, ignore_term=False, finish=lambda: None):
        self.pid, self.clock = pid, clock
        self.deadline = None if lifetime is None else clock.now + lifetime
        self.code, self.ignore_term, self.finish = code, ignore_term, finish
        self.returncode = None
        self.signals, self.waits = [], []
        self.ended_at = None

    def end(self, code):
        if self.returncode is None:
            self.returncode, self.ended_at = code, self.clock.now
            self.finish()

    def poll(self):
        if self.deadline is not None and self.clock.now >= self.deadline:
            self.end(self.code)
        return self.returncode

    def terminate(self):
        self.signals.append(('TERM', self.clock.now))
        if not self.ignore_term:
            self.end(-signal.SIGTERM)

    def kill(self):
        self.signals.append(('KILL', self.clock.now))
        self.end(-signal.SIGKILL)

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.poll() is None:
            if timeout is None:
                raise AssertionError('测试不允许无界等待存活的替身')
            self.clock.sleep(timeout)
            if self.poll() is None:
                raise subprocess.TimeoutExpired('fixture-child', timeout)
        return self.returncode


class Fixture:
    def __init__(self, directory, **settings):
        self.base = Path(directory).resolve()
        self.root, self.release = self.base / 'private', self.base / 'release'
        (self.root / 'config').mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        (self.release / 'scripts/p8').mkdir(parents=True)
        (self.release / 'scripts/p8/sensor_service.py').write_text('# fixture service\n')
        (self.release / 'guardlive').write_text('# fixture guardlive\n')
        (self.release / 'guardlive').chmod(0o700)
        self.config = dict(environment='authorized', captureScope='all_inbound_tcp',
            interface='ens17', allowedInterfaces=['ens17'], localAddresses=['192.0.2.10'],
            authorizedUntil='9999-12-31T00:00:00Z',
            sensorId='10000000-0000-4000-8000-000000000001',
            assetId='10000000-0000-4000-8000-000000000002',
            captureScopeId='10000000-0000-4000-8000-000000000003',
            upload=dict(baseUrl='https://127.0.0.1:18082'))
        self.save_config()
        self.meminfo = self.base / 'meminfo'
        self.meminfo.write_text('MemTotal: 2000000 kB\nMemAvailable: 1000000 kB\n')
        self.ip = self.base / 'ip'
        self.ip_output = self.base / 'ip.stdout'
        self.ip_output.write_text('2: ens17 inet 192.0.2.10/24 brd 192.0.2.255 scope global ens17\n'
                                  '2: ens17 inet6 fe80::1/64 scope link\n')
        self.ip.write_text('#!' + sys.executable + '\n'
            'from pathlib import Path\nimport json, sys\n'
            'p = Path(__file__)\n'
            'p.with_suffix(".argv").write_text(json.dumps(sys.argv[1:]))\n'
            'print(p.with_suffix(".stdout").read_text(), end="")\n')
        self.ip.chmod(0o700)
        self.clock = Clock()
        self.events, self.commands, self.processes = [], [], []
        self.capture_plans, self.drain_plans = [], []
        self.capture_boots, self.ip_calls = [], []
        self.free_disk = 20 * 1000**3
        self.settings = s.Settings(self.root, self.release, ip_command=str(self.ip),
            meminfo=self.meminfo, poll_seconds=1, **settings)
        self.runtime = s.Runtime(platform=lambda: 'linux', username=lambda: 'cybersensor',
            wall=self.clock.wall, monotonic=self.clock.monotonic, sleep=self.clock.sleep,
            disk_usage=self.disk_usage, run=self.read_ip, popen=self.spawn, log=self.events.append)
        self.supervisor = s.Supervisor(self.settings, self.runtime)

    def save_config(self):
        write_json(self.root / 'config/sensor.json', self.config)

    def disk_usage(self, path):
        assert path == '/', '必须检查根分区而非私有根的分区'
        return SimpleNamespace(free=self.free_disk)

    def read_ip(self, command, **kwargs):
        self.ip_calls.append((command, kwargs))
        assert command == [str(self.ip), '-o', 'addr', 'show', 'dev', 'ens17']
        assert kwargs == dict(capture_output=True, text=True, check=True, timeout=5)
        return SimpleNamespace(stdout=self.ip_output.read_text())

    def boot(self, *, batches=(1,), acks=(), report=True):
        boot = self.root / 'ledger/sensor' / str(uuid.uuid4())
        boot.mkdir(parents=True, mode=0o700)
        config = json.loads(json.dumps(self.config))
        config['bootId'] = boot.name
        config['upload']['spoolDir'] = str(boot / 'spool')
        write_json(boot / 'config.json', config)
        spool = boot / 'spool' / boot.name
        spool.mkdir(parents=True, mode=0o700)
        write_json(spool / 'meta.json', dict(bootId=boot.name, sensorId=config['sensorId']))
        for number in batches:
            write_json(spool / f'batch-{number:012d}.json', dict(sequence=number))
        for number in acks:
            write_json(spool / f'ack-{number:012d}.json', dict(status='accepted'))
        if report:
            write_json(boot / 'report.json', dict(status='completed', upload=dict(pendingBatches=0)))
        (boot / 'trace.jsonl').write_text('fixture trace\n')
        (boot / 'observations.jsonl.1').write_text('fixture observations\n')
        return boot

    def initialize(self):
        self.supervisor.preflight()
        self.supervisor.provision()

    def old(self, boot, seconds=s.RETENTION_SECONDS + 1):
        stamp = self.clock.wall() - seconds
        for path in [*boot.rglob('*'), boot]:
            os.utime(path, (stamp, stamp))

    def spawn(self, command, **kwargs):
        assert kwargs['cwd'] == str(self.release)
        assert kwargs['stdin'] == subprocess.DEVNULL and kwargs['close_fds']
        assert kwargs['env']['PYTHONDONTWRITEBYTECODE'] == '1'
        assert 'shell' not in kwargs and 'start_new_session' not in kwargs
        self.commands.append((command, self.clock.now))
        draining = '-drain' in command
        plans = self.drain_plans if draining else self.capture_plans
        plan = plans.pop(0) if plans else ({'code': 0} if draining else {'fatal': 'UNAUTHENTICATED'})
        if plan.get('start_error'):
            raise OSError('fixture secret must never be logged')
        if draining:
            boot = Path(command[2]).parent
            # 任一时刻至多有一个补传进程。
            assert all(p.poll() is not None for p in self.processes
                       if getattr(p, 'draining', False))
            def finish():
                if plan.get('code', 0) == 0 and not plan.get('ignore_term', False):
                    spool = boot / 'spool' / boot.name
                    for batch in spool.glob('batch-*.json'):
                        write_json(spool / batch.name.replace('batch-', 'ack-'), dict(status='accepted'))
        else:
            assert command == self.supervisor.capture_command()
            boot = self.boot(report=False)
            self.capture_boots.append(boot)
            def finish():
                if plan.get('report', True):
                    report = plan.get('report_value', dict(status='upload_incomplete',
                        upload=dict(fatalCode=plan.get('fatal', ''))))
                    write_json(boot / 'report.json', report)
                if plan.get('corrupt_report'):
                    (boot / 'report.json').write_text('{')
                plan.get('finish', lambda: None)()
        process = Process(1000 + len(self.processes), self.clock,
            lifetime=plan.get('lifetime', 1), code=plan.get('code', 0 if draining else 1),
            ignore_term=plan.get('ignore_term', False), finish=finish)
        process.draining = draining
        self.processes.append(process)
        return process


class FixtureTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rs-a2-', dir='/private/tmp')
        self.addCleanup(self.temp.cleanup)
        self.counter = 0

    def fixture(self, **settings):
        self.counter += 1
        directory = Path(self.temp.name) / str(self.counter)
        directory.mkdir(mode=0o700)
        return Fixture(directory, **settings)


class SupervisorTest(FixtureTestCase):
    def test_defaults_and_cli_standard_library_only(self):
        self.assertEqual((s.RESTART_SECONDS, s.STOP_TIMEOUT_SECONDS, s.DRAIN_INTERVAL_SECONDS,
                          s.RESOURCE_CHECK_SECONDS), (30, 8, 300, 10))
        self.assertEqual(s.LEDGER_MAX_BYTES, 5 * 1024**3)
        self.assertEqual(s.MIN_MEMORY_BYTES, 300_000_000)
        self.assertEqual(s.MIN_ROOT_FREE_BYTES, 10_000_000_000)
        # -S 不加载 site-packages，证实 supervisor 无 toolkit 的第三方导入链。
        result = subprocess.run([sys.executable, '-I', '-S', str(Path(s.__file__)), '--help'],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'--ip-command', result.stdout)

    def test_preflight_platform_user_and_static_scope(self):
        cases = [
            ('platform', lambda h: setattr(h.runtime, 'platform', lambda: 'darwin')),
            ('user', lambda h: setattr(h.runtime, 'username', lambda: 'root')),
            ('environment', lambda h: h.config.update(environment='research')),
            ('scope', lambda h: h.config.update(captureScope='service')),
            ('interfaces', lambda h: h.config.update(allowedInterfaces=['ens17', 'eth0'])),
            ('interface', lambda h: h.config.update(interface='-bad')),
            ('dynamic', lambda h: h.config.update(localAddressSource='interface')),
            ('empty source', lambda h: h.config.update(localAddressSource='')),
            ('null source', lambda h: h.config.update(localAddressSource=None)),
            ('expired', lambda h: h.config.update(authorizedUntil='2000-01-01T00:00:00Z')),
            ('timezone', lambda h: h.config.update(authorizedUntil='9999-01-01T00:00:00')),
            ('peer whitelist', lambda h: h.config.update(peerAddresses=['192.0.2.20'])),
            ('port whitelist', lambda h: h.config.update(servicePorts=[443])),
            ('service port', lambda h: h.config.update(servicePort=443)),
            ('lab', lambda h: h.config.update(lab={})),
        ]
        for name, change in cases:
            with self.subTest(name=name):
                h = self.fixture()
                change(h)
                h.save_config()
                self.assertEqual(h.supervisor.run(), 2)
                self.assertEqual(h.commands, [])

    def test_preflight_addresses_are_exact_set(self):
        for addresses in ([], ['192.0.2.11'], ['192.0.2.10', '192.0.2.11'],
                          ['127.0.0.1'], ['169.254.1.1'], ['0.0.0.0'], ['224.0.0.1'],
                          ['192.0.2.10', '192.0.2.10'], ['192.0.2.10', '2001:db8::10']):
            with self.subTest(addresses=addresses):
                h = self.fixture()
                h.config['localAddresses'] = addresses
                h.save_config()
                self.assertEqual(h.supervisor.run(), 2)
                self.assertFalse(h.commands)
        h = self.fixture()
        h.ip_output.write_text(h.ip_output.read_text() + '2: ens17 inet6 2001:db8::10/64 scope global\n')
        self.assertEqual(h.supervisor.run(), 2, '新增可采集 IPv6 不能静默忽略')

    def test_fake_ip_executable_and_unavailable_interface(self):
        h = self.fixture()
        expected = {s.ipaddress.ip_address('192.0.2.10')}
        self.assertEqual(s.interface_addresses('ens17', ip_command=h.ip), expected)
        self.assertEqual(json.loads(h.ip.with_suffix('.argv').read_text()),
                         ['-o', 'addr', 'show', 'dev', 'ens17'])
        for output in ('', 'not an address\n', '2: ens17 inet invalid\n'):
            h.ip_output.write_text(output)
            self.assertEqual(h.supervisor.run(), 2)
        h.ip.write_text('#!' + sys.executable + '\nraise SystemExit(1)\n')
        h.runtime.run = subprocess.run
        self.assertEqual(h.supervisor.run(), 2)
        self.assertFalse(h.commands)

    def test_loopback_https_constraint_is_not_relaxed(self):
        invalid = ['http://127.0.0.1:18082', 'https://example.invalid:443',
                   'https://127.0.0.1', 'https://127.0.0.1:99999',
                   'https://127.0.0.1:18082/path', 'https://127.0.0.1:18082?q=1',
                   'https://127.0.0.1:18082#x', 'https://user:fixture@127.0.0.1:18082']
        for url in invalid:
            for source in ('cli', 'config'):
                with self.subTest(url=url, source=source):
                    h = self.fixture()
                    if source == 'config':
                        h.config['upload']['baseUrl'] = url
                        h.save_config()
                    else:
                        h.supervisor.s = replace(h.settings, backend_url=url)
                    self.assertEqual(h.supervisor.run(), 2)
                    self.assertFalse(h.commands)

    def test_lock_conflict_and_release(self):
        h = self.fixture()
        h.initialize()
        lock = h.root / 'ledger/sensor.supervisor.lock'
        with s.exclusive_lock(lock):
            self.assertEqual(h.supervisor.run(), 2)
            self.assertFalse(h.commands)
        self.assertEqual(h.supervisor.run(), 3)
        with s.exclusive_lock(lock):
            self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_authorization_identity_set_and_all_fatal_branches(self):
        # 独立列出从后端与 guardup 审核的取值，避免“遍历实现集合”的同义测试。
        expected = {'UNAUTHENTICATED', 'FORBIDDEN', 'MACHINE_TLS_REQUIRED',
                    'MACHINE_IDENTITY_REQUIRED', 'SCOPE_DENIED', 'SENSOR_INACTIVE',
                    'AUTHORIZATION_INACTIVE', 'CONFIG_INACTIVE', 'BOOT_ID_MISMATCH',
                    'CAPTURE_SCOPE_INACTIVE', 'BUILD_NOT_APPROVED', 'SPOOL_IDENTITY_MISMATCH'}
        self.assertEqual(s.AUTH_IDENTITY_FATAL_CODES, expected)
        for code in sorted(expected):
            with self.subTest(code=code):
                h = self.fixture()
                h.capture_plans = [dict(fatal=code)]
                self.assertEqual(h.supervisor.run(), 3)
                self.assertEqual(len(h.capture_boots), 1)
                self.assertFalse(any(e['event'] == 'capture_retry' for e in h.events))

    def test_other_exits_wait_thirty_seconds_and_get_new_boot(self):
        plans = [dict(fatal='HEALTH_QUEUE_OVERFLOW'), dict(fatal='CAPACITY_EXCEEDED'),
                 dict(fatal='CONTRACT_UNSUPPORTED'), dict(fatal='IDEMPOTENCY_CONFLICT'),
                 dict(fatal='UNKNOWN_CODE'), dict(report=False), dict(corrupt_report=True),
                 dict(report_value=dict(upload=None)), dict(code=0), dict(code=3)]
        for plan in plans:
            with self.subTest(plan=plan):
                h = self.fixture()
                h.capture_plans = [plan, dict(fatal='UNAUTHENTICATED')]
                self.assertEqual(h.supervisor.run(), 3)
                self.assertEqual(len(h.capture_boots), 2)
                self.assertNotEqual(h.capture_boots[0], h.capture_boots[1])
                captures = [(cmd, at) for cmd, at in h.commands if '--parent-pid' in cmd]
                drain_start = next(at for cmd, at in h.commands if '-drain' in cmd)
                self.assertEqual(drain_start - h.processes[0].ended_at, 30)
                self.assertEqual(captures[1][1] - h.processes[0].ended_at, 31)
                self.assertTrue((h.capture_boots[0] / 'config.json').exists())

    def test_start_failure_retries_and_does_not_expose_error(self):
        h = self.fixture(restart_seconds=7)
        h.capture_plans = [dict(start_error=True), dict(fatal='UNAUTHENTICATED')]
        self.assertEqual(h.supervisor.run(), 3)
        self.assertEqual(h.commands[1][1] - h.commands[0][1], 7)
        self.assertNotIn('fixture secret', json.dumps(h.events))

    def test_report_is_bound_to_current_boot(self):
        h = self.fixture()
        h.initialize()
        old = h.boot(batches=())
        write_json(old / 'report.json', dict(upload=dict(fatalCode='UNAUTHENTICATED')))
        h.capture_plans = [dict(fatal='HEALTH_QUEUE_OVERFLOW'), dict(fatal='SCOPE_DENIED')]
        self.assertEqual(h.supervisor.run(), 3)
        self.assertEqual(len(h.capture_boots), 2)

    def test_capture_argv_matches_sensor_service_actual_options(self):
        h = self.fixture()
        self.assertEqual(h.supervisor.run(), 3)
        self.assertEqual(h.commands[0][0], [sys.executable,
            str(h.release / 'scripts/p8/sensor_service.py'), '--root', str(h.root),
            '--release', str(h.release), '--parent-pid', str(os.getpid()),
            '--backend-url', 'https://127.0.0.1:18082'])
        for name in ('sensor.stdout.log', 'sensor.stderr.log'):
            self.assertEqual((h.root / 'logs' / name).stat().st_mode & 0o777, 0o600)

    def test_drain_only_when_matching_ack_is_absent_and_is_sequential(self):
        h = self.fixture()
        h.initialize()
        confirmed = h.boot(batches=(1, 2), acks=(1, 2))
        empty = h.boot(batches=())
        pending = [h.boot(batches=(1, 2), acks=(1,)), h.boot(batches=(1,), acks=(2,))]
        for boot in pending:
            self.assertTrue(h.supervisor.pending_batches(boot))
        self.assertEqual(h.supervisor.pending_batches(confirmed), set())
        self.assertEqual(h.supervisor.run(), 3)
        drains = [cmd for cmd, _ in h.commands if '-drain' in cmd]
        self.assertEqual(len(drains), 2)
        for cmd in drains:
            boot = Path(cmd[2]).parent
            self.assertIn(boot, pending)
            self.assertNotIn(boot, (confirmed, empty))
            self.assertEqual(cmd, [str(h.release / 'guardlive'), '-config', str(boot / 'config.json'),
                                   '-drain', '-drain-timeout', '60s'])
        self.assertLess(h.commands.index((drains[-1], 1)), len(h.commands) - 1)

    def test_no_pending_batches_never_starts_drain(self):
        h = self.fixture()
        h.initialize()
        h.boot(batches=())
        h.boot(batches=(1,), acks=(1,))
        self.assertEqual(h.supervisor.run(), 3)
        self.assertFalse(any('-drain' in cmd for cmd, _ in h.commands))

    def test_nonfile_ack_and_foreign_meta_cannot_prove_confirmation(self):
        for kind in ('directory', 'symlink', 'foreign identity'):
            with self.subTest(kind=kind):
                h = self.fixture()
                h.initialize()
                boot = h.boot(acks=(1,))
                spool = boot / 'spool' / boot.name
                ack = spool / 'ack-000000000001.json'
                if kind == 'foreign identity':
                    write_json(spool / 'meta.json', dict(bootId=boot.name, sensorId=str(uuid.uuid4())))
                else:
                    ack.unlink()
                    if kind == 'directory':
                        ack.mkdir(mode=0o700)
                    else:
                        ack.symlink_to(spool / 'meta.json')
                h.old(boot)
                with self.assertRaises(s.StopSupervisor):
                    h.supervisor.pending_batches(boot)
                h.supervisor.cleanup()
                self.assertTrue((spool / 'batch-000000000001.json').exists())
                self.assertTrue((boot / 'config.json').exists())

    def test_drain_failure_retries_before_restart_and_never_overlaps_capture(self):
        # 补传心跳会改写后端 guard_boot_id，与采集并行会让当前采集被拒为 BOOT_ID_MISMATCH。
        h = self.fixture()
        h.initialize()
        old = h.boot()
        h.drain_plans = [dict(code=1), dict(code=0), dict(code=0)]
        h.capture_plans = [dict(lifetime=303, fatal='HEALTH_QUEUE_OVERFLOW'),
                           dict(fatal='UNAUTHENTICATED')]
        self.assertEqual(h.supervisor.run(), 3)
        drains = [(cmd, at) for cmd, at in h.commands if '-drain' in cmd]
        starts = [at for cmd, at in h.commands if '--parent-pid' in cmd]
        self.assertEqual(len(starts), 2)
        self.assertEqual(sum(Path(cmd[2]).parent == old for cmd, _ in drains), 2)
        self.assertFalse(any(starts[0] < at < starts[0] + 303 for _, at in drains))
        self.assertTrue(all(at <= starts[0] or starts[0] + 303 <= at <= starts[1] for _, at in drains))
        self.assertTrue(any(e['event'] == 'drain_failed' for e in h.events))

    def test_drain_missing_config_and_spawn_failure_do_not_block_capture(self):
        h = self.fixture()
        h.initialize()
        broken = h.boot()
        (broken / 'config.json').unlink()
        h.boot()
        h.drain_plans = [dict(start_error=True)]
        self.assertEqual(h.supervisor.run(), 3)
        self.assertEqual(len(h.capture_boots), 1)
        self.assertTrue(any(e['event'] == 'drain_skipped' for e in h.events))

    def test_drain_timeout_is_bounded_and_capture_still_starts(self):
        h = self.fixture()
        h.initialize()
        old = h.boot()
        h.drain_plans = [dict(lifetime=None, ignore_term=True, code=1)]
        self.assertEqual(h.supervisor.run(), 3)
        drain = h.processes[0]
        self.assertEqual(drain.signals, [('TERM', 90), ('KILL', 98)])
        self.assertTrue(h.supervisor.pending_batches(old))
        self.assertEqual(len(h.capture_boots), 1)

    def test_cleanup_keeps_only_report_for_old_fully_acked_boot(self):
        h = self.fixture()
        h.initialize()
        old = h.boot(batches=(1, 2), acks=(1, 2))
        report = (old / 'report.json').read_bytes()
        h.old(old)
        h.supervisor.cleanup()
        self.assertEqual([p.name for p in old.iterdir()], ['report.json'])
        self.assertEqual((old / 'report.json').read_bytes(), report)
        h.supervisor.cleanup()  # 清理过的摘要目录可安全重复扫描。
        self.assertEqual([p.name for p in old.iterdir()], ['report.json'])

    def test_cleanup_preserves_pending_recent_active_and_unprovable_boots(self):
        h = self.fixture()
        h.initialize()
        pending = h.boot(batches=(1, 2), acks=(1,))
        missing = h.boot(acks=(1,), report=False)
        corrupt = h.boot(acks=(1,))
        (corrupt / 'report.json').write_text('{')
        active = h.boot(acks=(1,))
        recent_ack = h.boot(acks=(1,))
        for boot in (pending, missing, corrupt, active, recent_ack):
            h.old(boot)
        os.utime(recent_ack / 'spool' / recent_ack.name / 'ack-000000000001.json', None)
        recent = h.boot(acks=(1,))
        boundary = h.boot(acks=(1,))
        h.old(boundary, s.RETENTION_SECONDS)
        h.supervisor.active_boot = active
        before = {boot: sorted(str(p.relative_to(boot)) for p in boot.rglob('*'))
                  for boot in (pending, missing, corrupt, active, recent_ack, recent, boundary)}
        h.supervisor.cleanup()
        for boot, names in before.items():
            self.assertEqual(sorted(str(p.relative_to(boot)) for p in boot.rglob('*')), names)

    def test_symlinks_and_foreign_spool_are_not_followed_or_cleaned(self):
        h = self.fixture()
        h.initialize()
        outside = h.base / 'outside'
        outside.mkdir(mode=0o700)
        marker = outside / 'preserve'
        marker.write_text('fixture')
        boot = h.boot(acks=(1,))
        (boot / 'extra').symlink_to(outside)
        h.old(boot)
        h.supervisor.cleanup()
        self.assertTrue(marker.exists())
        self.assertTrue((boot / 'config.json').exists())
        with self.assertRaises(s.StopSupervisor):
            list(s.tree_entries(h.root / 'ledger'))
        (boot / 'extra').unlink()
        config = json.loads((boot / 'config.json').read_text())
        config['upload']['spoolDir'] = str(outside)
        write_json(boot / 'config.json', config)
        h.old(boot)
        h.supervisor.cleanup()
        self.assertTrue((boot / 'config.json').exists())
        self.assertTrue(marker.exists())

    def test_ledger_over_limit_stops_before_cleanup_and_keeps_all_data(self):
        h = self.fixture(ledger_max_bytes=1)
        h.initialize()
        old = h.boot(acks=(1,))
        h.old(old)
        before = {str(p): p.read_bytes() for p in old.rglob('*') if p.is_file()}
        self.assertEqual(h.supervisor.run(), 4)
        self.assertFalse(h.commands)
        self.assertEqual(before, {str(p): p.read_bytes() for p in old.rglob('*') if p.is_file()})

    def test_ledger_all_files_count_and_limit_is_strictly_greater(self):
        h = self.fixture()
        h.initialize()
        file = h.root / 'ledger/observer-state.json'
        file.write_bytes(b'x' * 100)
        h.supervisor.s = replace(h.settings, ledger_max_bytes=100)
        h.supervisor.guard(force=True)
        file.write_bytes(b'x' * 101)
        with self.assertRaises(s.StopSupervisor) as error:
            h.supervisor.guard(force=True)
        self.assertEqual(error.exception.status, 4)

    def test_memory_and_root_disk_protect_before_capture(self):
        for resource in ('memory', 'disk'):
            with self.subTest(resource=resource):
                h = self.fixture()
                if resource == 'memory':
                    h.meminfo.write_text('MemAvailable: 292968 kB\n')  # 299999232 字节。
                else:
                    h.free_disk = s.MIN_ROOT_FREE_BYTES - 1
                self.assertEqual(h.supervisor.run(), 5)
                self.assertFalse(h.commands)
        h = self.fixture()
        h.meminfo.write_text('MemAvailable: 300000 kB\n')
        h.supervisor.s = replace(h.settings, min_memory_bytes=300000 * 1024)
        h.free_disk = s.MIN_ROOT_FREE_BYTES
        self.assertEqual(h.supervisor.run(), 3, '等于阈值仍允许采集')

    def test_running_guards_at_ten_seconds_stop_child_and_keep_spool(self):
        for kind, expected in (('memory', 5), ('disk', 5), ('ledger', 4), ('address', 2)):
            with self.subTest(kind=kind):
                h = self.fixture(ledger_max_bytes=10000)
                h.capture_plans = [dict(lifetime=None)]
                def change():
                    if h.clock.now >= 1:
                        if kind == 'memory':
                            h.meminfo.write_text('MemAvailable: 1 kB\n')
                        elif kind == 'disk':
                            h.free_disk = 1
                        elif kind == 'ledger':
                            (h.root / 'ledger/overflow').write_bytes(b'x' * 10001)
                        else:
                            h.ip_output.write_text('2: ens17 inet 192.0.2.11/24 scope global ens17\n')
                h.clock.hook = change
                self.assertEqual(h.supervisor.run(), expected)
                self.assertEqual(h.processes[0].signals, [('TERM', 10)])
                self.assertTrue((h.capture_boots[0] / 'spool').exists())

    def test_resource_guard_also_runs_during_drain_and_backoff(self):
        for phase in ('drain', 'backoff'):
            with self.subTest(phase=phase):
                h = self.fixture()
                if phase == 'drain':
                    h.initialize()
                    h.boot()
                    h.drain_plans = [dict(lifetime=None, code=1)]
                else:
                    h.capture_plans = [dict(fatal='HEALTH_QUEUE_OVERFLOW')]
                def low_memory():
                    if h.clock.now >= 2:
                        h.meminfo.write_text('MemAvailable: 1 kB\n')
                h.clock.hook = low_memory
                self.assertEqual(h.supervisor.run(), 5)
                self.assertLessEqual(h.clock.now, 11)
                if phase == 'drain':
                    self.assertFalse(h.capture_boots)
                    self.assertEqual(h.processes[0].signals, [('TERM', 10)])
                else:
                    self.assertEqual(len(h.capture_boots), 1)

    def test_address_changed_on_exit_prevents_restart(self):
        h = self.fixture()
        h.capture_plans = [dict(code=3, finish=lambda: h.ip_output.write_text(
            '2: ens17 inet 192.0.2.11/24 scope global ens17\n'))]
        self.assertEqual(h.supervisor.run(), 2)
        self.assertEqual(len(h.capture_boots), 1)

    def test_meminfo_invalid_and_unreadable_fail_closed(self):
        for content in ('MemFree: 1000000 kB\n', 'MemAvailable: -1 kB\n',
                        'MemAvailable: 500 MB\n'):
            with self.subTest(content=content):
                h = self.fixture()
                h.meminfo.write_text(content)
                self.assertEqual(h.supervisor.run(), 2)
                self.assertFalse(h.commands)
        h = self.fixture()
        h.meminfo.unlink()
        self.assertEqual(h.supervisor.run(), 2)

    def test_sigterm_forwarded_immediately_and_killed_after_eight_seconds(self):
        h = self.fixture()
        h.capture_plans = [dict(lifetime=None, ignore_term=True)]
        previous = signal.getsignal(signal.SIGTERM)
        h.clock.hook = lambda: h.supervisor.request_stop(signal.SIGTERM, None)
        self.assertEqual(h.supervisor.run(), 0)
        self.assertEqual(h.processes[0].signals, [('TERM', 1), ('KILL', 9)])
        self.assertIn(8, h.processes[0].waits)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
        with s.exclusive_lock(h.root / 'ledger/sensor.supervisor.lock'):
            pass

    def test_sigterm_during_drain_kills_after_eight_seconds_and_never_captures(self):
        h = self.fixture()
        h.initialize()
        h.boot()
        h.drain_plans = [dict(lifetime=None, code=1, ignore_term=True)]
        def stop():
            if h.clock.now >= 4:
                h.supervisor.request_stop(signal.SIGTERM, None)
        h.clock.hook = stop
        self.assertEqual(h.supervisor.run(), 0)
        self.assertEqual(h.processes[0].signals, [('TERM', 4), ('KILL', 12)])
        self.assertFalse(h.capture_boots)
        self.assertEqual(h.clock.now, 12)

    def test_stop_during_backoff_never_restarts(self):
        h = self.fixture()
        h.capture_plans = [dict(fatal='HEALTH_QUEUE_OVERFLOW')]
        def stop():
            if h.clock.now >= 3:
                h.supervisor.request_stop(signal.SIGTERM, None)
        h.clock.hook = stop
        self.assertEqual(h.supervisor.run(), 0)
        self.assertEqual(len(h.capture_boots), 1)

    def test_invalid_permissions_are_rejected_without_changing_existing_files(self):
        for location in ('config/sensor.json', 'logs/sensor.stdout.log', 'ledger/sensor.supervisor.lock'):
            with self.subTest(location=location):
                h = self.fixture()
                if not location.startswith('config'):
                    h.initialize()
                    (h.root / location).write_text('fixture existing\n')
                file = h.root / location
                file.chmod(0o644)
                before = file.read_bytes()
                self.assertEqual(h.supervisor.run(), 2)
                self.assertEqual(file.read_bytes(), before)
                self.assertEqual(file.stat().st_mode & 0o777, 0o644)


SERVICE_FIXTURE = '''import argparse, json, os, pathlib, uuid
p = argparse.ArgumentParser()
for name in ('root', 'release', 'parent-pid', 'backend-url'):
    p.add_argument('--' + name, required=True)
a = p.parse_args()
assert int(a.parent_pid) == os.getppid() and int(a.parent_pid) > 1
assert a.backend_url == 'https://127.0.0.1:18082'
root = pathlib.Path(a.root)
boot = root / 'ledger/sensor' / str(uuid.uuid4())
boot.mkdir(mode=0o700)
c = json.loads((root / 'config/sensor.json').read_text())
c['bootId'] = boot.name
c['upload']['baseUrl'] = a.backend_url
c['upload']['spoolDir'] = str(boot / 'spool')
config = boot / 'config.json'
config.write_text(json.dumps(c))
config.chmod(0o600)
(root / 'service-pid').write_text(str(os.getpid()))
os.execv(str(pathlib.Path(a.release) / 'guardlive'), [str(pathlib.Path(a.release) / 'guardlive'),
    '-config', str(config), '-out', str(boot / 'observations.jsonl'),
    '-trace', str(boot / 'trace.jsonl'), '-report', str(boot / 'report.json'),
    '-duration', '0', '-parent-pid', a.parent_pid, '-drain-timeout', '5s'])
'''

GUARD_FIXTURE = '''import json, os, pathlib, signal, sys, time
args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
assert args['-duration'] == '0' and args['-drain-timeout'] == '5s'
assert int(args['-parent-pid']) == os.getppid()
config = pathlib.Path(args['-config'])
root = config.parents[3]
def term(signum, frame):
    (root / 'term-received').write_text(str(os.getpid()))
    raise SystemExit(0)
signal.signal(signal.SIGTERM, term)
(root / 'exec-proof.json').write_text(json.dumps(dict(pid=os.getpid(), ppid=os.getppid(), argv=sys.argv)))
print('fixture stdout', flush=True)
print('fixture stderr', file=sys.stderr, flush=True)
if (root / 'wait-for-signal').exists():
    while True:
        time.sleep(0.01)
else:
    report = pathlib.Path(args['-report'])
    report.write_text(json.dumps(dict(upload=dict(fatalCode='UNAUTHENTICATED'))))
    report.chmod(0o600)
    raise SystemExit(1)
'''


class ExecIntegrationTest(FixtureTestCase):
    """仅执行本地 Python 替身；真实验证 PPID/exec/信号，绝不执行实际 guardlive。"""

    def real_fixture(self):
        h = self.fixture()
        (h.release / 'scripts/p8/sensor_service.py').write_text(SERVICE_FIXTURE)
        (h.release / 'guardlive').write_text('#!' + sys.executable + '\n' + GUARD_FIXTURE)
        h.runtime.popen = subprocess.Popen
        h.runtime.run = subprocess.run
        h.runtime.monotonic, h.runtime.wall, h.runtime.sleep = time.monotonic, time.time, time.sleep
        return h

    def test_real_exec_preserves_pid_and_parent_and_appends_private_logs(self):
        h = self.real_fixture()
        h.initialize()
        for name in ('sensor.stdout.log', 'sensor.stderr.log'):
            file = h.root / 'logs' / name
            file.write_text('existing fixture\n')
            file.chmod(0o600)
        self.assertEqual(h.supervisor.run(), 3)
        proof = json.loads((h.root / 'exec-proof.json').read_text())
        self.assertEqual(proof['pid'], int((h.root / 'service-pid').read_text()))
        self.assertEqual(proof['ppid'], os.getpid())
        boot = next((h.root / 'ledger/sensor').iterdir())
        self.assertEqual(proof['argv'], [str(h.release / 'guardlive'),
            '-config', str(boot / 'config.json'), '-out', str(boot / 'observations.jsonl'),
            '-trace', str(boot / 'trace.jsonl'), '-report', str(boot / 'report.json'),
            '-duration', '0', '-parent-pid', str(os.getpid()), '-drain-timeout', '5s'])
        for name, message in (('sensor.stdout.log', 'fixture stdout'), ('sensor.stderr.log', 'fixture stderr')):
            file = h.root / 'logs' / name
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(file.read_text(), 'existing fixture\n' + message + '\n')

    def test_real_sigterm_reaches_exec_child_and_no_child_survives(self):
        h = self.real_fixture()
        (h.root / 'wait-for-signal').touch()
        repository = str(Path(s.__file__).resolve().parents[2])
        runner = ("import sys; from pathlib import Path; from types import SimpleNamespace; "
                  "sys.path.insert(0, sys.argv[1]); from scripts.linux.supervisor import Settings, Runtime, Supervisor; "
                  "settings=Settings(Path(sys.argv[2]), Path(sys.argv[3]), ip_command=sys.argv[4], meminfo=Path(sys.argv[5])); "
                  "runtime=Runtime(platform=lambda:'linux', username=lambda:'cybersensor', "
                  "disk_usage=lambda _:SimpleNamespace(free=20000000000)); "
                  "raise SystemExit(Supervisor(settings,runtime).run())")
        process = subprocess.Popen([sys.executable, '-B', '-c', runner, repository,
            str(h.root), str(h.release), str(h.ip), str(h.meminfo)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child_pid = None
        try:
            deadline = time.monotonic() + 5
            while not (h.root / 'exec-proof.json').exists() and process.poll() is None:
                self.assertLess(time.monotonic(), deadline, '替身启动超时')
                time.sleep(0.01)
            proof = json.loads((h.root / 'exec-proof.json').read_text())
            child_pid = proof['pid']
            self.assertEqual(proof['ppid'], process.pid)
            process.send_signal(signal.SIGTERM)
            output, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, (output, error))
            self.assertEqual(int((h.root / 'term-received').read_text()), child_pid)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == '__main__':
    unittest.main()
