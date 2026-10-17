#!/usr/bin/env python3
"""复用演示总控：离线计划、真实预检、短期授权、冷却、可重入收尾和报告。

执行须显式提供本次 grant。dry-run 不创建目录、不取密、不连接后端/远端。
异常先撤销授权；任何清理失败保留准确对象及错误码，绝不暂停组合或改动 en0。
"""
import argparse
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.demo.common import CLEANUP, ROOT, VERSION, grant, instant, load, path, private, require, safe_main, scenes, sha, stamp, validate, write


class Runner:
    """依赖可替换以进行无网络的生命周期测试；持久化状态先于外部动作。"""
    def __init__(self, c, directory, state, control, remote, processes, *, clock=time.monotonic, sleep=time.sleep):
        self.c, self.d, self.s, self.control, self.remote, self.processes = c, Path(directory), state, control, remote, processes
        self.clock, self.sleep, self.stopped = clock, sleep, False
        self.root_process = None

    def save(self):
        write(self.d / 'state.json', self.s, replace=(self.d / 'state.json').exists())

    def wait(self, predicate, seconds, code, *, running=True):
        deadline = self.clock() + seconds
        while True:
            if running:
                require(not self.stopped and time.time() < instant(self.s['grant']['validUntil']) - 5, 'DEMO_INTERRUPTED_OR_EXPIRED')
                require(self.processes.alive(), 'DEMO_COMPONENT_EXITED')
                require(not (self.d / 'root/error.json').exists(), 'DEMO_ROOT_FAILED')
                if self.root_process:
                    require(self.root_process.poll() is None, 'DEMO_ROOT_EXITED')
            if predicate():
                return
            require(self.clock() < deadline, code)
            self.sleep(1)

    def capture_worker(self):
        try:
            value = self.remote.state(self.s['runId'])
            if value:
                self.s['worker'] = value
                write(self.d / 'worker.json', value, replace=True)
                self.save()
            return value
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            return None  # 入站阻断期间远端按本地时限自主运行；未知状态不能推进场景。

    def cool(self, seconds=240):
        """预算归零还需当前新鲜 healthy；无命令也必须连续保持健康 120 秒。"""
        healthy_since = None
        def ready():
            nonlocal healthy_since
            healthy = self.control.healthy()
            if not healthy:
                healthy_since = None
            elif healthy_since is None:
                healthy_since = self.clock()
            reset = self.control.reset_state()
            return healthy_since is not None and self.clock() - healthy_since >= 120 and reset['noActiveActions'] and self.control.recovered()
        self.wait(ready, seconds, 'DEMO_COOLDOWN_NOT_PROVEN')
        self.s['cleanup']['budgetRecovered'] = True
        self.save()

    def execute(self):
        from scripts.demo import preflight
        from scripts.demo.runtime import configurations, start_root
        ids, g = self.s['enrollment'], self.s['grant']
        checks = preflight.inspect(self.c, ids, self.remote, self.control, self.d / 'scenes.json')
        self.s.update(checks)
        self.save()
        # root 第一阶段只有只读核验；备份/业务授权发生在 ready 之后。
        self.s['rootRequested'] = True
        self.save()
        self.root_process = start_root(self.c, g, self.d, checks['interface'])
        self.wait(lambda: (self.d / 'root/ready.json').exists(), 120, 'DEMO_ROOT_NOT_READY')
        require(load(self.d / 'root/ready.json')['passed'], 'DEMO_ROOT_PREFLIGHT_FAILED')
        self.s['backup'] = self.control.backup()
        self.save()
        auth = self.control.authorize(g, checks['interface'], self.s['mode'])
        self.s['authorization'] = auth
        self.save()
        data, resolver = configurations(self.c, ids, g, auth, checks['interface'], self.d, self.control.bundle(), self.s['scenes'])
        self.processes.start('targets', [self.c['python'], '-B', ROOT / 'scripts/demo/targets.py', '--config', self.d / 'target-service.json'])
        self.wait(lambda: (self.d / 'targets-ready.json').exists(), 20, 'TARGET_SERVICES_NOT_READY')
        if self.s['mode'] == 'pf':
            write(self.d / 'root/input.json', data)
            self.wait(lambda: (self.d / 'root/boot.json').exists(), 60, 'EXECUTOR_BOOT_NOT_READY')
            resolver['scope']['ExecutorBootID'] = load(self.d / 'root/boot.json')['executorBootId']
            write(self.d / 'resolver.json', resolver)
            self.processes.start('resolver', [self.c['guardtargets'], '-config', self.d / 'resolver.json'])
        else:
            for role in ('recovery', 'run'):
                self.processes.start('observer-' + role, [self.c['python'], '-B', ROOT / 'scripts/p8/observer_executor.py', role, '--config', self.d / 'observer.json'])
        duration = min(1800, int(instant(g['validUntil']) - time.time()) - 10)
        require(duration > 240, 'RUN_WINDOW_EXHAUSTED')
        self.processes.start('sensor', [self.c['guardlive'], '-config', self.d / 'sensor.json', '-out', self.d / 'observations.jsonl',
                                        '-trace', self.d / 'capture.jsonl', '-report', self.d / 'sensor-report.json', '-duration', str(duration) + 's'])
        self.wait(self.control.healthy, 45, 'LIVE_HEALTH_NOT_READY')
        # 中断后的旧周期只能通过新健康链恢复；先恢复，后发包，不换预算身份。
        if not self.control.recovered():
            self.cool()
        self.s['remoteRequested'] = True
        self.save()
        worker_plan = dict(version=VERSION, grant=g, allowlistSha256=checks['allowlistSha256'], startAt=stamp())
        self.s['remoteLaunch'] = self.remote.start(g['runId'], worker_plan, self.d / 'scenes.json')
        self.save()
        for index, scene in enumerate(self.s['scenes']):
            def ended():
                w = self.capture_worker()
                return w and any(r['id'] == scene['id'] and r.get('finished') and r.get('endedAt') for r in w['scenes'])
            self.wait(ended, scene['durationSeconds'] + 60, 'SCENE_NOT_COMPLETED')
            self.s['cleanup']['budgetRecovered'] = False
            self.save()
            self.cool(scene['cooldownSeconds'] + 60)
            if index + 1 < len(self.s['scenes']):
                self.remote.marker(g['runId'], 'GO-' + self.s['scenes'][index + 1]['id'])
        self.wait(lambda: bool((self.capture_worker() or {}).get('stopped')), 90, 'WORKER_NOT_FINISHED')
        self.s['completed'] = True
        self.save()

    def teardown(self, abnormal):
        """每个清理项独立尝试；准确授权/PID/运行号，失败不会阻止其余清理，支持再次执行。"""
        errors = {}
        def attempt(name, op):
            try:
                okay = op()
                self.s['cleanup'][name] = okay is True
                if okay is not True:
                    errors[name] = 'NOT_VERIFIED'
            except BaseException as e:
                self.s['cleanup'][name] = False
                errors[name] = type(e).__name__
            self.save()
        if abnormal:
            attempt('authorizationRevoked', self.control.revoke)
        def attack_stop():
            if not self.s.get('remoteRequested'):
                return True
            self.remote.marker(self.s['runId'], 'STOP')
            self.wait(lambda: self.remote.stopped(self.s['runId']), 30, 'WORKER_STOP_UNVERIFIED', running=False)
            self.capture_worker()
            return True
        attempt('attackStopped', attack_stop)
        attempt('captureStopped', lambda: self.processes.stop('sensor'))
        attempt('targetsStopped', lambda: self.processes.stop('targets'))
        if not abnormal:
            attempt('authorizationRevoked', self.control.revoke)
        if self.s.get('rootRequested'):
            write(self.d / 'root/stop', b'1', replace=True)
            try:
                self.wait(lambda: (self.d / 'root/result.json').exists(), 150, 'ROOT_CLEANUP_UNVERIFIED', running=False)
                r = load(self.d / 'root/result.json')
                for k in ('pfEmpty', 'aliasesUnchanged', 'rootVerified'):
                    self.s['cleanup'][k] = r.get(k) is True
                self.s['rootResult'] = r
                if not r.get('passed'):
                    errors['rootExecution'] = 'FAILED'
                if self.root_process:
                    require(self.root_process.wait(timeout=30) == 0, 'ROOT_LAUNCHER_FAILED')
            except Exception as e:
                errors['root'] = type(e).__name__
        for name in ('resolver', 'observer-run', 'observer-recovery'):
            try:
                require(self.processes.stop(name), 'COMPONENT_STOP_UNVERIFIED')
            except BaseException as e:
                errors[name] = type(e).__name__
        try:
            reset = self.control.reset_state()
            for k in ('bindingSuspended', 'bundleActive'):
                self.s['cleanup'][k] = reset[k]
            self.s['cleanup']['authorizationRevoked'] = self.s['cleanup']['authorizationRevoked'] and reset['authorizationRevoked']
            self.s['cleanup']['budgetRecovered'] = self.control.recovered()
        except Exception as e:
            errors['controlState'] = type(e).__name__
        def en0_unchanged():
            from scripts.demo.preflight import en0
            return en0(self.c, self.control.applicant) == self.s.get('en0')
        attempt('en0Unchanged', en0_unchanged)
        self.s['cleanupErrors'] = errors
        self.s.setdefault('endedAt', stamp())
        self.save()
        try:
            write(self.d / 'facts.json', self.control.facts(self.s['startedAt'], self.s['endedAt']), replace=True)
        except Exception as e:
            self.s['factCollectionError'] = type(e).__name__
            self.save()
            write(self.d / 'facts.json', {'decisions': [], 'commands': [], 'receipts': [], 'budgetEvents': []}, replace=True)
        from scripts.demo.report import generate
        return generate(self.d)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--grant')
    p.add_argument('--run-id')
    p.add_argument('--scenes', help='例如 S0,S1,S2；默认全部')
    p.add_argument('--scenes-file', default=str(Path(__file__).with_name('scenes.json')))
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--teardown-only', metavar='RUN_ID')
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--pf', action='store_true')
    mode.add_argument('--alert-only', action='store_true')
    a = p.parse_args()
    raw_config = load(a.config, secret=not a.dry_run)
    if a.teardown_only and not a.dry_run:
        import re
        require(re.fullmatch(r'demo-\d{8}-\d{4}-\d{2,4}', a.teardown_only), 'RUN_ID_INVALID')
        saved = load(path(raw_config['root']) / 'runs' / a.teardown_only / 'state.json')
        rows = saved['scenes']
    else:
        rows = scenes(a.scenes_file, a.scenes.split(',') if a.scenes else None)
    c = validate(raw_config, rows)
    selected_mode = 'pf' if a.pf else 'alert-only'
    run_id = a.run_id or datetime.now().strftime('demo-%Y%m%d-%H%M-01')
    if a.dry_run:
        print(json.dumps({'runId': run_id, 'mode': selected_mode, 'scenes': [r['id'] for r in rows], 'scenesSha256': sha(a.scenes_file),
                          'writes': False, 'network': False, 'rootStarted': False, 'requiresGrant': True,
                          'steps': ['预检与基线比较', 'root只读PF核验', '整库备份恢复校验', '短期授权与独立批准', '靶服务及utun采集',
                                    '远端有界场景', 'TTL与连续健康冷却', '撤销授权与精确清理', '只读汇总报告']}, ensure_ascii=False, indent=2))
        return
    require(os.geteuid() != 0, 'DEMO_MUST_START_AS_USER')
    root = private(c['root'], True)
    from scripts.demo.remote import Remote
    from scripts.demo.control import Control
    from scripts.demo.runtime import Processes
    import re
    chosen = a.teardown_only or run_id
    require(re.fullmatch(r'demo-\d{8}-\d{4}-\d{2,4}', chosen), 'RUN_ID_INVALID')
    d = root / 'runs' / chosen
    with (private(root / 'locks', True) / 'controller.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if a.teardown_only:
            private(d, True)
            state = load(d / 'state.json')
            require(state['config'] == c, 'CLEANUP_CONFIG_CHANGED')
        else:
            require(a.grant, 'RUN_APPROVAL_REQUIRED')
            g = grant(c, rows, load(a.grant), sha(a.scenes_file), run_id, selected_mode, time.time())
            require(not d.exists(), 'RUN_DIRECTORY_EXISTS')
            # 上次清理不完整不发新流量；预算单项失败允许新授权先恢复健康链。
            for previous in (root / 'runs').glob('demo-*/state.json'):
                old = load(previous)
                if not any(old.get(k) for k in ('rootRequested', 'remoteRequested', 'processes', 'authorization')):
                    continue  # 只读预检失败从未进入运行；仍保留失败报告，但不要求不存在的组件清理。
                require(all(old.get('cleanup', {}).get(k) is True for k in CLEANUP if k != 'budgetRecovered'), 'PREVIOUS_CLEANUP_INCOMPLETE')
            d.mkdir(mode=0o700)
            (d / 'root').mkdir(mode=0o700)
            write(d / 'scenes.json', Path(a.scenes_file).read_bytes())
            state = dict(runId=run_id, config=c, enrollment=load(root / 'enrollment.json'), grant=g, mode=selected_mode,
                         purpose=g['purpose'], operator=g['operator'], startedAt=stamp(), scenes=rows, cleanup={k: False for k in CLEANUP}, completed=False)
            write(d / 'state.json', state)
        def save():
            write(d / 'state.json', state, replace=True)
        control = Control(c, state['enrollment'], d)
        runner = Runner(c, d, state, control, Remote(c['remote']), Processes(d, state, save))
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: setattr(runner, 'stopped', True))
        if a.teardown_only:
            result = runner.teardown(not state.get('completed'))
        else:
            try:
                runner.execute()
            except BaseException as e:
                state['errorType'] = type(e).__name__
                if isinstance(e, ValueError) and re.fullmatch('[A-Z0-9_:-]+', str(e)):
                    state['errorCode'] = str(e)
                runner.save()
            finally:
                result = runner.teardown(not state.get('completed'))
        print(json.dumps({'runId': chosen, 'passed': result['passed'], 'record': str(d / 'record.md')}, ensure_ascii=False))
        return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
