#!/usr/bin/env python3
"""P1 一次性 Windows 动态规则恢复探针，不接收网络命令、不授予生产执行资格。

独立 supervisor 持有子进程句柄；子进程持有 WFP 动态会话，以单调时钟到期删除。
双向心跳中断立即关闭/终止会话，observer 核验实际规则。账本追加落盘；重启/重跑
必须重新核对项目残留，再签发当前 boot+executor 的新命令，绝不重放旧租约。
"""
import argparse
import ctypes
import datetime as dt
import hashlib
import ipaddress
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

from wfp_native import Engine


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def timestamp(value):
    t = dt.datetime.fromisoformat(value)
    if t.tzinfo is None:
        raise ValueError('TIMEZONE_REQUIRED')
    return t.timestamp()


def write_new(path, value):
    path = Path(path); pending = path.with_name(path.name + '.' + uuid.uuid4().hex + '.pending')
    try:
        with pending.open('x', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=True, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
        # 同卷硬链接原子发布且绝不覆盖，观察者不会读到正在写入的半个 JSON。
        os.link(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def audit(base, role, event, **fields):
    with (base / (role + '.jsonl')).open('a', encoding='utf-8') as f:
        f.write(json.dumps({'utc': utc(), 'monotonic': time.monotonic(), 'event': event, **fields}) + '\n')
        f.flush(); os.fsync(f.fileno())


def powershell(text):
    # 固定本机只读命令，不接收任意 shell 文本作为外部参数。
    r = subprocess.run(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', text],
                       capture_output=True, text=True, timeout=12)
    if r.returncode:
        raise RuntimeError('PREFLIGHT_QUERY_FAILED')
    return json.loads(r.stdout.strip())


def boot_id():
    return powershell('(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString("o") | ConvertTo-Json -Compress')


def validate_scope(m, now):
    """授权文件只允许专用 canary 的两个相邻高端口，租期最长20分钟，不从 lab 标签推定授权。"""
    if not re.fullmatch(r'p1-[a-f0-9]{16}', m['runId']):
        raise ValueError('INVALID_RUN_ID')
    nets = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10')]
    a, b = ipaddress.ip_address(m['local']), ipaddress.ip_address(m['peer'])
    if a == b or any(ip.version != 4 or not any(ip in net for net in nets) for ip in (a, b)):
        raise ValueError('INVALID_PEERS')
    if type(m['port']) is not int or not 49152 <= m['port'] <= 65533 or m['controlPort'] != m['port'] + 1:
        raise ValueError('PROTECTED_OR_INVALID_PORT')
    if not now < timestamp(m['expiresUtc']) <= now + 1200:
        raise ValueError('SCOPE_EXPIRED_OR_TOO_LONG')
    if m['platform'] != 'Windows' or m['direction'] != 'inbound' or m['transport'] != 'tcp':
        raise ValueError('UNSUPPORTED_CAPABILITY')


def validate_command(c, m, ready, now):
    """固定30秒TTL；旧boot、旧executor、迟到、过期与越界全部拒绝，无隐式续租。"""
    if c['bootId'] != ready['bootId']:
        raise ValueError('STALE_BOOT')
    if c['executorId'] != ready['executorId']:
        raise ValueError('STALE_EXECUTOR')
    for k in ('runId', 'local', 'peer', 'port'):
        if c[k] != m[k]:
            raise ValueError('SCOPE_MISMATCH')
    if not re.fullmatch(r'[a-z0-9-]{1,40}', c['actionId']):
        raise ValueError('INVALID_ACTION_ID')
    issued, apply_by, until = (timestamp(c[k]) for k in ('issuedUtc', 'applyBy', 'blockUntil'))
    if issued > now or not issued <= now < apply_by or not 0 < apply_by - issued <= 10:
        raise ValueError('LATE_OR_FUTURE_COMMAND')
    if abs(until - issued - 30) > 0.001 or until > timestamp(m['expiresUtc']) or until <= now:
        raise ValueError('EXPIRED_OR_INVALID_LEASE')
    return until - now


def assert_isolation(m):
    # 四条隔离规则与阻断会话分开；精确核验二进制、组、方向和端点，不改变系统默认策略。
    if hashlib.sha256(Path(m['binary']).read_bytes()).hexdigest() != m['binarySha256']:
        raise ValueError('CANARY_CHANGED')
    group = 'HostGuard.' + m['runId']
    query = """$ErrorActionPreference='Stop'; [ordered]@{
      profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {[bool]$_.Enabled});
      blocks=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {$_.Name -like 'HostGuard.*.block.*'} | Select-Object -ExpandProperty Name);
      rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Group '%s' | ForEach-Object {
        $p=$_ | Get-NetFirewallPortFilter; $a=$_ | Get-NetFirewallAddressFilter; $b=$_ | Get-NetFirewallApplicationFilter;
        @{name=$_.Name;enabled=[string]$_.Enabled;action=[string]$_.Action;direction=[string]$_.Direction;
          protocol=[string]$p.Protocol;localPort=@($p.LocalPort);remote=@($a.RemoteAddress);local=@($a.LocalAddress);program=$b.Program}
      })} | ConvertTo-Json -Depth 5 -Compress""" % group
    r = powershell(query)
    if len(r['profiles']) != 3 or not all(r['profiles']) or r['blocks']:
        raise ValueError('FIREWALL_OR_LEGACY_RESIDUE')
    rules = {x['name'].removeprefix(group + '.'): x for x in r['rules']}
    if set(rules) != {'isolation-egress', 'isolation-peer', 'isolation-ports', 'allow-canary'}:
        raise ValueError('ISOLATION_RULES_MISSING')
    for role, rule in rules.items():
        if rule['enabled'] != 'True' or rule['program'].lower() != m['binary'].lower():
            raise ValueError('ISOLATION_PROGRAM_OR_ENABLED')
        if rule['action'] != ('Allow' if role == 'allow-canary' else 'Block'):
            raise ValueError('ISOLATION_ACTION')
        if rule['direction'] != ('Outbound' if role == 'isolation-egress' else 'Inbound'):
            raise ValueError('ISOLATION_DIRECTION')
    allow = rules['allow-canary']
    if (allow['remote'] != [m['peer']] or allow['local'] != [m['local']]
            or sorted(allow['localPort']) != sorted([str(m['port']), str(m['controlPort'])]) or allow['protocol'] != 'TCP'):
        raise ValueError('ISOLATION_ALLOW_SCOPE')
    n = int(ipaddress.ip_address(m['peer']))
    expected_peers = {f'0.0.0.1-{ipaddress.ip_address(n-1)}', f'{ipaddress.ip_address(n+1)}-255.255.255.254', '::/1', '8000::/1'}
    if set(rules['isolation-peer']['remote']) != expected_peers:
        raise ValueError('ISOLATION_PEER_SCOPE')
    if set(rules['isolation-ports']['localPort']) != {f'1-{m["port"]-1}', f'{m["controlPort"]+1}-65535'}:
        raise ValueError('ISOLATION_PORT_SCOPE')
    if (rules['isolation-egress']['protocol'] != 'Any' or rules['isolation-egress']['remote'] != ['Any']
            or rules['isolation-egress']['localPort'] != ['Any']):
        raise ValueError('ISOLATION_EGRESS_SCOPE')
    return {'legacyBlocks': 0, 'isolationRules': len(rules), 'firewallProfilesEnabled': True}


def owner(base, manifest, channel, fault):
    """独立于检测/控制连接运行；心跳来自实际恢复循环，挂起循环会被外部 watchdog 终止。"""
    engine = None; ids = []; ready = None
    try:
        m = json.loads(Path(manifest).read_text(encoding='utf-8-sig'))
        validate_scope(m, time.time())
        isolation = assert_isolation(m)
        boot = boot_id()
        with Engine() as observer:
            inventory = observer.inventory()
        if inventory['filters'] or inventory['sublayerPresent']:
            raise ValueError('RECOVERY_INCOMPLETE')
        ready = {'bootId': boot, 'executorId': str(uuid.uuid4()), 'pid': os.getpid(), 'isolation': isolation,
                 'reconciled': inventory, 'readyUtc': utc()}
        audit(base, 'owner', 'reconciled', **ready)
        write_new(base / 'ready.json', ready); channel.send({'event': 'ready'})
        last_parent = time.monotonic(); started = last_parent
        command_seen = False; deadline = None; clock_anchor = None
        while time.monotonic() - started < 90:
            now_m = time.monotonic()
            while channel.poll():
                channel.recv(); last_parent = now_m
            if now_m - last_parent > 0.5:
                raise RuntimeError('WATCHDOG_LOST')
            channel.send({'event': 'heartbeat'})
            command_path = base / 'command.json'
            if not ids and (base/'close-session').exists():
                audit(base,'owner','closed_before_command',newCommandsAccepted=False)
                return
            if not command_seen and command_path.exists():
                command_seen = True
                c = json.loads(command_path.read_text())
                now_wall, now_m = time.time(), time.monotonic()
                duration = validate_command(c, m, ready, now_wall)
                deadline = now_m + duration; clock_anchor = now_wall - now_m
                # 先写租约及意图，失败只留下审计；完整命令仅保存在受控目录。
                audit(base, 'owner', 'lease_accepted', actionId=c['actionId'], blockUntil=c['blockUntil'], deadlineMonotonic=deadline)
                channel.send({'event': 'lease', 'deadline': deadline})
                engine = Engine(dynamic=True)
                ids = engine.install(m['local'], m['peer'], m['port'], c['actionId'])
                if time.monotonic() >= deadline or not all(engine.exists(i) for i in ids):
                    raise RuntimeError('INSTALL_TOO_LATE_OR_UNVERIFIED')
                applied = {'filterIds': ids, 'installedUtc': utc(), 'deadlineMonotonic': deadline,
                           'blockUntil': c['blockUntil'], 'dynamic': True, 'persistent': False, 'ownerPid': os.getpid()}
                audit(base, 'owner', 'applied', **applied); write_new(base / 'applied.json', applied)
                channel.send({'event': 'applied', 'ids': ids, 'deadline': deadline})
            if ids:
                if fault == 'hang' and (base / 'trigger-fault').exists():
                    # 只用于明确选择的故障试验，watchdog须发现真实循环不再发送心跳。
                    time.sleep(60)
                reason = None
                if abs((time.time() - time.monotonic()) - clock_anchor) > 1:
                    reason = 'clock_untrusted'
                elif (base / 'close-session').exists():
                    reason = 'session_closed'
                elif time.monotonic() >= deadline:
                    reason = 'ttl_expired'
                if reason:
                    if reason == 'ttl_expired':
                        engine.remove(ids)
                    engine.close(); engine = None
                    with Engine() as observer:
                        remaining = [i for i in ids if observer.exists(i)]
                    if remaining:
                        raise RuntimeError('RECOVERY_FAILED')
                    audit(base, 'owner', 'removed_verified', reason=reason, remaining=0,
                          delaySeconds=time.monotonic()-deadline)
                    return
            if time.time() >= timestamp(m['expiresUtc']):
                raise RuntimeError('AUTHORIZATION_EXPIRED')
            time.sleep(0.025)
        raise RuntimeError('COMMAND_WAIT_TIMEOUT')
    except BaseException as e:
        # 不把异常原文/命令行写入审计，防止泄露端点或凭据。
        code = str(e) if isinstance(e, (ValueError, RuntimeError)) else type(e).__name__
        audit(base, 'owner', 'rejected_or_failed', code=code, errno=getattr(e, 'errno', None), winerror=getattr(e, 'winerror', None))
    finally:
        if engine:
            engine.close()
        channel.close()


def supervise(manifest, base, fault, stop_event=None):
    """持有子进程对象，避免PID复用误杀；30秒正常期限+1秒核验门槛始终不放宽。"""
    base.mkdir(parents=True, exist_ok=False)
    ctx = mp.get_context('spawn'); parent, child = ctx.Pipe()
    proc = ctx.Process(target=owner, args=(base, manifest, child, fault))
    proc.start(); child.close()
    audit(base, 'watchdog', 'started', ownerPid=proc.pid, supervisorPid=os.getpid(), fault=fault)
    started = last = time.monotonic(); active = False; ids = []; deadline = None; reason = 'owner_exit'
    try:
        with Engine() as observer:
            while proc.is_alive():
                now = time.monotonic()
                if stop_event is not None and stop_event.is_set():
                    # SCM STOP/PRESHUTDOWN 只停止本探针；所有者撤销，独立 observer 再核验。
                    (base/'close-session').touch(exist_ok=True)
                while True:
                    try:
                        if not parent.poll():
                            break
                        msg = parent.recv()
                    except (EOFError, OSError):
                        break
                    last = now
                    if msg['event'] == 'ready':
                        active = True
                    if msg['event'] in ('lease', 'applied'):
                        deadline = msg['deadline']
                    if msg['event'] == 'applied':
                        ids = msg['ids']
                        audit(base, 'watchdog', 'observed_applied', filterIds=ids, allPresent=all(observer.exists(i) for i in ids))
                if not proc.is_alive():
                    break
                if ids and fault == 'kill' and (base / 'trigger-fault').exists():
                    reason = 'owner_forced_exit'; proc.terminate(); break
                if (active and now-last > 0.5) or (not active and now-started > 35):
                    reason = 'heartbeat_timeout'; proc.terminate(); break
                if deadline is not None and now >= deadline + 0.25:
                    reason = 'deadline_watchdog'; proc.terminate(); break
                try:
                    parent.send('alive')
                except (OSError, EOFError):
                    break
                time.sleep(0.025)
            proc.join(timeout=2)
            if proc.is_alive():
                proc.kill(); proc.join(timeout=2)
            # 外部核验会话消失；保留首次观察时间，不把最终成功冒充按时恢复。
            verification_start = time.monotonic()
            while True:
                inventory = observer.inventory()
                if not inventory['filters'] and not inventory['sublayerPresent']:
                    break
                if time.monotonic()-verification_start >= 3:
                    break
                time.sleep(0.025)
            final = {'reason': reason, 'ownerExitCode': proc.exitcode, 'inventory': inventory,
                     'verifiedUtc': utc(), 'deadlineMonotonic': deadline,
                     'delaySeconds': None if deadline is None else time.monotonic()-deadline,
                     'strictRebootTtlPassed': False, 'productionAutoSupported': False}
            if stop_event is not None and stop_event.is_set():
                final['closedBeforeShutdown']=not inventory['filters'] and not inventory['sublayerPresent']
                audit(base,'watchdog','closed_before_shutdown' if final['closedBeforeShutdown'] else 'shutdown_cleanup_failed',
                      inventory=inventory,deadlineMonotonic=deadline,delaySeconds=final['delaySeconds'])
            write_new(base / 'final.json', final); audit(base, 'watchdog', 'final', **final)
    finally:
        if proc.is_alive():
            proc.terminate(); proc.join(timeout=3)
        parent.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('inspect', 'supervise'))
    p.add_argument('--manifest', type=Path); p.add_argument('--case-dir', type=Path)
    p.add_argument('--fault', choices=('none', 'kill', 'hang'), default='none')
    a = p.parse_args()
    if a.mode == 'inspect':
        with Engine() as e:
            print(json.dumps(e.inventory()))
    else:
        if not a.manifest or not a.case_dir:
            p.error('manifest and case-dir required')
        supervise(a.manifest, a.case_dir, a.fault)


if __name__ == '__main__':
    main()
