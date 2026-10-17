"""受 root 暂存清单约束的演示执行器；只改专属 anchor，跨次保留稳定预算账本和密钥。

preflight.json 触发只读核验；ready.json 后才允许用户态备份/授权。PF 模式 input.json
启动正式 executor run/recover；只告警模式只核验 PF 不变。stop 或授权到期进入收尾。
本程序不能直接从用户工作区提权运行，必须由 lab_root_launch.py 的冻结副本启动。
"""
from contextlib import ExitStack
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts/p5'))
from scripts.demo.common import address, instant, require, uid
from scripts.p5.g3_executor import assemble, give, owned, status, stop_process
from scripts.p5.pf_session import session, owned_rules_remain
from executor.common import canonical, parse, write_new
from executor.pf_lab import command, read_rules, existing_rules, USER_ANCHOR
from executor.platform import PF
from executor.subject_binding import configured, verify_config
from executor.config import load as load_config


def validate_boundary(b):
    """一次暂存绑定长期身份和目标；换地址/端口/密钥必须重新审查暂存，不接受运行时扩权。"""
    require(set(b) == {'assetId', 'executorId', 'sensorId', 'captureScopeId', 'macAddress', 'peerAddress',
                       'ports', 'protection', 'protectedPeers', 'bundleId', 'budgetKeySha256', 'subjectSha256'}, 'DEMO_BOUNDARY_INVALID')
    for k in ('assetId', 'executorId', 'sensorId', 'captureScopeId', 'bundleId'):
        uid(b[k])
    require(address(b['macAddress']) != address(b['peerAddress']), 'DEMO_BOUNDARY_INVALID')
    require(all(re.fullmatch('[0-9a-f]{64}', b[k]) for k in ('budgetKeySha256', 'subjectSha256')), 'DEMO_BOUNDARY_INVALID')
    ports = b['ports']
    require(set(ports) == {'http', 'ftp', 'ssh', 'scan'}, 'DEMO_BOUNDARY_INVALID')
    values = [ports[k] for k in ('http', 'ftp', 'ssh')] + ports['scan']
    require(len(set(values)) == len(values) and len(values) <= 128 and all(type(v) is int and 1024 <= v <= 65535 for v in values), 'DEMO_BOUNDARY_INVALID')
    require(set(b['protection']) == {'protectedBudgetTargetIds', 'protectedServicePorts'}, 'DEMO_PROTECTION_INVALID')
    require({22, 18080, 18082, 41641} <= set(b['protection']['protectedServicePorts']) and not set(values) & set(b['protection']['protectedServicePorts']), 'DEMO_PROTECTION_INVALID')
    import ipaddress
    for peer in b['protectedPeers']:
        require(ipaddress.ip_address(b['peerAddress']) not in ipaddress.ip_network(peer), 'DEMO_PEER_PROTECTED')
    return b


def snapshot(executor):
    """不启用 PF、不修改规则；未知规则/残留 anchor 拒绝，不能自动清理别人的规则。"""
    original, user, apple = read_rules(), read_rules(USER_ANCHOR), read_rules('com.apple/*')
    existing_rules(original, user)
    require('Status: Disabled' in command(['/sbin/pfctl', '-s', 'info'])[0], 'DEMO_PF_ALREADY_ENABLED')
    require(not owned_rules_remain(read_rules(PF.anchor_root(executor) + '/*')), 'DEMO_PF_NOT_EMPTY')
    require('inet 127.0.0.2 ' not in command(['/sbin/ifconfig', 'lo0'])[0], 'DEMO_ALIAS_PRESENT')
    return {'root': original.hex(), 'user': user.hex(), 'apple': apple.hex()}


def assemble_demo(data, work, b, interface):
    import hashlib
    for k in ('assetId', 'executorId', 'sensorId', 'captureScopeId', 'bundleId', 'protection'):
        require(data[k] == b[k], 'DEMO_INPUT_BOUNDARY_MISMATCH')
    require(data['peerAddresses'] == [b['peerAddress']] and data['servicePorts'] == sorted(b['ports'][k] for k in ('http', 'ftp', 'ssh')), 'DEMO_INPUT_BOUNDARY_MISMATCH')
    key = base64.b64decode(data['budgetKey'], validate=True)
    require(hashlib.sha256(key).hexdigest() == b['budgetKeySha256'], 'DEMO_BUDGET_KEY_CHANGED')
    c = assemble(data, work)
    # 固定 root 所有路径；不从用户输入接收持久化路径，也不迁移或清空旧账本。
    home = Path('/private/var/root/hostguard-demo') / b['executorId']
    home.mkdir(parents=True, mode=0o700, exist_ok=True)
    for p in (home.parent, home):
        st = p.lstat()
        require(not p.is_symlink() and st.st_uid == 0 and st.st_mode & 0o777 == 0o700, 'DEMO_LEDGER_UNTRUSTED')
    identity = canonical({k: b[k] for k in ('assetId', 'executorId', 'budgetKeySha256')})
    for filename, raw in (('identity.json', identity), ('budget.key', key)):
        p = home / filename
        if p.exists():
            require(owned(p, 0) == raw, 'DEMO_BUDGET_IDENTITY_CHANGED')
        else:
            write_new(p, raw)
    c.update(interface=interface, localAddresses=[b['macAddress']], protectedPeers=b['protectedPeers'], stateDir=str(home / 'state'), budgetKeyFile=str(home / 'budget.key'))
    return c


def run(directory, work, owner, max_seconds):
    import subprocess
    os.umask(0o077)
    require(sys.platform == 'darwin' and os.geteuid() == 0 and os.environ.get('HOSTGUARD_DEMO_BOUNDARY'), 'DEMO_STAGED_ROOT_REQUIRED')
    b = validate_boundary(parse(owned(Path(os.environ['HOSTGUARD_DEMO_BOUNDARY']), 0)))
    require(directory.is_dir() and not directory.is_symlink() and directory.stat().st_uid == owner, 'DEMO_RENDEZVOUS_INVALID')
    stop = False
    def signal_stop(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGINT, signal_stop)
    limit = time.monotonic() + min(max_seconds, 1800)
    def wait_file(name):
        while not (directory / name).exists():
            require(not stop and not (directory / 'stop').exists() and time.monotonic() < limit, 'DEMO_ROOT_WAIT_EXPIRED')
            time.sleep(.2)
        return parse(owned(directory / name, owner))
    initial = wait_file('preflight.json')
    g, interface = initial['grant'], initial['interface']
    require(g['runId'] == directory.parent.name, 'DEMO_RUN_ID_MISMATCH')
    require(re.fullmatch(r'utun\d+', interface), 'DEMO_UTUN_REQUIRED')
    require(g['reference'] == os.environ.get('HOSTGUARD_LAB_AUTHORIZATION') and g['mode'] in ('pf', 'alert-only'), 'DEMO_ROOT_AUTHORIZATION_MISMATCH')
    require(g['macAddress'] == b['macAddress'] and g['peerAddress'] == b['peerAddress'] and g['ports'] == b['ports'], 'DEMO_ROOT_SCOPE_MISMATCH')
    require(instant(g['validFrom']) <= time.time() < instant(g['validUntil']) and instant(g['validUntil']) - instant(g['validFrom']) <= 1800, 'DEMO_ROOT_AUTHORIZATION_EXPIRED')
    require('inet ' + b['macAddress'] + ' ' in command(['/sbin/ifconfig', interface])[0], 'DEMO_INTERFACE_CHANGED')
    binding = configured()
    require(binding and binding['subjectSha256'] == b['subjectSha256'] and binding['bundleId'] == b['bundleId'], 'DEMO_SUBJECT_MISMATCH')
    lockfile = Path('/private/var/root/hostguard-demo.lock')
    with lockfile.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = snapshot(b['executorId'])
        give(directory, owner, 'ready.json', {'passed': True, 'pfEmpty': True, 'aliasesUnchanged': True, 'mode': g['mode']})
        result = {'passed': False, 'mode': g['mode'], 'pfEmpty': False, 'aliasesUnchanged': False, 'rootVerified': False}
        try:
            if g['mode'] == 'pf':
                data = wait_file('input.json')
                require(data['authorization']['validUntil'] == g['validUntil'] and data['authorization']['validFrom'] == g['validFrom'], 'DEMO_ROOT_AUTHORIZATION_MISMATCH')
                c = assemble_demo(data, work, b, interface)
                verify_config(binding, c)
                with ExitStack() as stack:
                    helper, check, pf = stack.enter_context(session(work, b['executorId'], g['reference'], loopback_alias=False))
                    c['pfHelper'] = str(helper)
                    config = work / 'executor-config.json'
                    write_new(config, canonical(c))
                    load_config(config)
                    children = {}
                    for role in ('recover', 'run'):
                        log = stack.enter_context((work / (role + '.log')).open('xb'))
                        children[role] = subprocess.Popen([sys.executable, '-u', '-B', '-s', '-m', 'executor', role, '--config', str(config)], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                        stack.callback(stop_process, children[role], role + 'Stop', result)
                    boot_deadline = time.monotonic() + 45
                    boot = None
                    while not boot:
                        require(children['run'].poll() is None and time.monotonic() < boot_deadline, 'DEMO_EXECUTOR_NOT_READY')
                        time.sleep(1)
                        boot = status(sys.executable, config).get('executorBootId')
                    give(directory, owner, 'boot.json', {'executorBootId': boot})
                    while not stop and not (directory / 'stop').exists() and time.monotonic() < limit and time.time() < instant(g['validUntil']):
                        require(all(p.poll() is None for p in children.values()), 'DEMO_EXECUTOR_EXITED')
                        check()
                        value = status(sys.executable, config)
                        give(directory, owner, 'status.next', value)
                        os.replace(directory / 'status.next', directory / 'status.json')
                        time.sleep(1)
                    # 不续租、不再发包；仍给到期/撤销回执最多 90 秒上传，之后 stop() 只清本执行器规则。
                    drain = time.monotonic() + 90
                    while status(sys.executable, config)['activeRuleCount'] and time.monotonic() < drain:
                        time.sleep(1)
                    final = status(sys.executable, config)
                    result['drained'] = final['activeRuleCount'] == 0 and not final['pendingReceipts'] and not final['recoveryErrors']
                result['pfSession'] = pf
                require(pf['passed'] and result['drained'], 'DEMO_ROOT_DRAIN_FAILED')
            else:
                while not stop and not (directory / 'stop').exists() and time.monotonic() < limit and time.time() < instant(g['validUntil']):
                    require(snapshot(b['executorId']) == before, 'DEMO_PF_CHANGED')
                    time.sleep(1)
            result.update(pfEmpty=True, aliasesUnchanged=True, rootVerified=snapshot(b['executorId']) == before)
            result['passed'] = result['rootVerified']
        finally:
            # 即使主体失败，也尽量保留真实最终核对；不能把未知清理写为成功。
            try:
                result['pfEmpty'] = not owned_rules_remain(read_rules(PF.anchor_root(b['executorId']) + '/*'))
                result['rootVerified'] = snapshot(b['executorId']) == before
                result['aliasesUnchanged'] = 'inet 127.0.0.2 ' not in command(['/sbin/ifconfig', 'lo0'])[0]
            except Exception:
                result['rootVerified'] = False
            write_new(work / 'result.json', canonical(result))
            give(directory, owner, 'result.json', result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--owner-uid', type=int, required=True)
    p.add_argument('--max-seconds', type=int, default=1800)
    a = p.parse_args()
    try:
        require(a.work.is_dir() and not any(a.work.iterdir()), 'DEMO_WORK_NOT_EMPTY')
        result = run(a.directory, a.work, a.owner_uid, a.max_seconds)
        raise SystemExit(0 if result['passed'] else 1)
    except Exception as exc:
        try:
            give(a.directory, a.owner_uid, 'error.json', {'errorType': type(exc).__name__})
        except Exception:
            pass
        raise SystemExit(1)
