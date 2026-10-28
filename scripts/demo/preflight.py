"""执行前只读事实核对；不把配置声明当作已批准的 ACL、平台能力或现场测试证据。"""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
from scripts.demo.common import ROOT, digest, load, private, require, sha, uid


def command(argv):
    p = subprocess.run([str(v) for v in argv], capture_output=True, text=True, timeout=15)
    require(p.returncode == 0, 'PREFLIGHT_COMMAND_FAILED')
    return p.stdout.strip()


def interface_for(text, address):
    current, found = None, []
    for line in text.splitlines():
        if line and not line[0].isspace():
            current = line.split(':', 1)[0]
        if re.search(r'\binet ' + re.escape(address) + r'\s', line):
            found.append(current)
    require(len(found) == 1 and re.fullmatch(r'utun\d+', found[0]), 'TAILSCALE_INTERFACE_NOT_UNIQUE')
    return found[0]


def process_identity(pid):
    require(type(pid) is int and pid > 1, 'PROCESS_ID_INVALID')
    p = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'lstart=,command='], capture_output=True, text=True, timeout=5)
    return p.stdout.strip() if p.returncode == 0 else None


def en0(c, client):
    """按明确配置文件和 API 资产身份核对原 en0 进程；不停止/重启该进程。"""
    from scripts.p8.status import machine_rows
    plan = load(c['en0Plan'])
    cfg = load(plan['configFile'])
    require(cfg['interface'] == 'en0' and cfg['assetId'] == plan['assetId'] and cfg['sensorId'] == plan['sensorId'], 'EN0_PLAN_MISMATCH')
    output = command(['/bin/ps', '-ax', '-o', 'pid=,command='])
    pids = []
    for line in output.splitlines():
        try:
            pid, rest = line.strip().split(None, 1)
            argv = shlex.split(rest)
            if any(argv[i] == '-config' and argv[i + 1] == plan['configFile'] for i in range(len(argv) - 1)):
                pids.append(int(pid))
        except ValueError:
            continue
    require(len(pids) == 1, 'EN0_PROCESS_NOT_UNIQUE')
    rows = machine_rows(client, 'sensor-heartbeats', uid(plan['assetId']))
    sensor = next((s for s in rows if s['id'] == plan['sensorId']), {})
    require(sensor.get('freshness') == 'fresh', 'EN0_NOT_FRESH')
    return dict(pid=pids[0], identity=process_identity(pids[0]), configSha256=sha(plan['configFile']), bootId=sensor['bootId'])


def evidence(c, ids, mode):
    require(mode in ('pf', 'alert-only'), 'DEMO_MODE_INVALID')
    proof = load(c['proofFile'])
    require(proof['subjectSha256'] == c['subjectSha256'] and proof['macAddress'] == c['macAddress'] and proof['peerAddress'] == c['peerAddress'] and proof['ports'] == c['ports'], 'PREREQUISITE_SCOPE_CHANGED')
    require(proof['assetId'] == ids['assetId'] and proof['sensorId'] == ids['sensorId'], 'PREREQUISITE_IDENTITY_CHANGED')
    # 每项引用真实外部文件及摘要、独立审核记录；不接受只有 passed=true 的空证明。
    expected = ({'networkIsolation', 'capturePermission', 'coexistence'} if mode == 'alert-only' else
                {'networkIsolation', 'utunDirection', 'platformCanary', 'capturePermission', 'coexistence'})
    require(set(proof['evidence']) == expected, 'PREREQUISITES_INCOMPLETE')
    for k, row in proof['evidence'].items():
        require(row['reviewer'] and row['approvalReference'] and row['reviewer'] != row.get('operator'), 'PREREQUISITE_REVIEW_REQUIRED')
        require(sha(private(row['file'])) == row['sha256'], 'PREREQUISITE_CHANGED:' + k.upper())
    return digest(proof)


def inspect(c, ids, remote, control, scene_path, mode):
    import sys
    require(sys.platform == 'darwin' and os.geteuid() != 0, 'DEMO_MAC_USER_REQUIRED')
    iface = interface_for(command(['/sbin/ifconfig']), c['macAddress'])
    ts = json.loads(command([c['tailscale'], 'status', '--json']))
    require(c['macAddress'] in ts.get('TailscaleIPs', []) and ts.get('BackendState') == 'Running', 'TAILSCALE_NOT_READY')
    peer = next((p for p in ts.get('Peer', {}).values() if c['peerAddress'] in p.get('TailscaleIPs', [])), None)
    require(peer and peer.get('Online'), 'TAILSCALE_PEER_OFFLINE')
    remote_state = remote.inspect()
    sent = time.time()
    remote_time = remote.utc()
    received = time.time()
    require(received - sent <= 3 and sent - 1 <= remote_time / 1000 <= received + 1, 'REMOTE_CLOCK_UNVERIFIED')
    require(not remote_state['running'] and remote_state['orphanCount'] == 0 and c['peerAddress'] in remote_state['addresses'], 'REMOTE_NOT_RESET')
    allow = remote_state['allowlist']
    expected_allow = dict(macAddress=c['macAddress'], peerAddress=c['peerAddress'], ports=c['ports'], allowedPorts=[c['ports'][k] for k in ('http', 'ftp', 'ssh')] + c['ports']['scan'], nmap=c['remote']['nmap'])
    require(allow == expected_allow, 'REMOTE_ALLOWLIST_CHANGED')
    ports = expected_allow['allowedPorts'] + [c['targetPort']]
    listeners = subprocess.run(['/usr/sbin/lsof', '-nP', '-iTCP', '-sTCP:LISTEN', '-F', 'Pn'], capture_output=True, text=True, timeout=10)
    require(listeners.returncode in (0, 1), 'LISTENERS_UNVERIFIED')
    occupied = {int(m[1]) for m in re.finditer(r':(\d+)(?:\s|$)', listeners.stdout)}
    require(not set(ports) & occupied, 'DEMO_PORT_IN_USE')
    # BPF 只检查可读写的设备数量；真正打开所选 utun 失败会在发包前停止。
    bpf = [p for p in Path('/dev').glob('bpf[0-9]*') if os.access(p, os.R_OK | os.W_OK)]
    require(len(bpf) >= 2, 'SECOND_BPF_PERMISSION_REQUIRED')
    reset = control.reset_state(mode)
    require(all(reset[k] for k in ('bindingSuspended', 'authorizationRevoked', 'noActiveActions')), 'PREVIOUS_RUN_NOT_RESET')
    bundle = control.bundle(mode)
    enrollment = load(Path(c['root']) / 'enrollment.json')
    require(enrollment == ids and enrollment['guardliveSha256'] == sha(c['guardlive']), 'SENSOR_BUILD_NOT_ENROLLED')
    require(enrollment['interface'] == iface, 'INTERFACE_CONFIG_REAPPROVAL_REQUIRED')
    state = en0(c, control.applicant)
    backend_pid = command(['/usr/sbin/lsof', '-t', '-nP', '-iTCP:18082', '-sTCP:LISTEN']).splitlines()
    require(len(set(backend_pid)) == 1, 'BACKEND_PROCESS_NOT_UNIQUE')
    backend = process_identity(int(backend_pid[0]))
    require(backend and c['jar'] in shlex.split(backend), 'BACKEND_JAR_NOT_RUNNING')
    require(not command(['git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal']), 'RELEASE_WORKTREE_NOT_CLEAN')
    baseline = {'commit': command(['git', '-C', ROOT, 'rev-parse', 'HEAD']), 'jarSha256': sha(c['jar']),
                'sensorSha256': sha(c['guardlive']), 'resolverSha256': sha(c['guardtargets']),
                'executorRelease': c['executorRelease'], 'bundleId': c['bundleId'], 'subjectSha256': c['subjectSha256'],
                'subject': bundle['subject'], 'sceneSha256': sha(scene_path), 'prerequisitesSha256': evidence(c, ids, mode),
                'remotePython': remote_state['python'], 'remoteNmap': remote_state['nmap'],
                'workerSha256': remote_state['workerSha256'], 'macOS': command(['/usr/bin/sw_vers', '-productVersion']),
                'tailscale': command([c['tailscale'], 'version']).splitlines()[0]}
    require(remote_state['workerSha256'] == sha(ROOT / 'scripts/demo/worker.py') and remote_state['commonSha256'] == sha(ROOT / 'scripts/demo/common.py'), 'REMOTE_WORKER_CHANGED')
    old = load(c['baselineFile']) if Path(c['baselineFile']).exists() else None
    return {'interface': iface, 'baseline': baseline, 'sameBaseline': old == baseline,
            'baselineDifferences': sorted(k for k in baseline if not old or old.get(k) != baseline[k]),
            'en0': state, 'allowlistSha256': digest(allow), 'reset': reset}
