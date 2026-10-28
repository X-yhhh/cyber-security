"""本次运行的子进程与配置；账本/密钥长期复用，boot 与观察输出每次独立。"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import time
import uuid
from scripts.demo.common import ROOT, load, private, require, sha, write
from scripts.demo.preflight import process_identity


class Processes:
    def __init__(self, directory, state, save):
        self.d, self.state, self.save = Path(directory), state, save
        self.handles = {}

    def start(self, name, argv):
        argv = [str(v) for v in argv]
        require(name not in self.state.setdefault('processes', {}), 'PROCESS_ALREADY_RECORDED')
        self.state['processes'][name] = {'argv': argv, 'pid': None, 'identity': None}
        self.save()
        with (self.d / (name + '.log')).open('xb') as log:
            p = subprocess.Popen(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        self.handles[name] = p
        identity = process_identity(p.pid)
        self.state['processes'][name].update(pid=p.pid, identity=identity)
        self.save()
        require(identity and p.poll() is None, 'DEMO_COMPONENT_START_FAILED')
        return p

    def alive(self):
        return all(p.poll() is None for p in self.handles.values())

    def stop(self, name):
        r = self.state.get('processes', {}).get(name)
        if not r or r.get('stopped'):
            return True
        pid = r.get('pid')
        if pid is None:
            # 崩溃可能在 Popen 与 PID 落盘之间；只允许完整 argv 唯一匹配本次私有配置。
            output = subprocess.run(['/bin/ps', '-ax', '-o', 'pid=,command='], capture_output=True, text=True, check=True).stdout
            matches = []
            for line in output.splitlines():
                try:
                    n, text = line.strip().split(None, 1)
                    if shlex.split(text) == r['argv']:
                        matches.append(int(n))
                except ValueError:
                    pass
            require(len(matches) <= 1, 'PROCESS_IDENTITY_AMBIGUOUS')
            if matches:
                pid = matches[0]
                r.update(pid=pid, identity=process_identity(pid))
                self.save()
        current = process_identity(pid) if pid else None
        if current:
            require(current == r['identity'], 'PROCESS_IDENTITY_CHANGED')
            os.kill(pid, signal.SIGTERM)
            end = time.monotonic() + 20
            while process_identity(pid) == current and time.monotonic() < end:
                if name in self.handles and self.handles[name].poll() is not None:
                    break
                time.sleep(.1)
            if process_identity(pid) == current and (name not in self.handles or self.handles[name].poll() is None):
                os.kill(pid, signal.SIGKILL)
        if name in self.handles:
            self.handles[name].wait(timeout=5)
        r['stopped'] = process_identity(pid) != current or current is None or name in self.handles and self.handles[name].poll() is not None
        self.save()
        return r['stopped']


def peer_key(c, ids):
    """按稳定 enrollment 身份和 peer.key 生成观察用对端键；只读取密钥文件。"""
    secret = private(Path(c['root']) / 'config/peer.key').read_bytes()
    return hmac.new(secret, json.dumps(['host-guard-peer-v1', ids['assetId'], ids['sensorId'], 1, c['peerAddress']], separators=(',', ':')).encode(), hashlib.sha256).hexdigest()


def configurations(c, ids, g, auth, interface, directory, bundle, rows):
    """所有路径由本次私有目录和长期 enrollment 推出；不接收任意命令或环境变量。"""
    from executor.common import digest
    from executor.contract import capability_set_sha256, protected_ports_sha256
    d, stable = Path(directory), Path(c['root']) / 'config'
    ipc = stable / 'ipc'
    fps = load(ipc / 'fingerprints.json')
    boot = str(uuid.uuid4())
    sensor = dict(assetId=ids['assetId'], sensorId=ids['sensorId'], bootId=boot, captureScopeId=ids['captureScopeId'],
                  environment='lab', captureScope='lab_peer_tcp', localAddresses=[c['macAddress']], peerAddresses=[c['peerAddress']],
                  servicePorts=sorted([c['ports'][k] for k in ('http', 'ftp', 'ssh')] + c['ports']['scan']),
                  secretFile=str(stable / 'peer.key'), keyEpoch=1, interface=interface, allowedInterfaces=[interface],
                  authorizedUntil=g['validUntil'], captureLockDir=str(Path(c['root']) / 'locks'), upload=dict(baseUrl=c['baseUrl'], caFile=c['backendCA'],
                  certificateFile=str(ipc / 'collector.pem'), keyFile=str(ipc / 'collector.key'),
                  credentialFile=str(stable / 'sensor.credential'), spoolDir=str(d / 'spool'), healthWindowMs=1000))
    target_url = 'https://127.0.0.1:' + str(c['targetPort'])
    tls = dict(baseUrl=target_url, caFile=str(ipc / 'ca.pem'), certificateFile=str(ipc / 'collector.pem'), keyFile=str(ipc / 'collector.key'))
    observer = dict(mode='alert_only', assetId=ids['assetId'], executorId=ids['executorId'], authorizationId=auth['id'],
                    validUntil=g['validUntil'], baseUrl=c['baseUrl'], credentialFile=str(stable / 'executor.credential'),
                    caFile=c['backendCA'], certificateFile=str(ipc / 'executor.pem'), keyFile=str(ipc / 'executor.key'),
                    stateDir=str(Path(c['root']) / 'ledger/observer'), capabilityIds=[], bundleIds=[c['bundleId']])
    if g['mode'] == 'pf':
        sensor['liveTargets'] = dict(tls=tls, inboundPorts=c['ports']['scan'])
    target = dict(listen='127.0.0.1:' + str(c['targetPort']), certificateFile=str(ipc / 'server.pem'), keyFile=str(ipc / 'server.key'), caFile=str(ipc / 'ca.pem'), authorizedUntil=g['validUntil'],
                  scope=dict(AssetID=ids['assetId'], SensorID=ids['sensorId'], BootID=boot, CaptureScopeID=ids['captureScopeId'], Environment='lab', KeyEpoch=1,
                             LocalAddresses=[c['macAddress']], CollectorCertSHA256=fps['collector'], ExecutorCertSHA256=fps['executor'], MaxReferences=10000))
    key = peer_key(c, ids)
    allowed = [dict(local=c['macAddress'], peer=c['peerAddress'], peerKey=key, direction='inbound', scope='peer_inbound', servicePort=0)]
    allowed += [dict(local=c['macAddress'], peer=c['peerAddress'], peerKey=key, direction='inbound', scope='peer_service', servicePort=c['ports'][k]) for k in ('http', 'ftp', 'ssh')]
    target['registration'] = dict(backend=dict(baseUrl=c['baseUrl'], caFile=c['backendCA'], **c['backendTls']),
                                  credentialFile=str(stable / 'executor.credential'), budgetKeyFile=str(stable / 'budget.key'),
                                  identityFile=str(Path(c['root']) / 'ledger/registrar.json'), executorId=ids['executorId'], allowed=allowed)
    caps = sorted(cap['id'] for cap in c['capabilities'])
    inbound = sorted(cap['id'] for cap in c['capabilities'] if cap['payload'].get('scope') == 'peer_inbound')
    cap_cfg = dict(capabilityIds=caps, inboundCapabilities=[dict(capabilityId=cap, protectionSetSha256=digest(c['protection']), protectedPortsSha256=protected_ports_sha256(c['protection']['protectedServicePorts'])) for cap in inbound])
    data = {k: ids[k] for k in ('assetId', 'executorId', 'sensorId', 'captureScopeId')}
    data.update(authorization=auth, controlPlaneURL=c['baseUrl'], targetURL=target_url, peerAddresses=[c['peerAddress']],
                servicePorts=sorted(c['ports'][k] for k in ('http', 'ftp', 'ssh')), capabilityIds=caps, inboundCapabilityIds=inbound,
                capabilityHash=capability_set_sha256(cap_cfg), protection=c['protection'], bundleId=c['bundleId'], policySha256=bundle['subject']['policySha256'],
                commandTrust=load(c['commandTrust']), credential=private(stable / 'executor.credential').read_text().strip(),
                budgetKey=base64.b64encode(private(stable / 'budget.key').read_bytes()).decode())
    for name, f in dict(controlPlaneCA=c['backendCA'], targetCA=ipc / 'ca.pem', targetCertificate=ipc / 'executor.pem', targetKey=ipc / 'executor.key').items():
        data[name] = base64.b64encode(private(f).read_bytes()).decode()
    write(d / 'sensor.json', sensor)
    write(d / 'observer.json', observer)
    write(d / 'target-service.json', dict(macAddress=c['macAddress'], peerAddress=c['peerAddress'], ports=c['ports'], validUntil=g['validUntil'], ssh=any(r['tool'] == 'ssh_login' for r in rows)))
    return data, target


def start_root(c, g, directory, interface):
    """系统密码框启动已冻结 root 副本；两种模式均核验 PF，只告警模式不启用/修改 PF。"""
    p, d = load(c['rootPlan']), Path(directory)
    launcher = private(p['launcher'])
    require(sha(launcher) == p['launcherSha256'] and sha(Path(p['stage']) / 'manifest.json') == p['manifestSha256'], 'ROOT_STAGE_CHANGED')
    manifest = json.loads((Path(p['stage']) / 'manifest.json').read_bytes())
    boundary = load(Path(c['root']) / 'root-boundary.json')
    require(manifest['files']['demo-boundary.json']['sha256'] == sha(Path(p['stage']) / 'stage/demo-boundary.json'), 'ROOT_BOUNDARY_CHANGED')
    require(json.loads((Path(p['stage']) / 'stage/demo-boundary.json').read_bytes()) == boundary, 'ROOT_BOUNDARY_CHANGED')
    require(manifest['commit'] == c['executorRelease'], 'EXECUTOR_RELEASE_CHANGED')
    installed = '/private/var/root/hostguard-launcher-' + uuid.uuid4().hex + '.py'
    args = ['/usr/bin/python3', '-I', installed, '--stage', p['stage'], '--manifest-sha256', p['manifestSha256'],
            '--task', 'demo-executor', '--run-id', g['runId'], '--authorization-reference', g['reference'],
            '--owner-uid', str(os.getuid()), '--evidence-copy', str(d / 'root-evidence'), '--rendezvous', str(d / 'root'), '--max-seconds', '1800']
    q = shlex.quote
    script = ('umask 077; /bin/cp ' + q(str(launcher)) + ' ' + q(installed) + ' && /usr/sbin/chown 0:0 ' + q(installed) +
              ' && /bin/chmod 500 ' + q(installed) + ' && test "$(/usr/bin/shasum -a 256 ' + q(installed) + ')" = ' + q(p['launcherSha256'] + '  ' + installed) + ' && ' + shlex.join(args))
    write(d / 'root/preflight.json', dict(grant=g, interface=interface))
    with (d / 'root-launch.log').open('xb') as log:
        return subprocess.Popen(['/usr/bin/osascript', '-e', 'do shell script ' + json.dumps(script) + ' with administrator privileges'], stdout=log, stderr=subprocess.STDOUT)
