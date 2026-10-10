#!/usr/bin/env python3
"""P1 macOS PF 隔离探针：自有 anchor、精确状态删除和两个独立 launchd 进程。

仅在 PF 原为关闭、无状态、系统默认根规则的主机运行。只允许回环两个高端口，
不安装常驻执行器、不接收网络命令、不修改 /etc/pf.conf。退出恢复根规则和自身
enable token；全程不 flush 全局状态，不关闭其他组件的 PF 引用。
"""
import argparse
from contextlib import ExitStack
from datetime import datetime,timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

PF='/sbin/pfctl'
# 已核对 DIOCKILLSTATES 实参的 pfctl 字节；ad886b… 为 2026-10-08 系统更新后版本（静态证据见 pf_abi_evidence.py）。
PF_SHA256S=frozenset({'b9d584580d258388079890bf3a1436a899b8b2d29ccab08e101ad9675a960962',
                      'ad886b1eb52f3aae6e14a06471fb3a41f01c96f41890c461833c6cc4d7f32743'})


def run(args,timeout=8):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError('COMMAND_FAILED:'+Path(args[0]).name+':'+p.stderr[-300:])
    return p.stdout,p.stderr


def put(path,value):
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.pending')
    with temporary.open('x') as stream:
        json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    temporary.chmod(0o600);os.replace(temporary,path)


def audit(base,role,event,**details):
    with (base/(role+'.jsonl')).open('a') as stream:
        stream.write(json.dumps(dict(event=event,monotonic=time.monotonic(),utc=datetime.now(timezone.utc).isoformat(),**details))+'\n')
        stream.flush();os.fsync(stream.fileno())


def rules(manifest,blocked=False):
    p=manifest['port'];peer=manifest['peer'];local=manifest['local'];iface=manifest['interface']
    # 回环同一包经过本机收发路径，按完整单向端点范围匹配，避免出站先建 state。
    block=f'block drop quick on {iface} inet proto tcp from {peer} to {local} port {p}\n' if blocked else ''
    return block+f'pass quick on {iface} inet proto tcp from {peer} to {local} port {{ {p}, {p+1} }} flags any keep state (if-bound)\n'


def load(manifest,blocked,lease=None):
    path=Path(manifest['base'])/('blocked.rules' if blocked else 'baseline.rules')
    # PF 事务 ticket 不能由两个恢复进程同时替换；锁仅覆盖本命名空间短事务。
    # owner 被终止时内核释放 flock，独立恢复器仍可接管；不持锁等待租约。
    with (Path(manifest['base'])/'anchor.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if blocked:
            # 在事务锁内再次核验，恢复器发出清理意图后禁止迟到的安装反向覆盖恢复。
            if lease is None:raise ValueError('BLOCK_REQUIRES_BOUNDED_LEASE')
            case=Path(manifest['base'])/lease['case']
            if (time.monotonic()>=lease['deadline'] or time.time()>=manifest['authorizationUntil']
                or abs((time.time()-time.monotonic())-lease['clockAnchor'])>1
                or any((case/name).exists() for name in ('revoke','clear-requested.json','cleared.json'))):
                return False
        actual=inventory(manifest)
        if actual['rules'] and actual['blockRules']==int(blocked):return True
        run([PF,'-a',manifest['anchor'],'-f',str(path)])
        return True


def inventory(manifest):
    text,_=run([PF,'-a',manifest['anchor'],'-sr'])
    return {'blockRules':sum(line.startswith('block ') for line in text.splitlines()),'rules':text}


def worker(manifest,role):
    base=Path(manifest['base']);seen=set();active=None
    put(base/(role+'-ready.json'),{'pid':os.getpid(),'role':role})
    while time.time()<manifest['authorizationUntil']:
        put(base/(role+'-heartbeat.json'),{'monotonic':time.monotonic()})
        lease_path=base/'lease.json'
        if lease_path.exists():
            lease=json.loads(lease_path.read_text());case=base/lease['case']
            if not re.fullmatch(r'(ttl|revoke|executor-crash)',lease['case']):raise ValueError('INVALID_CASE')
            if role=='owner' and lease['id'] not in seen:
                seen.add(lease['id'])
                if not time.monotonic()<lease['deadline'] or abs((time.time()-time.monotonic())-lease['clockAnchor'])>1:
                    audit(base,role,'lease_rejected');continue
                if not load(manifest,True,lease):
                    audit(base,role,'lease_rejected',reason='closed_before_install');continue
                killed,_=run([manifest['helper'],'kill',manifest['local'],manifest['peer'],str(manifest['port']),manifest['interface']])
                actual=inventory(manifest)
                if actual['blockRules']!=1:raise RuntimeError('BLOCK_NOT_OBSERVED')
                put(case/'applied.json',{'installedMonotonic':time.monotonic(),'deadline':lease['deadline'],'stateKill':json.loads(killed),'inventory':actual})
                audit(base,role,'applied',case=lease['case'])
                active=lease
            # 安装后到回执落盘前也可能崩溃；恢复不能依赖执行者已经写出成功回执。
            if not (case/'cleared.json').exists():
                now=time.monotonic();reason=None
                if now>=lease['deadline']:reason='ttl_expired'
                if (case/'revoke').exists():reason='explicit_revoke'
                if abs((time.time()-now)-lease['clockAnchor'])>1:reason='clock_untrusted'
                if role=='observer':
                    h=base/'owner-heartbeat.json'
                    if not h.exists() or now-json.loads(h.read_text())['monotonic']>.6:reason='executor_heartbeat_lost'
                if reason:
                    put(case/'clear-requested.json',{'reason':reason,'monotonic':now})
                    load(manifest,False)
                    actual=inventory(manifest)
                    if actual['blockRules']!=0:raise RuntimeError('RECOVERY_NOT_VERIFIED')
                    # 只允许独立观察者发布验收时刻；所有者只能报告自己的删除动作。
                    audit(base,role,'cleared',case=lease['case'],reason=reason,delaySeconds=time.monotonic()-lease['deadline'])
                    if role=='observer':
                        put(case/'cleared.json',{'reason':reason,'observerPid':os.getpid(),'inventory':actual,'delaySeconds':time.monotonic()-lease['deadline']})
        time.sleep(.05)
    # 授权结束时清空自有 anchor；授权时间绝不随心跳延长。
    with (base/'anchor.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        run([PF,'-a',manifest['anchor'],'-f','/dev/null'])
    audit(base,role,'authorization_expired')


def wait_file(path,seconds):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if path.exists():return json.loads(path.read_text())
        time.sleep(.05)
    raise RuntimeError('EVIDENCE_WAIT_TIMEOUT:'+path.name)


def echo(sock):
    try:
        payload=b'hostguard-pf-canary';sock.sendall(payload)
        return sock.recv(len(payload))==payload
    except OSError:return False


def connect(m,port):
    s=socket.socket();s.settimeout(.45);s.bind((m['peer'],0))
    try:s.connect((m['local'],port));return s
    except BaseException:s.close();raise


def fresh(m,port):
    try:
        with connect(m,port) as s:return echo(s)
    except OSError:return False


def probe(args):
    base=args.output.resolve();base.mkdir(parents=True,exist_ok=False);base.chmod(0o700)
    info,_=run([PF,'-s','info']);root,_=run([PF,'-sr']);nat,_=run([PF,'-sn'])
    conf=Path('/etc/pf.conf').read_bytes()
    expected='scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n'
    if 'Status: Disabled' not in info or not re.search(r'current entries\s+0\b',info) or root!=expected:
        raise RuntimeError('P1_REQUIRES_UNCHANGED_DISABLED_BASELINE')
    if hashlib.sha256(Path(PF).read_bytes()).hexdigest() not in PF_SHA256S:raise RuntimeError('PFCTL_ABI_IDENTITY_CHANGED')
    abi,_=run([str(args.helper.resolve()),'--abi'])
    if not json.loads(abi)['kernelMatches']:raise RuntimeError('KERNEL_NOT_VERIFIED')
    ident=uuid.uuid4().hex[:12];anchor='hostguard/p1-'+ident
    m=dict(base=str(base),anchor=anchor,local='127.0.0.1',peer='127.0.0.2',port=args.port,interface='lo0',
           helper=str(args.helper.resolve()),authorizationUntil=time.time()+600)
    put(base/'manifest.json',m);put(base/'before.json',{'info':info,'rootRules':root,'natRules':nat,'pfConfSha256':hashlib.sha256(conf).hexdigest()})
    (base/'original.conf').write_bytes(conf)
    (base/'probe.conf').write_bytes(conf+f'\nanchor "{anchor}"\n'.encode())
    (base/'baseline.rules').write_text(rules(m));(base/'blocked.rules').write_text(rules(m,True))
    run([PF,'-nf',str(base/'probe.conf')]);run([PF,'-a',anchor,'-nf',str(base/'blocked.rules')])
    token=None;loaded=[];listeners=[];threads=[];stop=threading.Event();result={'cases':{},'passed':False,'scope':'macOS IPv4 TCP loopback canary','productionAutoSupported':False}
    def handle(conn):
        try:
            with conn:
                conn.settimeout(.2)
                while not stop.is_set():
                    try:data=conn.recv(256)
                    except socket.timeout:continue
                    if not data:break
                    conn.sendall(data)
        except OSError:pass
    def accept(server):
        while not stop.is_set():
            try:c,address=server.accept()
            except socket.timeout:continue
            except OSError:break
            if address[0]!=m['peer']:c.close();continue
            t=threading.Thread(target=handle,args=(c,),daemon=True);threads.append(t);t.start()
    try:
        for port in (m['port'],m['port']+1):
            s=socket.socket();s.bind((m['local'],port));s.listen(8);s.settimeout(.2);listeners.append(s)
            t=threading.Thread(target=accept,args=(s,),daemon=True);threads.append(t);t.start()
        run([PF,'-f',str(base/'probe.conf')]);load(m,False)
        enabled_out,enabled_err=run([PF,'-E']);match=re.search(r'Token\s*:\s*(\d+)',enabled_out+enabled_err)
        if not match:raise RuntimeError('ENABLE_TOKEN_NOT_CAPTURED')
        token=match[1]
        for role in ('owner','observer'):
            label='org.xyhhh.hostguard.p1.'+ident+'.'+role
            plist={'Label':label,'ProgramArguments':[sys.executable,str(Path(__file__).resolve()),'worker','--manifest',str(base/'manifest.json'),'--role',role],
                'RunAtLoad':True,'KeepAlive':False,'StandardOutPath':str(base/(role+'.stdout')),'StandardErrorPath':str(base/(role+'.stderr'))}
            path=base/(role+'.plist');path.write_bytes(plistlib.dumps(plist));path.chmod(0o644)
            run(['/bin/launchctl','bootstrap','system',str(path)]);loaded.append(label)
            wait_file(base/(role+'-ready.json'),8)
        for scenario in ('ttl','revoke','executor-crash'):
            case=base/scenario;case.mkdir();r={};result['cases'][scenario]=r
            with ExitStack() as stack:
                target=stack.enter_context(connect(m,m['port']));control=stack.enter_context(connect(m,m['port']+1))
                r['before']={'targetExisting':echo(target),'controlExisting':echo(control)}
                if not all(r['before'].values()):raise RuntimeError('BASELINE_CONNECTION_FAILED')
                r['statesBefore'],_=run([PF,'-ss','-vv'])
                now=time.monotonic();put(base/'lease.json',{'case':scenario,'id':str(uuid.uuid4()),'deadline':now+30,'clockAnchor':time.time()-now})
                r['applied']=wait_file(case/'applied.json',8)
                r['during']={'targetExisting':echo(target),'targetNew':fresh(m,m['port']),
                    'controlExisting':echo(control),'controlNew':fresh(m,m['port']+1)}
                r['statesDuring'],_=run([PF,'-ss','-vv'])
                if r['during']!={'targetExisting':False,'targetNew':False,'controlExisting':True,'controlNew':True}:
                    raise RuntimeError('NARROW_BLOCK_NOT_VERIFIED')
                if scenario=='revoke':(case/'revoke').touch()
                elif scenario=='executor-crash':run(['/bin/launchctl','kill','SIGKILL','system/'+loaded[0]])
                r['cleared']=wait_file(case/'cleared.json',32)
                r['after']={'targetNew':fresh(m,m['port']),'controlExisting':echo(control),'controlNew':fresh(m,m['port']+1)}
                r['passed']=all(r['after'].values()) and r['cleared']['delaySeconds']<=1 and r['cleared']['inventory']['blockRules']==0
                if not r['passed']:raise RuntimeError('RECOVERY_ACCEPTANCE_FAILED')
        result['passed']=True
    except BaseException as exc:
        result['error']=type(exc).__name__+':'+str(exc)
    finally:
        try:
            for label in reversed(loaded):
                try:run(['/bin/launchctl','bootout','system/'+label])
                except RuntimeError:
                    result.setdefault('cleanupErrors',[]).append('launchd:'+label);result['passed']=False
            run([PF,'-a',anchor,'-f','/dev/null'])
            result['finalBlockInventory']=inventory(m)
            stop.set()
            for s in listeners:s.close()
            for t in threads:t.join(timeout=.3)
            for port in (m['port'],m['port']+1):run([m['helper'],'kill',m['local'],m['peer'],str(port),m['interface']])
            current,_=run([PF,'-sr'])
            if Path('/etc/pf.conf').read_bytes()!=conf or current!=root+f'anchor "{anchor}" all\n':
                raise RuntimeError('ROOT_RULES_CHANGED_RESTORE_REQUIRES_REVIEW')
            run([PF,'-f',str(base/'original.conf')])
            if token is not None:run([PF,'-X',token]);token=None
            restored,_=run([PF,'-sr']);restored_info,_=run([PF,'-s','info'])
            result['restoredRootRules']=restored==root
            result['restoredDisabled']='Status: Disabled' in restored_info
            result['listenersClosed']=all(s.fileno()==-1 for s in listeners)
            if not all(result[k] for k in ('restoredRootRules','restoredDisabled','listenersClosed')):
                raise RuntimeError('FINAL_BASELINE_NOT_RESTORED')
        except BaseException as exc:
            result.setdefault('cleanupErrors',[]).append(str(exc));result['passed']=False
        finally:
            # 根规则被其他组件改变时不覆盖它；仍释放且只释放本次 enable 引用。
            if token is not None:
                try:run([PF,'-X',token])
                except BaseException as exc:
                    result.setdefault('cleanupErrors',[]).append('enable_reference:'+str(exc));result['passed']=False
        put(base/'result.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='cases'}),flush=True)
    return 0 if result['passed'] else 1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['probe','worker'])
    p.add_argument('--manifest',type=Path);p.add_argument('--role',choices=['owner','observer'])
    p.add_argument('--output',type=Path);p.add_argument('--helper',type=Path);p.add_argument('--port',type=int,default=55231)
    a=p.parse_args()
    if os.geteuid()!=0:p.error('需要本轮明确授权的 root 维护上下文')
    if a.mode=='worker':return worker(json.loads(a.manifest.read_text()),a.role)
    if not a.output or not a.helper or not 49152<=a.port<=65532:p.error('缺少独立产物目录、ABI helper 或专用高端口')
    return probe(a)


if __name__=='__main__':raise SystemExit(main())
