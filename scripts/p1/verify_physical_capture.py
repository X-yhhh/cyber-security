#!/usr/bin/env python3
"""两台授权主机物理接口的有界良性回显与 Go 同句柄复算。

server/client 分别在服务端/客户端执行，各自只登记两端 IPv4 和一个高端口。
最多三条普通连接，不扫描、不生成攻击；Windows 另保存运行中实际 Npcap 模块身份。
原始端点、头部轨迹和临时 HMAC 密钥只写入调用者指定的私有证据目录。
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
import ipaddress
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time
import uuid

from verify_live_capture import sha,receive


def modules(pid):
    """只查询本轮 Go PID 实际加载的抓包 DLL；磁盘存在不能代替加载证据。"""
    code=(f"$ErrorActionPreference='Stop';@(Get-Process -Id {pid}).Modules|"
          "Where-Object {$_.ModuleName -in @('wpcap.dll','Packet.dll')}|ForEach-Object {"
          "@{name=$_.ModuleName;path=$_.FileName;version=$_.FileVersionInfo.FileVersion;"
          "sha256=(Get-FileHash $_.FileName -Algorithm SHA256).Hash;"
          "signature=(Get-AuthenticodeSignature $_.FileName).Status.ToString()}}|ConvertTo-Json -Compress")
    value=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],
                         capture_output=True,text=True,timeout=12,check=True)
    rows=json.loads(value.stdout)
    return rows if isinstance(rows,list) else [rows]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['server','client','https'])
    for name in ['binary','output']:p.add_argument('--'+name,type=Path,required=True)
    for name in ['local','peer','interface']:p.add_argument('--'+name,required=True)
    p.add_argument('--port',type=int,default=55175)
    p.add_argument('--duration',type=int,default=32)
    a=p.parse_args()
    addresses=[ipaddress.ip_address(v) for v in (a.local,a.peer)]
    if any(v.version!=4 or v.is_loopback or v.is_unspecified or v.is_multicast for v in addresses) or not addresses[0].is_private or a.local==a.peer:
        p.error('须登记两台私有 IPv4 主机的物理接口地址')
    if a.mode=='https':
        # 直连主机不可达时，仅允许固定公开示例站点；最多9个完整 GET，无认证/上传/重定向。
        resolved={r[4][0] for r in socket.getaddrinfo('example.com',443,socket.AF_INET,socket.SOCK_STREAM)}
        if a.port!=443 or a.peer not in resolved:p.error('HTTPS 验收只允许已解析的 example.com:443')
    elif not addresses[1].is_private or not 49152<=a.port<=65533:
        p.error('回显须使用私有对端和高端口')
    if not 25<=a.duration<=90:p.error('有界时限无效')
    base=a.output.resolve();base.mkdir(parents=True,exist_ok=False,mode=0o700)
    binary=a.binary.resolve();secret=base/'peer-key.bin';secret.write_bytes(os.urandom(32));secret.chmod(0o600)
    config={key:str(uuid.uuid4()) for key in ['assetId','sensorId','bootId','captureScopeId']}
    config.update(localAddresses=[a.local],peerAddresses=[a.peer],servicePort=a.port,
        serviceEndpoint='local' if a.mode=='server' else 'peer',secretFile=str(secret),keyEpoch=1,
        interface=a.interface,allowedInterfaces=[a.interface],
        authorizedUntil=(datetime.now(timezone.utc)+timedelta(seconds=a.duration+30)).isoformat())
    cfg=base/'config.json';cfg.write_text(json.dumps(config,indent=2)+'\n');cfg.chmod(0o600)
    result=dict(mode=a.mode,binarySha256=sha(binary),networkScope='registered_physical_interface',
                automaticExecutionSupported=False,connections=0)
    stop=threading.Event();errors=[];workers=[];server=None;acceptor=None;proc=None
    def handle(conn):
        try:
            with conn:
                conn.settimeout(2)
                while not stop.is_set():
                    try:data=conn.recv(1024)
                    except socket.timeout:continue
                    if not data:break
                    conn.sendall(data)
        except OSError as exc:errors.append(type(exc).__name__)
    def serve():
        while not stop.is_set():
            try:conn,peer=server.accept()
            except socket.timeout:continue
            except OSError:break
            if peer[0]!=a.peer or result['connections']>=3:
                conn.close();errors.append('UNEXPECTED_CONNECTION');continue
            result['connections']+=1
            worker=threading.Thread(target=handle,args=(conn,),daemon=True);workers.append(worker);worker.start()
    try:
        if a.mode=='server':
            server=socket.socket();server.bind((a.local,a.port));server.listen(3);server.settimeout(.2)
            acceptor=threading.Thread(target=serve,daemon=True);acceptor.start()
        with (base/'live.stdout').open('x') as out,(base/'live.stderr').open('x') as err:
            proc=subprocess.Popen([str(binary),'-config',str(cfg),'-duration',str(a.duration)+'s',
                '-out',str(base/'live.jsonl'),'-trace',str(base/'trace.jsonl')],stdout=out,stderr=err)
            end=time.monotonic()+8
            while not (base/'trace.jsonl').exists() or (base/'trace.jsonl').stat().st_size==0:
                if proc.poll() is not None or time.monotonic()>=end:raise RuntimeError('LIVE_NOT_READY')
                time.sleep(.1)
            (base/'ready.json').write_text(json.dumps(dict(pid=proc.pid,interface=a.interface))+'\n')
            if os.name=='nt':result['loadedModules']=modules(proc.pid)
            if a.mode in ('client','https'):
                def client(index):
                    with socket.socket() as conn:
                        conn.settimeout(10 if a.mode=='https' else 3);conn.bind((a.local,0));conn.connect((a.peer,a.port))
                        if a.mode=='https':
                            context=ssl.create_default_context()
                            with context.wrap_socket(conn,server_hostname='example.com') as secure:
                                count=0
                                for turn in range(3):
                                    secure.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: HostGuard-Benign-Acceptance/1\r\nConnection: keep-alive\r\n\r\n')
                                    response=http.client.HTTPResponse(secure);response.begin()
                                    if response.status!=200:raise RuntimeError('HTTPS_BUSINESS_STATUS')
                                    data=response.read(65537)
                                    if len(data)>65536 or not data:raise RuntimeError('HTTPS_RESPONSE_BOUND')
                                    count+=1
                                    if response.will_close:break
                                    if turn<2:time.sleep(4+index*.1)
                                return count
                        end=time.monotonic()+19;count=0
                        while time.monotonic()<end:
                            data=('hostguard-benign-%d-%d'%(index,count)).encode().ljust(256,b'.')
                            conn.sendall(data)
                            if receive(conn,len(data))!=data:raise RuntimeError('ECHO_MISMATCH')
                            count+=1;time.sleep(.15+index*.03)
                        return count
                with ThreadPoolExecutor(max_workers=3) as pool:result['echoRounds']=list(pool.map(client,range(3)))
                result['connections']=3
            result['captureExitCode']=proc.wait(timeout=a.duration+5)
        if result['captureExitCode']!=0:raise RuntimeError('CAPTURE_FAILED')
        replay=subprocess.run([str(binary),'-config',str(cfg),'-replay',str(base/'trace.jsonl'),
            '-out',str(base/'replay.jsonl')],capture_output=True,text=True,timeout=20)
        (base/'replay.stderr').write_text(replay.stderr)
        if replay.returncode:raise RuntimeError('REPLAY_FAILED')
        rows=[json.loads(x) for x in (base/'live.jsonl').read_text().splitlines()]
        events=[json.loads(x) for x in (base/'trace.jsonl').read_text().splitlines()]
        result.update(observations=len(rows),parents=len({r['parentConnectionId'] for r in rows}),
            profiles=dict(Counter(r['profile'] for r in rows)),directions=dict(Counter(r['direction'] for r in rows)),
            traceKinds=dict(Counter(e['kind'] for e in events)),drops=max((e['drops'] for e in events),default=-1),
            dropsKnown=any(e['kind']=='tick' and e['dropsKnown'] for e in events),
            liveSha256=sha(base/'live.jsonl'),replaySha256=sha(base/'replay.jsonl'),traceSha256=sha(base/'trace.jsonl'),
            sameBytes=(base/'live.jsonl').read_bytes()==(base/'replay.jsonl').read_bytes(),businessErrors=errors)
        dlls={m['name'].lower() for m in result.get('loadedModules',[])}
        result['passed']=bool(rows) and result['sameBytes'] and result['drops']==0 and result['dropsKnown'] and result['parents']==3 and result['connections']==3 and not errors and not result['traceKinds'].get('gap',0) and (os.name!='nt' or {'wpcap.dll','packet.dll'}<=dlls)
    except BaseException as exc:result.update(passed=False,error=type(exc).__name__+':'+str(exc))
    finally:
        if proc is not None and proc.poll() is None:proc.terminate();proc.wait(timeout=5)
        stop.set()
        if server is not None:server.close()
        if acceptor is not None:acceptor.join(timeout=1)
        for worker in workers:worker.join(timeout=1)
        result['serverClosed']=server is None or server.fileno()==-1
        result['captureClosed']=proc is None or proc.poll() is not None
        (base/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
    return 0 if result.get('passed') else 1


if __name__=='__main__':raise SystemExit(main())
