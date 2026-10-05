#!/usr/bin/env python3
"""两端同句柄 live 验收：仅回环良性回显，逐字节复算真实头部/Tick/drop轨迹。

使用原生 Go/Npcap 或 Go/libpcap 程序；无 Python 特征提取替代。输入严格为
127.0.0.1/127.0.0.2 和独占高端口，最多三条连接，成功也不授予自动执行资格。
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import uuid


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def receive(sock,size):
    result=bytearray()
    while len(result)<size:
        part=sock.recv(size-len(result))
        if not part:raise RuntimeError('BENIGN_CONNECTION_CLOSED')
        result.extend(part)
    return bytes(result)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--port',type=int,default=55165)
    args=p.parse_args()
    if not 49152<=args.port<=65533:p.error('专用高端口范围无效')
    binary=args.binary.resolve();base=args.output.resolve();base.mkdir(parents=True,exist_ok=False)
    secret=base/'peer-key.bin';secret.write_bytes(os.urandom(32));secret.chmod(0o600)
    config={key:str(uuid.uuid4()) for key in ['assetId','sensorId','bootId','captureScopeId']}
    device=r'\Device\NPF_Loopback' if os.name=='nt' else 'lo0'
    config.update(localAddresses=['127.0.0.1'],peerAddresses=['127.0.0.2'],servicePort=args.port,
        secretFile=str(secret),keyEpoch=1,interface=device,allowedInterfaces=[device],
        authorizedUntil=(datetime.now(timezone.utc)+timedelta(minutes=2)).isoformat())
    cfg=base/'config.json';cfg.write_text(json.dumps(config,indent=2)+'\n');cfg.chmod(0o600)
    result={'binarySha256':sha(binary),'networkScope':'loopback_only','connections':3,'automaticExecutionSupported':False}
    stop=threading.Event();errors=[];threads=[];server=socket.socket()
    if os.name=='nt':server.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
    server.bind(('127.0.0.1',args.port));server.listen(3);server.settimeout(.2)
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
            if peer[0]!='127.0.0.2':conn.close();errors.append('UNEXPECTED_PEER');continue
            worker=threading.Thread(target=handle,args=(conn,),daemon=True);threads.append(worker);worker.start()
    acceptor=threading.Thread(target=serve,daemon=True);acceptor.start()
    proc=None
    try:
        with (base/'live.stdout').open('x') as out,(base/'live.stderr').open('x') as err:
            proc=subprocess.Popen([str(binary),'-config',str(cfg),'-duration','24s','-out',str(base/'live.jsonl'),'-trace',str(base/'trace.jsonl')],stdout=out,stderr=err)
            (base/'capture-pid.json').write_text(json.dumps({'pid':proc.pid})+'\n')
            time.sleep(1)
            if proc.poll() is not None:raise RuntimeError('LIVE_EXITED_BEFORE_TRAFFIC')
            def client(index):
                with socket.socket() as conn:
                    conn.settimeout(2);conn.bind(('127.0.0.2',0));conn.connect(('127.0.0.1',args.port))
                    end=time.perf_counter()+19;count=0
                    while time.perf_counter()<end:
                        payload=('hostguard-benign-%d-%d'%(index,count)).encode().ljust(256,b'.')
                        conn.sendall(payload)
                        if receive(conn,len(payload))!=payload:raise RuntimeError('ECHO_CONTENT_MISMATCH')
                        count+=1;time.sleep(.15+index*.03)
                    return count
            with ThreadPoolExecutor(max_workers=3) as pool:result['echoRounds']=list(pool.map(client,range(3)))
            result['captureExitCode']=proc.wait(timeout=12)
        if result['captureExitCode']!=0:raise RuntimeError('LIVE_CAPTURE_FAILED')
        replay=subprocess.run([str(binary),'-config',str(cfg),'-replay',str(base/'trace.jsonl'),'-out',str(base/'replay.jsonl')],capture_output=True,text=True,timeout=20)
        (base/'replay.stdout').write_text(replay.stdout);(base/'replay.stderr').write_text(replay.stderr)
        if replay.returncode:raise RuntimeError('REPLAY_FAILED')
        rows=[json.loads(x) for x in (base/'live.jsonl').read_text().splitlines()]
        trace=[json.loads(x) for x in (base/'trace.jsonl').read_text().splitlines()]
        result.update(observations=len(rows),profiles=dict(Counter(r['profile'] for r in rows)),
            parents=len({r['parentConnectionId'] for r in rows}),traceKinds=dict(Counter(e['kind'] for e in trace)),
            sameBytes=(base/'live.jsonl').read_bytes()==(base/'replay.jsonl').read_bytes(),
            drops=max((e['drops'] for e in trace),default=-1),
            dropsKnown=any(e['kind']=='tick' and e['dropsKnown'] for e in trace),
            liveSha256=sha(base/'live.jsonl'),replaySha256=sha(base/'replay.jsonl'),traceSha256=sha(base/'trace.jsonl'),
            businessErrors=errors)
        result['passed']=bool(rows) and result['sameBytes'] and result['drops']==0 and result['dropsKnown'] and result['parents']==3 and not errors and not result['traceKinds'].get('gap',0)
    except BaseException as exc:
        result.update(passed=False,error=type(exc).__name__+':'+str(exc))
    finally:
        if proc is not None and proc.poll() is None:proc.terminate();proc.wait(timeout=5)
        stop.set();server.close();acceptor.join(timeout=1)
        for thread in threads:thread.join(timeout=1)
        result['serverClosed']=server.fileno()==-1
        result['captureClosed']=proc is None or proc.poll() is not None
        (base/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
    return 0 if result.get('passed') else 1


if __name__=='__main__':raise SystemExit(main())
