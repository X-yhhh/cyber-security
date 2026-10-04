#!/usr/bin/env python3
"""显式授权回环 HTTP 的低并发长期良性任务，研究观察与任务证据旁路分离。

唯一服务 IPv4/TCP/80，最多4路并发、每批最长180秒、整轮最多1800秒。任务
包含按服务端进度持续30/60/120秒的下载和最终完成的合法分段请求；不重放攻击。
原生采集可由 Npcap 绑定完成；Go live 另行验收，任务 sleep 不能替代 PCAP 实际时长。
"""
import argparse
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import socket
import threading
import time
import uuid
import sys


class NativeCapture:
    """复用已验证的 Npcap 绑定，只保存原生链路；新路径不再生成去 AF 头副本。"""
    def __init__(self, root):
        # 本机应用树与 Windows 专用交付目录均可使用同一冻结绑定。
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'p2/data_readiness'))
        from benign_loopback import Capture,Header,Stats
        self.capture=Capture(root);self.Header,self.Stats=Header,Stats;self.root=root
        self.thread=threading.Thread(target=self.run,daemon=True)
    def run(self):
        import ctypes as c
        import struct
        import os
        cap=self.capture
        try:
            with (self.root/'native.pcap').open('xb') as f:
                f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,cap.link))
                hp,data=c.POINTER(self.Header)(),c.POINTER(c.c_ubyte)()
                while not cap.stop.is_set():
                    result=cap.lib.pcap_next_ex(cap.handle,c.byref(hp),c.byref(data))
                    if result==0:time.sleep(.002);continue
                    if result!=1:raise RuntimeError('捕获失败')
                    h=hp.contents
                    if h.caplen!=h.length or h.caplen>65535:raise RuntimeError('捕获截短')
                    f.write(struct.pack('<IIII',h.sec,h.usec,h.caplen,h.length)+c.string_at(data,h.caplen));cap.frames+=1
                f.flush();os.fsync(f.fileno())
        except BaseException as e:cap.error=type(e).__name__
    def close(self):
        import ctypes as c
        cap=self.capture;cap.stop.set();self.thread.join(5)
        if self.thread.is_alive():raise RuntimeError('捕获线程未停止')
        stats=self.Stats();valid=cap.lib.pcap_stats(cap.handle,c.byref(stats))==0
        cap.lib.pcap_close(cap.handle);cap.dll_dir.close()
        result=dict(frames=cap.frames,nativeLink=cap.link,error=cap.error,
            stats={k:getattr(stats,k) for k,_ in self.Stats._fields_} if valid else None,
            passed=valid and not cap.error and cap.frames>0 and stats.dropped==stats.interfaceDropped==stats.networkDropped==0)
        (self.root/'capture.json').write_text(json.dumps(result,indent=2)+'\n');return result


def utc():return datetime.now(timezone.utc).isoformat()


def validate_scope(scope, now=None):
    """逐轮新授权；来源/目标只允许两个不同回环地址，不续用历史任务授权。"""
    now=time.time() if now is None else now
    if (scope['local'],scope['peer'])!=('127.0.0.1','127.0.0.2'):
        raise ValueError('只允许两个已登记回环地址')
    if ipaddress.ip_address(scope['local']).version!=4 or ipaddress.ip_address(scope['peer']).version!=4 or scope['port']!=80:
        raise ValueError('当前任务仅 IPv4/TCP/80')
    if scope['maxConcurrent']!=4 or scope['batchSeconds']!=180 or scope['isolationSeconds']<155:
        raise ValueError('任务预算与隔离要求不符')
    expiry=datetime.fromisoformat(scope['authorizedUntil']).timestamp()
    if not now<expiry<=now+1800:raise ValueError('须提供本轮最多30分钟新授权')
    if not scope.get('assetId') or not scope.get('authorizationId'):raise ValueError('缺少资产/授权引用')
    if scope.get('captureInterface')!='\\Device\\NPF_Loopback':raise ValueError('只允许登记的 Npcap 回环接口')
    return expiry


def serve(local, peer, port, records):
    """固定大小确定性内容；成功必须完整收发且哈希匹配，正常完成请求记录真实时间。"""
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):pass
        def do_GET(self):
            if self.client_address[0]==peer and self.path=='/wait/30':
                begin=time.monotonic();time.sleep(30);self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'OK')
                records.append(dict(kind='long_poll',elapsedSeconds=time.monotonic()-begin,success=True));return
            if self.client_address[0]==peer and self.path=='/range':
                data=bytes(range(256))*8;start=0
                if self.headers.get('Range')=='bytes=512-':start=512
                elif self.headers.get('Range') is not None:self.send_error(400);return
                self.send_response(206 if start else 200);self.send_header('Content-Length',str(len(data)-start));self.end_headers();self.wfile.write(data[start:])
                records.append(dict(kind='range_resume' if start else 'range_initial',success=True));return
            if self.client_address[0]!=peer or self.path not in ('/stream/30','/stream/60','/stream/120'):
                self.send_error(403);return
            seconds=int(self.path.rsplit('/',1)[1]);begin=time.monotonic();start=utc()
            chunk=bytes(range(256))*4;count=seconds*10
            self.send_response(200);self.send_header('Content-Length',str(len(chunk)*count));self.end_headers()
            ok=False
            try:
                for i in range(count):
                    # 单连接持续由服务端实际发送，避免数据瞬间进入缓冲后客户端只 sleep。
                    time.sleep(max(0,begin+(i+1)*.1-time.monotonic()));self.wfile.write(chunk);self.wfile.flush()
                ok=True
            finally:records.append(dict(kind='paced_download',seconds=seconds,beganUtc=start,endedUtc=utc(),elapsedSeconds=time.monotonic()-begin,success=ok))
        def do_POST(self):
            if self.client_address[0]!=peer or self.path!='/complete' or self.headers.get('Content-Length')!='9':
                self.send_error(403);return
            begin=time.monotonic();start=utc();data=self.rfile.read(9)
            self.send_response(200 if data==b'123456789' else 400);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'OK')
            records.append(dict(kind='legal_segmented_request',beganUtc=start,endedUtc=utc(),elapsedSeconds=time.monotonic()-begin,success=data==b'123456789'))
    class Server(ThreadingHTTPServer):
        # Windows 禁止共享绑定；已有服务占用时拒绝，不停止或替换其他监听者。
        allow_reuse_address=False
        daemon_threads=True
        def server_bind(self):
            if sys.platform=='win32':
                self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
            super().server_bind()
    server=Server((local,port),Handler);server.timeout=.2
    return server


def request(scope, seconds, segmented=False):
    """绑定唯一 peer，不接收任意 URL；分段请求必定结束，最多一个此类并发连接。"""
    with socket.socket() as sock:
        sock.settimeout(140);sock.bind((scope['peer'],0));sock.connect((scope['local'],scope['port']))
        if segmented:
            for part in (b'POST /complete HTTP/1.1\r\n',b'Host: fixture\r\nContent-Length: 9\r\n',b'Connection: close\r\n\r\n'):
                sock.sendall(part);time.sleep(seconds/6)
            for part in (b'123',b'456',b'789'):
                sock.sendall(part);time.sleep(seconds/6)
        else:sock.sendall(f'GET /stream/{seconds} HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n'.encode())
        data=bytearray()
        while True:
            b=sock.recv(65536)
            if not b:break
            data.extend(b)
            if len(data)>2*1024*1024:raise ValueError('响应超出固定预算')
        head,body=bytes(data).split(b'\r\n\r\n',1)
        expected=b'OK' if segmented else bytes(range(256))*4*(seconds*10)
        if not head.startswith(b'HTTP/1.1 200 ') or body!=expected:raise ValueError('业务未完整成功')
        return dict(bodyBytes=len(body),bodySha256=hashlib.sha256(body).hexdigest(),success=True)


def wait_and_resume(scope):
    """低并发长轮询后按已消费512字节恢复；完整内容哈希验证正常结束。"""
    import http.client
    def connection():
        return http.client.HTTPConnection(scope['local'],scope['port'],timeout=40,source_address=(scope['peer'],0))
    with closing(connection()) as c:
        c.request('GET','/wait/30');r=c.getresponse()
        if r.status!=200 or r.read()!=b'OK':raise ValueError('长轮询失败')
    with closing(connection()) as c:
        c.request('GET','/range');r=c.getresponse()
        if r.status!=200:raise ValueError('首次内容失败')
        beginning=r.read(512)
    with closing(connection()) as c:
        c.request('GET','/range',headers={'Range':'bytes=512-'});r=c.getresponse()
        if r.status!=206:raise ValueError('恢复响应失败')
        body=beginning+r.read()
    if body!=bytes(range(256))*8:raise ValueError('恢复内容哈希不符')
    return dict(kind='wait_and_range_resume',bodyBytes=len(body),bodySha256=hashlib.sha256(body).hexdigest(),success=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--role',choices=['train','validation_selection','validation_calibration','independent_development'],required=True)
    p.add_argument('--capture',action='store_true',help='显式启用本轮授权的 Windows Npcap 回环采集')
    a=p.parse_args();scope=json.loads(a.scope.read_text());expiry=validate_scope(scope)
    if time.time()+180>expiry:raise ValueError('剩余授权不足一批')
    a.output.mkdir(parents=True,exist_ok=False);records=[];begin=time.monotonic();start=utc()
    server=serve(scope['local'],scope['peer'],scope['port'],records)
    capture=None
    try:
        if a.capture:
            capture=NativeCapture(a.output);capture.thread.start()
    except BaseException:
        server.server_close();raise
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    timer=threading.Timer(180,server.shutdown);timer.start()
    results=[];error=None
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            work=[pool.submit(request,scope,s) for s in (30,60,120)]+[pool.submit(request,scope,60,True)]
            results=[f.result() for f in work]
        results.append(wait_and_resume(scope))
    except Exception as e:error=type(e).__name__
    finally:
        timer.cancel();server.shutdown();server.server_close();thread.join(timeout=3)
        capture_result=capture.close() if capture else None
        result=dict(activityId=str(uuid.uuid4()),role=a.role,authorizationId=scope['authorizationId'],
            beganUtc=start,endedUtc=utc(),elapsedSeconds=time.monotonic()-begin,serverRecords=records,clientResults=results,
            success=error is None and len(results)==5 and all(r['success'] for r in records) and (capture_result is None or capture_result['passed']),error=error,capture=capture_result,
            listenerClosed=server.socket.fileno()==-1,pcapDurationVerified=False,modelFits=0)
        (a.output/'task.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'success':result['success'],'elapsedSeconds':result['elapsedSeconds'],'listenerClosed':result['listenerClosed']}))
    if not result['success']:raise SystemExit(1)


if __name__=='__main__':main()
