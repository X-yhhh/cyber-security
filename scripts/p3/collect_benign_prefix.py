#!/usr/bin/env python3
"""限时采集八批不同的正常HTTP任务；仅Windows登记回环、四路并发，无防火墙操作。

每批是实际的新任务和新连接，大小/节奏在采集前冻结。预登记任务完成且内容
匹配才可标正常；后续使用真实PCAP和Go提取，绝不通过换UUID复制模型输入。
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'p1'))
from benign_long_tasks import NativeCapture

ROLES = ['train', 'validation_selection', 'validation_calibration'] + ['independent_development'] * 5


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def profiles():
    """确定性业务矩阵；完整内容、时长和分包均改变，局限仍是同一个主机域。"""
    return [dict(batch=i + 1, role=ROLES[i], durationSeconds=39 + 3 * i,
                 chunks=83 + 7 * i, chunkBytes=337 + 59 * i, uploadChunks=9 + i,
                 uploadIntervalSeconds=2.1 + .21 * i, uploadChunkBytes=211 + 43 * i,
                 pollSeconds=30 + i, rangeBytes=6173 + 863 * i)
            for i in range(8)]


def content(size):
    return (bytes(range(256)) * ((size + 255) // 256))[:size]


def run_batch(root, profile, deadline):
    """专有绑定既有端口占用即失败；所有客户端固定源地址，实际返回内容逐条核验。"""
    if time.time() + 85 >= deadline:
        raise TimeoutError('剩余授权不足一批')
    root.mkdir(mode=0o700)
    save(root / 'profile.json', profile)
    begin = time.monotonic()
    server_records = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass
        def respond(self, status, data):
            self.send_response(status); self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close'); self.end_headers()
            self.wfile.write(data); self.wfile.flush()
        def do_GET(self):
            if self.client_address[0] != '127.0.0.2':
                self.send_error(403); return
            if self.path == '/stream':
                size = profile['chunkBytes']; chunks = profile['chunks']
                self.send_response(200); self.send_header('Content-Length', str(size * chunks))
                self.send_header('Connection', 'close'); self.end_headers()
                start = time.monotonic()
                for n in range(chunks):
                    time.sleep(max(0, start + (n + 1) * profile['durationSeconds'] / chunks - time.monotonic()))
                    self.wfile.write(content(size)); self.wfile.flush()
            elif self.path == '/poll':
                time.sleep(profile['pollSeconds']); self.respond(200, b'OK')
            elif self.path == '/retry':
                self.respond(503, b'RETRY')
            elif self.path == '/range':
                offset = 1024 if self.headers.get('Range') == 'bytes=1024-' else 0
                self.respond(206 if offset else 200, content(profile['rangeBytes'])[offset:])
            else:
                self.send_error(404); return
            server_records.append(dict(path=self.path, peerPort=self.client_address[1], success=True))
        def do_POST(self):
            size = profile['uploadChunks'] * profile['uploadChunkBytes']
            if self.client_address[0] != '127.0.0.2' or self.path != '/upload' or self.headers.get('Content-Length') != str(size):
                self.send_error(403); return
            data = self.rfile.read(size)
            expected = content(profile['uploadChunkBytes']) * profile['uploadChunks']
            if data != expected:
                self.send_error(400); return
            self.respond(200, b'OK')
            server_records.append(dict(path=self.path, peerPort=self.client_address[1], success=True))
    class Server(ThreadingHTTPServer):
        allow_reuse_address = False
        daemon_threads = True
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()
    server = Server(('127.0.0.1', 80), Handler)
    capture = None; thread = None; timer = None; results = []; error = None
    def request(path, expected, status=200, upload=False, resumed=False):
        with socket.socket() as sock:
            sock.settimeout(80); sock.bind(('127.0.0.2', 0)); sock.connect(('127.0.0.1', 80))
            port = sock.getsockname()[1]
            method = 'POST' if upload else 'GET'
            headers = f'{method} {path} HTTP/1.1\r\nHost: local-fixture\r\nConnection: close\r\n'
            if resumed: headers += 'Range: bytes=1024-\r\n'
            if upload: headers += f"Content-Length: {profile['uploadChunks'] * profile['uploadChunkBytes']}\r\n"
            sock.sendall((headers + '\r\n').encode('ascii'))
            if upload:
                for _ in range(profile['uploadChunks']):
                    time.sleep(profile['uploadIntervalSeconds'])
                    sock.sendall(content(profile['uploadChunkBytes']))
            data = bytearray()
            while chunk := sock.recv(65536):
                data.extend(chunk)
                if len(data) > 2 * 1024 * 1024: raise ValueError('响应超出预算')
            head, body = bytes(data).split(b'\r\n\r\n', 1)
            if int(head.split(b' ')[1]) != status or body != expected:
                raise ValueError('正常业务状态或内容不符')
            return dict(path=path, peerPort=port, status=status, bodyBytes=len(body),
                        bodySha256=hashlib.sha256(body).hexdigest(), success=True)
    def retries():
        return [request('/retry', b'RETRY', 503),
                request('/range', content(profile['rangeBytes'])),
                request('/range', content(profile['rangeBytes'])[1024:], 206, resumed=True)]
    try:
        capture = NativeCapture(root); capture.thread.start()
        time.sleep(.15)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        timer = threading.Timer(85, server.shutdown); timer.start()
        with ThreadPoolExecutor(max_workers=4) as pool:
            tasks = [pool.submit(request, '/stream', content(profile['chunkBytes']) * profile['chunks']),
                     pool.submit(request, '/upload', b'OK', upload=True),
                     pool.submit(request, '/poll', b'OK'), pool.submit(retries)]
            for task in tasks:
                result = task.result()
                results.extend(result if isinstance(result, list) else [result])
        time.sleep(.15)
    except BaseException as exc:
        error = type(exc).__name__
    finally:
        if timer: timer.cancel()
        if thread: server.shutdown(); thread.join(3)
        server.server_close()
        captured = capture.close() if capture else None
        result = dict(activityId=str(uuid.uuid4()), role=profile['role'], batch=profile['batch'],
                      profile=profile, elapsedSeconds=time.monotonic() - begin,
                      records=results, serverRecords=server_records, capture=captured,
                      listenerClosed=server.socket.fileno() == -1,
                      success=error is None and len(results) == 6 and len(server_records) == 6 and captured is not None and captured['passed'],
                      error=error, modelFits=0)
        save(root / 'task.json', result)
    if not result['success']:
        raise RuntimeError('正常任务/采集失败: ' + str(error))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if sys.platform != 'win32': raise RuntimeError('仅登记Windows回环环境')
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    start = time.time(); deadline = start + 1800
    save(args.output / 'registration.json', dict(version='p3-cde-benign-v1',
         authorization='本轮用户要求完成P3-C困难正常流量补齐',
         local='127.0.0.1', peer='127.0.0.2', servicePort=80,
         captureInterface='\\Device\\NPF_Loopback', maxConcurrent=4,
         authorizedUntil=datetime.fromtimestamp(deadline, timezone.utc).isoformat(),
         maximumSeconds=1800, isolationSeconds=155, profiles=profiles(),
         sourceDomainCount=1, firewallChanges=False, scriptSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    for i, profile in enumerate(profiles()):
        result = run_batch(args.output / f'batch-{i + 1:02}', profile, deadline)
        print(json.dumps({k: result[k] for k in ('batch', 'success', 'elapsedSeconds', 'listenerClosed')}), flush=True)
        if i < 7:
            if time.time() + 155 + 85 >= deadline: raise TimeoutError('整轮授权预算不足')
            time.sleep(155)
    save(args.output / 'complete.json', dict(status='completed', batches=8,
         elapsedSeconds=time.time() - start, listenerReleased=True, modelFits=0))


if __name__ == '__main__':
    main()
