#!/usr/bin/env python3
"""限时采集预登记的正常HTTP任务；仅Windows登记回环、四路并发，无防火墙操作。

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
from prefix_contract import planned_role, collection_gate
from capture_health_observer import ROLE_ORDER, ledger_append, ledger_check, ledger_ready_at, require_live

ISOLATION_SECONDS = 155
INTER_ACTIVITY_SECONDS = max(ISOLATION_SECONDS, 120 + 60 + 10)
MAXIMUM_ACTIVE_SECONDS = 1800

ROLES = ['train'] * 2 + ['validation_selection'] * 2 + ['validation_calibration'] * 2 + ['independent_development'] * 2


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def profiles():
    """确定性业务矩阵；完整内容、时长和分包均改变，局限仍是同一个主机域。"""
    original = [dict(batch=i + 1, role=ROLES[i], plannedRole=ROLES[i], durationSeconds=39 + 3 * i,
                 chunks=83 + 7 * i, chunkBytes=337 + 59 * i, uploadChunks=9 + i,
                 uploadIntervalSeconds=2.1 + .21 * i, uploadChunkBytes=211 + 43 * i,
                 pollSeconds=30 + i, rangeBytes=6173 + 863 * i)
            for i in range(8)]
    additional = [
        (9, 45, 52, 1024, 17, 1.2, 512, 25, 12288),
        (10, 64, 94, 1536, 19, 1.5, 768, 35, 16384),
        (11, 75, 140, 2048, 21, 1.8, 1024, 45, 20480),
    ]
    return original + [dict(batch=batch, role='independent_development',
        plannedRole='independent_development', durationSeconds=duration,
        chunks=chunks, chunkBytes=chunk_bytes, uploadChunks=upload_chunks,
        uploadIntervalSeconds=upload_interval, uploadChunkBytes=upload_bytes,
        pollSeconds=poll, rangeBytes=range_bytes)
        for batch,duration,chunks,chunk_bytes,upload_chunks,upload_interval,upload_bytes,poll,range_bytes in additional]


def content(size):
    return (bytes(range(256)) * ((size + 255) // 256))[:size]


def run_batch(root, profile, deadline, health=None):
    """专有绑定既有端口占用即失败；所有客户端固定源地址，实际返回内容逐条核验。"""
    planned_role(profile)
    if time.time() + 85 >= deadline:
        raise TimeoutError('剩余授权不足一批')
    if health: ledger_check(health[0], profile['plannedRole'], INTER_ACTIVITY_SECONDS)
    before = require_live(*health) if health else None
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
        after = continuity = None
        if health:
            try:
                after = require_live(*health)
                continuity = (after['observerSessionId'] == before['observerSessionId']
                              and after['healthySinceMs'] == before['healthySinceMs'])
            except (OSError, ValueError) as exc:
                error = error or 'HEALTH_OBSERVER: ' + str(exc); continuity = False
        result = dict(activityId=str(uuid.uuid4()), role=profile['role'], plannedRole=planned_role(profile), batch=profile['batch'],
                      profile=profile, elapsedSeconds=time.monotonic() - begin,
                      records=results, serverRecords=server_records, capture=captured,
                      captureHealth=dict(before=before, after=after, continuous=continuity),
                      listenerClosed=server.socket.fileno() == -1,
                      success=(error is None and len(results) == 6 and len(server_records) == 6 and captured is not None
                               and captured['passed'] and (health is None or continuity is True)),
                      error=error, modelFits=0)
        save(root / 'task.json', result)
        if health:
            ledger_append(health[0], dict(kind='benign', activityId=result['activityId'], plannedRole=result['plannedRole'],
                                          batch=profile['batch'], endedAt=time.time(), success=result['success']))
    if not result['success']:
        raise RuntimeError('正常任务/采集失败: ' + str(error))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--runtime-plan', type=Path, required=True)
    p.add_argument('--prefit-report', type=Path, required=True)
    p.add_argument('--asset-id', required=True, help='已登记资产 UUID，跨采集活动复用')
    p.add_argument('--sensor-id', required=True, help='已登记传感器 UUID')
    p.add_argument('--authorization-id', required=True, help='本轮实际执行授权 ID')
    p.add_argument('--authorized-until', required=True, help='本轮授权截止 ISO-8601，覆盖整个 P3-B 收口期间')
    p.add_argument('--health-observer', type=Path, required=True,
                   help='已运行的 capture_health_observer 输出目录；须与攻击活动共用同一会话')
    p.add_argument('--role', required=True, choices=ROLE_ORDER, help='本次只执行该角色的良性批次')
    p.add_argument('--batches', nargs='+', type=int,
                   help='显式选择本次会话预登记的批次；省略时执行该角色的全部批次')
    args = p.parse_args()
    selected = [profile for profile in profiles() if profile['plannedRole'] == args.role]
    if args.batches is not None:
        if len(set(args.batches))!=len(args.batches) or set(args.batches)-{p['batch'] for p in selected}:
            raise ValueError('批次重复或不属于登记角色')
        selected = [profile for profile in selected if profile['batch'] in set(args.batches)]
    if not selected: raise ValueError('未选择任何已登记良性批次')
    uuid.UUID(args.asset_id); uuid.UUID(args.sensor_id)
    collection_gate(args.runtime_plan, args.prefit_report)
    if sys.platform != 'win32': raise RuntimeError('仅登记Windows回环环境')
    start = time.time(); deadline = datetime.fromisoformat(args.authorized_until).timestamp()
    if not start < deadline <= start + 48 * 3600: raise ValueError('授权截止须覆盖整个 P3-B 收口期间（最多 48 小时）')
    health = (args.health_observer, args.asset_id, args.sensor_id)
    observer = require_live(*health)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    save(args.output / 'registration.json', dict(version='p3-cde-benign-v3', assetId=args.asset_id, sensorId=args.sensor_id,
         authorizationId=args.authorization_id, healthObserver=observer,
         local='127.0.0.1', peer='127.0.0.2', servicePort=80,
         captureInterface='\\Device\\NPF_Loopback', maxConcurrent=4,
         authorizedUntil=args.authorized_until, maximumActiveSeconds=MAXIMUM_ACTIVE_SECONDS,
         isolationSeconds=ISOLATION_SECONDS, interActivitySeconds=INTER_ACTIVITY_SECONDS, role=args.role, profiles=selected,
         sourceDomainCount=1, firewallChanges=False, scriptSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    ledger_check(args.health_observer, args.role, 0)
    wait = ledger_ready_at(args.health_observer, INTER_ACTIVITY_SECONDS) - time.time()
    if wait > 0:
        if time.time() + wait + 85 >= deadline: raise TimeoutError('等待组间隔后授权不足')
        time.sleep(wait)
    results = []; active = 0.0
    for i, profile in enumerate(selected):
        if active + 85 > MAXIMUM_ACTIVE_SECONDS: raise TimeoutError('良性活动总时长预算不足')
        result = run_batch(args.output / f'batch-{profile["batch"]:02}', profile, deadline, health)
        active += result['elapsedSeconds']
        results.append({k:result[k] for k in ('activityId','batch','plannedRole','success')})
        print(json.dumps({k: result[k] for k in ('batch', 'success', 'elapsedSeconds', 'listenerClosed')}), flush=True)
        if i < len(selected) - 1:
            if time.time() + INTER_ACTIVITY_SECONDS + 85 >= deadline: raise TimeoutError('整轮授权预算不足')
            time.sleep(INTER_ACTIVITY_SECONDS)
    save(args.output / 'complete.json', dict(status='completed', role=args.role, batches=len(selected), results=results,
         elapsedSeconds=time.time() - start, listenerReleased=True, modelFits=0))


if __name__ == '__main__':
    main()
