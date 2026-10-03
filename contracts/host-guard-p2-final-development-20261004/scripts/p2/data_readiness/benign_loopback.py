#!/usr/bin/env python3
"""在明确授权的 win-dev 回环 TCP/80 上执行有界正常业务并记录连接真值。

只绑定 127.0.0.1:80，客户端只绑定 127.0.0.2；最多四路并发。Npcap
只捕获这两个地址之间的 TCP/80。未获得独占监听或捕获丢包时拒绝验收。
不修改防火墙/系统策略；退出时关闭监听和捕获。总时限为 30 分钟。
"""
import argparse
import concurrent.futures
import ctypes as c
import datetime as dt
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import random
import socket
import struct
import threading
import time
import urllib.parse
import uuid


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def save(path, value):
    with path.open('x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')


class Header(c.Structure):
    _fields_ = [('sec', c.c_long), ('usec', c.c_long), ('caplen', c.c_uint), ('length', c.c_uint)]


class BPF(c.Structure):
    _fields_ = [('length', c.c_uint), ('insns', c.c_void_p)]


class Stats(c.Structure):
    _fields_ = [(name, c.c_uint) for name in ('received', 'dropped', 'interfaceDropped', 'captured', 'sent', 'networkDropped')]


class Capture:
    """保存 Npcap 原件；DLT_NULL 仅去掉可验证的 AF_INET 头，另存 RAW 副本。"""
    def __init__(self, root):
        self.root = root
        self.stop = threading.Event()
        self.error = None
        self.frames = 0
        dll = Path(os.environ['WINDIR']) / 'System32' / 'Npcap'
        self.dll_dir = os.add_dll_directory(str(dll))
        self.lib = lib = c.CDLL(str(dll / 'wpcap.dll'))
        lib.pcap_open_live.argtypes = [c.c_char_p, c.c_int, c.c_int, c.c_int, c.c_char_p]
        lib.pcap_open_live.restype = c.c_void_p
        lib.pcap_compile.argtypes = [c.c_void_p, c.POINTER(BPF), c.c_char_p, c.c_int, c.c_uint]
        lib.pcap_setfilter.argtypes = [c.c_void_p, c.POINTER(BPF)]
        lib.pcap_freecode.argtypes = [c.POINTER(BPF)]
        lib.pcap_setnonblock.argtypes = [c.c_void_p, c.c_int, c.c_char_p]
        lib.pcap_datalink.argtypes = [c.c_void_p]
        lib.pcap_next_ex.argtypes = [c.c_void_p, c.POINTER(c.POINTER(Header)), c.POINTER(c.POINTER(c.c_ubyte))]
        lib.pcap_close.argtypes = [c.c_void_p]
        lib.pcap_stats.argtypes = [c.c_void_p, c.POINTER(Stats)]
        err = c.create_string_buffer(256)
        self.handle = lib.pcap_open_live(b'\\Device\\NPF_Loopback', 65535, 0, 50, err)
        if not self.handle:
            raise RuntimeError('Npcap 回环接口不可用')
        try:
            self.link = lib.pcap_datalink(self.handle)
            if self.link not in (0, 12, 101):
                raise ValueError('未知回环链路类型')
            code = BPF()
            expression = b'ip and tcp and host 127.0.0.1 and host 127.0.0.2 and port 80'
            if lib.pcap_compile(self.handle, c.byref(code), expression, 1, 0xffffffff):
                raise RuntimeError('捕获过滤器编译失败')
            try:
                if lib.pcap_setfilter(self.handle, c.byref(code)):
                    raise RuntimeError('捕获过滤器设置失败')
            finally:
                lib.pcap_freecode(c.byref(code))
            if lib.pcap_setnonblock(self.handle, 1, err):
                raise RuntimeError('不能启用非阻塞捕获')
        except BaseException:
            lib.pcap_close(self.handle)
            self.dll_dir.close()
            raise
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            with (self.root / 'native.pcap').open('xb') as native, (self.root / 'raw.pcap').open('xb') as raw:
                native.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.link))
                raw.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
                hp, data = c.POINTER(Header)(), c.POINTER(c.c_ubyte)()
                while not self.stop.is_set():
                    result = self.lib.pcap_next_ex(self.handle, c.byref(hp), c.byref(data))
                    if result == 0:
                        time.sleep(.002)
                        continue
                    if result != 1:
                        raise RuntimeError('捕获读取失败')
                    h = hp.contents
                    if h.caplen != h.length or h.caplen > 65535:
                        raise ValueError('捕获被截断')
                    frame = c.string_at(data, h.caplen)
                    native.write(struct.pack('<IIII', h.sec, h.usec, len(frame), h.length) + frame)
                    if self.link == 0:
                        if frame[:4] != struct.pack('<I', 2):
                            raise ValueError('DLT_NULL 不是 AF_INET')
                        frame = frame[4:]
                    if not frame or frame[0] >> 4 != 4:
                        raise ValueError('不是 IPv4')
                    raw.write(struct.pack('<IIII', h.sec, h.usec, len(frame), len(frame)) + frame)
                    self.frames += 1
                for f in (native, raw):
                    f.flush()
                    os.fsync(f.fileno())
        except BaseException as exc:
            self.error = type(exc).__name__ + ': ' + str(exc)

    def close(self):
        self.stop.set()
        self.thread.join(5)
        if self.thread.is_alive():
            raise RuntimeError('捕获线程未停止')
        stats = Stats()
        valid = self.lib.pcap_stats(self.handle, c.byref(stats)) == 0
        self.lib.pcap_close(self.handle)
        self.dll_dir.close()
        report = dict(frames=self.frames, nativeLink=self.link, normalizedLink=101,
                      conversion='DLT_NULL AF_INET header removed only; IP bytes/timestamps preserved' if self.link == 0 else 'unchanged IP bytes',
                      error=self.error, stats={k: getattr(stats, k) for k, _ in Stats._fields_} if valid else None)
        report['passed'] = valid and not self.error and self.frames > 0 and stats.dropped == stats.interfaceDropped == stats.networkDropped == 0
        save(self.root / 'capture.json', report)
        return report


class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = True

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, *args):
        pass

    def do_GET(self):
        try:
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            size = int(q['size'][0])
            seed = int(q['seed'][0])
            delay = float(q.get('delay', ['0.002'])[0])
            if not 512 <= size <= 196608 or not .001 <= delay <= .03:
                raise ValueError('任务参数超限')
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if q.get('retry') == ['1']:
                self.send_response(503)
                self.send_header('Content-Length', '0')
                self.send_header('Retry-After', '0')
                self.end_headers()
                return
            body = random.Random(seed).randbytes(size)
            start = 0
            if self.headers.get('Range'):
                value = self.headers['Range']
                if not value.startswith('bytes=') or not value.endswith('-'):
                    raise ValueError('非法 Range')
                start = int(value[6:-1])
                if not 0 < start < size:
                    raise ValueError('Range 超限')
            self.send_response(206 if start else 200)
            self.send_header('Content-Length', str(size - start))
            if start:
                self.send_header('Content-Range', f'bytes {start}-{size-1}/{size}')
            self.end_headers()
            for at in range(start, size, 800):
                self.wfile.write(body[at:at + 800])
                self.wfile.flush()
                time.sleep(delay)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # 登记的主动中断任务允许客户端提前结束。


def run_session(root, role, ordinal, deadline, scale):
    """每批是独立业务会话组；连接记录含临时端点，仅保存于忽略目录。"""
    root.mkdir()
    capture = Capture(root)
    capture.thread.start()
    began = utc()
    rows = []
    lock = threading.Lock()
    rng = random.Random(2026100400 + ordinal)
    tasks = []
    for kind in ('normal_download', 'normal_concurrency', 'slow_download', 'legitimate_retry', 'range_resume'):
        for i in range(scale):
            tasks.append((kind, rng.randrange(10000, 10**8), rng.randrange(8192, 32768)))
    def task(entry):
        kind, seed, size = entry
        if kind == 'slow_download':
            size *= 4
        expected = random.Random(seed).randbytes(size)
        task_id = str(uuid.uuid4())
        def request(retry=False, start=0, abort=False):
            if time.monotonic() > deadline:
                raise TimeoutError('授权时限到期')
            record = dict(taskId=task_id, kind=kind, startedUtc=utc(), role=role,
                          expectedIntent='authorized_benign', taskSeed=seed, fixtureBytes=size)
            conn = http.client.HTTPConnection('127.0.0.1', 80, timeout=12, source_address=('127.0.0.2', 0))
            body = b''
            try:
                conn.connect()
                record['peer'] = list(conn.sock.getsockname())
                record['server'] = ['127.0.0.1', 80]
                delay = .014 if kind == 'slow_download' else .002 + (seed % 5) * .001
                path = f'/fixture?size={size}&seed={seed}&delay={delay}&retry={int(retry)}'
                conn.request('GET', path, headers={'Range': f'bytes={start}-'} if start else {})
                response = conn.getresponse()
                body = response.read(size // 4 if abort else size + 1)
                record.update(status=response.status, bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), intentionalAbort=abort)
                record['passed'] = ((response.status == 503 and not body) if retry else
                                    response.status == (206 if start else 200) and body == expected[start:start + len(body)] and
                                    len(body) == (size // 4 if abort else size - start))
            except (OSError, http.client.HTTPException) as exc:
                record.update(passed=False, error=type(exc).__name__)
            finally:
                conn.close()
                record['endedUtc'] = utc()
                with lock:
                    rows.append(record)
                    with (root / 'connections.jsonl').open('a', encoding='utf-8') as f:
                        f.write(json.dumps(record) + '\n')
            return body
        if kind == 'legitimate_retry':
            request(retry=True)
            time.sleep(.03)
            request()
        elif kind == 'range_resume':
            part = request(abort=True)
            time.sleep(.04)
            request(start=len(part))
        else:
            request()
    try:
        time.sleep(.25)
        for kind in ('normal_download', 'normal_concurrency', 'slow_download', 'legitimate_retry', 'range_resume'):
            subset = [t for t in tasks if t[0] == kind]
            with concurrent.futures.ThreadPoolExecutor(max_workers=1 if kind == 'normal_download' else 4) as pool:
                list(pool.map(task, subset))
        time.sleep(.5)
    finally:
        report = capture.close()
    result = dict(version='p2-controlled-loopback-session-v1', role=role, ordinal=ordinal,
                  activityId=str(uuid.uuid4()), beganUtc=began, endedUtc=utc(),
                  connections=len(rows), tasks=len(tasks), kinds=sorted({r['kind'] for r in rows}),
                  taskFailures=sum(not r['passed'] for r in rows), capturePassed=report['passed'],
                  evidenceTier='controlled_task', scope='win-dev loopback TCP/80; not physical NIC or production host validation',
                  passed=report['passed'] and bool(rows) and all(r['passed'] for r in rows))
    save(root / 'session.json', result)
    print(json.dumps({k: result[k] for k in ('ordinal', 'role', 'connections', 'taskFailures', 'passed')}), flush=True)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--smoke', action='store_true')
    a = p.parse_args()
    if os.name != 'nt' or a.output.exists():
        raise ValueError('要求 Windows 和不存在的输出目录')
    a.output.mkdir(parents=True)
    begin = time.monotonic()
    deadline = begin + 1740
    server = Server(('127.0.0.1', 80), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sessions = []
    roles = ['diagnostic_smoke'] if a.smoke else ['train', 'validation_selection', 'validation_calibration'] * 2
    timer = threading.Timer(1770, server.shutdown)
    timer.daemon = True
    timer.start()
    try:
        for i, role in enumerate(roles):
            if time.monotonic() > deadline - 120:
                raise TimeoutError('剩余授权时间不足')
            result = run_session(a.output / f'session-{i:02d}', role, i, deadline, 2 if a.smoke else 24)
            sessions.append(result)
            if not result['passed']:
                raise RuntimeError('业务或捕获未通过，保留失败并停止')
            if i + 1 < len(roles):
                print(json.dumps({'event': 'context_isolation', 'seconds': 155}), flush=True)
                time.sleep(155)
    finally:
        timer.cancel()
        server.shutdown()
        server.server_close()
        thread.join(5)
        save(a.output / 'run.json', dict(version='p2-controlled-loopback-run-v1', sessions=sessions,
             elapsedSeconds=round(time.monotonic() - begin, 3), listenerClosed=server.fileno() == -1,
             firewallModified=False, systemPolicyModified=False,
             passed=len(sessions) == len(roles) and all(s['passed'] for s in sessions)))


if __name__ == '__main__':
    main()
