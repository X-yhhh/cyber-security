#!/usr/bin/env python3
"""独立连续采集健康观察器：跨活动持续输出 host-guard-capture-health/1.0.0 哈希链。

观察器是与采集脚本分离的长进程，在整轮攻击/困难良性活动及其间隔内持续运行；
每条记录覆盖不超过 5 秒，计数取自同一 Npcap 回环过滤器的 pcap_stats。区间端点
由会话起点墙钟加单调时钟推进，clockSkewMs 记录墙钟相对单调时钟的漂移（只能
发现跳变，不证明绝对时间正确）。统计不可读、排空线程故障或调度迟到都写成
captureGap/未知计数，不补造健康。观察器不发包、不改防火墙，到授权截止或收到
停止文件即退出，并写出供冻结器绑定的健康登记；targetBindings 由冻结阶段填写。
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid

from capture_health import COUNTERS, IDENTITY, VERSION, HealthChain, content_hash, stamp

WINDOW_MS = 4900
MAX_INTERVAL_MS = 5000
MAX_LIVE_DELAY_MS = 10000
MAX_SESSION_SECONDS = 4 * 3600
FILTER = 'ip and tcp and host 127.0.0.1 and host 127.0.0.2 and port 80'
INTERFACE = r'\Device\NPF_Loopback'
RECORDS = 'health-records.jsonl'
BINDING = 'observer-binding.json'
REGISTRY = 'health-registry.json'
STOP = 'STOP'


def iso(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())


class HealthObserver:
    """把计数快照转成连续哈希链；时钟和计数源可注入，便于无 Npcap 的确定性测试。"""

    def __init__(self, output, identity, config, build_sha256, stats, *, monotonic=time.monotonic, wall=time.time):
        self.output, self.stats = Path(output), stats
        self.monotonic, self.wall = monotonic, wall
        self.identity = {k: identity[k] for k in IDENTITY}
        self.config_sha256 = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.build_sha256 = build_sha256
        self.binding = dict(self.identity, configSha256=self.config_sha256, buildSha256=build_sha256)
        self.sequence, self.previous = 0, None
        self.mono0, self.wall0 = monotonic(), wall()
        self.last_end_ms = self.wall0 * 1000
        self.last_counters = self._read()

    def _now_ms(self):
        return (self.wall0 + self.monotonic() - self.mono0) * 1000

    def _read(self):
        """返回三项累计计数；任何读取失败都记为 null，校验器据此判定未知。"""
        try:
            values = self.stats()
        except Exception:
            values = None
        if not isinstance(values, dict) or set(values) != set(COUNTERS):
            return {k: None for k in COUNTERS}
        return {k: v if type(v) is int and v >= 0 else None for k, v in values.items()}

    def _emit(self, start, end, counters, gap):
        payload = dict(self.binding, healthVersion=VERSION, healthWindowId=f"{self.identity['observerSessionId']}:{self.sequence}",
                       sequence=self.sequence, intervalStart=iso(start), intervalEnd=iso(end),
                       previousSha256=self.previous, counterStart=self.last_counters, counterEnd=counters,
                       captureGap=bool(gap), clockSkewMs=round(self.wall() * 1000 - self._now_ms()))
        digest = content_hash(payload)
        with (self.output / RECORDS).open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\n')
            stream.flush(); os.fsync(stream.fileno())
        self.sequence += 1
        self.previous, self.last_end_ms, self.last_counters = digest, end, counters
        return payload

    def tick(self, fault=False):
        """输出 [上次终点, 现在]；调度迟到时按 5 秒切片全部标记缺口，不把未观察时段算健康。"""
        now = self._now_ms()
        if now <= self.last_end_ms:
            return []
        counters = self._read()
        late = now - self.last_end_ms > MAX_INTERVAL_MS
        emitted = []
        while now - self.last_end_ms > MAX_INTERVAL_MS:
            emitted.append(self._emit(self.last_end_ms, self.last_end_ms + MAX_INTERVAL_MS, counters, True))
        if now > self.last_end_ms:
            emitted.append(self._emit(self.last_end_ms, now, counters, late or fault))
        return emitted

    def run(self, until, stop_event, fault=lambda: False):
        while not stop_event.is_set() and self.wall() < until and not (self.output / STOP).exists():
            deadline = self.monotonic() + WINDOW_MS / 1000
            while self.monotonic() < deadline and not stop_event.is_set():
                time.sleep(min(.05, max(0, deadline - self.monotonic())))
            self.tick(fault())


def open_session(output, *, asset_id, sensor_id, authorization_id, authorized_until, stats, config, build_sha256,
                 monotonic=time.monotonic, wall=time.time):
    """独占创建输出目录并先落盘可信绑定，再产生任何健康记录。"""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    identity = dict(assetId=asset_id, sensorId=sensor_id, captureScopeId=str(uuid.uuid4()),
                    observerSessionId=str(uuid.uuid4()))
    observer = HealthObserver(output, identity, config, build_sha256, stats, monotonic=monotonic, wall=wall)
    save(output / BINDING, dict(version='p3-capture-health-binding-v1', healthVersion=VERSION,
         binding=observer.binding, config=config, authorizationId=authorization_id,
         authorizedUntil=authorized_until, startedAt=iso(observer.last_end_ms)))
    return observer


def finalize(output, stop_reason):
    """写健康登记；authenticatedCollectionRef 绑定授权与观察器绑定文件哈希。"""
    output = Path(output)
    binding = json.loads((output / BINDING).read_text(encoding='utf-8'))
    records = (output / RECORDS).read_text(encoding='utf-8').splitlines() if (output / RECORDS).exists() else []
    save(output / REGISTRY, dict(version='p3-capture-health-registry-v1', healthVersion=VERSION,
         recordsFile=RECORDS, recordsSha256=file_sha(output / RECORDS) if records else None, records=len(records),
         observerBindings=[binding['binding']], targetBindings={},
         authenticatedCollectionRef=binding['authorizationId'] + ':' + file_sha(output / BINDING),
         bindingSha256=file_sha(output / BINDING), stopReason=stop_reason,
         stoppedAt=datetime.now(timezone.utc).isoformat(), modelFits=0))


def require_live(output, asset_id, sensor_id, now_ms=None):
    """采集脚本在每个活动前后调用：链必须完整、身份一致、最新记录健康且实时。

    返回当前连续健康段起点；活动前后的起点不同说明活动期间健康中断。
    """
    output = Path(output)
    binding = json.loads((output / BINDING).read_text(encoding='utf-8'))['binding']
    if (binding['assetId'], binding['sensorId']) != (asset_id, sensor_id):
        raise ValueError('健康观察器资产/传感器身份不符')
    chain = HealthChain([binding]); state = None
    for line in (output / RECORDS).read_text(encoding='utf-8').splitlines():
        state = chain.accept(json.loads(line))
    if state is None:
        raise ValueError('健康观察器尚无记录')
    now_ms = time.time() * 1000 if now_ms is None else now_ms
    if state['reason'] is not None or state['since'] is None:
        raise ValueError('健康观察器最新区间不健康: ' + str(state['reason']))
    if not 0 <= now_ms - state['end'] <= MAX_LIVE_DELAY_MS:
        raise ValueError('健康观察器记录不实时')
    return dict(observerSessionId=binding['observerSessionId'], captureScopeId=binding['captureScopeId'],
                healthySinceMs=state['since'], throughMs=state['end'], sequence=state['sequence'],
                sha256=state['sha256'])


LEDGER = 'activity-ledger.jsonl'
ROLE_ORDER = ('train', 'validation_selection', 'validation_calibration', 'independent_development')


def ledger_entries(output):
    path = Path(output) / LEDGER
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()] if path.exists() else []


def ledger_check(output, role, gap_seconds, now=None):
    """同一观察会话共享稳定目标：角色只能按时间前进，且距上一活动结束至少 gap_seconds。

    攻击与良性脚本共用该账本，防止交错角色破坏连续预算的角色访问顺序。
    """
    if role not in ROLE_ORDER: raise ValueError('未知角色: ' + str(role))
    entries = ledger_entries(output)
    now = time.time() if now is None else now
    if entries:
        if ROLE_ORDER.index(role) < max(ROLE_ORDER.index(e['plannedRole']) for e in entries):
            raise ValueError('角色顺序倒退：同一稳定目标须按 train→选型→校准→独立开发采集')
        wait = max(e['endedAt'] for e in entries) + gap_seconds - now
        if wait > 0: raise ValueError(f'距上一活动结束不足 {gap_seconds} 秒，还需 {wait:.0f} 秒')
    return entries


def ledger_ready_at(output, gap_seconds):
    """返回共享账本允许下一活动开始的最早时刻；空账本返回 0。"""
    entries = ledger_entries(output)
    return max(e['endedAt'] for e in entries) + gap_seconds if entries else 0.0


def ledger_append(output, entry):
    with (Path(output) / LEDGER).open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(entry, sort_keys=True) + '\n'); stream.flush(); os.fsync(stream.fileno())


class NpcapStats:
    """独立 Npcap 句柄：同一回环过滤器，排空并丢弃报文，只读取累计统计。"""

    def __init__(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'p2/data_readiness'))
        from benign_loopback import Capture, Header, Stats
        import ctypes as c
        observer = self

        class Drain(Capture):
            def run(self):
                hp, data = c.POINTER(Header)(), c.POINTER(c.c_ubyte)()
                try:
                    while not self.stop.is_set():
                        result = self.lib.pcap_next_ex(self.handle, c.byref(hp), c.byref(data))
                        if result == 0: time.sleep(.002); continue
                        if result != 1: raise RuntimeError('健康观察器读取失败')
                        if hp.contents.caplen != hp.contents.length: raise ValueError('健康观察器捕获截短')
                        self.frames += 1
                except BaseException as exc:
                    self.error = type(exc).__name__
                    observer.fault = True

        self.c, self.Stats, self.fault = c, Stats, False
        self.handle = Drain(Path('.'))
        self.handle.thread.start()

    def __call__(self):
        stats = self.Stats()
        if self.fault or self.handle.lib.pcap_stats(self.handle.handle, self.c.byref(stats)) != 0:
            raise RuntimeError('pcap_stats 不可用')
        return dict(packetsSeen=stats.received, kernelDrops=stats.dropped, capacityDrops=stats.interfaceDropped)

    def close(self):
        self.handle.stop.set(); self.handle.thread.join(5)
        if self.handle.thread.is_alive(): raise RuntimeError('健康观察器排空线程未停止')
        self.handle.lib.pcap_close(self.handle.handle); self.handle.dll_dir.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--asset-id', required=True)
    p.add_argument('--sensor-id', required=True)
    p.add_argument('--authorization-id', required=True)
    p.add_argument('--authorized-until', required=True)
    args = p.parse_args()
    uuid.UUID(args.asset_id); uuid.UUID(args.sensor_id)
    until = datetime.fromisoformat(args.authorized_until).timestamp()
    if not time.time() < until <= time.time() + MAX_SESSION_SECONDS:
        raise ValueError('健康观察授权须在未来 4 小时内截止')
    if sys.platform != 'win32':
        raise RuntimeError('仅登记 Windows 回环环境')
    stats = NpcapStats()
    config = dict(interface=INTERFACE, filter=FILTER, windowMs=WINDOW_MS, maxIntervalMs=MAX_INTERVAL_MS,
                  counters=dict(packetsSeen='pcap_stat.ps_recv', kernelDrops='pcap_stat.ps_drop',
                                capacityDrops='pcap_stat.ps_ifdrop'),
                  clockSkew='wall_minus_session_monotonic_ms')
    reason = 'authorization_expired'
    try:
        observer = open_session(args.output, asset_id=args.asset_id, sensor_id=args.sensor_id,
                                authorization_id=args.authorization_id, authorized_until=args.authorized_until,
                                stats=stats, config=config, build_sha256=file_sha(__file__))
        stop = threading.Event()
        print(json.dumps(dict(status='observing', **observer.identity)), flush=True)
        try:
            observer.run(until, stop, lambda: stats.fault)
        except KeyboardInterrupt:
            reason = 'interrupted'
        if (args.output / STOP).exists(): reason = 'stop_file'
        observer.tick(stats.fault)
    finally:
        stats.close()
        if (args.output / BINDING).exists(): finalize(args.output, reason)
    print(json.dumps(dict(status='stopped', reason=reason)), flush=True)


if __name__ == '__main__':
    main()
