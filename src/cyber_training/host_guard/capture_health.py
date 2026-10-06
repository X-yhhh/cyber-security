"""独立健康旁证的受限 JCS 哈希链验证；未知计数、断链和身份漂移不能恢复额度。

本模块只验证外部可信采集登记所绑定的原始记录，不把文件哈希当来源认证。
研究回放使用离线旁证；实际机器认证与 OS 规则核对由 P4/P5 实现。
"""
from datetime import datetime
import hashlib
import json
import math

VERSION = 'host-guard-capture-health/1.0.0'
COUNTERS = ('packetsSeen', 'kernelDrops', 'capacityDrops')
IDENTITY = ('assetId', 'sensorId', 'captureScopeId', 'observerSessionId')


def stamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('健康时刻缺少时区')
    return parsed.timestamp() * 1000


def content_hash(payload):
    """协议限 ASCII 字段名和安全整数；该子集的紧凑 UTF-8 JSON 等价于 JCS。

    浮点、非 ASCII 扩展字段名和超出 IEEE754 精确整数范围的数一律拒绝，
    避免跨语言序列化差异。摘要不写回 payload，防止自引用。
    """
    def check(value):
        if isinstance(value, dict):
            if any(not isinstance(k, str) or not k.isascii() for k in value):
                raise ValueError('健康字段名不是协议 ASCII')
            for item in value.values(): check(item)
        elif isinstance(value, list):
            for item in value: check(item)
        elif type(value) is int:
            if abs(value) > 2**53 - 1: raise ValueError('健康整数越界')
        elif value is not None and not isinstance(value, (str, bool)):
            raise ValueError('健康协议只允许安全整数与字符串，不接受浮点')
    check(payload)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                                     allow_nan=False).encode('utf-8')).hexdigest()


class HealthChain:
    """可信绑定由运行计划注入；调用方不可从待验证文件自身推导可信身份。

    顺序接收健康记录，proof 只覆盖已经接收的完整区间。时序或计数异常会
    中断健康段；重复 sequence 的相同内容幂等，不同内容拒绝整个来源。
    """
    def __init__(self, trusted_bindings):
        self.trusted = {tuple(b[k] for k in IDENTITY): b for b in trusted_bindings}
        self.states = {}
        self.seen = {}

    def accept(self, payload, received_at=None):
        required = set(IDENTITY) | {'healthVersion', 'healthWindowId', 'sequence', 'intervalStart',
            'intervalEnd', 'previousSha256', 'counterStart', 'counterEnd', 'captureGap',
            'clockSkewMs', 'configSha256', 'buildSha256'}
        if not required <= payload.keys() or payload['healthVersion'] != VERSION:
            raise ValueError('健康记录结构或版本不符')
        key = tuple(payload[k] for k in IDENTITY)
        digest = content_hash(payload)
        seq = payload['sequence']
        if type(seq) is not int or seq < 0: raise ValueError('健康序号无效')
        previous_digest = self.seen.get((key, seq))
        if previous_digest is not None:
            if previous_digest != digest: raise ValueError('健康重复序号内容冲突')
            return self.states[key]
        start, end = stamp(payload['intervalStart']), stamp(payload['intervalEnd'])
        if not math.isfinite(start) or not 0 < end - start <= 5000.001:
            raise ValueError('健康区间必须在 0 到 5 秒内')
        old = self.states.get(key)
        if (old is None and (seq != 0 or payload['previousSha256'] is not None)) or (
                old is not None and (seq != old['sequence'] + 1 or payload['previousSha256'] != old['sha256'])):
            raise ValueError('健康链序号或前序哈希不连续')
        binding = self.trusted.get(key)
        reason = None
        if not binding or binding.get('configSha256') != payload['configSha256'] or binding.get('buildSha256') != payload['buildSha256']:
            reason = 'UNTRUSTED_OBSERVER'
        for counter in ('counterStart', 'counterEnd'):
            if set(payload[counter]) != set(COUNTERS): raise ValueError('健康计数结构不符')
            if any(type(v) is not int or v < 0 for v in payload[counter].values()):
                reason = reason or 'UNKNOWN_COUNTER'
        if reason != 'UNKNOWN_COUNTER' and all(type(v) is int for c in ('counterStart', 'counterEnd') for v in payload[c].values()):
            if any(payload['counterEnd'][k] < payload['counterStart'][k] for k in COUNTERS):
                reason = reason or 'COUNTER_ROLLBACK'
            if any(payload['counterEnd'][k] != payload['counterStart'][k] for k in ('kernelDrops', 'capacityDrops')):
                reason = reason or 'CAPTURE_DROPS'
        if payload['captureGap'] is not False: reason = reason or 'CAPTURE_GAP'
        if type(payload['clockSkewMs']) is not int or abs(payload['clockSkewMs']) > 1000:
            reason = reason or 'CLOCK_UNTRUSTED'
        if received_at is not None and not 0 <= received_at - end <= 10000:
            reason = reason or 'HEALTH_RECEIVE_DELAY'
        contiguous = old is not None and abs(old['end'] - start) <= .001 and old['counterEnd'] == payload['counterStart']
        if old is not None and not contiguous: reason = reason or 'INTERVAL_OR_COUNTER_GAP'
        since = (old['since'] if old and contiguous and old['since'] is not None else start) if reason is None else None
        state = dict(sequence=seq, sha256=digest, start=start, end=end, since=since,
                     counterEnd=payload['counterEnd'], reason=reason)
        self.states[key] = state
        self.seen[(key, seq)] = digest
        return state

    def proof(self, identity, since, at):
        """仅已验证链完整覆盖请求区间才给出摘要；未来窗口不能证明当前健康。"""
        state = self.states.get(tuple(identity[k] for k in IDENTITY))
        if state and state['since'] is not None and state['since'] <= since <= at <= state['end']:
            return dict(sinceMs=state['since'], throughMs=at, sha256=state['sha256'])
        return None
