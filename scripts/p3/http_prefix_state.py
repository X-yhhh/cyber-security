"""来源限定的标签旁路；有界 TCP 重组与因果 HTTP 状态，不是现场攻击签名。

只有发布活动/原件/端点/SYN epoch 与标签关联另行通过后，行为证据才可用于
研究正例。合法分段请求也可产生相同结构，绝不能单凭结构把未知流标攻击。
"""
from collections import Counter
import re

# RFC 9110 method=token。扩展方法（如来源中的 FAKEVERB）不表示正常或攻击，
# 仅允许解析其消息边界；标签仍须有发布来源和逐连接行为的独立绑定。
REQUEST_LINE = re.compile(rb"([!#$%&'*+\-.^_`|~0-9A-Za-z]+) [^ \r\n]+ HTTP/1\.[01]\r\n")


class CausalHTTP:
    """首请求最多 32KiB，乱序最多 8KiB；保留已生成证据，未来坏包不反写过去。

    慢读取需要响应/窗口的独立规则，本状态机只报告未资格化，不猜测其起点。
    body 仅支持无歧义 Content-Length；分块编码先显式保持 Unknown。
    """
    def __init__(self, mode='auto', max_bytes=32768, reorder_bytes=8192):
        self.mode = mode
        self.limit, self.reorder_limit = max_bytes, reorder_bytes
        self.base = None
        self.request = bytearray()
        self.pending = {}
        self.invalid = None
        self.onset = None
        self.complete = None
        self.first_payload = None
        self.header_ready = None
        self.continuations = 0
        self.payload_shapes = Counter()
        self.evidence = []
        self.detected_mode = None
        self.body_length = None
        self.header_end = None
        self.last_ts = None

    def add(self, packet, payload):
        ts = packet['ts']
        if self.invalid:
            return
        if self.last_ts is not None and ts < self.last_ts:
            self.invalid = 'timestamp_regression'; return
        self.last_ts = ts
        if packet.get('offloadSized', False):
            self.invalid = 'offload_sized_prefix'; return
        if packet['flags'] & 2 and not packet['flags'] & 16:
            if self.base is None:
                self.base = (packet['seq'] + 1) % 2**32
            elif self.base != (packet['seq'] + 1) % 2**32:
                self.invalid = 'different_syn_epoch'
            # SYN 的载荷属于 seq+1，不能让 fast-open 载荷静默丢失。
            if not payload:
                return
        if not payload:
            return
        if self.base is None or not packet['payloadFullyCaptured']:
            self.invalid = 'missing_syn_or_truncated_payload'; return
        start = (packet['seq'] + bool(packet['flags'] & 2) - self.base) % 2**32
        if start >= 2**31 or start + len(payload) > self.limit:
            self.invalid = 'review_bound'; return
        before = len(self.request)
        for off, value in enumerate(payload, start):
            old = self.request[off] if off < before else self.pending.get(off)
            if old is not None and old != value:
                self.invalid = 'conflicting_overlap'; return
            if off >= before:
                self.pending[off] = value
        if len(self.pending) > self.reorder_limit and start > before:
            self.invalid = 'reorder_bound'; return
        while len(self.request) in self.pending:
            self.request.append(self.pending.pop(len(self.request)))
        if len(self.request) == before:
            return  # ACK-only、全重传和缺口后的缓存不算进展。
        if self.first_payload is None:
            self.first_payload = ts
        novel = bytes(self.request[before:])
        shape = ('get_request' if novel.startswith(b'GET ') else 'post_request' if novel.startswith(b'POST ') else
                 'numeric_x_a' if re.fullmatch(rb'X-a: [0-9]+\r\n', novel) else
                 'literal_b_x_a' if novel == b'X-a: b\r\n' else 'other')
        self.payload_shapes[shape] += 1
        if self.complete is not None:
            return
        data = bytes(self.request)
        line = REQUEST_LINE.match(data)
        if line is None:
            return
        end = data.find(b'\r\n\r\n')
        if end < 0:
            if self.header_ready is None:
                self.header_ready = ts
            elif ts > self.header_ready and before >= line.end() and len(data) > before:
                # 判断整个已连续重组的头部结构，容纳跨包字段/多字段/任意值。
                self._record(ts, 'slow_header', before, len(data))
            return
        self.header_end = end + 4
        headers = data[line.end():end].split(b'\r\n')
        if any(h.lower().startswith(b'transfer-encoding:') for h in headers):
            self.invalid = 'chunked_body_rule_unqualified'; return
        lengths = [h.split(b':', 1)[1].strip() for h in headers if h.lower().startswith(b'content-length:')]
        if len(lengths) > 1 or lengths and not lengths[0].isdigit():
            self.invalid = 'ambiguous_content_length'; return
        self.body_length = int(lengths[0]) if lengths else 0
        if len(data) - self.header_end >= self.body_length:
            self.complete = ts
        elif self.header_ready is None or self.detected_mode == 'slow_header':
            self.header_ready = ts
        elif ts > self.header_ready and before >= self.header_end:
            self._record(ts, 'slow_body', before-self.header_end, len(data)-self.header_end)

    def _record(self, ts, mode, before, after):
        if self.mode not in ('auto', mode):
            return
        self.detected_mode = mode
        self.continuations += 1
        if self.onset is None:
            self.onset = ts
        self.evidence.append({'evidenceAvailableAtUs': ts, 'mode': mode,
                              'contiguousBytesBefore': before, 'contiguousBytesAfter': after,
                              'prefixQualityAsOf': 'continuous_complete_capture'})

    def snapshot(self):
        """调用方复制不可变时间点；后续完整关闭、截短或冲突只能影响后续资格。"""
        return {'evidence': [dict(e) for e in self.evidence], 'invalid': self.invalid,
                'pendingBytes': len(self.pending), 'completeAtUs': self.complete}
