"""P3-A 受控文件、标签和切分契约；不运行捕获内容，也不拟合模型。"""
import collections
import hashlib
import ipaddress
import json
import os
import math
from datetime import datetime, timezone
from pathlib import Path

PLAN = 'p3-multiclass-20261006-v1'
LABEL_VERSION = 'host-guard-label/2'
CLASS_VERSION = 'host-guard-class-map/1'
CLASSES = ('normal', 'port_scan', 'brute_force', 'dos_flood', 'dos_slow')
MAPPING = {
    'FTP-Patator': 'brute_force', 'SSH-Patator': 'brute_force',
    'DoS Slowloris': 'dos_slow', 'DoS Slowhttptest': 'dos_slow',
    'DoS Hulk': 'dos_flood', 'DoS GoldenEye': 'dos_flood', 'DDoS': 'dos_flood',
    'Portscan': 'port_scan', 'Infiltration - Portscan': 'port_scan',
}
SPLITS = ('train', 'validation', 'test')
FEATURES = frozenset(('elapsedMs bytesOutbound bytesInbound packetsOutbound packetsInbound '
    'lengthMin lengthMax lengthMean lengthStd iatMeanUs iatStdUs synCount synAckCount '
    'rstCount finCount handshakeSeen').split())
CONTEXT = frozenset(('windowSeconds coverageMs peerFlowStarts peerSynCount peerRstCount '
    'peerDistinctServicePorts hostFlowStarts hostDistinctPeers peerBytesOutbound peerBytesInbound').split())
NULLABLE = frozenset(('iatMeanUs iatStdUs synCount synAckCount rstCount finCount handshakeSeen').split())
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def micros(value):
    """CSV 时间明确解释为 UTC；避免浮点 Unix 时间损失首包微秒。"""
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    delta = stamp - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def digest(path, algorithms=('sha256',)):
    hashes = {name: hashlib.new(name) for name in algorithms}
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b''):
            for value in hashes.values():
                value.update(chunk)
    return {name: value.hexdigest() for name, value in hashes.items()}


def controlled_root(path):
    """产物只能落在忽略的缓存/制品目录；绝不覆盖已有冻结目录。"""
    path = Path(path).resolve()
    if not any(part in ('.cache', 'artifacts') for part in path.parts):
        raise ValueError('产物必须位于受控 .cache 或 artifacts 目录')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def create(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                     'w', encoding='utf-8')


def write_json(path, value):
    with create(path) as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write('\n')


def line(stream, value):
    stream.write(json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n')


def rows(path):
    with Path(path).open(encoding='utf-8') as stream:
        for value in stream:
            yield json.loads(value)


def internal(address):
    return ipaddress.ip_address(address) in ipaddress.ip_network('192.168.10.0/24')


def endpoint(value):
    address, port = value.rsplit(':', 1)
    return address.strip('[]'), int(port)


def tuple_key(protocol, first, second):
    return json.dumps([int(protocol), *sorted((list(first), list(second)))],
                      separators=(',', ':'))


def decide(matches, local, peer, excluded_window=False, reviewed_web=False):
    """按 label/2 六档判定；冲突 fail-closed，BENIGN 不证明外部来源正常。

    excluded_window 是不纳入攻击类型的整段主机隔离，优先于 normal 回退；
    已明确关联的纳入攻击仍按第一档处理，Attempted 只逐连接排除。
    """
    labels = {row['rawLabel'] for row in matches}
    if len(labels) > 1:
        return None, 'association_conflict', 'ambiguous'
    raw = next(iter(labels), None)
    if raw in MAPPING:
        return MAPPING[raw], None, 'publisher_documented'
    if raw and raw != 'BENIGN':
        return None, 'attempted' if 'Attempted' in raw else 'excluded_attack_type', 'ambiguous'
    if peer == '172.16.0.1':
        return None, 'unmatched_nat_source', 'ambiguous'
    if excluded_window:
        return None, 'excluded_host_time_window', 'ambiguous'
    if internal(local) and internal(peer):
        return 'normal', None, 'publisher_documented'
    if reviewed_web and raw == 'BENIGN' and not internal(local) and internal(peer):
        return 'normal', None, 'analyst_reviewed'
    return None, 'external_or_unassociated', 'ambiguous'


def normal_split(start, end=None):
    """UTC 每日十分钟块固定按 60/20/20 分配，不使用随机行切分。

    固定十块周期：六 train、二 validation、二 test；每个实际集合转换
    边界的前后 30 秒起始连接排除，块内部同集合边界不制造额外损失。
    """
    day_start = start // (86400 * 1000000) * (86400 * 1000000)
    block, offset = divmod(start - day_start, 600 * 1000000)
    cycle = ('train',) * 6 + ('validation',) * 2 + ('test',) * 2
    role = cycle[block % 10]
    if ((role != cycle[((block - 1) % 144) % 10] and offset <= 30 * 1000000) or
            (role != cycle[((block + 1) % 144) % 10] and offset >= 570 * 1000000)):
        return None
    if end is not None:
        # 长连接不能携带另一个集合的上下文；整个连接与保护区相交即排除。
        for boundary in range((start // 600000000 + 1) * 600000000,
                              end + 30000001, 600000000):
            before = cycle[(boundary // 600000000 - 1) % 144 % 10]
            after = cycle[(boundary // 600000000) % 144 % 10]
            if before != after and start <= boundary + 30000000 and end >= boundary - 30000000:
                return None
    return role


SPLIT_VERSION = 'host-guard-split/2'
RUN_GAP_US = 60 * 1000000
GUARD_US = 30 * 1000000
MIN_PER_SPLIT = 50
TARGET = {'train': .6, 'validation': .2, 'test': .2}


def runs(records):
    """按空闲间隔切运行段：下一连接起点晚于此前全部连接结束 60 秒以上即为新段。

    60 秒是 30 秒上下文窗口的两倍，段间任何 30 秒窗口都不会同时覆盖两段报文。
    """
    ordered = sorted(records, key=lambda row: (row['startUs'], row['physicalConnectionId']))
    result, horizon = [], None
    for row in ordered:
        if horizon is None or row['startUs'] - horizon > RUN_GAP_US:
            result.append([])
        result[-1].append(row)
        horizon = max(horizon or 0, row['endUs'])
    return result


def allocate_runs(segments):
    """整段分配：按规模从大到小交给当前缺口最大的集合，平局按 train/validation/test。"""
    total = sum(len(segment) for segment in segments)
    current = dict.fromkeys(SPLITS, 0)
    roles = {}
    for index in sorted(range(len(segments)), key=lambda i: (-len(segments[i]), segments[i][0]['startUs'])):
        role = max(SPLITS, key=lambda split: (TARGET[split] * total - current[split], -SPLITS.index(split)))
        roles[index] = role
        current[role] += len(segments[index])
    return roles, current


def time_bounds(segments):
    """把活跃时长（各段首末连接起点之间，去掉段间空闲）按 60/80% 映射回绝对时间。"""
    spans = [(segment[0]['startUs'], segment[-1]['startUs']) for segment in segments]
    active = sum(end - start for start, end in spans)
    bounds = []
    for fraction in (.6, .8):
        remaining = active * fraction
        for start, end in spans:
            if remaining <= end - start:
                bounds.append(start + int(remaining))
                break
            remaining -= end - start
    return bounds


def guarded_counts(starts, ends, first, second):
    """给定两条边界时三个集合保留的连接数；与任一边界保护区相交的完整连接不计。"""
    crossing = ((starts <= first + GUARD_US) & (ends >= first - GUARD_US)) | (
        (starts <= second + GUARD_US) & (ends >= second - GUARD_US))
    kept = ~crossing
    return (int((kept & (starts < first)).sum()),
            int((kept & (starts >= first) & (starts < second)).sum()),
            int((kept & (starts >= second)).sum()))


def search_bounds(records, segments, step_us=5 * 1000000):
    """在比例边界附近按 5 秒网格搜索边界，使保留连接最多。

    只用连接起止时间；约束 train ≥ 50%、validation 与 test 各 ≥ 15%（相对保留量）。
    长连接（如慢速 DoS）跨越比例边界时会被整条排除，固定比例点会吞掉整次突发。
    """
    import numpy as np
    starts = np.array([row['startUs'] for row in records], dtype=np.int64)
    ends = np.array([row['endUs'] for row in records], dtype=np.int64)
    first0, second0 = time_bounds(segments)
    low, high = int(starts.min()), int(starts.max())
    span = high - low
    grid = lambda centre, radius: range(max(low, centre - radius), min(high, centre + radius) + 1, step_us)
    best = None
    for first in grid(first0, int(span * .15)):
        for second in grid(second0, int(span * .1)):
            if second - first < 2 * GUARD_US:
                continue
            train, validation, test = guarded_counts(starts, ends, first, second)
            kept = train + validation + test
            if not kept or train < .5 * kept or validation < .15 * kept or test < .15 * kept:
                continue
            key = (kept, -abs(first - first0) - abs(second - second0))
            if best is None or key > best[0]:
                best = (key, [first, second])
    return best[1] if best else [first0, second0]


def scenario_split(records):
    """单个原始攻击场景的切分；返回连接映射与可审计说明。

    至少三段且整段分配后每个集合都有 50 条以上时整段分配，不在一次工具运行内部切开；
    否则在活跃时长 60/80% 附近搜索两条边界（见 search_bounds），完整连接与任一边界前后 30 秒相交即排除。
    """
    segments = runs(records)
    if len(segments) >= 3:
        roles, current = allocate_runs(segments)
        if min(current.values()) >= MIN_PER_SPLIT:
            mapping = {row['physicalConnectionId']: roles[index]
                       for index, segment in enumerate(segments) for row in segment}
            return mapping, {'method': 'whole_runs', 'runs': [
                {'startUs': segment[0]['startUs'], 'connections': len(segment), 'split': roles[index]}
                for index, segment in enumerate(segments)]}
    bounds = search_bounds(records, segments)
    mapping = {}
    for row in records:
        start, end = row['startUs'], row['endUs']
        mapping[row['physicalConnectionId']] = (
            None if any(start <= bound + GUARD_US and end >= bound - GUARD_US for bound in bounds)
            else 'train' if start < bounds[0] else 'validation' if start < bounds[1] else 'test')
    return mapping, {'method': 'active_time', 'runs': len(segments), 'boundsUs': bounds}


def assign_splits(items):
    """全部合格连接的切分：正常流量按十分钟块，攻击按 (日期, 原始场景) 分别切分。

    每个攻击场景在每个集合不足 50 条连接即失败，不静默接受缺失行为的验证集。
    """
    assignments, scenarios = {}, collections.defaultdict(list)
    for item in items:
        if item['label'] == 'normal':
            assignments[item['physicalConnectionId']] = normal_split(item['startUs'], item['endUs'])
        else:
            scenarios[(item['day'], item['originalScenario'])].append(item)
    report = {}
    for (day, scenario), records in sorted(scenarios.items()):
        mapping, info = scenario_split(records)
        counts = collections.Counter(split for split in mapping.values() if split)
        info['connections'] = {split: counts[split] for split in SPLITS}
        info['guardExcluded'] = sum(1 for split in mapping.values() if split is None)
        if min(info['connections'].values()) < MIN_PER_SPLIT:
            raise ValueError(f'场景切分不足 {MIN_PER_SPLIT}: {day} {scenario} {info["connections"]}')
        assignments.update(mapping)
        report[f'{day}:{scenario}'] = info
    return assignments, report


def unique_connections(records):
    """相同原件/五元组/首包时间对应多个 parent 时，整组排除避免错合并。"""
    grouped = {}
    for row in records:
        grouped.setdefault(row['physicalConnectionId'], []).append(row)
    rejected = [row for items in grouped.values() if len(items) > 1 for row in items]
    return {key: items[0] for key, items in grouped.items() if len(items) == 1}, rejected


def model_input(observation):
    """仅导出冻结 43+3 输入；身份、地址、时间、profile 和标签均为旁路。"""
    if observation['contractVersion'] != 'host-guard/5.0.0-rc.2':
        raise ValueError('观察契约不符')
    if set(observation['features']) != FEATURES:
        raise ValueError('特征字段不符')
    contexts = observation['contexts']
    if [row['windowSeconds'] for row in contexts] != [1, 5, 30]:
        raise ValueError('上下文窗口不符')
    for record in [observation['features'], *contexts]:
        if record is not observation['features'] and set(record) != CONTEXT:
            raise ValueError('上下文字段不符')
        for key, value in record.items():
            if value is None and record is observation['features'] and key in NULLABLE:
                continue
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise ValueError('输入存在非法空值、数值或单位范围: ' + key)
    return {key: observation[key] for key in
            ('features', 'contexts', 'transport', 'direction', 'serviceClass')}


def applicable(observation):
    return (observation['direction'] == 'inbound' and observation['transport'] == 'tcp'
            and observation['addressFamily'] == 'ipv4')


def defective(observation):
    return any(observation['quality'][key] for key in
               ('captureGap', 'latePacket', 'truncated', 'offloadSuspected', 'capacityDrop'))
