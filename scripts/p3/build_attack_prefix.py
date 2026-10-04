#!/usr/bin/env python3
"""把受控攻击采集结果接入 rc.2 prefix 观察；只生成开发待分区材料，不批准训练。

每组活动独立引擎、独立 boot、独立 PCAP；起点为首个 SYN（攻击发起方向）。
Unknown 不映射正常；不批准训练；不读取 P6 封存特征/标签/分数。
输出格式与 build_collected_benign.py 对齐，可直接喂 freeze_prefix_corpus.py。
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'p1'))
from verify_prefix_corpus import lines, read, sha, time_ms
from build_qualified_prefix import target_key

# 场景 → (sourceId, family, labelRuleVersion)
SCENARIO_META = {
    'controlled_slowloris': (
        'controlled_windows_http_cde',
        'slowloris',
        'p3-cde-controlled-slowloris-syn-onset-v1',
    ),
    'controlled_slowhttptest': (
        'controlled_windows_http_cde',
        'slowhttptest',
        'p3-cde-controlled-slowhttptest-syn-onset-v1',
    ),
}

# 受控回环范围；任何超出此范围的包都拒绝
AUTHORIZED_ADDRS = {0x7f000001, 0x7f000002}  # 127.0.0.1, 127.0.0.2
SERVICE_IP  = 0x7f000001
SERVICE_PORT = 80


def _ip_int(b4):
    return (b4[0] << 24) | (b4[1] << 16) | (b4[2] << 8) | b4[3]


def _parse_pcap_conns(pcap_path):
    """读取原生 DLT_NULL PCAP，返回 {(src_ip,src_port,dst_ip,dst_port): conn_dict}。

    只追踪首个 SYN epoch；RST/FIN 均记录关闭时刻；不尝试重组 TCP 载荷。
    """
    conns = {}
    with pcap_path.open('rb') as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError('PCAP 文件头截短')
        magic = struct.unpack_from('<I', header)[0]
        if magic != 0xa1b2c3d4:
            raise ValueError('非登记原生 NULL 链路（小端）')
        while True:
            rec_hdr = f.read(16)
            if not rec_hdr:
                break
            if len(rec_hdr) < 16:
                raise ValueError('截短记录头')
            sec, micro, cap_len, wire_len = struct.unpack('<IIII', rec_hdr)
            frame = f.read(cap_len)
            if len(frame) != cap_len or cap_len != wire_len or micro >= 1_000_000:
                raise ValueError('截短或非标准记录')
            at = sec * 1_000_000 + micro
            # DLT_NULL：前 4 字节为 AF；IPv4 = 2（小端 \x02\x00\x00\x00）
            if len(frame) < 24 or frame[:4] != b'\x02\x00\x00\x00':
                continue
            ip = frame[4:]
            if len(ip) < 20 or ip[9] != 6:  # not TCP
                continue
            ihl = (ip[0] & 0x0f) * 4
            if len(ip) < ihl + 20:
                continue
            src_ip = _ip_int(ip[12:16])
            dst_ip = _ip_int(ip[16:20])
            if {src_ip, dst_ip} != AUTHORIZED_ADDRS:
                raise ValueError('包超出授权回环范围')
            tcp = ip[ihl:]
            src_port = (tcp[0] << 8) | tcp[1]
            dst_port = (tcp[2] << 8) | tcp[3]
            flags = tcp[13]
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            rst = bool(flags & 0x04)
            fin = bool(flags & 0x01)
            # 攻击方向：PEER → SERVICE
            forward = (src_ip == 0x7f000002 and dst_ip == SERVICE_IP and dst_port == SERVICE_PORT)
            key = (src_ip, src_port, dst_ip, dst_port) if forward else (dst_ip, dst_port, src_ip, src_port)
            c = conns.get(key)
            if syn and not ack and forward:
                if c is None:
                    conns[key] = dict(
                        firstUs=at, lastUs=at, closeUs=None,
                        synUs=at, peerPort=src_port,
                        frames=1, synAck=False,
                    )
                # 只追踪首个 SYN epoch；重复 SYN 忽略
                continue
            if c is None:
                continue
            c['lastUs'] = max(c['lastUs'], at)
            c['frames'] += 1
            if syn and ack and not forward:
                c['synAck'] = True
            if (rst or fin) and c['closeUs'] is None:
                c['closeUs'] = at
    return conns


def audit_group(group_dir):
    """核验单组活动目录：PCAP、activity.json、零丢包。"""
    activity = read(group_dir / 'activity.json')
    if not activity['success']:
        raise ValueError(f'活动 {group_dir.name} 失败: {activity.get("error")}')
    cap = activity.get('capture', {})
    if not cap.get('passed', False):
        raise ValueError(f'采集未通过：{cap}')
    if cap.get('stats') and (
        cap['stats'].get('dropped', 0) or
        cap['stats'].get('ifdrop', 0) or
        cap['stats'].get('ifDropped', 0)
    ):
        raise ValueError('捕获有丢包')
    pcap = group_dir / 'native.pcap'
    if not pcap.exists():
        raise ValueError('native.pcap 不存在')
    conns = _parse_pcap_conns(pcap)
    if not conns:
        raise ValueError('未找到任何授权范围内的 TCP 连接')
    connected = activity.get('attackResult', {}).get('connected', 0)
    if connected and len(conns) < connected:
        raise ValueError(f'PCAP 连接数 {len(conns)} 少于攻击报告 {connected}')
    return activity, conns


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',      type=Path, required=True,
                   help='collect_attack_prefix.py 的输出根目录')
    p.add_argument('--extractor', type=Path, required=True,
                   help='Go guardextract 可执行文件路径')
    p.add_argument('--output',    type=Path, required=True,
                   help='输出目录（不得已存在）')
    args = p.parse_args()

    complete = read(args.root / 'complete.json')
    if complete.get('status') != 'completed':
        raise ValueError('整轮采集未完成')
    registration = read(args.root / 'registration.json')

    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    secret = args.output / 'peer-key.bin'
    secret.write_bytes(os.urandom(32))
    secret.chmod(0o600)
    identity = dict(
        assetId=str(uuid.uuid4()),
        sensorId=str(uuid.uuid4()),
        secretFile=str(secret.resolve()),
        keyEpoch=1,
    )

    rows = []; observations = []; timelines = []; audits = []
    previous_end = None

    # 按场景聚合组，每个 activityId 构成独立防泄漏组
    group_dirs = sorted(
        d for d in args.root.iterdir()
        if d.is_dir() and d.name.startswith('group-')
    )

    for group_dir in group_dirs:
        if not (group_dir / 'activity.json').exists():
            continue
        activity, conns = audit_group(group_dir)

        mode        = activity['mode']          # 'slowloris' | 'slowhttptest'
        scenario    = 'controlled_' + mode
        activity_id = activity['activityId']
        group_ordinal = activity['groupOrdinal']

        if scenario not in SCENARIO_META:
            raise ValueError(f'未知攻击模式: {mode}')
        source_id, family, label_rule = SCENARIO_META[scenario]

        # 时间段顺序检查（相邻组隔离 ≥155 秒）
        start_us = min(c['firstUs'] for c in conns.values())
        end_us   = max(c['lastUs']  for c in conns.values())
        if previous_end is not None and start_us - previous_end < 155_000_000:
            raise ValueError(f'{group_dir.name}: 与上一组隔离不足 155 秒')
        previous_end = end_us

        # Go 提取器
        work = args.output / group_dir.name
        work.mkdir()
        config = dict(
            identity,
            bootId=str(uuid.uuid4()),
            captureScopeId=str(uuid.uuid4()),
            localAddresses=['127.0.0.1'],
        )
        (work / 'config.json').write_text(json.dumps(config) + '\n')
        result = subprocess.run(
            [str(args.extractor.resolve()),
             '-config',  str(work / 'config.json'),
             '-pcap',    str(group_dir / 'native.pcap'),
             '-out',     str(work / 'observations.jsonl'),
             '-ledger',  str(work / 'ledger.jsonl'),
             '-report',  str(work / 'extraction.json')],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode:
            raise RuntimeError('GO_EXTRACTION_FAILED:' + result.stderr[-300:])

        ex = read(work / 'extraction.json')
        for key, path in [
            ('pcapSha256',         group_dir / 'native.pcap'),
            ('observationsSha256', work / 'observations.jsonl'),
            ('localLedgerSha256',  work / 'ledger.jsonl'),
        ]:
            if ex[key] != sha(path):
                raise ValueError(f'{group_dir.name}: Go 原件身份不符 ({key})')
        if ex['status'] != 'completed' or ex['version'] != 'host-guard/5.0.0-rc.2':
            raise ValueError(f'{group_dir.name}: Go 契约不符')

        # parent 绑定：按 SYN 时刻与 PCAP 解析结果精确关联
        parents = {}
        kept = Counter()
        target = target_key(identity['assetId'], '127.0.0.1:80', '127.0.0.2:0')

        for obs, ledger in zip(
            lines(work / 'observations.jsonl'),
            lines(work / 'ledger.jsonl'),
            strict=True,
        ):
            if obs['observationId'] != ledger['observationId']:
                raise ValueError('观察旁路错配')
            ep     = ledger['Endpoints']
            parent = obs['parentConnectionId']
            # 只保留服务端方向的观察（本机服务接收攻击连接）
            if ep['Local'] != '127.0.0.1:80':
                continue
            if parent not in parents:
                peer_port = int(ep['Peer'].rsplit(':', 1)[1])
                # 按对端端口和首包时刻精确绑定到 PCAP 解析出的连接
                cand_key = (0x7f000002, peer_port, SERVICE_IP, SERVICE_PORT)
                c = conns.get(cand_key)
                if c is None:
                    continue  # 无对应 SYN，跳过
                obs_first_us = int(time_ms(obs['firstSeenAt']) * 1000)
                if abs(c['firstUs'] - obs_first_us) > 2_000_000:  # 2 秒容差
                    continue
                parents[parent] = c

            conn = parents[parent]
            qual = obs.get('quality', {})
            if any(qual.get(k) for k in (
                'captureGap', 'latePacket', 'truncated',
                'offloadSuspected', 'capacityDrop',
            )):
                kept['quality_rejected'] += 1
                continue
            if obs.get('profile') != 'flow-prefix-v1':
                kept['profile_mismatch'] += 1
                continue

            # 起点为首个 SYN（已由 PCAP 解析确定），onsetUs = conn['synUs']
            rows.append(dict(
                observationId=obs['observationId'],
                parentConnectionId=parent,
                activityId=activity_id,
                associationGroup=activity_id,
                sourceId=source_id,
                scenario=scenario,
                split='independent_development',
                label=1,
                family=family,
                evidenceTier='controlled_attack',
                attackMode=mode,
                groupOrdinal=group_ordinal,
                labelRuleVersion=label_rule,
                onsetMode='first_forward_syn',
                onsetUs=conn['synUs'],
                captureSha256=ex['pcapSha256'],
                firstSeenAt=obs['firstSeenAt'],
                asOf=obs['asOf'],
                budgetTargetId=target,
            ))
            observations.append(obs)
            kept['kept'] += 1

        # 逐 parent 的时间线条目
        for parent, c in parents.items():
            timelines.append(dict(
                episodeId=hashlib.sha256((activity_id + parent).encode()).hexdigest(),
                parentConnectionId=parent,
                activityId=activity_id,
                scenario=scenario,
                label=1,
                targetId=target,
                startMs=c['firstUs']  / 1000,
                endMs=c['lastUs']     / 1000,
                synUs=c['synUs'],
                closeUs=c['closeUs'],
                hasObservation=any(r['parentConnectionId'] == parent for r in rows),
                basis='controlled_attack_syn_onset_verified_pcap',
            ))

        audits.append(dict(
            group=group_dir.name,
            activityId=activity_id,
            scenario=scenario,
            mode=mode,
            groupOrdinal=group_ordinal,
            connections=len(conns),
            keptObservations=kept['kept'],
            rejectedQuality=kept['quality_rejected'],
            rejectedProfile=kept['profile_mismatch'],
            captureDrops=activity['capture'].get('stats', {}).get('dropped', 0),
            captureFrames=activity['capture'].get('frames', 0),
            captureSha256=ex['pcapSha256'],
            activitySha256=sha(group_dir / 'activity.json'),
            extractionSha256=sha(work / 'extraction.json'),
        ))
        print(json.dumps({k: audits[-1][k] for k in
                          ('group', 'scenario', 'groupOrdinal',
                           'connections', 'keptObservations')}), flush=True)

    # 输出三份 JSONL + readiness.json
    for name, values in [
        ('index.jsonl',          rows),
        ('observations.jsonl',   observations),
        ('label-timeline.jsonl', timelines),
    ]:
        with (args.output / name).open('x', encoding='utf-8') as f:
            for v in values:
                f.write(json.dumps(v) + '\n')

    scenarios_present = sorted({r['scenario'] for r in rows})
    report = dict(
        version='p3-cde-qualified-attack-v1',
        observations=len(rows),
        parents=len({r['parentConnectionId'] for r in rows}),
        activities=len(audits),
        scenarios=scenarios_present,
        sourceDomainCount=1,
        split='independent_development',
        trainingAllowed=False,
        rolesFrozen=False,
        finalRead=False,
        modelFits=0,
        groupAudits=audits,
        authorizationRef='docs/p3/controlled-attack-authorization.json',
        registrationSha256=sha(args.root / 'registration.json'),
        extractorSha256=sha(args.extractor),
        outputHashes={n: sha(args.output / n)
                      for n in ('index.jsonl', 'observations.jsonl', 'label-timeline.jsonl')},
    )
    (args.output / 'readiness.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in
                      ('observations', 'parents', 'activities', 'scenarios')}))


if __name__ == '__main__':
    main()
