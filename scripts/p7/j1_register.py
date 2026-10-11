#!/usr/bin/env python3
"""J1 validation 片段登记。只读 CIC 原件和冻结标签，不读取 test 数据或模型预测。

按冻结 validation 连接成员过滤 TCP 报文，保留原捕获顺序/时间/长度；不注入、
不排序、不更改载荷。--preroll-seconds>0 时在每段窗口前追加同一选择条件、同一来源的
上下文预热报文：只取切分台账中 split 为 validation 或未分配（保护区/排除，null）的连接，
train/test 连接按台账元数据排除、不读内容；窗口内报文与不加预热时逐字节相同，预热期
不计入 J1-8—J1-10 的起点与时延。输出目录必须不存在；清单冻结后只允许核验，不允许替换。
原始地址、旁路和 PCAP 均只写忽略的受控目录，正式报告只引用摘要。
"""
import argparse
from collections import defaultdict
import hashlib
import ipaddress
import json
import mmap
from pathlib import Path
import struct
import uuid


def sha(path, algorithm="sha256"):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    Path(path).chmod(0o600)


def load_rows(path):
    with Path(path).open() as stream:
        return [json.loads(line) for line in stream]


def tcp_tuple(data, pos, length):
    if length < 54 or data[pos + 12:pos + 14] != b"\x08\x00":
        return None
    ip = pos + 14
    if data[ip] >> 4 != 4 or data[ip + 9] != 6:
        return None
    header = (data[ip] & 15) * 4
    if header < 20 or 14 + header + 4 > length:
        return None
    # 非首片不能把片段数据误读成 TCP 端口。
    if struct.unpack_from("!H", data, ip + 6)[0] & 0x1fff:
        return None
    source, dest = data[ip + 12:ip + 16], data[ip + 16:ip + 20]
    sport, dport = struct.unpack_from("!HH", data, ip + header)
    return tuple(sorted(((source, sport), (dest, dport))))


def tuple_for(row):
    return tuple(sorted((ipaddress.ip_address(endpoint[0]).packed, endpoint[1])
                        for endpoint in (row["local"], row["peer"])))


def concurrency(rows, start, end):
    events = []
    for row in rows:
        low, high = max(start, row["startUs"]), min(end, row["endUs"])
        if high > low:
            events.extend(((low, 1), (high, -1)))
    active = maximum = 0
    for _, delta in sorted(events):
        active += delta
        maximum = max(maximum, active)
    return maximum


def packet_records(data):
    """返回原容器头和原记录；PCAPNG 只支持单 section/单 Ethernet 接口。"""
    if bytes(data[:4]) != b"\x0a\x0d\x0d\x0a":
        magic = bytes(data[:4])
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">" if magic == b"\xa1\xb2\xc3\xd4" else None
        if endian is None or struct.unpack_from(endian + "I",data,20)[0] != 1:
            raise ValueError("只接受 Ethernet 捕获")
        yield bytes(data[:24]), None
        offset = 24
        while offset < len(data):
            seconds,micros,size,original_size=struct.unpack_from(endian+"IIII",data,offset)
            if size>original_size or offset+16+size>len(data):
                raise ValueError("PCAP 截断")
            yield None,(offset,16+size,offset+16,size,seconds*1_000_000+micros)
            offset+=16+size
        return
    endian = "<" if bytes(data[8:12]) == b"\x4d\x3c\x2b\x1a" else ">"
    offset=0; interfaces=sections=0; resolution=1_000_000; header=[]
    while offset<len(data):
        kind,length=struct.unpack_from(endian+"II",data,offset)
        if length<12 or length%4 or offset+length>len(data) or struct.unpack_from(endian+"I",data,offset+length-4)[0]!=length:
            raise ValueError("PCAPNG 容器损坏")
        if kind==0x0a0d0d0a:
            sections+=1
            if sections!=1: raise ValueError("多 section 捕获")
            header.append(bytes(data[offset:offset+length]))
        elif kind==1:
            interfaces+=1
            if interfaces!=1 or struct.unpack_from(endian+"H",data,offset+8)[0]!=1:
                raise ValueError("多接口或非 Ethernet 捕获")
            option=offset+16
            while option+4<=offset+length-4:
                code,size=struct.unpack_from(endian+"HH",data,option);option+=4
                if code==0:break
                if option+size>offset+length-4:raise ValueError("接口选项损坏")
                if code==9:
                    value=data[option];resolution=2**(value&127) if value&128 else 10**value
                option+=(size+3)//4*4
            header.append(bytes(data[offset:offset+length]))
            yield b"".join(header),None
        elif kind==6:
            interface,high,low,size,original_size=struct.unpack_from(endian+"IIIII",data,offset+8)
            if interfaces!=1 or interface!=0 or size>original_size or 28+size>length-4:
                raise ValueError("报文块截断或跨接口")
            timestamp=((high<<32)|low)*1_000_000//resolution
            yield None,(offset,length,offset+28,size,timestamp)
        elif kind in (2,3):
            raise ValueError("不支持无完整时间戳的报文块")
        offset+=length


def register(args):
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    clips = args.output / "clips"
    clips.mkdir(mode=0o700)
    ledger = {r["physicalConnectionId"]: r["split"] for r in load_rows(args.frozen / "split-ledger.jsonl")}
    split = {k for k, v in ledger.items() if v == "validation"}
    # 预热只作上下文：validation 或台账未分配（保护区等），train/test 一律排除。
    context = {k for k, v in ledger.items() if v in ("validation", None)}
    preroll = args.preroll_seconds * 1_000_000
    preroll_families = set(args.preroll_families or ["port_scan", "brute_force", "dos_flood", "dos_slow", "normal"])
    manifest = json.loads((args.frozen / "split-manifest.json").read_text())
    if manifest["splitRuleVersion"] != "host-guard-split/2":
        raise ValueError("切分版本必须为 host-guard-split/2")
    registry = json.loads(args.registry.read_text())
    specs = []
    # whole_runs 的 Portscan 取较长的 validation 活动；其余为 active_time 冻结段。
    choices = [
        ("port_scan", "friday", "192.168.10.50", "friday:Portscan", 2, 30),
        ("brute_force", "tuesday", "192.168.10.50", "tuesday:FTP-Patator", 90, 180),
        ("dos_flood", "wednesday", "192.168.10.50", "wednesday:DoS Hulk", 35, 45),
        ("dos_slow", "wednesday", "192.168.10.50", "wednesday:DoS Slowloris", 95, 100),
    ]
    for family, day, host, activity, duration, spacing in choices:
        labels = load_rows(args.labels / f"{day}-{host.replace('.', '-')}" / "labels.jsonl")
        eligible = [r for r in labels if r["physicalConnectionId"] in split and r["label"] == family
                    and r["activityId"].startswith(activity + ":")]
        warm = [r for r in labels if r["physicalConnectionId"] in context and r["label"] == family
                and r["activityId"].startswith(activity + ":")]
        if not eligible:
            raise ValueError(f"validation 连接缺失: {family}")
        bounds = manifest["splitScenarios"][activity].get("boundsUs")
        first = min(r["startUs"] for r in eligible)
        if bounds:
            first = max(first, bounds[0] + 31_000_000)
        begin = first // 1_000_000 * 1_000_000
        for index in range(3):
            start, end = begin + index * spacing * 1_000_000, begin + (index * spacing + duration) * 1_000_000
            if bounds and end > bounds[1] - 30_000_000:
                raise ValueError(f"validation 隔离边界不足: {family}")
            rows = [r for r in eligible if r["startUs"] <= end and r["endUs"] >= start]
            if not rows or len({tuple_for(r)[0][0] for r in rows}) == 0:
                raise ValueError(f"片段无连接: {family}-{index+1}")
            peers = {r["peer"][0] for r in rows}
            if len(peers) != 1:
                raise ValueError("攻击片段须单来源")
            maximum = concurrency(rows, start, end)
            if family == "dos_slow" and maximum < 5:
                raise ValueError("慢速片段未达到 5 条并发连接")
            spec = dict(segmentId=f"{family}-{index+1}", family=family, day=day, host=host,
                        peer=next(iter(peers)), startUs=start, endUs=end, connections=rows,
                        maxConcurrentConnections=maximum, selection="frozen_validation_time_order")
            if preroll and family in preroll_families:
                spec["prerollConnections"] = [r for r in warm if r["peer"][0] == spec["peer"]
                                              and r["startUs"] < start and r["endUs"] >= start - preroll]
            specs.append(spec)
    # 正常片段选 Monday 的前六个至少 360 秒跨度的 validation 时间块；不看预测或质量分数。
    day, host = "monday", "192.168.10.50"
    labels = load_rows(args.labels / f"{day}-{host.replace('.', '-')}" / "labels.jsonl")
    groups = defaultdict(list)
    normal_warm = [r for r in labels if r["physicalConnectionId"] in context and r["label"] == "normal" and not r["websiteSupplement"]]
    for row in labels:
        if row["physicalConnectionId"] in split and row["label"] == "normal" and not row["websiteSupplement"]:
            groups[row["startUs"] // 600_000_000].append(row)
    for block, rows in sorted(groups.items()):
        if len([r for r in specs if r["family"] == "normal"]) == 6:
            break
        start, end = block * 600_000_000 + 31_000_000, block * 600_000_000 + 569_000_000
        rows = [r for r in rows if r["startUs"] <= end and r["endUs"] >= start]
        span = min(end, max((r["endUs"] for r in rows), default=0)) - max(start, min((r["startUs"] for r in rows), default=end))
        if span < 360_000_000:
            continue
        spec = dict(segmentId=f"normal-{1+sum(r['family']=='normal' for r in specs)}",family="normal",day=day,
                    host=host,startUs=start,endUs=end,connections=rows,maxConcurrentConnections=concurrency(rows,start,end),
                    selection="first_six_validation_blocks_with_360s_label_span")
        if preroll and "normal" in preroll_families:
            spec["prerollConnections"] = [r for r in normal_warm if r["startUs"] < start and r["endUs"] >= start - preroll]
        specs.append(spec)
    if sum(r["family"] == "normal" for r in specs) != 6:
        raise ValueError("正常片段不足")
    write(args.output / "selection.json", specs)
    sources = []
    for source in registry["pcaps"]:
        day = source["day"]
        day_specs = [s for s in specs if s["day"] == day]
        if not day_specs:
            continue
        path = args.pcaps / f"{day.title()}-WorkingHours.pcap"
        if sha(path) != source["sha256"]:
            raise ValueError(f"原件摘要不符: {day}")
        official_md5=(args.pcaps/f"{day.title()}-WorkingHours.md5").read_text().split()[0].lower()
        actual_md5=sha(path,"md5")
        if actual_md5!=source["md5"] or actual_md5!=official_md5:
            raise ValueError(f"官方 MD5 不符: {day}")
        outputs, hashes, counters, times, scoring = [], [], [], [], []
        lookup = defaultdict(list)
        for index, spec in enumerate(day_specs):
            target = clips / (spec["segmentId"] + ".pcap")
            target.touch(mode=0o600, exist_ok=False)
            outputs.append(target.open("wb")); hashes.append(hashlib.sha256()); counters.append(0); times.append([])
            scoring.append([0, None, None, hashlib.sha256()])
            for connection in spec["connections"]:
                low, high = max(spec["startUs"], connection["startUs"]), min(spec["endUs"], connection["endUs"])
                lookup[tuple_for(connection)].append((low, high, index))
            # 预热窗口 [start-preroll, start)；与窗口内区间不重叠，窗口内选择不变。
            for connection in spec.get("prerollConnections", []):
                low, high = max(spec["startUs"] - preroll, connection["startUs"]), min(spec["startUs"] - 1, connection["endUs"])
                if high >= low:
                    lookup[tuple_for(connection)].append((low, high, index))
        with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for header,record in packet_records(data):
                if header is not None:
                    for output,digest in zip(outputs,hashes):output.write(header);digest.update(header)
                    continue
                offset,record_size,packet_offset,size,timestamp=record
                key = tcp_tuple(data,packet_offset,size)
                if key in lookup:
                    selected = {index for low, high, index in lookup[key] if low <= timestamp <= high}
                    if selected:
                        packet = bytes(data[offset:offset + record_size])
                        for index in selected:
                            outputs[index].write(packet); hashes[index].update(packet); counters[index] += 1
                            if timestamp >= day_specs[index]["startUs"]:
                                window = scoring[index]; window[0] += 1; window[3].update(packet)
                                window[1] = timestamp if window[1] is None else window[1]; window[2] = timestamp
                            if not times[index]:
                                times[index].append(timestamp)
                            if len(times[index]) == 1:
                                times[index].append(timestamp)
                            else:
                                times[index][1] = timestamp
        for index, spec in enumerate(day_specs):
            outputs[index].close()
            if not counters[index]:
                raise ValueError("空片段")
            spec.update(pcapSha256=hashes[index].hexdigest(), packets=counters[index],
                        sourceFirstUs=times[index][0], sourceLastUs=times[index][1],
                        observedDurationSeconds=(times[index][1]-times[index][0])/1_000_000,
                        pcapRef=f"{args.artifact_prefix}/clips/{spec['segmentId']}.pcap")
            if preroll and spec["family"] not in preroll_families:
                # 未加预热的类别仍保留同长的传感器采集预热（与原 v8 换绑的 captureWarmupSeconds 相同），PCAP 不变。
                spec["captureStartUs"] = spec["sourceFirstUs"] - preroll
            if preroll and spec["family"] in preroll_families:
                packets, first, last, digest = scoring[index]
                if not packets:
                    raise ValueError("窗口内无报文")
                # 时延起点与时长按窗口内报文计；采集起点为预热起点，预热期报文只作上下文。
                spec.update(prerollSeconds=args.preroll_seconds, captureStartUs=spec["startUs"] - preroll,
                            prerollPackets=counters[index] - packets, prerollConnections=len(spec["prerollConnections"]),
                            scoringFirstUs=first, scoringLastUs=last, scoringPackets=packets,
                            scoringRecordsSha256=digest.hexdigest(),
                            observedDurationSeconds=(last - first) / 1_000_000)
        sources.append(dict(day=day,sha256=source["sha256"],md5=actual_md5,officialMd5Matched=True,
                            officialMd5FileSha256=sha(args.pcaps/f"{day.title()}-WorkingHours.md5"),
                            bytes=path.stat().st_size,macVerified=True))
        print(json.dumps(dict(day=day,segments=len(day_specs),packets=sum(counters))),flush=True)
    normal_seconds=sum(s["observedDurationSeconds"] for s in specs if s["family"]=="normal")
    if normal_seconds < 1800:
        raise ValueError(f"正常 PCAP 实际跨度不足 30 分钟: {normal_seconds}")
    public=[]
    for spec in specs:
        public.append({k:v for k,v in spec.items() if k not in ("connections","host","peer")})
    write(args.output / "draft-scenario.json",dict(scenarioId=str(uuid.uuid4()),stage="J1",environment="research",speed=1,
          selectionProtocol="frozen-validation-membership/1" if not preroll else "frozen-validation-membership/1+preroll-context/1",
          prerollSeconds=args.preroll_seconds,prerollFamilies=sorted(preroll_families) if preroll else [],testRead=False,newFits=0,
          splitManifestSha256=sha(args.frozen/"split-manifest.json"),splitLedgerSha256=sha(args.frozen/"split-ledger.jsonl"),
          sourceHashes=sources,normalDurationSeconds=normal_seconds,segments=public))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen",type=Path,required=True);parser.add_argument("--labels",type=Path,required=True)
    parser.add_argument("--registry",type=Path,required=True);parser.add_argument("--pcaps",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True);parser.add_argument("--artifact-prefix",required=True)
    parser.add_argument("--preroll-seconds",type=int,default=0,choices=range(0,61),metavar="0..60",
                        help="窗口前上下文预热秒数；0 保持原登记行为")
    parser.add_argument("--preroll-families",nargs="+",choices=["port_scan","brute_force","dos_flood","dos_slow","normal"],
                        help="施加预热的类别，缺省为全部；未列出的类别保持冷启动片段（检测门槛只会更严）")
    register(parser.parse_args())
