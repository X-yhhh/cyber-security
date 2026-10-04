#!/usr/bin/env python3
"""P1 只读标签复核：保留旧审计，用精确时间和 TCP 序号解释歧义，不生成训练标签。"""
import argparse
import bisect
import collections
import hashlib
import ipaddress
import json
import struct
from decimal import Decimal
from pathlib import Path


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def micros(value):
    """Zeek 微秒时间用十进制定点解析，避免浮点时间误差扩大关联窗口。"""
    return int(Decimal(value) * 1_000_000)


def read_labels(path, scenario):
    labels, seen, fields = [], set(), None
    for line in path.read_text().splitlines():
        if line.startswith('#fields\t'):
            fields = line.split()[1:]
        if not line or line.startswith('#'):
            continue
        values = line.split()
        if fields is None or len(values) != len(fields):
            raise ValueError('标签字段布局不符')
        v = dict(zip(fields, values))
        if v['uid'] in seen:
            raise ValueError('重复 UID')
        seen.add(v['uid'])
        a = (int(ipaddress.IPv4Address(v['id.orig_h'])), int(v['id.orig_p']))
        b = (int(ipaddress.IPv4Address(v['id.resp_h'])), int(v['id.resp_p']))
        start = micros(v['ts'])
        labels.append(dict(id=digest(scenario+'\0'+v['uid']), start=start,
                           end=start+(0 if v['duration']=='-' else micros(v['duration'])),
                           durationKnown=v['duration']!='-', proto=v['proto'],
                           tuple=(v['proto'], *sorted((a,b))), orig=a, resp=b,
                           label=v['label'], detail=v.get('detailed-label',v.get('det_label')),
                           state=v['conn_state'], origPkts=int(v['orig_pkts']),
                           respPkts=int(v['resp_pkts'])))
    return labels


def packets(path):
    """完整校验以太网经典 PCAP；不支持的链路/截断容器拒绝，不解释载荷。"""
    with path.open('rb') as f:
        head=f.read(24)
        formats={b'\xd4\xc3\xb2\xa1':('<',1),b'\xa1\xb2\xc3\xd4':('>',1),
                 b'\x4d\x3c\xb2\xa1':('<',1000),b'\xa1\xb2\x3c\x4d':('>',1000)}
        if len(head)!=24 or head[:4] not in formats:
            raise ValueError('需要完整经典 PCAP')
        endian, divisor=formats[head[:4]]
        if struct.unpack(endian+'I',head[20:24])[0]!=1:
            raise ValueError('仅支持 Ethernet')
        while True:
            hdr=f.read(16)
            if not hdr: return
            if len(hdr)!=16: raise ValueError('PCAP 记录头截断')
            sec, frac, captured, original=struct.unpack(endian+'IIII',hdr)
            if captured>16*1024*1024 or captured>original:
                raise ValueError('非法报文长度')
            b=f.read(captured)
            if len(b)!=captured: raise ValueError('PCAP 报文截断')
            if len(b)<34 or b[12:14]!=b'\x08\x00': continue
            ihl=(b[14]&15)*4
            total=struct.unpack('!H',b[16:18])[0]
            frag=struct.unpack('!H',b[20:22])[0]
            if b[14]>>4!=4 or ihl<20 or frag&0x3fff or len(b)<14+total:
                continue
            proto={6:'tcp',17:'udp'}.get(b[23])
            off=14+ihl
            minimum=20 if proto=='tcp' else 8
            if not proto or total<ihl+minimum: continue
            src,dst=struct.unpack('!II',b[26:34])
            sport,dport=struct.unpack('!HH',b[off:off+4])
            a,bb=(src,sport),(dst,dport)
            flags=seq=payload=0
            if proto=='tcp':
                thl=(b[off+12]>>4)*4
                if thl<20 or total<ihl+thl: continue
                seq=struct.unpack('!I',b[off+4:off+8])[0]
                flags=b[off+13];payload=total-ihl-thl
            else: payload=total-ihl-8
            yield (proto,*sorted((a,bb))), (sec*1_000_000+frac//divisor,a,flags,seq,payload,total)


def analyse(raw, audits, stem, scenario):
    labelpath=raw/(stem+'-conn.log.labeled');pcap=raw/(stem+'.pcap')
    labels=read_labels(labelpath,scenario)
    old=json.loads((audits/(stem+'-v1-audit.json')).read_text())
    selected={s['connectionDigest'] for s in old['samples'] if s['publisherDetailedLabel']=='DDoS'}
    wanted={l['tuple'] for l in labels if l['id'] in selected}
    bytuple=collections.defaultdict(list)
    for key,p in packets(pcap):
        if key in wanted: bytuple[key].append(p)
    for ps in bytuple.values(): ps.sort(key=lambda p:p[0])
    details=[]
    for l in labels:
        if l['id'] not in selected:continue
        ps=bytuple[l['tuple']]; times=[p[0] for p in ps]
        def window(tolerance):
            return ps[bisect.bisect_left(times,l['start']-tolerance):
                      bisect.bisect_right(times,l['end']+tolerance)]
        strict=window(0);near=window(1);wide=window(1000)
        adjacent=[x for x in labels if x['tuple']==l['tuple'] and x['id']!=l['id']
                  and x['start']<=l['end']+1000 and l['start']<=x['end']+1000]
        syn=[p for p in near if p[2]&2 and not p[2]&16]
        first=ps[bisect.bisect_left(times,l['start'])] if bisect.bisect_left(times,l['start'])<len(ps) else None
        details.append(dict(connectionDigest=l['id'],publisherPackets=l['origPkts']+l['respPkts'],
                            exactWindowPackets=len(strict),oneMicrosecondWindowPackets=len(near),
                            oneMillisecondWindowPackets=len(wide),adjacentLabelsAt1ms=len(adjacent),
                            exactStartPackets=times.count(l['start']),
                            firstPacketDeltaUs=None if first is None else first[0]-l['start'],
                            synPacketsAt1us=len(syn),distinctSynSequencesAt1us=len({p[3] for p in syn}),
                            payloadBytesAt1us=sum(p[4] for p in near),
                            correction='diagnostic_only_original_counters_retained',
                            eligibleForSupervision=False))
    families={}
    for family in sorted({l['detail'] for l in labels}):
        ls=[l for l in labels if l['detail']==family]
        pairs=collections.Counter((l['proto'],l['orig'][0],l['resp']) for l in ls)
        families[family]=dict(labels=len(ls),protocols=dict(collections.Counter(l['proto'] for l in ls)),
             states=dict(collections.Counter(l['state'] for l in ls)),
             zeroPacketRows=sum(l['origPkts']+l['respPkts']==0 for l in ls),
             peerServiceGroups=len(pairs),largestPeerServiceGroup=max(pairs.values()),
             handshakeEstablishedRows=sum(l['state'] in {'SF','S1','S2','S3','RSTO','RSTR'} for l in ls),
             labelScope='final_only')
    return dict(scenario=scenario,pcapSha256=sha(pcap),labelSha256=sha(labelpath),
                sourceAuditSha256=sha(audits/(stem+'-v1-audit.json')),familyCensus=families,
                ddosSampleDiagnostics=details,
                diagnosticsDoNotResolveConnectionEpochs=True,trainingExecuted=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--raw',type=Path,required=True);p.add_argument('--audits',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise ValueError('报告已存在；保留旧证据并使用新路径')
    out=dict(version='p1-label-diagnosis-v1',codeSha256=sha(Path(__file__)),
             scenarios=[analyse(a.raw,a.audits,s,'CTU-IoT-Malware-Capture-'+i)
                        for s,i in [('hakai','8-1'),('muhstik','3-1'),('mirai','34-1')]])
    with a.output.open('x') as f:json.dump(out,f,ensure_ascii=False,indent=2);f.write('\n')
    a.output.chmod(0o600)
    print(json.dumps({'scenarios':len(out['scenarios']),'ddosSamples':len(out['scenarios'][2]['ddosSampleDiagnostics'])}))


if __name__=='__main__':main()
