#!/usr/bin/env python3
"""P1 CIC 修正表与完整 PCAP 的确定性抽查；不训练、不分配 final_test、不改源标签。

公开报告仅包含摘要与统计。UTC 微秒五元组窗口按 ±1us 核对双向计数/载荷；
保留失败、重叠、连接中段和 offload 诊断。HTTP payload 起点是待审查候选，
不会因为看到 GET 就自动将整个 prefix 标为攻击。
"""
import argparse
import collections
import csv
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
from pcap_reference import frames,tcp,Metrics

ATTACKS={'DoS Slowloris','DoS Slowhttptest','DoS Hulk','DoS GoldenEye','DDoS'}
EPOCH=dt.datetime(1970,1,1)


def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def timestamp(text):
    delta=dt.datetime.fromisoformat(text)-EPOCH
    return (delta.days*86400+delta.seconds)*1000000+delta.microseconds


def endpoints(row):
    return ((int(ipaddress.IPv4Address(row['Src IP'])),int(row['Src Port'])),
            (int(ipaddress.IPv4Address(row['Dst IP'])),int(row['Dst Port'])))


def compact(row,day,reason):
    a,b=endpoints(row);start=timestamp(row['Timestamp'])
    return {'id':hashlib.sha256((day+'\0'+row['id']).encode()).hexdigest(),'rowId':row['id'],
            'key':tuple(sorted((a,b))),'origin':a,'responder':b,'start':start,
            'end':start+int(row['Flow Duration']),'label':row['Label'],
            'attemptedCategory':int(row['Attempted Category']),'selection':reason,
            'fwdPackets':int(row['Total Fwd Packet']),'bwdPackets':int(row['Total Bwd packets']),
            'fwdPayload':int(row['Total Length of Fwd Packet']),'bwdPayload':int(row['Total Length of Bwd Packet'])}


def choose(labels,day):
    pools=collections.defaultdict(list);counts=collections.Counter();destinations=collections.Counter()
    def retain(pool,score,item,n):
        items=pools[pool];items.append((score,item));items.sort(key=lambda x:x[0]);del items[n:]
    with labels.open() as f:
        for row in csv.DictReader(f):
            counts[row['Label']]+=1
            if row['Protocol']!='6' or row['Dst Port']!='80':continue
            c=compact(row,day,'');rank=c['id'];label=c['label']
            if label in ATTACKS:
                destinations[c['responder'][0]]+=1;retain(label,rank,c,10)
            elif label=='BENIGN':
                retain('benign_random',rank,c,10)
                retain('benign_bulk',(-(c['fwdPayload']+c['bwdPayload']),rank),c,5)
                retain('benign_packet_heavy',(-(c['fwdPackets']+c['bwdPackets']),rank),c,5)
            elif 'Attempted' in label:retain('attempted_boundary',rank,c,10)
    selected={}
    for reason,pool in pools.items():
        for _,item in pool:
            if item['id'] not in selected:selected[item['id']]={**item,'selection':reason}
    # 同一目标服务的正常连接另列，避免用其他主机的下载掩盖来源混淆。
    target=destinations.most_common(1)[0][0]
    same=[]
    with labels.open() as f:
        for row in csv.DictReader(f):
            if row['Protocol']=='6' and row['Dst Port']=='80' and row['Label']=='BENIGN':
                if int(ipaddress.IPv4Address(row['Dst IP']))==target:same.append(compact(row,day,'benign_same_target_service'))
    for item in sorted(same,key=lambda x:x['id'])[:10]:selected.setdefault(item['id'],item)
    chosen=list(selected.values());wanted={c['key'] for c in chosen};windows=collections.defaultdict(list)
    with labels.open() as f:
        for row in csv.DictReader(f):
            if row['Protocol']!='6':continue
            try:a,b=endpoints(row)
            except ipaddress.AddressValueError:continue
            key=tuple(sorted((a,b)))
            if key in wanted:
                start=timestamp(row['Timestamp']);windows[key].append((start,start+int(row['Flow Duration']),row['id']))
    for c in chosen:
        c['overlappingRows']=sum(rid!=c['rowId'] and start<=c['end']+1 and end>=c['start']-1 for start,end,rid in windows[c['key']])
        c['sameAttackTarget']=c['responder'][0]==target
    return chosen,dict(counts),len(same)


def run(pcap,labels,day,expected):
    selected,census,same=choose(labels,day);bykey=collections.defaultdict(list)
    for c in selected:
        c['observed']=collections.Counter();c['firstPacket']=None;c['firstPayload']=None;c['firstHTTP']=None
        c['synSequences']=set();c['snapshots']={sec:Metrics(c['responder'][0],c['start']+sec*1000000) for sec in (1,5)}
        c['final']=Metrics(c['responder'][0],c['end']+1);bykey[c['key']].append(c)
    audit={};quality=collections.Counter()
    for ts,data,wire,link in frames(pcap,audit):
        packet=tcp(ts,data,wire,link,quality)
        if packet is None or packet['key'] not in bykey:continue
        for c in bykey[packet['key']]:
            if not c['start']-1<=ts<=c['end']+1:continue
            forward=packet['src']==c['origin'];tag='fwd' if forward else 'bwd'
            c['observed'][tag+'Packets']+=1;c['observed'][tag+'Payload']+=packet['payloadBytes']
            c['observed']['offloadSizedPackets']+=packet['offloadSized']
            if c['firstPacket'] is None or ts<c['firstPacket']['ts']:c['firstPacket']=packet
            if forward and packet['payloadBytes'] and (c['firstPayload'] is None or ts<c['firstPayload']):c['firstPayload']=ts
            if forward and packet['httpRequestStart'] and (c['firstHTTP'] is None or ts<c['firstHTTP']):c['firstHTTP']=ts
            if packet['flags']&2 and not packet['flags']&16:c['synSequences'].add((packet['src'],packet['seq']))
            for tracker in [*c['snapshots'].values(),c['final']]:tracker.add(packet)
    if audit['md5']!=expected:raise ValueError('完整 PCAP 与预期 MD5 不一致')
    rows=[]
    for c in selected:
        fields=('fwdPackets','bwdPackets','fwdPayload','bwdPayload')
        mismatches=[name for name in fields if c['observed'][name]!=c[name]]
        first=c['firstPacket'];join='matched'
        if first is None:join='unmatched'
        elif c['overlappingRows']:join='ambiguous'
        elif mismatches:join='inconsistent'
        syn_start=first is not None and first['flags']&2!=0 and first['flags']&16==0 and first['src']==c['origin']
        epoch=syn_start and len(c['synSequences'])==1
        rows.append({'connectionDigest':c['id'],'publisherLabel':c['label'],'attemptedCategory':c['attemptedCategory'],
                     'selection':c['selection'],'sameAttackTargetService':c['sameAttackTarget'],'join':join,
                     'expected':{name:c[name] for name in fields},'observed':dict(c['observed']),
                     'mismatchedFields':mismatches,'overlappingLabelRows':c['overlappingRows'],
                     'firstPacketDeltaUs':None if first is None else first['ts']-c['start'],
                     'singleSynEpochObserved':epoch,'distinctSynSequences':len(c['synSequences']),
                     'narrowTargetMetadataConstructible':join=='matched' and epoch,
                     'firstForwardPayloadDeltaUs':None if c['firstPayload'] is None else c['firstPayload']-c['start'],
                     'firstHTTPRequestDeltaUs':None if c['firstHTTP'] is None else c['firstHTTP']-c['start'],
                     'prefixes':{str(sec):{'hasPacketAtOrAfterDeadline':c['final'].last is not None and c['final'].last>=c['start']+sec*1000000,
                                  'features':tracker.report()} for sec,tracker in c['snapshots'].items()},
                     'finalFeatures':c['final'].report(),
                     'prefixSupervisionApproved':False})
    return {'version':'p1-cic-join-probe-v1','day':day,'codeSha256':sha(Path(__file__)),
            'referenceCodeSha256':sha(Path(__file__).with_name('pcap_reference.py')),
            'labelSha256':sha(labels),'pcap':audit,'packetQuality':dict(quality),'labelCensus':census,
            'sameTargetBenignRowsAvailable':same,'samples':rows,'joinCounts':dict(collections.Counter(r['join'] for r in rows)),
            'mode':'offline_reference_no_training','samplePolicy':'10 per HTTP attack family; 20 general benign incl bulk; 10 same target benign; 10 Attempted',
            'contextFeaturesImplemented':False,'finalTestAllocated':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pcap',type=Path,required=True);p.add_argument('--labels',type=Path,required=True)
    p.add_argument('--day',choices=['wednesday','friday'],required=True);p.add_argument('--expected-md5',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise FileExistsError('报告已存在，须保留历史证据')
    report=run(a.pcap,a.labels,a.day,a.expected_md5)
    with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({'day':a.day,'samples':len(report['samples']),'joinCounts':report['joinCounts']}))


if __name__=='__main__':main()
