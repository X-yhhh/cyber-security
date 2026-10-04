#!/usr/bin/env python3
"""审查八批受控任务的跨活动重复，并生成完整 parent 排除后的待分区索引。

重复判据与公开源一致：去端点、10ms相对时序、方向/flags/IP和载荷长度。
所有重复 parent 整体排除，不选一个容易的角色保留。没有精确重复仍不证明
近重复消失或独立网络域；最终分区仍须另行冻结。
"""
import argparse
from collections import Counter,defaultdict
from datetime import datetime
import hashlib,json,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'p1'))
from pcap_reference import tcp


def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def micros(s):return round(datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()*1e6)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    stable={r['observationId']:r['budgetTargetId'] for r in map(json.loads,(a.root/'qualified-prefix-index.jsonl').open())}
    digests=defaultdict(list);indices=[];hashes={}
    for batch in sorted(a.root.glob('batch-*')):
        if not (batch/'audit-stable-v1/summary.json').exists():continue
        task=json.loads((batch/'task.json').read_text());conns={};quality=Counter()
        hashes[batch.name]=sha(batch/'native.pcap')
        with (batch/'native.pcap').open('rb') as f:
            head=f.read(24)
            if head[:4]!=b'\xd4\xc3\xb2\xa1' or struct.unpack_from('<I',head,20)[0]!=0:raise ValueError('只审已验证 NULL 原件')
            while True:
                h=f.read(16)
                if not h:break
                if len(h)!=16:raise ValueError('记录头截短')
                sec,micro,cap,wire=struct.unpack('<IIII',h);b=f.read(cap)
                if len(b)!=cap or cap!=wire or b[:4]!=struct.pack('<I',2):raise ValueError('报文或 AF 无效')
                ts=sec*1000000+micro;v=tcp(ts,b[4:],wire-4,101,quality)
                if v is None:raise ValueError('非登记 TCP 报文')
                syn=bool(v['flags']&2 and not v['flags']&16)
                if syn:conns.setdefault(v['key'],dict(first=ts,h=hashlib.sha256(),packets=0,peerPort=v['src'][1]))
                c=conns.get(v['key'])
                if c is None:raise ValueError('缺 SYN 的连接')
                c['packets']+=1;c['h'].update(json.dumps([(ts-c['first'])//10000,v['dst'][1]==80,v['flags'],v['ipBytes'],v['payloadBytes']]).encode())
        parents={}
        for line in (batch/'extraction-stable-v1/ledger.jsonl').open():
            row=json.loads(line);ep=row['Endpoints'];parents[(int(ep['Peer'].rsplit(':',1)[1]),micros(row['First']))]=row['parentConnectionId']
        for c in conns.values():
            if c['packets']<10:continue
            parent=parents.get((c['peerPort'],c['first']))
            if parent is None:raise ValueError('完整 SYN parent 未对应 Go 账本')
            digests[c['h'].hexdigest()].append(dict(batch=batch.name,role=task['role'],parentConnectionId=parent,packets=c['packets']))
        for line in (batch/'audit-stable-v1/prefix-index.jsonl').open():
            row=json.loads(line)
            if row['observationId'] not in stable:raise ValueError('缺少稳定目标预算旁路')
            row['budgetTargetId']=stable[row['observationId']];indices.append(row)
    groups=[v for v in digests.values() if len({r['batch'] for r in v})>1]
    excluded={r['parentConnectionId'] for g in groups for r in g};safe=[r for r in indices if r['parentConnectionId'] not in excluded]
    a.output.mkdir(exist_ok=False)
    with (a.output/'prefix-index.jsonl').open('x') as f:
        for row in safe:f.write(json.dumps(row)+'\n')
    result=dict(version='controlled-connection-sequence-audit-v2',auditedBatches=len(hashes),timestampBucketUs=10000,exactRepeatedHeaderSequenceGroups=len(groups),crossRoleRepeatedGroups=sum(len({r['role'] for r in g})>1 for g in groups),excludedParents=len(excluded),prefixObservationsBefore=len(indices),excludedPrefixObservations=len(indices)-len(safe),retainedPrefixObservations=len(safe),retainedByRole=dict(Counter(r['split'] for r in safe)),captureHashes=hashes,indexSha256=sha(a.output/'prefix-index.jsonl'),groups=groups,rolesFrozen=False,trainingAllowed=False,limitation='所有跨活动精确重复parent排除；相同主机/任务和其他近重复仍需分区审查，五次任务不代表五个独立网络域')
    (a.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ['groups','captureHashes']}))
if __name__=='__main__':main()
