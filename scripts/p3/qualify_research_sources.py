#!/usr/bin/env python3
"""两个已取得来源的可复算谱系审查；不评分、不训练、不把包名当逐连接真值。

先提交角色预留文件；final 只检查完整性/哈希，不生成请求特征。低于150秒的
同源相邻捕获整体关联，关联到 final 的材料全部封存；不能用换 UUID 拆组。
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'p1'))
from pcap_reference import frames, tcp
from http_prefix_state import CausalHTTP


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def integrity(path):
    """只检查经典 PCAP 记录边界；修尾派生件保留原件并明确上下文损失。"""
    with path.open('rb') as f:
        header=f.read(24)
        endian={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>'}.get(header[:4])
        if endian is None or len(header)!=24:
            raise ValueError('需要已登记的经典 PCAP')
        version=struct.unpack(endian+'HH',header[4:8]); snap,link=struct.unpack(endian+'II',header[16:])
        if version!=(2,4) or link not in (1,12,101):raise ValueError('PCAP 版本/链路无效')
        good=24;count=0;first=last=None;truncated=regressions=0
        while True:
            h=f.read(16)
            if not h:break
            if len(h)!=16:break
            sec,usec,cap,wire=struct.unpack(endian+'IIII',h)
            if usec>=1000000 or cap>wire or cap>snap or cap>16*1024*1024:raise ValueError('非尾部完整性错误')
            b=f.read(cap)
            if len(b)!=cap:break
            ts=sec*1000000+usec
            if first is None:first=ts
            regressions+=last is not None and ts<last;last=ts
            truncated+=cap<wire;count+=1;good=f.tell()
    return dict(bytes=path.stat().st_size,sha256=sha(path),lastCompleteOffset=good,
                containerComplete=good==path.stat().st_size,frames=count,firstUs=first,lastUs=last,
                snapTruncatedFrames=truncated,timestampRegressions=regressions,link=link)


def inspect_connections(path, tail_cutoff=None):
    """SYN epoch 整体处理；前向 HTTP 状态只作候选证据，需另关联发布活动/日志。

    去地址的精确报文谱系用于排除重复；正常完成和未完成分开，408/无告警不转正常。
    """
    audit={};quality=Counter();conns={};completed=[]
    def finish(c):
        if c['packets']<2:return
        state=c['state']
        completed.append(dict(firstUs=c['first'],lastUs=c['last'],packets=c['packets'],
            closed=c['closed'],requestCompletedAtUs=state.complete,evidenceAvailableAtUs=state.onset,
            detectedMode=state.detected_mode,invalid=state.invalid,
            boundaryExcluded=tail_cutoff is not None and c['last']>=tail_cutoff,
            sequenceDigest=c['digest'].hexdigest(),provenanceQualified=False,label=None))
    for ts,b,wire,link in frames(path,audit):
        p=tcp(ts,b,wire,link,quality)
        if p is None:continue
        key=p['key'];syn=bool(p['flags']&2 and not p['flags']&16)
        c=conns.get(key)
        if syn and (c is None or c['syn']!=p['seq'] or c['origin']!=p['src']):
            if c:finish(c)
            c=dict(first=ts,last=ts,syn=p['seq'],origin=p['src'],state=CausalHTTP(),
                   digest=hashlib.sha256(),packets=0,closed=False)
            conns[key]=c
        if c is None:continue
        c['last']=ts;c['packets']+=1;c['closed']|=bool(p['flags']&5)
        c['digest'].update(json.dumps([int((ts-c['first'])//10000),p['src']==c['origin'],p['flags'],p['ipBytes'],p['payloadBytes']]).encode())
        if p['src']==c['origin']:
            c['state'].add(p,b[p['payloadOffset']:p['payloadOffset']+p['payloadBytes']])
    for c in conns.values():finish(c)
    return completed,dict(quality)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sources',type=Path,required=True);p.add_argument('--reservation',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--tail-repairs',type=Path);a=p.parse_args()
    repairs=json.loads(a.tail_repairs.read_text()) if a.tail_repairs else {}
    reserve=json.loads(a.reservation.read_text());initial=set(reserve['finalMembers'])
    if reserve.get('modelScoresRead') or reserve.get('finalFeaturesRead'):raise ValueError('封存前已暴露')
    a.output.mkdir(parents=True,exist_ok=False)
    source_rows=[]
    for source in ('taara','rios'):
        for path in sorted((a.sources/source).rglob('*.pcap')):
            member=str(path.relative_to(a.sources/source));meta=integrity(path)
            role='final_reserved' if member in initial else 'development_unassigned'
            source_rows.append(dict(source=source,member=member,path=path,role=role,**meta))
    (a.output/'integrity-before-analysis.json').write_text(json.dumps([{k:v for k,v in r.items() if k!='path'} for r in source_rows],indent=2))
    parent=list(range(len(source_rows)))
    def find(i):
        while parent[i]!=i:parent[i]=parent[parent[i]];i=parent[i]
        return i
    def union(i,j):parent[find(j)]=find(i)
    for i,r in enumerate(source_rows):
        for j,s in enumerate(source_rows[:i]):
            if r['source']==s['source'] and r['firstUs']<s['lastUs']+150000000 and s['firstUs']<r['lastUs']+150000000:union(i,j)
    final_groups={find(i) for i,r in enumerate(source_rows) if r['role']=='final_reserved'}
    sequences={};duplicates=[]
    for i,r in enumerate(source_rows):
        r['associationGroup']=f"capture-group-{find(i)}"
        if find(i) in final_groups:
            r['role']='final_reserved';r['featureRead']=False;continue
        path=r['path'];cutoff=None
        if not r['containerComplete']:
            # 仅已知 TAARA 尾损允许派生；未知损坏不能自动修复。
            allowed=repairs.get(r['source']+'/'+r['member'])
            if allowed is None or (r['sha256'],r['bytes'],r['lastCompleteOffset'])!=(allowed['sha256'],allowed['bytes'],allowed['lastCompleteOffset']):raise ValueError('未登记损坏')
            derived=a.output/'derived'/path.name;derived.parent.mkdir(exist_ok=True)
            with path.open('rb') as src,derived.open('xb') as dst:dst.write(src.read(r['lastCompleteOffset']))
            r['derivativeSha256']=sha(derived);r['excludedTailBytes']=r['bytes']-r['lastCompleteOffset'];path=derived;cutoff=r['lastUs']-150000000
        conns,q=inspect_connections(path,cutoff)
        r['featureRead']=True;r['connectionCandidates']=len(conns);r['headerQuality']=q
        r['modeCandidates']=dict(Counter(c['detectedMode'] or 'unknown' for c in conns))
        r['completedRequestCandidates']=sum(c['requestCompletedAtUs'] is not None for c in conns)
        r['qualifiedLabels']=0
        with (a.output/f'connections-{i}.jsonl').open('x') as f:
            for c in conns:f.write(json.dumps(c)+'\n')
        for c in conns:
            if c['packets']<10:continue
            sig=c['sequenceDigest']
            if sig in sequences and sequences[sig]!=i:
                j=sequences[sig];duplicates.append([j,i]);union(i,j)
            else:sequences[sig]=i
    for i,r in enumerate(source_rows):
        r['associationGroup']=f"capture-group-{find(i)}"
        r['cluster']=r['source']+'-'+datetime.fromtimestamp(r['firstUs']/1e6,timezone.utc).date().isoformat()
        r.pop('path')
    # final 原件不解析报文模式；它的截尾修复只能作完整性派生，不生成模型输入。
    for r in source_rows:
        if r['role']=='final_reserved' and not r['containerComplete']:
            if r['member']!='Acquire/Skenario Ringan 3/capture-skenario-ringan-2.pcap' or r['lastCompleteOffset']!=1941450:raise ValueError('未知 final 损坏')
            src=a.sources/r['source']/r['member'];dst=a.output/'final-integrity-derivative.pcap'
            with src.open('rb') as s,dst.open('xb') as d:d.write(s.read(r['lastCompleteOffset']))
            r['integrityDerivativeSha256']=sha(dst);r['excludedTailBytes']=r['bytes']-r['lastCompleteOffset']
    dev=[r for r in source_rows if r['role']!='final_reserved']
    summary=dict(version='resolution-source-qualification-v1',reservationSha256=sha(a.reservation),
        captures=source_rows,developmentAssociationGroups=len({r['associationGroup'] for r in dev}),
        developmentSourceDayClusters=len({r['cluster'] for r in dev}),duplicateSequenceEdges=len(duplicates),
        qualifiedAttackActivities=0,qualifiedBenignActivities=0,finalFeaturesRead=False,modelFits=0,
        status='blocked',blockers=['PUBLISHER_ACTIVITY_AND_REQUEST_LOG_JOIN_REQUIRED','ROLES_NOT_FROZEN','INDEPENDENT_GROUPS_NOT_QUALIFIED'],
        limitation='模式结构不是真值；session/来源日/域分别报告，全部逐连接标签当前 Unknown')
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='captures'}))


if __name__=='__main__':main()
