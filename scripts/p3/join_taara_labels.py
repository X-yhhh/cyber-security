#!/usr/bin/env python3
"""TAARA 开发材料的来源限定标签：论文登记、完整 SYN epoch、HTTP 状态与 Apache 请求日志交叉关联。

只读谱系清单中已暴露的开发捕获；final_reserved 完全跳过。论文表 II 指定
攻击端/服务端，表 V 指定正常 host；日志不带源端口，歧义关联明确保留 Unknown。
Suricata 告警不参与标签。输出含私有端点，只能留在受控忽略目录，不能进入模型。
"""
import argparse
from collections import Counter,defaultdict
from datetime import datetime
import hashlib,ipaddress,json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'p1'))
from pcap_reference import frames,tcp
from http_prefix_state import CausalHTTP

VERSION='taara-publisher-http-apache-v1'
ATTACK=int(ipaddress.IPv4Address('192.168.1.9'))
BENIGN=int(ipaddress.IPv4Address('192.168.1.2'))
VICTIM=int(ipaddress.IPv4Address('192.168.1.8'))

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def parse_logs(folder):
    """按含时区的原始时刻匹配整秒；未解析行和同一请求歧义均单列。"""
    rows=[];bad=0;hashes={}
    for p in folder.glob('access*.log'):
        hashes[p.name]=sha(p)
        for line in p.open(errors='replace'):
            m=re.match(r'^(\S+) \S+ \S+ \[([^]]+)\] "([^"]*)" (\d+) (\S+)',line)
            if not m:bad+=1;continue
            try:
                peer=int(ipaddress.IPv4Address(m[1]));t=datetime.strptime(m[2],'%d/%b/%Y:%H:%M:%S %z')
            except ValueError:bad+=1;continue
            rows.append(dict(peer=peer,second=int(t.timestamp()),request=m[3],status=int(m[4])))
    return rows,bad,hashes

def inspect(path):
    """复用因果旁路；反向最多32KiB，只读取 HTTP 响应行供日志关联，不提取模型特征。"""
    audit={};quality=Counter();active={};done=[]
    def finish(c):
        v=c.pop('state');resp=c.pop('response');c['requestLine']=bytes(v.request).split(b'\r\n',1)[0].decode('latin1')
        status=re.match(rb'HTTP/1\.[01] ([0-9]{3}) ',resp)
        c.update(status=int(status[1]) if status else None,completeAtUs=v.complete,evidence=v.evidence,
                 evidenceAvailableAtUs=v.onset,firstPayloadUs=v.first_payload,mode=v.detected_mode,invalid=v.invalid)
        done.append(c)
    for ts,b,wire,link in frames(path,audit):
        p=tcp(ts,b,wire,link,quality)
        if not p:continue
        syn=bool(p['flags']&2 and not p['flags']&16);key=p['key'];c=active.get(key)
        if syn and (c is None or c['syn']!=p['seq'] or c['origin']!=p['src']):
            if c:finish(c)
            c=dict(origin=p['src'],destination=p['dst'],syn=p['seq'],firstUs=ts,lastUs=ts,state=CausalHTTP('slow_header'),response=bytearray(),responseAtUs=None,packets=0)
            active[key]=c
        if not c:continue
        c['lastUs']=max(c['lastUs'],ts);c['packets']+=1
        payload=b[p['payloadOffset']:p['payloadOffset']+p['payloadBytes']]
        if p['src']==c['origin']:c['state'].add(p,payload)
        elif payload and payload.startswith(b'HTTP/') and not c['response']:
            c['response'].extend(payload[:32768]);c['responseAtUs']=ts
    for c in active.values():finish(c)
    return done,audit,dict(quality)

def main():
    a=argparse.ArgumentParser(description=__doc__)
    for k in ['sources','qualification','paper','output']:a.add_argument('--'+k,type=Path,required=True)
    args=a.parse_args();q=json.loads(args.qualification.read_text());args.output.mkdir(parents=True,exist_ok=False)
    registration=dict(version=VERSION,paperSha256=sha(args.paper),qualificationSha256=sha(args.qualification),scriptSha256=sha(Path(__file__)),sourceScope='paper Table II/V + named capture + Apache request, no Suricata alerts',finalRead=False)
    (args.output/'registration.json').write_text(json.dumps(registration,indent=2)+'\n')
    summaries=[];all_rows=[]
    for meta in q['captures']:
        if meta['source']!='taara' or meta['role']=='final_reserved':continue
        path=args.sources/'taara'/meta['member']
        if sha(path)!=meta['sha256'] or not meta['containerComplete']:raise ValueError('开发原件完整性不符')
        logs,bad,log_hashes=parse_logs(path.parent);conns,capture,quality=inspect(path)
        if capture['sha256']!=meta['sha256']:raise ValueError('读取过程中原件变化')
        log_index=defaultdict(list);conn_index=defaultdict(list)
        for i,r in enumerate(logs):log_index[(r['peer'],r['second'],r['request'],r['status'])].append(i)
        for i,c in enumerate(conns):
            if c['responseAtUs'] is not None:conn_index[(c['origin'][0],c['responseAtUs']//1000000,c['requestLine'],c['status'])].append(i)
        decisions=Counter();reasons=Counter();unique_logs=set()
        for i,c in enumerate(conns):
            k=(c['origin'][0],(c['responseAtUs'] or -1000000)//1000000,c['requestLine'],c['status'])
            matched=log_index.get(k,[]);unique=len(matched)==1 and len(conn_index.get(k,[]))==1
            if unique:unique_logs.add(matched[0])
            scope=c['destination']==(VICTIM,80)
            attack=(scope and c['origin'][0]==ATTACK and bool(c['evidence']) and unique and c['status'] in (400,408))
            normal=(scope and c['origin'][0]==BENIGN and c['completeAtUs'] is not None and unique and c['status']==200 and c['invalid'] is None)
            label=1 if attack else 0 if normal else None
            why=[]
            if not scope:why.append('outside_documented_service')
            if not unique:why.append('no_unique_apache_request_join')
            if c['origin'][0] not in (ATTACK,BENIGN):why.append('undocumented_peer_role')
            if c['origin'][0]==ATTACK and not c['evidence']:why.append('no_causal_header_continuation')
            if label is None and not why:why.append('request_or_status_not_qualified')
            decisions[str(label)]+=1;reasons.update(why)
            row=dict(captureSha256=meta['sha256'],associationGroup=meta['associationGroup'],sourceDayCluster=meta['cluster'],member=meta['member'],sourceConnectionId=hashlib.sha256(json.dumps([meta['sha256'],c['origin'],c['destination'],c['syn'],c['firstUs']]).encode()).hexdigest(),origin=c['origin'],destination=c['destination'],firstUs=c['firstUs'],lastUs=c['lastUs'],label=label,evidenceTier='publisher_documented',labelRuleVersion=VERSION,apacheUniqueJoin=unique,attackStartUs=c['firstUs'] if attack else None,attackStartIntervalUs=[c['firstUs'],c['firstPayloadUs']] if attack else None,evidenceAvailableAtUs=c['evidenceAvailableAtUs'] if attack else None,causalEvidence=c['evidence'] if attack else [],completeAtUs=c['completeAtUs'],futureConnectionIssue=c['invalid'],reasons=why,role='development_unassigned')
            all_rows.append(row)
        summaries.append(dict(member=meta['member'],associationGroup=meta['associationGroup'],cluster=meta['cluster'],connections=len(conns),labels=dict(decisions),unknownReasons=dict(reasons),apacheLogRows=len(logs),apacheLogUnparsed=bad,uniqueApacheRowsJoined=len(unique_logs),apacheHashes=log_hashes,captureSha256=capture['sha256'],quality=quality))
    with (args.output/'labels.jsonl').open('x') as f:
        for r in all_rows:f.write(json.dumps(r)+'\n')
    positives=[r for r in all_rows if r['label']==1];negatives=[r for r in all_rows if r['label']==0]
    result=dict(version=VERSION,captures=summaries,qualifiedAttackAssociationGroups=len({r['associationGroup'] for r in positives}),qualifiedAttackSourceDayClusters=len({r['sourceDayCluster'] for r in positives}),attackConnections=len(positives),benignConnections=len(negatives),unknownConnections=sum(r['label'] is None for r in all_rows),labelsSha256=sha(args.output/'labels.jsonl'),finalRead=False,modelFits=0,prefixDatasetFrozen=False,rolesFrozen=False,status='partial',limitations=['TAARA slow_header only; CIC2017 slow-read remains unqualified','Apache log lacks source ports; ambiguous same-second identical requests excluded','Association groups do not prove independence of shared source-day experiments'])
    (args.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='captures'}))
if __name__=='__main__':main()
