#!/usr/bin/env python3
"""用原生 PCAP 验证本轮低并发正常业务；Go 观察/账本另验，不生成替代模型特征。

只允许登记的 DLT_NULL AF_INET 或 RAW 链路、两回环地址和 TCP/80；重组仅
用于核验 HTTP 内容/任务，输出私有连接旁路。截短、冲突、缺口、非正常任务拒绝。
"""
import argparse
from collections import Counter
from datetime import datetime
import hashlib,json,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'p1'))
from pcap_reference import tcp


def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def us(text):return round(datetime.fromisoformat(text.replace('Z','+00:00')).timestamp()*1e6)
def reassemble(parts,base):
    """有界完整字节流；相同重传可合并，冲突或序号缺口拒绝业务验收。"""
    pieces=[((seq-base)%2**32,b) for seq,b in parts]
    if not pieces:return b''
    end=max(s+len(b) for s,b in pieces)
    if end>2*1024*1024:raise ValueError('业务字节流超出预算')
    data=bytearray(end);seen=bytearray(end)
    for s,b in pieces:
        for i,v in enumerate(b,s):
            if seen[i] and data[i]!=v:raise ValueError('冲突 TCP 重叠')
            data[i]=v;seen[i]=1
    if not all(seen):raise ValueError('TCP 业务序号缺口')
    return bytes(data)

def verify(batch,extraction):
    task=json.loads((batch/'task.json').read_text())
    if not task['success'] or not task['listenerClosed'] or not task['capture']['passed']:raise ValueError('任务或采集未通过')
    clock_path=batch.parent/'final-resource-audit.json';tolerance=0.0
    if clock_path.exists():
        # 本轮实测 Python 3.12 Windows 定时器为15.625ms，保留PCAP真实值而非取整。
        clock=json.loads(clock_path.read_text())
        tolerance=clock['clockInfo']['monotonic']['resolution']
        if not 0<tolerance<=.02:raise ValueError('未登记的任务时钟精度')
    conns={};quality=Counter();count=0;first=last=None
    with (batch/'native.pcap').open('rb') as f:
        h=f.read(24)
        if len(h)!=24 or h[:4]!=b'\xd4\xc3\xb2\xa1':raise ValueError('未登记容器')
        link=struct.unpack_from('<I',h,20)[0]
        if link not in (0,12,101):raise ValueError('未登记原生链路')
        while True:
            h=f.read(16)
            if not h:break
            if len(h)!=16:raise ValueError('容器头截短')
            sec,micro,cap,wire=struct.unpack('<IIII',h);b=f.read(cap)
            if len(b)!=cap or cap!=wire or micro>=1000000 or cap>65535:raise ValueError('容器或报文截短')
            ts=sec*1000000+micro;first=ts if first is None else min(first,ts);last=ts if last is None else max(last,ts)
            if link==0:
                if b[:4]!=struct.pack('<I',2):raise ValueError('非 AF_INET 的 NULL 输入')
                # 标签/业务旁路只读原件；现场特征始终由 Go 对原生 PCAP 提取。
                p=tcp(ts,b[4:],wire-4,101,quality);ip=b[4:]
            else:p=tcp(ts,b,wire,link,quality);ip=b
            count+=1
            if not p or {p['src'][0],p['dst'][0]}!={0x7f000001,0x7f000002}:raise ValueError('捕获超出授权地址')
            forward=p['dst']==(0x7f000001,80)
            if not forward and p['src']!=(0x7f000001,80):raise ValueError('捕获超出服务')
            key=p['key'];c=conns.get(key);syn=bool(p['flags']&2 and not p['flags']&16)
            if syn:
                if not forward:raise ValueError('未知主动方向')
                if c and c['base']!=(p['seq']+1)%2**32:raise ValueError('同五元组多 epoch')
                if c is None:c=dict(base=(p['seq']+1)%2**32,reverseBase=None,firstUs=ts,lastUs=ts,closeUs=None,request=[],response=[],peerPort=p['src'][1]);conns[key]=c
            if c is None:raise ValueError('捕获缺 SYN 起点')
            c['lastUs']=max(c['lastUs'],ts)
            if p['flags']&5 and c['closeUs'] is None:c['closeUs']=ts
            if not forward and p['flags']&2:c['reverseBase']=(p['seq']+1)%2**32
            payload=ip[p['payloadOffset']:p['payloadOffset']+p['payloadBytes']]
            if payload:c['request' if forward else 'response'].append(((p['seq']+bool(p['flags']&2))%2**32,payload))
    records=[];kinds=Counter();durations={}
    for c in conns.values():
        if c['reverseBase'] is None or c['closeUs'] is None:raise ValueError('握手/结束证据不足')
        req=reassemble(c['request'],c['base']);resp=reassemble(c['response'],c['reverseBase'])
        header,body=resp.split(b'\r\n\r\n',1);line=req.split(b'\r\n',1)[0].decode('ascii');method,path,protocol=line.split(' ')
        status=int(header.split(b' ')[1]);lengths=[v.split(b':',1)[1].strip() for v in header.split(b'\r\n') if v.lower().startswith(b'content-length:')]
        if len(lengths)!=1 or int(lengths[0])!=len(body):raise ValueError('HTTP 响应不完整')
        if path.startswith('/stream/'):
            seconds=int(path.rsplit('/',1)[1]);expected=bytes(range(256))*4*seconds*10;kind=f'download_{seconds}';durations[seconds]=(c['lastUs']-c['firstUs'])/1e6
            if seconds not in (30,60,120) or not seconds-tolerance<=durations[seconds]<=seconds+3:raise ValueError('真实下载连接时长不符')
        elif path=='/complete':
            expected=b'OK';kind='legal_segmented_request'
            if method!='POST' or req.split(b'\r\n\r\n',1)[1]!=b'123456789':raise ValueError('合法分段请求未完整结束')
        elif path=='/wait/30':expected=b'OK';kind='long_poll';durations['long_poll']=(c['lastUs']-c['firstUs'])/1e6
        elif path=='/range':
            resumed=b'Range: bytes=512-\r\n' in req;expected=(bytes(range(256))*8)[512 if resumed else 0:];kind='range_resume' if resumed else 'range_initial'
            if status!=(206 if resumed else 200):raise ValueError('Range 状态不符')
        else:raise ValueError('不是登记任务路径')
        if body!=expected or status not in (200,206):raise ValueError('业务内容/状态不符')
        kinds[kind]+=1;records.append(dict(peerPort=c['peerPort'],firstUs=c['firstUs'],lastUs=c['lastUs'],closedAtUs=c['closeUs'],kind=kind,bodySha256=hashlib.sha256(body).hexdigest(),passed=True))
    expected_kinds={k:1 for k in ['download_30','download_60','download_120','legal_segmented_request','long_poll','range_initial','range_resume']}
    if dict(kinds)!=expected_kinds or count!=task['capture']['frames']:raise ValueError('任务/捕获计数不符')
    if not 30-tolerance<=durations['long_poll']<=33:raise ValueError('真实长轮询时长不符')
    times=sorted([(r['firstUs'],1) for r in records]+[(r['closedAtUs'],-1) for r in records]);active=maximum=0
    for _,delta in times:active+=delta;maximum=max(maximum,active)
    if maximum>4:raise ValueError('真实并发超限')
    ex=json.loads((extraction/'extraction.json').read_text())
    if ex['pcapSha256']!=sha(batch/'native.pcap') or ex['observationsSha256']!=sha(extraction/'observations.jsonl') or ex['localLedgerSha256']!=sha(extraction/'ledger.jsonl'):raise ValueError('Go 观察/原件绑定不符')
    prefixes=0;parents=set();defects=Counter();bound=[]
    for o,l in zip(map(json.loads,(extraction/'observations.jsonl').open()),map(json.loads,(extraction/'ledger.jsonl').open()),strict=True):
        if o['observationId']!=l['observationId'] or o['parentConnectionId']!=l['parentConnectionId']:raise ValueError('观察/账本顺序不符')
        e=l['Endpoints'];port=int(e['Peer'].rsplit(':',1)[1]);matched=[r for r in records if r['peerPort']==port and abs(us(o['firstSeenAt'])-r['firstUs'])<=1 and us(o['lastPacketAt'])<=r['lastUs']+1]
        if e['Local']!='127.0.0.1:80' or len(matched)!=1:continue
        bad=[k for k,v in o['quality'].items() if v is True]
        defects.update(bad)
        if bad or o['profile']!='flow-prefix-v1':continue
        parents.add(o['parentConnectionId']);prefixes+=1
        bound.append(dict(observationId=o['observationId'],parentConnectionId=o['parentConnectionId'],activityId=task['activityId'],split=task['role'],label=0,evidenceTier='controlled_task',firstSeenAt=o['firstSeenAt'],asOf=o['asOf'],taskKind=matched[0]['kind']))
    result=dict(version='long-benign-pcap-audit-v1',passed=True,activityId=task['activityId'],role=task['role'],nativeLink=link,frames=count,pcapSha256=sha(batch/'native.pcap'),taskSha256=sha(batch/'task.json'),extractionSha256=sha(extraction/'extraction.json'),connections=len(records),maxConcurrent=maximum,actualConnectionSeconds=durations,captureDrops=task['capture']['stats']['dropped'],listenerClosed=task['listenerClosed'],qualifiedPrefixObservations=prefixes,qualifiedParents=len(parents),qualityDefects=dict(defects),pcapDurationSeconds=(last-first)/1e6,goLiveVerified=False)
    result['nominalDurationToleranceSeconds']=tolerance
    result['clockEvidenceSha256']=sha(clock_path) if clock_path.exists() else None
    result['version']='long-benign-pcap-audit-v2' if clock_path.exists() else 'long-benign-pcap-audit-v1'
    result['verifierSha256']=sha(Path(__file__))
    return result,records,bound

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--batch',type=Path,required=True);p.add_argument('--extraction',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result,records,bound=verify(a.batch,a.extraction);a.output.mkdir(exist_ok=False)
    for name,rows in [('connections.jsonl',records),('prefix-index.jsonl',bound)]:
        with (a.output/name).open('x') as f:
            for r in rows:f.write(json.dumps(r)+'\n')
    (a.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
