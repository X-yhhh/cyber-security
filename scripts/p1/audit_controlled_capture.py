#!/usr/bin/env python3
"""核验受控良性抓包范围与头部参考值；不从无攻击标签推导正常，也不输出原始端点。"""
import argparse
import collections
import hashlib
import ipaddress
import json
from pathlib import Path
from pcap_reference import frames,tcp,Metrics


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--pcap',type=Path,required=True)
    p.add_argument('--task-report',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():raise FileExistsError('保留历史报告')
    m=json.loads(a.manifest.read_text());task=json.loads(a.task_report.read_text())
    local=int(ipaddress.IPv4Address(m['local']));peer=int(ipaddress.IPv4Address(m['peer']))
    ports={m['port'],m['controlPort']};audit={};quality=collections.Counter();flows={};offload=0
    for ts,data,wire,link in frames(a.pcap,audit):
        packet=tcp(ts,data,wire,link,quality)
        if packet is None:raise ValueError('捕获出现范围外协议或不可解析头部')
        if {packet['src'][0],packet['dst'][0]}!={local,peer}:raise ValueError('捕获越过授权端点')
        service=packet['src'][1] if packet['src'][0]==local else packet['dst'][1]
        if service not in ports:raise ValueError('捕获越过授权服务')
        key=packet['key'];offload+=packet['offloadSized']
        if key not in flows:
            flows[key]={'first':ts,'last':ts,'service':'target' if service==m['port'] else 'control',
                        'final':Metrics(local,2**63-1),'prefixes':{s:Metrics(local,ts+s*1000000) for s in (1,5)}}
        flow=flows[key];flow['last']=ts
        for tracker in [flow['final'],*flow['prefixes'].values()]:tracker.add(packet)
    if not audit['frames']:raise ValueError('空捕获不构成证据')
    result={'version':'p1-controlled-capture-audit-v2','pcap':audit,'scopeVerified':True,
            'codeSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'referenceCodeSha256':hashlib.sha256(Path(__file__).with_name('pcap_reference.py').read_bytes()).hexdigest(),
            'manifestSha256':hashlib.sha256(a.manifest.read_bytes()).hexdigest(),
            'labelEvidence':'controlled_task','taskReportSha256':hashlib.sha256(a.task_report.read_bytes()).hexdigest(),
            'successfulClientTasks':sum(t['passed'] for t in task['tasks']),
            'failedClientTasks':sum(not t['passed'] for t in task['tasks']),
            'legitimateTimeoutsRetained':True,'packetQuality':dict(quality),'offloadSizedPackets':offload,
            'contextFeaturesImplemented':False,'flows':[]}
    for key,flow in flows.items():
        result['flows'].append({'connectionDigest':hashlib.sha256(str(key).encode()).hexdigest(),
            'serviceRole':flow['service'],'observedSpanMs':(flow['last']-flow['first'])/1000,
            'finalFeatures':flow['final'].report(),
            'prefixes':{str(s):{'hasPacketAtOrAfterDeadline':flow['last']>=flow['first']+s*1000000,
                               'features':tracker.report()} for s,tracker in flow['prefixes'].items()}})
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'frames':audit['frames'],'connections':len(flows),'offloadSizedPackets':offload,'scopeVerified':True}))


if __name__=='__main__':main()
