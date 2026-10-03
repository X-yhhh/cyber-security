#!/usr/bin/env python3
"""P1 受控良性任务：固定文件正常下载、四路并发和一次断点恢复；不生成攻击流量。"""
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import time
import threading
from pathlib import Path

# 固定4 MiB夹具的前256 KiB更新片段；较低带宽链路也能在180秒任务边界内完成。
SIZE=256*1024
EXPECTED=hashlib.sha256(bytes(range(251))*(SIZE//251)+bytes(range(SIZE%251))).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise FileExistsError('保留已有任务记录')
    m=json.loads(a.manifest.read_text());host=m['local'];port=m['port']
    ip=ipaddress.IPv4Address(host)
    if not (ip.is_private or ip in ipaddress.ip_network('100.64.0.0/10')) or not 49152<=port<=65533:
        raise ValueError('目标超出授权探针范围')
    progress=a.output.with_suffix('.progress.jsonl')
    if progress.exists():raise FileExistsError('任务进展记录已存在')
    progress.touch();lock=threading.Lock()
    def record(result):
        with lock:
            with progress.open('a') as f:f.write(json.dumps(result)+'\n')
        return result
    def download(kind,index,service=port):
        start=dt.datetime.now(dt.timezone.utc).isoformat();tick=time.monotonic()
        c=http.client.HTTPConnection(host,service,timeout=30)
        try:
            c.request('GET','/fixture.bin',headers={'Range':f'bytes=0-{SIZE-1}'});r=c.getresponse();body=r.read(SIZE+1)
            h=hashlib.sha256(body).hexdigest()
            return record({'kind':kind,'index':index,'startedUtc':start,'endedUtc':dt.datetime.now(dt.timezone.utc).isoformat(),
                    'elapsedMs':round((time.monotonic()-tick)*1000,3),'status':r.status,'bytes':len(body),'sha256':h,
                    'passed':r.status==206 and len(body)==SIZE and h==EXPECTED})
        except (OSError,http.client.HTTPException) as exc:
            return record({'kind':kind,'index':index,'startedUtc':start,'error':type(exc).__name__,'bytes':0,'passed':False})
        finally:c.close()
    report={'version':'p1-controlled-benign-http-v1','labelEvidence':'controlled_task',
            'maxConcurrentDownloads':4,'fixtureBytes':4*1024*1024,'requestedSegmentBytes':SIZE,'segmentSha256':EXPECTED,
            'tasks':[],'trafficGeneration':'ordinary_get_and_range_only'}
    report['tasks'] += [download('sequential',i) for i in range(2)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        report['tasks'] += list(pool.map(lambda i:download('concurrent',i),range(4)))
    start=dt.datetime.now(dt.timezone.utc).isoformat()
    c=http.client.HTTPConnection(host,port,timeout=30)
    try:c.request('GET','/fixture.bin',headers={'Range':f'bytes=0-{SIZE-1}'});r=c.getresponse();head=r.read(65536)
    finally:c.close()
    c=http.client.HTTPConnection(host,port,timeout=30)
    try:
        c.request('GET','/fixture.bin',headers={'Range':f'bytes={len(head)}-{SIZE-1}'})
        r=c.getresponse();tail=r.read(SIZE+1);h=hashlib.sha256(head+tail).hexdigest()
        report['tasks'].append({'kind':'interrupted_then_range_resume','startedUtc':start,
            'endedUtc':dt.datetime.now(dt.timezone.utc).isoformat(),'status':r.status,'bytes':len(head)+len(tail),
            'sha256':h,'passed':r.status==206 and len(head)+len(tail)==SIZE and h==EXPECTED})
    finally:c.close()
    report['tasks'].append(download('unaffected_control',0,m['controlPort']))
    report['passed']=all(t['passed'] for t in report['tasks'])
    with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({'passed':report['passed'],'tasks':len(report['tasks']),
                      'validatedBytes':sum(t['bytes'] for t in report['tasks'])}),flush=True)
    if not report['passed']:raise SystemExit(1)


if __name__=='__main__':main()
