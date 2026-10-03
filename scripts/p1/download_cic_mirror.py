#!/usr/bin/env python3
"""用已有 Kaggle SDK 下载同一公开 PCAP 的镜像，分段响应严格校验，完成后核对指定来源的 MD5。

只接受本轮两项固定文件；不记录认证信息或签名 URL。不把部分文件当作完整数据。
分段状态可恢复；每段仅在写入并 fsync 后确认完成。镜像的许可声明不能替代官方条件。
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import threading
import time
from pathlib import Path

import requests
from kaggle.api.kaggle_api_extended import KaggleApi, ApiDownloadDatasetRequest

FILES = {
    'wednesday': ('Wednesday-WorkingHours/Wednesday-WorkingHours.pcap', 13420789612),
    'friday': ('Friday-WorkingHours/Friday-WorkingHours.pcap', 8839309056),
}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--day',choices=FILES,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--md5',required=True)
    parser.add_argument('--checksum-source',choices=('official','mirror'),default='official',
                        help='校验文件的实际取得来源；镜像校验不等于官方独立核验')
    parser.add_argument('--workers',type=int,default=4,choices=range(1,17))
    args=parser.parse_args()
    if len(args.md5)!=32 or any(x not in '0123456789abcdef' for x in args.md5):
        raise ValueError('需要有效 MD5')
    filename,size=FILES[args.day]
    output=args.output
    if output.exists():raise FileExistsError('目标已存在，禁止覆盖')
    output.parent.mkdir(parents=True,exist_ok=True)
    partial=output.with_suffix(output.suffix+'.partial')
    ledger=partial.with_suffix(partial.suffix+'.json')
    block=64*1024*1024
    api=KaggleApi();api.authenticate()
    with api.build_kaggle_client() as client:
        request=ApiDownloadDatasetRequest()
        request.owner_slug='congyuanxu';request.dataset_slug='cicids2017';request.file_name=filename
        response=client.datasets.dataset_api_client.download_dataset(request)
    if response.status_code!=200 or int(response.headers.get('Content-Length',0))!=size:
        response.close();raise ValueError('镜像大小/状态不符')
    url=response.url;headers=dict(response.request.headers);response.close()
    chunks=[(n,min(size-1,n+block-1)) for n in range(0,size,block)]
    state={'version':1,'day':args.day,'size':size,'blockBytes':block,'done':[]}
    if ledger.exists():
        state=json.loads(ledger.read_text())
        if state['size']!=size or state['day']!=args.day or state['blockBytes']!=block:
            raise ValueError('续传状态不符')
    elif partial.exists():
        raise ValueError('无分段账本的部分文件不能直接复用')
    fd=os.open(partial,os.O_CREAT|os.O_RDWR,0o600)
    os.ftruncate(fd,size)
    lock=threading.Lock();started=time.monotonic();initial=len(state['done'])
    def save():
        tmp=ledger.with_suffix('.pending')
        tmp.write_text(json.dumps(state,sort_keys=True)+'\n');tmp.replace(ledger)
    save()
    def transfer(pair):
        start,end=pair
        for attempt in range(4):
            try:
                h={**headers,'Range':f'bytes={start}-{end}','Accept-Encoding':'identity'}
                with requests.get(url,headers=h,stream=True,timeout=(20,60)) as r:
                    if r.status_code!=206 or r.headers.get('Content-Range')!=f'bytes {start}-{end}/{size}':
                        raise ValueError('服务器不支持精确分段')
                    pos=start
                    for data in r.iter_content(1024*1024):
                        if pos+len(data)>end+1:raise ValueError('分段超长')
                        view=memoryview(data)
                        while view:
                            written=os.pwrite(fd,view,pos)
                            if not written:raise IOError('写入未完成')
                            pos+=written;view=view[written:]
                    if pos!=end+1:raise ValueError('分段截断')
                os.fsync(fd)
                with lock:
                    state['done'].append(start);save()
                    count=len(state['done']);elapsed=time.monotonic()-started
                    print(json.dumps({'completeChunks':count,'totalChunks':len(chunks),
                        'newMiBPerSecond':round((count-initial)*block/max(1,elapsed)/1048576,2)}),flush=True)
                return
            except Exception as exc:
                if attempt==3:
                    # requests 异常含签名 URL；只报告类型，保留未确认段供后续重试。
                    raise RuntimeError('分段失败: '+type(exc).__name__) from None
                time.sleep(min(8,2**attempt))
    try:
        pending=[c for c in chunks if c[0] not in set(state['done'])]
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            list(pool.map(transfer,pending))
    finally:
        os.close(fd)
    md5=hashlib.md5();sha=hashlib.sha256()
    with partial.open('rb') as f:
        while data:=f.read(8*1024*1024):md5.update(data);sha.update(data)
    if md5.hexdigest()!=args.md5:raise ValueError('预期 MD5 不符，禁止用于分析')
    partial.rename(output)
    state.update({'status':'complete','md5':md5.hexdigest(),'sha256':sha.hexdigest(),
                  'mirror':'congyuanxu/cicids2017','file':filename,
                  'checksumSource':args.checksum_source,
                  'officialChecksumVerified':args.checksum_source=='official'})
    save();print(json.dumps({k:v for k,v in state.items() if k!='done'}),flush=True)


if __name__=='__main__':
    main()
