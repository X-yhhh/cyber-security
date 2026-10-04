#!/usr/bin/env python3
"""记录/核对 P2 契约、提取器、golden、评估计划的确切内容；清单本身不参与循环哈希。"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def build():
    paths=set()
    for pattern in ('docs/contracts/**/*.json','sensor/internal/hostguard/*.go','sensor/cmd/guard*/*.go',
                    'sensor/testdata/hostguard-v5/*','scripts/p2/*.py','scripts/p2/*.java'):
        paths.update(p for p in ROOT.glob(pattern) if p.is_file())
    paths.update(ROOT/p for p in ('sensor/go.mod','sensor/go.sum','sensor/internal/packet/parse.go',
                                 'sensor/internal/synth/synth.go','docs/检测与处置契约.md','docs/p2/evaluation-plan.json'))
    # Windows Path 排序不区分大小写；按相对 POSIX 文本排序保证两平台清单字节一致。
    files={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
           for p in sorted(paths,key=lambda p:p.relative_to(ROOT).as_posix())}
    collection=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return dict(version='p2-freeze-manifest-v1',contractVersion='host-guard/5.0.0-rc.2',
                purpose='immutable research candidate; not release approval',collectionSha256=collection,files=files)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');p.add_argument('--output',type=Path,default=ROOT/'docs/p2/freeze-manifest.json');a=p.parse_args()
    result=build();text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if a.check:
        if a.output.read_text(encoding='utf-8')!=text:raise SystemExit('P2 冻结清单与当前文件不一致')
    else:
        with a.output.open('x',encoding='utf-8',newline='\n') as f:f.write(text)
    print(json.dumps(dict(files=len(result['files']),collectionSha256=result['collectionSha256'],status='passed')))

if __name__=='__main__':main()
