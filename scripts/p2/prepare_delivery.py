#!/usr/bin/env python3
"""装配 Windows 离线交付：公开源码/契约与忽略的开发观察分开，禁止复制原始端点或密钥。"""
import argparse
import hashlib
import json
import shutil
import tarfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    frozen=json.loads((ROOT/'docs/p2/freeze-manifest.json').read_text())
    for name,expected in frozen['files'].items():
        if sha(ROOT/name)!=expected:raise ValueError('冻结内容已变化，拒绝交付: '+name)
    a.out.mkdir(mode=0o700)
    public=a.out/'host-guard-v5-rc2';public.mkdir()
    for name in frozen['files']:
        target=public/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
    shutil.copyfile(ROOT/'docs/p2/freeze-manifest.json',public/'freeze-manifest.json')
    # 同时保留仓库原路径，让收件端可直接运行 freeze.py --check。
    shutil.copyfile(ROOT/'docs/p2/freeze-manifest.json',public/'docs/p2/freeze-manifest.json')
    private=a.out/'host-guard-p2-development';private.mkdir(mode=0o700)
    for name in ['partition-index.jsonl','partition-manifest.json']:
        shutil.copyfile(a.run/name,private/name)
    ids={json.loads(line)['observationId'] for line in (a.run/'partition-index.jsonl').open()};found=set()
    with (private/'observations.jsonl').open('x') as out:
        for split in ('train','validation'):
            for line in (a.run/f'{split}-observations.jsonl').open():
                o=json.loads(line)
                if o['observationId'] in ids:
                    if o['observationId'] in found:raise ValueError('重复观察')
                    found.add(o['observationId']);out.write(line)
    if found!=ids:raise ValueError('分区索引指向缺失观察')
    manifest={p.relative_to(a.out).as_posix():sha(p) for p in sorted(a.out.rglob('*')) if p.is_file()}
    (a.out/'delivery-manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
    for folder in (public,private):
        with tarfile.open(a.out/(folder.name+'.tar.gz'),'w:gz') as tar:tar.add(folder,arcname=folder.name)
    print(json.dumps(dict(files=len(manifest),retainedObservations=len(found),endpointLedgerIncluded=False,keyIncluded=False)))

if __name__=='__main__':main()
