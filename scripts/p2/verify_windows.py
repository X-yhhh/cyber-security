#!/usr/bin/env python3
"""Windows 本机离线验收：核对同步清单，实际执行提取器/测试，不改训练文件或系统配置。"""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bundle',type=Path,required=True);a=p.parse_args();root=a.bundle.resolve()
    if platform.system()!='Windows':raise SystemExit('必须在 Windows 实际执行')
    manifest=json.loads((root/'transfer-manifest.json').read_text())
    for name,h in manifest.items():
        if sha(root/name)!=h:raise SystemExit('同步制品哈希不符: '+name)
    cfg=json.loads((root/'private-config.json').read_text());cfg['secretFile']=str(root/'peer-key.bin')
    config=root/'windows-config.json'
    if config.exists():
        if json.loads(config.read_text())!=cfg:raise SystemExit('已有验证配置不匹配')
    else:
        with config.open('x') as f:json.dump(cfg,f)
    commands=[
        [str(root/'hostguard.test.exe'),'-test.v'],
        [str(root/'guardgolden.exe'),'-dir',str(root/'golden'),'-check'],
        [str(root/'guardextract.exe'),'-config',str(config),'-pcap',str(root/'controlled.pcap'),
         '-out',str(root/'windows-observations.jsonl'),'-report',str(root/'windows-extraction.json')],
    ]
    results=[]
    for i,cmd in enumerate(commands):
        try:
            run=subprocess.run(cmd,text=True,encoding='utf-8',errors='replace',capture_output=True,timeout=120)
            (root/f'command-{i}.log').write_text(run.stdout+'\n'+run.stderr)
            results.append(dict(program=Path(cmd[0]).name,exitCode=run.returncode,logSha256=sha(root/f'command-{i}.log')))
        except OSError as error:
            results.append(dict(program=Path(cmd[0]).name,exitCode=None,windowsError=getattr(error,'winerror',None),
                                status='blocked_by_system_policy' if getattr(error,'winerror',None)==4551 else 'launch_failed'))
    extractor_ok=len(results)==3 and results[2]['exitCode']==0
    passed=len(results)==3 and all(r['exitCode']==0 for r in results)
    actual=sha(root/'windows-observations.jsonl') if extractor_ok else None
    expected=(root/'expected-observations.sha256').read_text().strip()
    passed=passed and actual==expected
    blocked=any(r.get('windowsError')==4551 for r in results)
    report=dict(version='p2-windows-verification-v1',status='passed' if passed else 'blocked' if blocked else 'failed',
                system=platform.system(),machine=platform.machine(),osVersion=platform.version(),
                python=sys.version.split()[0],commands=results,filesHashVerified=len(manifest),
                observationSha256=actual,expectedObservationSha256=expected,
                goldenExecuted=True if len(results)>=2 and results[1]['exitCode']==0 else False,
                extractorExecuted=True if len(results)==3 and results[2]['exitCode']==0 else False,
                trainingExecuted=False,liveCaptureExecuted=False,firewallModified=False)
    with (root/'windows-verification.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report));raise SystemExit(0 if passed else 1)

if __name__=='__main__':main()
