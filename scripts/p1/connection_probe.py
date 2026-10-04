#!/usr/bin/env python3
"""P1 普通 TCP 回显实测。只向已登记 peer 的两个高端口发送固定问候，不构造攻击流量。"""
import argparse
import base64
import datetime as dt
import json
import re
import socket
import subprocess
import time
from pathlib import Path

GREETING=b'host-guard-p1-canary\n'


def evaluate(report):
    """以连接、规则和恢复证据判定，失败或缺证不能因命令正常退出而通过。"""
    expected = {
        'before': {'targetExisting':True, 'targetNew':True, 'controlExisting':True, 'controlNew':True},
        'during': {'targetExisting':False, 'targetNew':False, 'controlExisting':True, 'controlNew':True},
        'after': {'targetNew':True, 'controlExisting':True, 'controlNew':True},
    }
    failures = [f'{phase}.{name}' for phase, checks in expected.items()
                for name, value in checks.items()
                if report.get(phase, {}).get(name, {}).get('ok') is not value]
    if report.get('remainingBlockRules') != 0:
        failures.append('remainingBlockRules')
    tasks = report.get('recoveryTask', [])
    if len(tasks) != 1 or tasks[0].get('lastResult') != 0:
        failures.append('independentRecovery')
    return {'passed':not failures, 'failedChecks':failures}


def run_ps(host,script,check=True):
    encoded=base64.b64encode(script.encode('utf-16le')).decode()
    cmd=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',host,
         'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand '+encoded]
    return subprocess.run(cmd,capture_output=True,text=True,timeout=35,check=check)


def echo(sock):
    started=time.monotonic()
    try:
        sock.sendall(GREETING);buf=b''
        while len(buf)<len(GREETING):
            v=sock.recv(len(GREETING)-len(buf))
            if not v:return {'ok':False,'error':'closed'}
            buf+=v
        return {'ok':buf==GREETING,'elapsedMs':round((time.monotonic()-started)*1000,3),
                'observedUtc':dt.datetime.now(dt.timezone.utc).isoformat()}
    except OSError as e:return {'ok':False,'error':type(e).__name__,'elapsedMs':round((time.monotonic()-started)*1000,3)}


def connection(peer,port):
    s=socket.create_connection((peer,port),timeout=3);s.settimeout(3);return s


def fresh(peer,port):
    try:
        with connection(peer,port) as s:return echo(s)
    except OSError as e:return {'ok':False,'error':type(e).__name__}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',required=True,type=Path);p.add_argument('--remote-dir',required=True)
    p.add_argument('--host',required=True);p.add_argument('--case',choices=['ttl','process-exit','channel-loss'],required=True)
    p.add_argument('--suffix',default='')
    p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    m=json.loads(a.manifest.read_text());peer=m['local'];port=m['port']
    if not 49152<=port<=65533 or a.output.exists() or not re.fullmatch('[a-z0-9-]{0,10}',a.suffix):raise ValueError('范围/输出无效')
    case_id=a.case+a.suffix
    q=lambda s:"'"+s.replace("'","''")+"'"
    script=q(a.remote_dir+'\\windows-rule-probe.ps1');manifest=q(a.remote_dir+'\\manifest.json')
    report={'case':a.case,'startedUtc':dt.datetime.now(dt.timezone.utc).isoformat()}
    with connection(peer,port) as target,connection(peer,port+1) as control:
        report['before']={'targetExisting':echo(target),'controlExisting':echo(control),
                          'targetNew':fresh(peer,port),'controlNew':fresh(peer,port+1)}
        if not all(v['ok'] for v in report['before'].values()):raise RuntimeError('Baseline failed')
        cmd=f"$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop'; & {script} -Mode Block -ManifestPath {manifest} -Case {case_id}"
        if a.case=='process-exit':cmd+='; Stop-Process -Id $PID -Force'
        if a.case=='channel-loss':
            cmd+='; Write-Output CONTROL_CHANNEL_READY; Start-Sleep -Seconds 90'
            enc=base64.b64encode(cmd.encode('utf-16le')).decode()
            child=subprocess.Popen(['ssh','-o','BatchMode=yes',a.host,'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand '+enc],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            line=child.stdout.readline();lease=json.loads(line)
            if child.stdout.readline().strip()!='CONTROL_CHANNEL_READY':raise RuntimeError('Channel setup failed')
            child.terminate();child.wait(timeout=5);report['controlChannelTerminated']=True
        else:
            r=run_ps(a.host,cmd,check=a.case!='process-exit')
            lease=json.loads(r.stdout.strip().splitlines()[-1]);report['actionProcessExit']=r.returncode
        report['lease']=lease
        report['during']={'targetExisting':echo(target),'targetNew':fresh(peer,port),
                          'controlExisting':echo(control),'controlNew':fresh(peer,port+1)}
        print(json.dumps({'case':a.case,'during':report['during']}),flush=True)
        expiry=dt.datetime.fromisoformat(lease['expiresUtc'].replace('Z','+00:00'))
        time.sleep(max(0,(expiry-dt.datetime.now(dt.timezone.utc)).total_seconds())+2)
        report['after']={'targetNew':fresh(peer,port),'controlExisting':echo(control),'controlNew':fresh(peer,port+1)}
        report['observedAfterUtc']=dt.datetime.now(dt.timezone.utc).isoformat()
        status=run_ps(a.host,f"$ProgressPreference='SilentlyContinue'; & {script} -Mode Status -ManifestPath {manifest}")
        state=json.loads(status.stdout);report['remainingBlockRules']=sum('.block.' in r['name'] for r in state['rules'])
        report['recoveryTask']=[t for t in state['cleanupTasks'] if t['name']==lease['name']+'.Cleanup']
        report['services']=state['services'];report['firewallEnabled']=state['firewallEnabled']
    report['evaluation']=evaluate(report)
    with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({'case':a.case,'after':report['after'],'remainingBlockRules':report['remainingBlockRules']}),flush=True)
    if not report['evaluation']['passed']:
        raise SystemExit(1)


if __name__=='__main__':main()
