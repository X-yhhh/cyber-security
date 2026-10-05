#!/usr/bin/env python3
"""仅在用户明确验收窗口运行一次真实重启；不重试重启、不重放旧租约。

前三阶段连接和动态规则须先通过，剩余租期不足5秒则拒绝重启。
启动后采集独立观察器原始证据，不能以重新连接成功替代严格TTL核验。
"""
import argparse
import base64
import json
from pathlib import Path
import time

from connection_probe import connection, echo, fresh
from run_wfp_probe import await_file, launch, quote, remote, gitbash_to_windows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host',required=True);p.add_argument('--remote-root',required=True)
    p.add_argument('--python',required=True);p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--execute-one-reboot',action='store_true',required=True)
    a=p.parse_args();root=a.remote_root;case=root+'\\reboot-01';manifest=root+'\\manifest.json'
    if a.output.exists():p.error('Output already exists; a reboot attempt cannot be reused')
    m=json.loads(a.manifest.read_text());r={'case':'reboot','rebootCommandAttempts':0}
    try:
        r['supervisorPid']=launch(a.host,a.python,f'{root}\\wfp_probe.py supervise --manifest {manifest} --case-dir {case}',root)
        r['ready']=await_file(a.host,case+'\\ready.json',25)
        r['watcherPid']=launch(a.host,a.python,f'{root}\\wfp_reboot_observer.py watch --manifest {manifest} --case-dir {case}',root)
        remote(a.host,f"$end=[DateTime]::UtcNow.AddSeconds(10);while(-not(Test-Path {quote(case+'\\reboot-watch.jsonl')})){{if([DateTime]::UtcNow -ge $end){{throw 'WATCHER_NOT_READY'}};Start-Sleep -Milliseconds 100}}")
        code=[]
        binary_win = gitbash_to_windows(m['binary'])
        root_win = gitbash_to_windows(root)
        for port in (m['port'],m['controlPort'],m['controlPort']+1):
            args = f'--listen {m["local"]}:{port} --peer {m["peer"]} --duration 180s'
            code.append(f"$x=Start-Process -FilePath {quote(binary_win)} -ArgumentList {quote(args)} -WorkingDirectory {quote(root_win)} -WindowStyle Hidden -PassThru;if(-not $x){{throw 'CANARY_FAILED'}};$x.Id")
        r['canaryPids']=[int(x) for x in remote(a.host,';'.join(code)).splitlines()]
        time.sleep(.5)
        r['isolationDeniedPort']=fresh(m['local'],m['controlPort']+1)
        with connection(m['local'],m['port']) as target,connection(m['local'],m['controlPort']) as control:
            r['before']={'targetExisting':echo(target),'targetNew':fresh(m['local'],m['port']),
                         'controlExisting':echo(control),'controlNew':fresh(m['local'],m['controlPort'])}
            if not all(x['ok'] for x in r['before'].values()) or r['isolationDeniedPort']['ok']:
                raise RuntimeError('BASELINE_FAILED_NO_REBOOT')
            c={k:m[k] for k in ('runId','local','peer','port')}
            c.update(bootId=r['ready']['bootId'],executorId=r['ready']['executorId'],actionId='reboot-01',issuedUtc=None,applyBy=None,blockUntil=None)
            data=base64.b64encode(json.dumps(c).encode()).decode()
            script=f"$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{data}')) | ConvertFrom-Json;$n=[DateTime]::UtcNow;$c.issuedUtc=$n.ToString('o');$c.applyBy=$n.AddSeconds(10).ToString('o');$c.blockUntil=$n.AddSeconds(30).ToString('o');[IO.File]::WriteAllText({quote(case+'\\command.pending')},($c | ConvertTo-Json));[IO.File]::Move({quote(case+'\\command.pending')},{quote(case+'\\command.json')});$end=$n.AddSeconds(8);while(-not(Test-Path {quote(case+'\\applied.json')})){{if([DateTime]::UtcNow -ge $end){{throw 'APPLY_TIMEOUT'}};Start-Sleep -Milliseconds 50}};Get-Content {quote(case+'\\applied.json')} -Raw"
            r['applied']=json.loads(remote(a.host,script))
            r['during']={'targetExisting':echo(target),'targetNew':fresh(m['local'],m['port']),
                         'controlExisting':echo(control),'controlNew':fresh(m['local'],m['controlPort'])}
            if any(r['during'][k]['ok'] is not v for k,v in {'targetExisting':False,'targetNew':False,'controlExisting':True,'controlNew':True}.items()):
                raise RuntimeError('BLOCK_NOT_VERIFIED_NO_REBOOT')
            # 意图必须在本机和远端各落盘一次；网络失败后不重试 shutdown，改查boot与系统事件。
            r['rebootCommandAttempts']=1
            a.output.write_text(json.dumps(r,indent=2)+'\n')
            code=f"$c=Get-Content {quote(case+'\\command.json')} -Raw | ConvertFrom-Json;$n=[DateTime]::UtcNow;if($n -ge [DateTime]::Parse($c.blockUntil).ToUniversalTime().AddSeconds(-5)){{throw 'INSUFFICIENT_LEASE_NO_REBOOT'}};if(Test-Path {quote(case+'\\final.json')}){{throw 'SESSION_ALREADY_CLOSED_NO_REBOOT'}};$actual=& {quote(a.python)} {quote(root+'\\wfp_probe.py')} inspect | ConvertFrom-Json;if(@($actual.filters).Count -ne 2){{throw 'FILTERS_NOT_ACTIVE_NO_REBOOT'}};$intent=@{{requestedUtc=[DateTime]::UtcNow.ToString('o');bootId=$c.bootId;blockUntil=$c.blockUntil;filterCount=@($actual.filters).Count;authorizedSingleReboot=$true}};$f=[IO.File]::Open({quote(case+'\\restart-intent.json')},[IO.FileMode]::CreateNew);try{{$b=[Text.Encoding]::UTF8.GetBytes(($intent | ConvertTo-Json));$f.Write($b,0,$b.Length);$f.Flush($true)}}finally{{$f.Dispose()}};& shutdown.exe /r /t 0 /d p:0:0 /c 'HostGuard P1 authorized one-time acceptance';if($LASTEXITCODE -ne 0){{throw 'SHUTDOWN_REQUEST_FAILED'}};'REBOOT_REQUEST_ACCEPTED'"
            r['dispatchResult']=remote(a.host,code)
    except Exception as error:
        r['error']=str(error)
    finally:
        a.output.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({k:r[k] for k in ('rebootCommandAttempts','dispatchResult','error') if k in r}))
    if 'error' in r:
        raise SystemExit(1)


if __name__=='__main__':main()
