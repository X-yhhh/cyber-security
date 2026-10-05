#!/usr/bin/env python3
"""从授权 Mac 对 win-dev 做一次真实 SCM STOP/PRESHUTDOWN 验收。

复用已获准 Python 和 canary，四条程序级网络隔离规则另有 SYSTEM 到期清理。
只操作新登记的服务/任务/规则；重启意图先落盘，SSH 中断后只查状态、不重发。
所有端点和进程证据保存在忽略目录，不激活模型、不改变系统应用控制。
"""
import argparse
import base64
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import subprocess
import time
import uuid

from connection_probe import connection,echo,fresh
from run_wfp_probe import remote,quote,await_file,launch,write_remote,evaluate


def command(root,python,name,case):
    return f'"{python}" "{root}\\wfp_bootstrap.py" --module-dir "{root}" --logs "{root}\\service-logs" --mode service --manifest "{root}\\manifest.json" --service-name "{name}" --case-dir "{root}\\{case}"'


def setup(a,m):
    q=quote;group='HostGuard.'+m['runId'];p=a.remote_root
    # 隔离仅针对专用 canary 程序，绝不限制共享 Python、SSH 或 Tailscale。
    code=f"""$m=Get-Content {q(p+'\\manifest.json')} -Raw|ConvertFrom-Json;$g={q(group)};
if((Get-FileHash $m.binary).Hash.ToLowerInvariant() -ne $m.binarySha256){{throw 'CANARY_HASH_MISMATCH'}};
if(@(Get-NetFirewallProfile|Where-Object {{-not $_.Enabled}}).Count){{throw 'FIREWALL_DISABLED'}};
if(@(Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue).Count){{throw 'NAMESPACE_EXISTS'}};
New-Item {q(p+'\\service-logs')} -ItemType Directory -ErrorAction Stop|Out-Null;
New-Item {q(p+'\\boot-logs')} -ItemType Directory -ErrorAction Stop|Out-Null;
$principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest;
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;
foreach($suffix in @('isolation-egress','isolation-peer','isolation-ports','allow-canary')){{
 $n=$g+'.'+$suffix;$action=New-ScheduledTaskAction -Execute ($env:WINDIR+'\\System32\\netsh.exe') -Argument ('advfirewall firewall delete rule name='+$n);
 Register-ScheduledTask -TaskName ($n+'.Cleanup') -Action $action -Principal $principal -Settings $settings -Trigger (New-ScheduledTaskTrigger -Once -At ([DateTime]::Parse($m.expiresUtc).ToLocalTime()))|Out-Null;
}};
$ip=[Net.IPAddress]::Parse($m.peer);$b=$ip.GetAddressBytes();[Array]::Reverse($b);$n=[BitConverter]::ToUInt32($b,0);
function Addr([uint32]$v){{$b=[BitConverter]::GetBytes($v);[Array]::Reverse($b);([Net.IPAddress]::new($b)).ToString()}};
$outside=@(('0.0.0.1-'+(Addr ($n-1))),((Addr ($n+1))+'-255.255.255.254'),'::/1','8000::/1');
$b=@{{Group=$g;Program=$m.binary;Profile='Any';PolicyStore='PersistentStore';Enabled='True'}};
New-NetFirewallRule @b -Name ($g+'.isolation-egress') -DisplayName ($g+'.isolation-egress') -Direction Outbound -Action Block -Protocol Any|Out-Null;
New-NetFirewallRule @b -Name ($g+'.isolation-peer') -DisplayName ($g+'.isolation-peer') -Direction Inbound -Action Block -Protocol Any -RemoteAddress $outside|Out-Null;
$lower='1-'+([int]$m.port-1).ToString();$upper=([int]$m.controlPort+1).ToString()+'-65535';
New-NetFirewallRule @b -Name ($g+'.isolation-ports') -DisplayName ($g+'.isolation-ports') -Direction Inbound -Action Block -Protocol TCP -LocalPort @($lower,$upper)|Out-Null;
New-NetFirewallRule @b -Name ($g+'.allow-canary') -DisplayName ($g+'.allow-canary') -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $m.local -RemoteAddress $m.peer -LocalPort @($m.port,$m.controlPort)|Out-Null;
'ISOLATION_INSTALLED'"""
    remote(a.host,code)


def install_service(a,name,case):
    remote(a.host,f"New-Service -Name {quote(name)} -BinaryPathName {quote(command(a.remote_root,a.python,name,case))} -StartupType Manual -DependsOn BFE|Out-Null;Start-Service {quote(name)}")


def apply_command(a,m,case,ready):
    c={k:m[k] for k in ('runId','local','peer','port')}
    c.update(bootId=ready['bootId'],executorId=ready['executorId'],actionId=case)
    value=base64.b64encode(json.dumps(c).encode()).decode();folder=a.remote_root+'\\'+case
    script=f"$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{value}'))|ConvertFrom-Json;$n=[DateTime]::UtcNow;"
    for name,offset in [('issuedUtc',0),('applyBy',10),('blockUntil',30)]:
        script+=f"$c|Add-Member NoteProperty {name} ($n.AddSeconds({offset}).ToString('o'));"
    script+=f"$f=[IO.File]::Open({quote(folder+'\\command.pending')},[IO.FileMode]::CreateNew);try{{$b=[Text.Encoding]::UTF8.GetBytes(($c|ConvertTo-Json));$f.Write($b,0,$b.Length);$f.Flush($true)}}finally{{$f.Dispose()}};[IO.File]::Move({quote(folder+'\\command.pending')},{quote(folder+'\\command.json')})"
    remote(a.host,script)
    return await_file(a.host,folder+'\\applied.json',8)


def run_case(a,m,case,name,reboot):
    result={'case':case};root=a.remote_root;folder=root+'\\'+case
    result['canaryPids']=[launch(a.host,m['binary'],f'--listen {m["local"]}:{port} --peer {m["peer"]} --duration 180s',root) for port in (m['port'],m['controlPort'],m['controlPort']+1)]
    (a.output/(case+'-launch.json')).write_text(json.dumps(result,indent=2)+'\n')
    time.sleep(.3);result['isolationDeniedPort']=fresh(m['local'],m['controlPort']+1)
    install_service(a,name,case);result['ready']=await_file(a.host,folder+'\\ready.json',25)
    with connection(m['local'],m['port']) as target,connection(m['local'],m['controlPort']) as control:
        result['before']={'targetExisting':echo(target),'targetNew':fresh(m['local'],m['port']),
            'controlExisting':echo(control),'controlNew':fresh(m['local'],m['controlPort'])}
        if not all(x['ok'] for x in result['before'].values()) or result['isolationDeniedPort']['ok']:raise RuntimeError('ISOLATED_BASELINE_FAILED')
        result['applied']=apply_command(a,m,case,result['ready'])
        result['during']={'targetExisting':echo(target),'targetNew':fresh(m['local'],m['port']),
            'controlExisting':echo(control),'controlNew':fresh(m['local'],m['controlPort'])}
        if any(result['during'][k]['ok']!=v for k,v in dict(targetExisting=False,targetNew=False,controlExisting=True,controlNew=True).items()):raise RuntimeError('NARROW_BLOCK_FAILED')
        if not reboot:
            remote(a.host,f'Stop-Service {quote(name)}')
            result['final']=await_file(a.host,folder+'\\final.json',8)
            result['after']={'targetNew':fresh(m['local'],m['port']),'controlExisting':echo(control),'controlNew':fresh(m['local'],m['controlPort'])}
            result['managementAfter']=json.loads(remote(a.host,"@(Get-Service sshd,Tailscale|ForEach-Object {$_.Status -eq 'Running'})|ConvertTo-Json -Compress"))==[True,True]
            result['evaluation']=evaluate(result)
        else:
            # 此分支只在明确的一次维护授权下调用；发送前同步保存，网络失败不重发。
            (a.output/'reboot-intent.json').write_text(json.dumps(result,indent=2)+'\n')
            script=f"$c=Get-Content {quote(folder+'\\command.json')} -Raw|ConvertFrom-Json;if([DateTime]::UtcNow -ge [DateTime]::Parse($c.blockUntil).ToUniversalTime().AddSeconds(-5)){{throw 'INSUFFICIENT_LEASE_NO_REBOOT'}};if(Test-Path {quote(root+'\\reboot-requested.json')}){{throw 'REBOOT_ALREADY_CONSUMED'}};$i=@{{bootId=$c.bootId;blockUntil=$c.blockUntil;requestedUtc=[DateTime]::UtcNow.ToString('o')}};$f=[IO.File]::Open({quote(root+'\\reboot-requested.json')},[IO.FileMode]::CreateNew);try{{$b=[Text.Encoding]::UTF8.GetBytes(($i|ConvertTo-Json));$f.Write($b,0,$b.Length);$f.Flush($true)}}finally{{$f.Dispose()}};& ($env:WINDIR+'\\System32\\shutdown.exe') /r /t 0 /d p:0:0 /c 'Authorized HostGuard P1 SCM recovery acceptance';if($LASTEXITCODE -ne 0){{throw 'REBOOT_REQUEST_FAILED'}};'REBOOT_REQUEST_ACCEPTED'"
            try:result['dispatch']=remote(a.host,script)
            except RuntimeError:result['dispatch']='connection_interrupted_check_state_without_retry'
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ['host','remote-root','python']:p.add_argument('--'+key,required=True)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--execute-one-reboot',action='store_true')
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);m=json.loads(a.manifest.read_text())
    if not m['runId'].startswith('p1-') or len(m['runId'])!=19:raise ValueError('NEW_SCOPE_REQUIRED')
    names=['HostGuard.P1.'+m['runId'][3:]+'.Stop','HostGuard.P1.'+m['runId'][3:]+'.Reboot']
    result={'rebootAuthorized':a.execute_one_reboot,'passed':False};canaries=[]
    try:
        write_remote(a.host,a.remote_root+'\\manifest.json',m);setup(a,m)
        result['stop']=run_case(a,m,'scm-stop-01',names[0],False);canaries+=result['stop']['canaryPids']
        (a.output/'stop.json').write_text(json.dumps(result['stop'],indent=2)+'\n')
        if not result['stop']['evaluation']['passed']:raise RuntimeError('SCM_STOP_FAILED_NO_REBOOT')
        remote(a.host,';'.join(f"$p=Get-Process -Id {pid} -ErrorAction SilentlyContinue;if($p -and $p.Path -eq {quote(m['binary'])}){{$p.Kill()}}" for pid in canaries));canaries=[]
        if a.execute_one_reboot:
            task='HostGuard.P1.'+m['runId'][3:]+'.BootObserve';result['bootTask']=task
            bootargs=f'"{a.remote_root}\\wfp_bootstrap.py" --module-dir "{a.remote_root}" --logs "{a.remote_root}\\boot-logs" --mode boot --manifest "{a.remote_root}\\manifest.json"'
            remote(a.host,f"$a=New-ScheduledTaskAction -Execute {quote(a.python)} -Argument {quote(bootargs)};$p=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest;$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;Register-ScheduledTask -TaskName {quote(task)} -Action $a -Principal $p -Settings $s -Trigger (New-ScheduledTaskTrigger -AtStartup)|Out-Null")
            result['reboot']=run_case(a,m,'scm-reboot-01',names[1],True)
            (a.output/'reboot-dispatch.json').write_text(json.dumps(result['reboot'],indent=2)+'\n')
            old=result['reboot']['ready']['bootId'];end=time.monotonic()+240;new=None
            while time.monotonic()<end:
                time.sleep(10)
                try:
                    probe='import sys,json;sys.path.insert(0,'+repr(a.remote_root)+');from wfp_probe import boot_id;print(json.dumps(boot_id()))'
                    current=json.loads(remote(a.host,'& '+quote(a.python)+' -c '+quote(probe)))
                    if current!=old:new=current;break
                except RuntimeError:continue
            if new is None:raise RuntimeError('NEW_BOOT_NOT_OBSERVED_NO_RETRY')
            result['newBootId']=new
            result['reboot']['final']=await_file(a.host,a.remote_root+'\\scm-reboot-01\\final.json',5)
            script=f"$end=[DateTime]::UtcNow.AddSeconds(50);do{{$f=Get-ChildItem {quote(a.remote_root+'\\boot-logs')} -Filter boot-observation.json -Recurse|Select-Object -First 1;if($f){{Get-Content $f.FullName -Raw;break}};Start-Sleep -Milliseconds 300}}while([DateTime]::UtcNow -lt $end);if(-not $f){{throw 'AUTOMATIC_BOOT_OBSERVER_MISSING'}}"
            result['bootObservation']=json.loads(remote(a.host,script));canaries+=result['bootObservation'].get('canaryPids',[])
            result['postBootTraffic']={'target':fresh(m['local'],m['port']),'control':fresh(m['local'],m['controlPort'])}
            rejection="import json,time,sys; from pathlib import Path; sys.path.insert(0,"+repr(a.remote_root)+"); from wfp_probe import validate_command,boot_id; p=Path("+repr(a.remote_root)+"); c=json.loads((p/'scm-reboot-01'/'command.json').read_text()); m=json.loads((p/'manifest.json').read_text());\ntry: validate_command(c,m,{'bootId':boot_id(),'executorId':'new-executor'},time.time()); print('UNEXPECTED_ACCEPT')\nexcept ValueError as e: print(str(e))"
            result['oldCommandRejection']=remote(a.host,'& '+quote(a.python)+' -c '+quote(rejection)).strip()
            result['passed']=(result['reboot']['final'].get('closedBeforeShutdown') is True and result['reboot']['final']['delaySeconds']<=1
                and result['bootObservation']['inventory']=={'sublayerPresent':False,'filters':[]}
                and result['bootObservation']['status']=='reconciled_no_commands_accepted'
                and all(v['ok'] for v in result['postBootTraffic'].values()) and result['oldCommandRejection']=='STALE_BOOT')
        else:result['passed']=True
    except BaseException as exc:result['error']=type(exc).__name__+':'+str(exc)
    finally:
        q=quote;group='HostGuard.'+m['runId']
        try:
            for name in names:
                remote(a.host,f"$s=Get-Service {q(name)} -ErrorAction SilentlyContinue;if($s){{if($s.Status -ne 'Stopped'){{Stop-Service {q(name)}}};& ($env:WINDIR+'\\System32\\sc.exe') delete {q(name)}|Out-Null}}")
            # 中途失败也从提前落盘的本轮 PID 清单恢复清理范围，不按进程名批量结束。
            for launch_file in a.output.glob('*-launch.json'):
                canaries.extend(json.loads(launch_file.read_text())['canaryPids'])
            for pid in set(canaries):remote(a.host,f"$p=Get-Process -Id {pid} -ErrorAction SilentlyContinue;if($p -and $p.Path -eq {q(m['binary'])}){{$p.Kill()}}")
            boot_task='HostGuard.P1.'+m['runId'][3:]+'.BootObserve'
            cleanup=f"Get-NetFirewallRule -Group {q(group)} -ErrorAction SilentlyContinue|Remove-NetFirewallRule;Get-ScheduledTask|Where-Object {{ $_.TaskName.StartsWith({q(group+'.')}) -or $_.TaskName -eq {q(boot_task)} }}|Unregister-ScheduledTask -Confirm:$false"
            remote(a.host,cleanup)
            result['cleanup']=json.loads(remote(a.host,'& '+q(a.python)+' '+q(a.remote_root+'\\wfp_probe.py')+' inspect'))
        except BaseException as exc:result['cleanupError']=str(exc);result['passed']=False
        (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':result['passed'],'error':result.get('error'),'cleanup':result.get('cleanup'),'rebootAuthorized':a.execute_one_reboot}),flush=True)
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
