#!/usr/bin/env python3
"""从已授权 Mac peer 驱动 Windows 单个 WFP 故障场景，保留失败与连接原证据。

要求先完成独立网络隔离。不会重启主机、不改变默认策略，不读取训练资产。
所有原始端点、PID及本地路径输出到忽略的 artifacts；汇总报告另行去敏。
"""
import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import time

from connection_probe import connection, echo, fresh


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def ssh_args():
    """单轮可显式选择IPv4；不改机器全局SSH配置，故障通道与管理通道使用同一目标。"""
    args = ['ssh', '-4', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10']
    address = os.environ.get('P1_SSH_IPV4')
    if address:
        args += ['-o', 'HostName=' + address, '-o', 'ControlPath=none']
    control = os.environ.get('P1_SSH_CONTROL_PATH')
    if control and not address:
        args += ['-o', 'ControlPath=' + control]
    return args


def remote(host, code):
    script = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + code
    encoded = base64.b64encode(script.encode('utf-16le')).decode()
    try:
        r = subprocess.run(ssh_args()+[host, 'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand '+encoded],
                           capture_output=True,text=True,timeout=40)
    except subprocess.TimeoutExpired:
        raise RuntimeError('SSH_TIMEOUT_STATE_UNKNOWN') from None
    if r.returncode:
        raise RuntimeError('REMOTE_STEP_FAILED:' + r.stderr[-600:])
    return r.stdout.strip()


def fetch(host, path):
    return json.loads(remote(host, f'Get-Content -LiteralPath {quote(path)} -Raw'))


def await_file(host, path, seconds):
    # 在远端有界等待，避免反复SSH轮询；独立恢复进程不依赖此等待。
    code = f"$end=[DateTime]::UtcNow.AddSeconds({seconds});while(-not(Test-Path -LiteralPath {quote(path)})){{if([DateTime]::UtcNow -ge $end){{throw 'FILE_WAIT_TIMEOUT'}};Start-Sleep -Milliseconds 200}};Get-Content -LiteralPath {quote(path)} -Raw"
    return json.loads(remote(host, code))


def write_remote(host, path, value):
    content = base64.b64encode(json.dumps(value).encode()).decode()
    # 目标已存在时 [IO.File]::Move 会失败；先删除再移动，使重跑幂等。
    remote(host, f"$b=[Convert]::FromBase64String('{content}');"
                 f"$f=[IO.File]::Open({quote(path+'.pending')},[IO.FileMode]::CreateNew);"
                 f"try{{$f.Write($b,0,$b.Length);$f.Flush($true)}}finally{{$f.Dispose()}};"
                 f"if(Test-Path -LiteralPath {quote(path)}){{Remove-Item -LiteralPath {quote(path)} -Force}};"
                 f"[IO.File]::Move({quote(path+'.pending')},{quote(path)})")


def gitbash_to_windows(path):
    """Convert /e/Workspace/... Git Bash paths to E:\\Workspace\\... Windows paths."""
    import re
    m = re.match(r'^/([a-zA-Z])(/.*)?$', path)
    if m:
        drive = m.group(1).upper()
        rest = (m.group(2) or '').replace('/', '\\')
        return drive + ':' + rest
    return path


def launch(host, executable, arguments, directory):
    """用 Start-Process 创建独立后台进程。
    原 Win32_Process.Create WMI 路径在 SSH 非交互式会话（无桌面令牌）下始终报 PROCESS_CREATE_FAILED；
    Start-Process -WindowStyle Hidden 在同一 SSH 会话里可以创建独立进程且不继承 stdin。
    Git Bash 风格路径 /e/... 需转为 Windows 路径 E:\\... 才能被 PowerShell 识别。
    """
    exe_win = gitbash_to_windows(executable)
    dir_win = gitbash_to_windows(directory)
    # arguments 是字符串，里面的路径也需要转换
    import re
    args_win = re.sub(r'/([a-zA-Z])(/[^\s\'\"]*)', lambda m: m.group(1).upper() + ':' + m.group(2).replace('/', '\\'), arguments)
    code = (f"$p=Start-Process -FilePath {quote(exe_win)} "
            f"-ArgumentList {quote(args_win)} "
            f"-WorkingDirectory {quote(dir_win)} "
            f"-WindowStyle Hidden -PassThru;"
            f"if(-not $p){{throw 'PROCESS_CREATE_FAILED'}};"
            f"$p.Id")
    return int(remote(host, code))


def evaluate(r):
    expected = {'before': {'targetExisting': True, 'targetNew': True, 'controlExisting': True, 'controlNew': True},
                'during': {'targetExisting': False, 'targetNew': False, 'controlExisting': True, 'controlNew': True},
                'after': {'targetNew': True, 'controlExisting': True, 'controlNew': True}}
    failures = [phase+'.'+key for phase, row in expected.items() for key, value in row.items()
                if r.get(phase, {}).get(key, {}).get('ok') is not value]
    final = r.get('final', {})
    if final.get('inventory') != {'sublayerPresent': False, 'filters': []}:
        failures.append('dynamic_objects_remaining')
    if final.get('delaySeconds') is None or final['delaySeconds'] > 1:
        failures.append('ttl_deadline_missed')
    if not r.get('applied', {}).get('dynamic'):
        failures.append('dynamic_session_unproven')
    if not r.get('managementAfter', False):
        failures.append('management_not_verified')
    if r.get('isolationDeniedPort',{}).get('ok') is not False:
        failures.append('isolation_not_verified')
    return {'passed': not failures, 'failedChecks': failures}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True); p.add_argument('--remote-root', required=True)
    p.add_argument('--python', required=True); p.add_argument('--manifest', required=True, type=Path)
    p.add_argument('--case', required=True, choices=('ttl','close-session','kill','hang','detector-exit','channel-loss'))
    p.add_argument('--case-id', required=True); p.add_argument('--output', required=True, type=Path)
    a = p.parse_args(); m = json.loads(a.manifest.read_text()); root = a.remote_root
    if not a.case_id.replace('-','').isalnum() or a.output.exists():
        p.error('unique safe case-id/output required')
    case = root + '\\' + a.case_id; manifest = root + '\\manifest.json'
    r = {'case': a.case, 'caseId': a.case_id, 'startedUtc': dt.datetime.now(dt.timezone.utc).isoformat()}
    canaries = []; channel = None
    try:
        fault = a.case if a.case in ('kill','hang') else 'none'
        args = f'{root}\\wfp_probe.py supervise --manifest {manifest} --case-dir {case} --fault {fault}'
        r['supervisorPid'] = launch(a.host, a.python, args, root)
        r['ready'] = await_file(a.host, case+'\\ready.json', 25)
        launches = []
        for port in (m['port'], m['controlPort'], m['controlPort']+1):
            cmd = f'--listen {m["local"]}:{port} --peer {m["peer"]} --duration 100s'
            command = '"' + m['binary'] + '" ' + cmd
            launches.append(f"$p=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine={quote(command)};CurrentDirectory={quote(root)}}};if($p.ReturnValue -ne 0){{throw 'CANARY_START_FAILED'}};$p.ProcessId")
        canaries = [int(x) for x in remote(a.host, ';'.join(launches)).splitlines()]
        time.sleep(0.5)
        r['isolationDeniedPort'] = fresh(m['local'], m['controlPort']+1)
        with connection(m['local'], m['port']) as target, connection(m['local'], m['controlPort']) as control:
            r['before'] = {'targetExisting': echo(target), 'controlExisting': echo(control),
                           'targetNew': fresh(m['local'],m['port']), 'controlNew': fresh(m['local'],m['controlPort'])}
            if not all(v['ok'] for v in r['before'].values()) or r['isolationDeniedPort']['ok']:
                raise RuntimeError('BASELINE_OR_ISOLATION_FAILED')
            # 在目标机器取真实时间签发一次性本地探针命令，避免跨机墙钟误差。
            c = {k:m[k] for k in ('runId','local','peer','port')}
            c.update(bootId=r['ready']['bootId'], executorId=r['ready']['executorId'], actionId=a.case_id,
                     issuedUtc=None, applyBy=None, blockUntil=None)
            content=base64.b64encode(json.dumps(c).encode()).decode()
            code=f"$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{content}')) | ConvertFrom-Json;$now=[DateTime]::UtcNow;$c.issuedUtc=$now.ToString('o');$c.applyBy=$now.AddSeconds(10).ToString('o');$c.blockUntil=$now.AddSeconds(30).ToString('o');[IO.File]::WriteAllText({quote(case+'\\command.pending')},($c | ConvertTo-Json));[IO.File]::Move({quote(case+'\\command.pending')},{quote(case+'\\command.json')});$end=$now.AddSeconds(8);while(-not(Test-Path {quote(case+'\\applied.json')})){{if([DateTime]::UtcNow -ge $end){{throw 'APPLY_TIMEOUT'}};Start-Sleep -Milliseconds 50}};Get-Content {quote(case+'\\applied.json')} -Raw"
            r['applied'] = json.loads(remote(a.host,code))
            r['during'] = {'targetExisting': echo(target),'targetNew': fresh(m['local'],m['port']),
                           'controlExisting': echo(control),'controlNew': fresh(m['local'],m['controlPort'])}
            if a.case in ('kill','hang','close-session'):
                trigger = 'close-session' if a.case == 'close-session' else 'trigger-fault'
                remote(a.host, f"New-Item -ItemType File -Path {quote(case+'\\'+trigger)} | Out-Null")
            elif a.case == 'detector-exit':
                # 专用无害检测器替身；进程句柄归本命令，不接触活动应用或训练进程。
                r['detectorFault'] = json.loads(remote(a.host, "$p=Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 45' -WindowStyle Hidden -PassThru; $pidValue=$p.Id; $p.Kill();$p.WaitForExit();@{stubPid=$pidValue;exited=$p.HasExited} | ConvertTo-Json -Compress"))
            elif a.case == 'channel-loss':
                code = "Write-Output CHANNEL_READY;Start-Sleep -Seconds 45"
                enc = base64.b64encode(code.encode('utf-16le')).decode()
                channel = subprocess.Popen(ssh_args()+[a.host,
                    'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand '+enc],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if channel.stdout.readline().strip() != 'CHANNEL_READY':
                    raise RuntimeError('CHANNEL_SETUP_FAILED')
                channel.terminate(); channel.wait(timeout=5); r['controlChannelTerminated'] = True
            r['final'] = await_file(a.host, case+'\\final.json', 28)
            r['after'] = {'targetNew': fresh(m['local'],m['port']), 'controlExisting': echo(control),
                          'controlNew': fresh(m['local'],m['controlPort'])}
            r['managementAfter'] = json.loads(remote(a.host, "@(Get-Service sshd,Tailscale | ForEach-Object {$_.Status -eq 'Running'}) | ConvertTo-Json -Compress")) == [True,True]
        r['evaluation'] = evaluate(r)
    except Exception as e:
        r['error'] = str(e)
        r['evaluation'] = {'passed': False, 'failedChecks': ['runner_or_probe_failure']}
    finally:
        if channel and channel.poll() is None:
            channel.terminate()
        # 只终止路径及PID均匹配的本轮canary；不按名称批量结束其他进程。
        if canaries:
            code=';'.join(f"$p=Get-Process -Id {ident} -ErrorAction SilentlyContinue;if($p -and $p.Path -eq {quote(m['binary'])}){{$p.Kill()}}" for ident in canaries)
            try:
                remote(a.host, code)
            except Exception as error:
                # 清理状态不明不能吞掉先前证据；独立本机恢复仍按原期限运行。
                r['cleanupError']=str(error)
                r['evaluation']={'passed':False,'failedChecks':['cleanup_not_verified']}
        a.output.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'case':a.case,'evaluation':r['evaluation']}),flush=True)
    if not r['evaluation']['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
