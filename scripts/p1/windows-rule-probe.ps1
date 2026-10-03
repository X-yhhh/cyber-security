<#
P1 有界规则探针，不是生产执行器。只操作本次 manifest 的独立命名空间。
Prepare 验证 SYSTEM 原生 netsh 清理任务；Block 只允许指定 IPv4 peer/TCP 高端口，TTL 固定30秒。
恢复器不依赖检测/SSH进程，按墙钟到期清理，启动后单独触发清理；管理端口不可入选。
必须在授权资产运行；不改变防火墙 profile、默认策略、用户原有规则或应用控制。
#>
param(
 [Parameter(Mandatory=$true)][ValidateSet('Prepare','Isolate','Block','Status','Cleanup')][string]$Mode,
 [Parameter(Mandatory=$true)][string]$ManifestPath,
 [ValidatePattern('^[a-z0-9-]{1,32}$')][string]$Case='ttl',
 [ValidateSet('Inbound','Outbound')][string]$Direction='Inbound'
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$m=Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$dir=Split-Path -Parent $ManifestPath
if($m.runId -notmatch '^p1-[a-f0-9]{16}$'){throw 'Invalid run ID'}
$group='HostGuard.'+$m.runId
$ip=[Net.IPAddress]::Parse($m.peer)
$local=[Net.IPAddress]::Parse($m.local)
if($ip.AddressFamily -ne 'InterNetwork' -or $local.AddressFamily -ne 'InterNetwork' -or $ip.Equals($local)){throw 'Invalid IPv4 peers'}
foreach($value in @($ip,$local)){
 $b=$value.GetAddressBytes()
 if(-not($b[0]-eq 10 -or ($b[0]-eq 172 -and $b[1]-ge 16 -and $b[1]-le 31) -or ($b[0]-eq 192 -and $b[1]-eq 168) -or ($b[0]-eq 100 -and $b[1]-ge 64 -and $b[1]-le 127))){throw 'Only private/overlay addresses'}
}
if($m.port -lt 49152 -or $m.port -gt 65533 -or $m.controlPort -ne $m.port+1){throw 'Invalid dedicated ports'}
if([DateTime]::Parse($m.expiresUtc).ToUniversalTime() -gt [DateTime]::UtcNow.AddMinutes(20)){throw 'Session exceeds 20 minutes'}
function Owned {
 @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $group -ErrorAction SilentlyContinue | Where-Object {$_.Name.StartsWith($group+'.')})
}
function Audit([string]$event,[int]$count){
 @{event=$event;count=$count;at=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Compress | Add-Content -LiteralPath "$dir\recovery.jsonl" -Encoding UTF8
}
function UTC-OrNull($value){if($null -eq $value){return $null};([DateTime]$value).ToUniversalTime().ToString('o')}
function Remove-Owned {
 $rules=@(Owned);$rules | Remove-NetFirewallRule -ErrorAction Stop; Audit 'cleanup' $rules.Count
}
function Register-Cleanup([string]$name,[DateTime]$when){
 # 使用系统自带 netsh，SYSTEM 不执行脚本，不修改执行策略。
 $action=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\netsh.exe" -Argument "advfirewall firewall delete rule name=$name"
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 # 实测合并的 Once/Boot 任务在重启后延迟约10分钟才清理，因此拆开触发器。
 # Boot 延迟15秒避开服务启动早期；失败最多重试两次。重试结果1也可能表示规则已不存在，
 # 验收仍以实际规则清零和事件时间为准，不能只看任务退出码。本修订须单独实测启动语义。
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName "$name.Cleanup" -Action $action -Principal $principal -Trigger (New-ScheduledTaskTrigger -Once -At $when.ToLocalTime()) -Settings $settings | Out-Null
 $boot=New-ScheduledTaskTrigger -AtStartup; $boot.Delay='PT15S'
 $bootSettings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName "$name.Boot.Cleanup" -Action $action -Principal $principal -Trigger $boot -Settings $bootSettings | Out-Null
}
function Assert-Active {
 if([DateTime]::UtcNow -ge [DateTime]::Parse($m.expiresUtc).ToUniversalTime()){throw 'Expired session'}
 if(-not(Test-Path "$dir\native-recovery-verified.json")){throw 'Independent recovery has not passed'}
 if((Get-FileHash -LiteralPath $m.binary).Hash.ToLowerInvariant() -ne $m.binarySha256){throw 'Canary binary changed'}
}
if($Mode -eq 'Prepare'){
 if(@(Owned).Count -ne 0 -or (Test-Path "$dir\native-recovery-verified.json")){throw 'Namespace already exists'}
 if((Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {-not $_.Enabled}).Count -gt 0){throw 'Firewall disabled'}
 $name="$group.disabled-probe"
 try {
  Register-Cleanup $name ([DateTime]::UtcNow.AddSeconds(8))
  New-NetFirewallRule -Name $name -DisplayName $name -Group $group -Enabled False -Direction Inbound -Action Block -Protocol TCP -LocalPort $m.port -RemoteAddress $m.peer | Out-Null
  Start-Sleep -Seconds 12
  $info=Get-ScheduledTaskInfo "$name.Cleanup"
  if(@(Owned | Where-Object Name -eq $name).Count -ne 0 -or $info.LastTaskResult -ne 0){throw 'Native recovery smoke failed'}
  [IO.File]::WriteAllText("$dir\native-recovery-verified.json",(@{verifiedUtc=[DateTime]::UtcNow.ToString('o');lastResult=$info.LastTaskResult;disabledRuleRemoved=$true} | ConvertTo-Json))
  foreach($suffix in @('isolation-egress','isolation-peer','isolation-ports','allow-canary')){Register-Cleanup "$group.$suffix" ([DateTime]::Parse($m.expiresUtc).ToUniversalTime())}
  Audit 'native_recovery_verified' 1
 } catch {Remove-Owned;throw}
} elseif($Mode -eq 'Isolate'){
 Assert-Active
 # 对专用 canary 程序阻止所有主动外联；入站仅允许唯一 peer 和两个探针端口。
 # 这组网络层隔离规则不作用于 sshd/Tailscale 或共享的 PowerShell/Python 程序。
 $bytes=$ip.GetAddressBytes();[Array]::Reverse($bytes);$n=[BitConverter]::ToUInt32($bytes,0)
 function Addr([uint32]$x){$b=[BitConverter]::GetBytes($x);[Array]::Reverse($b);([Net.IPAddress]::new($b)).ToString()}
 # Windows 拒绝 IPv6 ::/0；两个 /1 经禁用规则验证可表达相同范围。
 $outside=@(('0.0.0.1-'+(Addr ($n-1))),((Addr ($n+1))+'-255.255.255.254'),'::/1','8000::/1')
 $otherPorts=@("1-$([int]$m.port-1)","$([int]$m.controlPort+1)-65535")
 $base=@{Group=$group;Program=$m.binary;Profile='Any';PolicyStore='PersistentStore';Enabled='True'}
 try {
  New-NetFirewallRule @base -Name "$group.isolation-egress" -DisplayName "$group.isolation-egress" -Direction Outbound -Action Block -Protocol Any | Out-Null
  New-NetFirewallRule @base -Name "$group.isolation-peer" -DisplayName "$group.isolation-peer" -Direction Inbound -Action Block -RemoteAddress $outside -Protocol Any | Out-Null
  New-NetFirewallRule @base -Name "$group.isolation-ports" -DisplayName "$group.isolation-ports" -Direction Inbound -Action Block -Protocol TCP -LocalPort $otherPorts | Out-Null
  New-NetFirewallRule @base -Name "$group.allow-canary" -DisplayName "$group.allow-canary" -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $m.local -RemoteAddress $m.peer -LocalPort @($m.port,$m.controlPort) | Out-Null
  Audit 'isolation_installed' 4
 } catch {Remove-Owned;throw}
} elseif($Mode -eq 'Block'){
 Assert-Active
 $name="$group.block.$Case"
 if(Test-Path "$dir\$Case.lease.json"){throw 'Case already used'}
 $start=[DateTime]::UtcNow
 $lease=@{name=$name;case=$Case;createdUtc=$start.ToString('o');expiresUtc=$start.AddSeconds(30).ToString('o')}
 # 先写不可变租约，再加规则：中途失败只会留下可清理的空租约。
 [IO.File]::WriteAllText("$dir\$Case.lease.pending",($lease | ConvertTo-Json))
 [IO.File]::Move("$dir\$Case.lease.pending","$dir\$Case.lease.json")
 Register-Cleanup $name $start.AddSeconds(30)
 if([DateTime]::UtcNow -ge $start.AddSeconds(28)){throw 'Cleanup deadline too close; no rule installed'}
 $params=@{Name=$name;DisplayName=$name;Group=$group;Direction=$Direction;Action='Block';Protocol='TCP';LocalAddress=$m.local;RemoteAddress=$m.peer;Profile='Any';PolicyStore='PersistentStore';Enabled='True'}
 if($Direction -eq 'Inbound'){$params.LocalPort=$m.port}else{$params.RemotePort=$m.port}
 New-NetFirewallRule @params | Out-Null
 Audit ('block_installed:'+$Case) 1
 $lease | ConvertTo-Json -Compress
} elseif($Mode -eq 'Cleanup'){
 Remove-Owned
 Get-ScheduledTask | Where-Object {$_.TaskName.StartsWith($group+'.') -and $_.TaskName.EndsWith('.Cleanup')} | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false}
} elseif($Mode -eq 'Status'){
 $rules=@(Owned)
 [ordered]@{group=$group;observedUtc=[DateTime]::UtcNow.ToString('o');rules=@($rules | ForEach-Object {
  $port=$_ | Get-NetFirewallPortFilter;$addr=$_ | Get-NetFirewallAddressFilter;$app=$_ | Get-NetFirewallApplicationFilter
  @{name=$_.Name;action=$_.Action.ToString();direction=$_.Direction.ToString();protocol=$port.Protocol;localPort=$port.LocalPort;remotePort=$port.RemotePort;localAddress=$addr.LocalAddress;remoteAddress=$addr.RemoteAddress;program=$app.Program}
 });cleanupTasks=@(Get-ScheduledTask | Where-Object {$_.TaskName.StartsWith($group+'.') -and $_.TaskName.EndsWith('.Cleanup')} | ForEach-Object {$i=Get-ScheduledTaskInfo $_.TaskName;@{name=$_.TaskName;state=[string]$_.State;lastResult=$i.LastTaskResult;lastRun=(UTC-OrNull $i.LastRunTime);nextRun=(UTC-OrNull $i.NextRunTime)}});firewallEnabled=@(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled);services=@(Get-Service sshd,Tailscale,MpsSvc | Select-Object Name,Status)} | ConvertTo-Json -Depth 8
}
