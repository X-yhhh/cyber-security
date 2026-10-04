# 同一 SYSTEM 启动/按需入口：先落盘诊断，再启动获准解释器；不执行防火墙写操作。
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$ModuleDirectory,
    [Parameter(Mandatory=$true)][string]$CaseDirectory,
    [ValidateSet('preflight','boot')][string]$Mode='preflight',
    [string]$Manifest
)
$ErrorActionPreference='Stop'
$exitCode=1
# CaseDirectory 由任务安装方预建、限定 ACL；不从网络命令接受路径。
$CaseDirectory=Join-Path $CaseDirectory ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')+'-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $CaseDirectory
$log=Join-Path $CaseDirectory 'launcher.jsonl'
function Log-Entry($Value) {
    $Value.utc=[DateTime]::UtcNow.ToString('o')
    $line=($Value | ConvertTo-Json -Compress -Depth 5)+[Environment]::NewLine
    $bytes=[Text.Encoding]::UTF8.GetBytes($line)
    $f=[IO.File]::Open($log,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {$f.Write($bytes,0,$bytes.Length);$f.Flush($true)} finally {$f.Dispose()}
}
try {
    Log-Entry @{event='launcher_entered';systemIdentity=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');cwd=(Get-Location).Path}
    foreach ($p in @($Python,$ModuleDirectory,$CaseDirectory)) {
        if (-not [IO.Path]::IsPathRooted($p) -or -not (Test-Path -LiteralPath $p)) {throw 'ABSOLUTE_PATH_UNAVAILABLE'}
    }
    $observer=Join-Path $ModuleDirectory 'wfp_reboot_observer.py'
    $version=& $Python --version 2>&1
    if ($LASTEXITCODE -ne 0) {throw 'INTERPRETER_UNAVAILABLE'}
    Log-Entry @{event='interpreter_checked';version=[string]$version;pythonSha256=(Get-FileHash -LiteralPath $Python -Algorithm SHA256).Hash;observerSha256=(Get-FileHash -LiteralPath $observer -Algorithm SHA256).Hash}
    $arguments=@(('"'+$observer+'"'),$Mode,'--case-dir',('"'+$CaseDirectory+'"'))
    if ($Mode -eq 'boot') {
        if (-not $Manifest -or -not [IO.Path]::IsPathRooted($Manifest)) {throw 'BOOT_MANIFEST_REQUIRED'}
        $arguments+=@('--manifest',('"'+$Manifest+'"'))
    }
    $proc=Start-Process -FilePath $Python -ArgumentList $arguments -WorkingDirectory $ModuleDirectory -PassThru -Wait -NoNewWindow -RedirectStandardOutput (Join-Path $CaseDirectory 'python.stdout.log') -RedirectStandardError (Join-Path $CaseDirectory 'python.stderr.log')
    $exitCode=$proc.ExitCode
    Log-Entry @{event='interpreter_exited';exitCode=$exitCode}
} catch {
    # 私有受控目录保留真实异常/调用栈；公开报告只引用去敏错误码与证据哈希。
    Log-Entry @{event='launcher_failed';type=$_.Exception.GetType().FullName;message=$_.Exception.Message;stack=$_.ScriptStackTrace}
}
exit $exitCode
