# 只读核验主机、策略、抓包依赖和指定 canary 程序的实际启动；不调整任何系统策略。
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CanaryPath,
    [Parameter(Mandatory=$true)][string]$ReportPath
)
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$binary = Get-Item -LiteralPath $CanaryPath
$signature = Get-AuthenticodeSignature -LiteralPath $binary.FullName
$start = [ordered]@{ started=$false; exitCode=$null; nativeErrorCode=$null; errorType=$null; selfCheck=$null }
$process = New-Object Diagnostics.Process
$process.StartInfo = New-Object Diagnostics.ProcessStartInfo
$process.StartInfo.FileName = $binary.FullName
$process.StartInfo.Arguments = '--self-check'
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
try {
    [void]$process.Start()
    if (-not $process.WaitForExit(10000)) {
        $process.Kill()
        $start.errorType = 'startup_timeout'
    } else {
        $start.exitCode = $process.ExitCode
        $stdout = $process.StandardOutput.ReadToEnd()
        [void]$process.StandardError.ReadToEnd()
        if ($process.ExitCode -eq 0) {
            $check = $stdout | ConvertFrom-Json
            if ($check.started -eq $true -and $check.os -eq 'windows' -and $check.version -eq 'p1-canary-v1') {
                $start.started = $true
                $start.selfCheck = $check
            } else { $start.errorType = 'unexpected_self_check' }
        } else { $start.errorType = 'nonzero_exit' }
    }
} catch {
    $errorObject = $_.Exception
    while ($null -ne $errorObject.InnerException) { $errorObject = $errorObject.InnerException }
    $start.errorType = $errorObject.GetType().FullName
    if ($errorObject -is [ComponentModel.Win32Exception]) { $start.nativeErrorCode = $errorObject.NativeErrorCode }
} finally { $process.Dispose() }
$drivers = @(Get-CimInstance Win32_SystemDriver | Where-Object {$_.Name -in @('npcap','npf')} | ForEach-Object {
    [ordered]@{name=$_.Name; state=$_.State; startMode=$_.StartMode}
})
$dllPresent = (Test-Path -LiteralPath "$env:WINDIR\System32\Npcap\wpcap.dll")
$ciPolicy = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
    [ordered]@{name=$_.Name; enabled=[bool]$_.Enabled; inbound=$_.DefaultInboundAction.ToString(); outbound=$_.DefaultOutboundAction.ToString()}
})
$adapters = @(Get-NetAdapter | ForEach-Object {
    [ordered]@{interfaceIndex=$_.ifIndex; status=$_.Status.ToString(); type=$_.InterfaceDescription}
})
$report = [ordered]@{
    version='p1-windows-preflight-v1'; observedAt=[DateTime]::UtcNow.ToString('o')
    os=[ordered]@{caption=$os.Caption; version=$os.Version; build=$os.BuildNumber; bootUtc=$os.LastBootUpTime.ToUniversalTime().ToString('o')}
    elevated=$admin
    canary=[ordered]@{sha256=(Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); authenticode=$signature.Status.ToString(); startup=$start}
    npcap=[ordered]@{drivers=$drivers; wpcapDllPresent=$dllPresent; liveCaptureVerified=$false}
    smartAppControlState=$ciPolicy.VerifiedAndReputablePolicyState
    firewallProfiles=$profiles; adapters=$adapters
    isolatedLabVerified=$false; firewallModified=$false; restartPerformed=$false
    platformActionStatus='not_tested'; captureReadiness=($drivers.Count -gt 0 -and $dllPresent)
}
$encoded = [Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 12) + "`n")
$file = [IO.File]::Open($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $file.Write($encoded,0,$encoded.Length); $file.Flush($true) } finally { $file.Dispose() }
[pscustomobject]@{binaryStarted=$start.started; nativeErrorCode=$start.nativeErrorCode; captureDependencyPresent=$report.captureReadiness; firewallModified=$false} | ConvertTo-Json -Compress
if (-not $start.started) { exit 2 }
if (-not $report.captureReadiness) { exit 3 }
