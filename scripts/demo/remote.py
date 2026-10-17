"""只操作预先登记的 win-dev 演示目录；不接受 shell 模板或按进程名终止的命令。"""
import base64
import json
from pathlib import Path
import subprocess
from scripts.demo.common import ROOT, digest, require


def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


class Remote:
    def __init__(self, config, execute=subprocess.run):
        self.c, self.execute = config, execute
        require(config['host'] == 'win-dev', 'REMOTE_HOST_NOT_ALLOWED')
        self.root = config['root'].rstrip('/')

    def ps(self, script):
        command = base64.b64encode(('$ErrorActionPreference="Stop"; [Console]::OutputEncoding=[Text.Encoding]::UTF8; ' + script).encode('utf-16-le')).decode()
        r = self.execute(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', self.c['host'],
                          'powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', command],
                         capture_output=True, timeout=20)
        require(r.returncode == 0, 'REMOTE_OPERATION_FAILED')
        return r.stdout.decode('utf-8-sig').strip()

    def directory(self, run_id):
        import re
        require(re.fullmatch(r'demo-\d{8}-\d{4}-\d{2,4}', run_id), 'RUN_ID_INVALID')
        return self.root + '/runs/' + run_id

    def put(self, destination, raw, *, identical=False):
        require(destination.startswith(self.root + '/') and '..' not in destination.split('/'), 'REMOTE_PATH_INVALID')
        payload = base64.b64encode(raw).decode()
        require(len(payload) < 150000, 'REMOTE_INPUT_TOO_LARGE')
        existing = ('if((Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash -eq ' + ps_literal(__import__('hashlib').sha256(raw).hexdigest()) + '){exit 0}; ') if identical else ''
        self.ps(self.guard_path(destination) + '$p=' + ps_literal(destination) + '; if(Test-Path -LiteralPath $p){' + existing + 'throw "EXISTS"}; '
                '[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p))|Out-Null; '
                '[IO.File]::WriteAllBytes($p,[Convert]::FromBase64String(' + ps_literal(payload) + '))')

    def guard_root(self):
        """远端私有根目录不能是 junction，ACL 只能授予当前用户、SYSTEM 与管理员。"""
        return ('$root=' + ps_literal(self.root) + '; $me=[Security.Principal.WindowsIdentity]::GetCurrent().User; '
                '$item=Get-Item -LiteralPath $root; $walk=$item; while($walk){'
                'if($walk.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "REPARSE"}; $walk=$walk.Parent}; '
                '$acl=Get-Acl -LiteralPath $root; if(!$acl.AreAccessRulesProtected){throw "ACL_INHERITED"}; '
                'foreach($a in $acl.Access){$sid=$a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; '
                'if($a.AccessControlType -eq "Allow" -and $sid -notin @($me.Value,"S-1-5-18","S-1-5-32-544")){throw "ACL_NOT_PRIVATE"}}; ')

    def guard_path(self, destination):
        """每次读写前拒绝路径中已有的 junction/软链接，不让子目录绕过固定私有根。"""
        require(destination.startswith(self.root + '/') and '..' not in destination.split('/'), 'REMOTE_PATH_INVALID')
        return (self.guard_root() + '$check=' + ps_literal(destination) + '; '
                'while($check -and $check.Length -gt $root.Length){if(Test-Path -LiteralPath $check){'
                '$i=Get-Item -LiteralPath $check; if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "REPARSE"}}; '
                '$check=[IO.Path]::GetDirectoryName($check)}; ')

    def install(self, c):
        """一次性准备才调用；不安装 Npcap/nmap、不改远端 PATH，已有文件拒绝覆盖。"""
        # 仅首次创建的演示目录设置 ACL；已有目录须已符合私有条件，不能顺便改用户已有数据权限。
        self.ps('$p=' + ps_literal(self.root) + '; $walk=$p; while($walk){if(Test-Path -LiteralPath $walk){if((Get-Item -LiteralPath $walk).Attributes -band [IO.FileAttributes]::ReparsePoint){throw "REPARSE"}}; $walk=[IO.Path]::GetDirectoryName($walk)}; if(!(Test-Path -LiteralPath $p)){'
                '[IO.Directory]::CreateDirectory($p)|Out-Null; $me=[Security.Principal.WindowsIdentity]::GetCurrent().User; '
                '$acl=New-Object Security.AccessControl.DirectorySecurity; $acl.SetOwner($me); $acl.SetAccessRuleProtection($true,$false); '
                'foreach($sid in @($me.Value,"S-1-5-18","S-1-5-32-544")){'
                '$id=[Security.Principal.SecurityIdentifier]::new($sid); '
                '$rule=[Security.AccessControl.FileSystemAccessRule]::new($id,"FullControl","ContainerInherit,ObjectInherit","None","Allow"); '
                '$acl.AddAccessRule($rule)}; Set-Acl -LiteralPath $p -AclObject $acl}; ' + self.guard_root() +
                '[IO.Directory]::CreateDirectory((Join-Path $root "runs"))|Out-Null')
        for relative in ('scripts/demo/common.py', 'scripts/demo/worker.py'):
            self.put(self.root + '/' + relative, (ROOT / relative).read_bytes(), identical=True)
        allow = dict(macAddress=c['macAddress'], peerAddress=c['peerAddress'],
                     ports=c['ports'], allowedPorts=[c['ports'][k] for k in ('http', 'ftp', 'ssh')] + c['ports']['scan'], nmap=self.c['nmap'])
        self.put(self.root + '/allowlist.json', json.dumps(allow).encode(), identical=True)
        return digest(allow)

    def utc(self):
        """单独测时避免工具版本/CIM 查询耗时扩大时钟误差。"""
        return int(self.ps('[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()'))

    def inspect(self):
        """只读版本和精确运行目录状态；残留进程、地址或工具漂移使预检失败。"""
        script = (self.guard_root() + '$allow=Get-Content -Raw -LiteralPath ' + ps_literal(self.root + '/allowlist.json') + '|ConvertFrom-Json; '
                  '$ip=@(Get-NetIPAddress -AddressFamily IPv4|Select-Object -ExpandProperty IPAddress); '
                  '$runs=@(); Get-ChildItem -Directory -LiteralPath ' + ps_literal(self.root + '/runs') + ' -ErrorAction SilentlyContinue|ForEach-Object {'
                  '$f=Join-Path $_.FullName "launch.json"; if(Test-Path $f){$l=Get-Content -Raw $f|ConvertFrom-Json; '
                  '$p=Get-Process -Id $l.pid -ErrorAction SilentlyContinue; if($p -and [string]$p.StartTime.ToUniversalTime().Ticks -eq $l.ticks){$runs+=$_.Name}}}; '
                  '$scriptPath=' + ps_literal(self.root + '/scripts/demo/worker.py') + '; '
                  '$w=(Get-FileHash -Algorithm SHA256 -LiteralPath $scriptPath).Hash.ToLower(); '
                  '$common=(Get-FileHash -Algorithm SHA256 -LiteralPath ' + ps_literal(self.root + '/scripts/demo/common.py') + ').Hash.ToLower(); '
                  # 启动后尚未写 launch.json 的崩溃窗口也不能绕过残留检查。
                  '$orphans=@(Get-CimInstance Win32_Process|Where-Object {$_.CommandLine -and $_.CommandLine.Contains($scriptPath)}); '
                  '$v=& ' + ps_literal(self.c['python']) + ' --version; if($LASTEXITCODE -ne 0){throw "PYTHON"}; '
                  '$n=& ' + ps_literal(self.c['nmap']) + ' --version; if($LASTEXITCODE -ne 0){throw "NMAP"}; '
                  '@{allowlist=$allow;addresses=$ip;running=$runs;orphanCount=$orphans.Count;workerSha256=$w;commonSha256=$common;'
                  'utc=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();python=($v|Select-Object -First 1);nmap=($n|Select-Object -First 1)}|ConvertTo-Json -Depth 10 -Compress')
        return json.loads(self.ps(script))

    def start(self, run_id, plan, scene_path):
        d = self.directory(run_id)
        self.put(d + '/scenes.json', Path(scene_path).read_bytes())
        plan = dict(plan, allowlist=self.root + '/allowlist.json', scenesFile=d + '/scenes.json')
        self.put(d + '/plan.json', json.dumps(plan).encode())
        args = subprocess.list2cmdline(['-B', self.root + '/scripts/demo/worker.py', '--plan', d + '/plan.json'])
        script = (self.guard_path(d + '/plan.json') + '$p=Start-Process -FilePath ' + ps_literal(self.c['python']) + ' -ArgumentList ' + ps_literal(args) +
                  ' -WorkingDirectory ' + ps_literal(d) + ' -RedirectStandardOutput ' + ps_literal(d + '/stdout.log') +
                  ' -RedirectStandardError ' + ps_literal(d + '/stderr.log') + ' -PassThru -WindowStyle Hidden; '
                  '$l=@{pid=$p.Id;ticks=[string]$p.StartTime.ToUniversalTime().Ticks}; '
                  '$l|ConvertTo-Json -Compress|Set-Content -Encoding utf8 -LiteralPath ' + ps_literal(d + '/launch.json') + '; '
                  '$l|ConvertTo-Json -Compress')
        return json.loads(self.ps(script))

    def marker(self, run_id, name):
        require(name == 'STOP' or name in ('GO-S0', 'GO-S1', 'GO-S2', 'GO-S3', 'GO-S4'), 'REMOTE_MARKER_INVALID')
        self.ps(self.guard_path(self.directory(run_id) + '/' + name) + '[IO.File]::WriteAllText(' + ps_literal(self.directory(run_id) + '/' + name) + ',"1")')

    def state(self, run_id):
        d = self.directory(run_id)
        script = (self.guard_path(d + '/worker-state.json') + '$f=' + ps_literal(d + '/worker-state.json') + '; if(Test-Path -LiteralPath $f){Get-Content -Raw -LiteralPath $f}else{"null"}')
        return json.loads(self.ps(script))

    def stopped(self, run_id):
        """完整 plan 路径匹配 CIM 命令行，同时核对记录 PID+创建时刻；不按进程名批量终止。"""
        d = self.directory(run_id)
        script = (self.guard_path(d + '/launch.json') + '$d=' + ps_literal(d) + '; if(!(Test-Path -LiteralPath $d)){"true";exit}; '
                  '$matches=@(Get-CimInstance Win32_Process|Where-Object {$_.CommandLine -and $_.CommandLine.Contains(' + ps_literal(d + '/plan.json') + ')}); '
                  '$running=$matches.Count -gt 0; $f=Join-Path $d "launch.json"; if(Test-Path $f){'
                  '$l=Get-Content -Raw $f|ConvertFrom-Json; $p=Get-Process -Id $l.pid -ErrorAction SilentlyContinue; '
                  'if($p -and [string]$p.StartTime.ToUniversalTime().Ticks -eq $l.ticks){$running=$true}}; (!$running)|ConvertTo-Json -Compress')
        return json.loads(self.ps(script)) is True
