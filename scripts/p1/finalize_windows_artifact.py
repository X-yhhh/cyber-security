#!/usr/bin/env python3
"""Windows 制品身份入口：研究包可未签名，正式包必须完成受信任 Authenticode 签名。

输入必须匹配调用者固定的 SHA-256，输出到新目录，不覆盖原件。正式模式仅引用
现有证书存储中的私钥，不导入/导出私钥，不创建自签证书，不改变 SAC/WDAC。
使用已安装且签名有效的微软 SignTool，SHA-256 + RFC3161 时间戳并独立验签。
签名和可启动不授予模型发布或防火墙自动执行资格。
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit


def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def quote(value):
    return "'"+str(value).replace("'","''")+"'"


def powershell(script):
    """固定只读证书/系统查询；参数逐项引用，不接受外部任意脚本。"""
    import base64
    code="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+script
    encoded=base64.b64encode(code.encode('utf-16le')).decode()
    r=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',encoded],
                     capture_output=True,text=True,timeout=45)
    if r.returncode:raise RuntimeError('WINDOWS_IDENTITY_QUERY_FAILED')
    return json.loads(r.stdout)


def signature(path):
    return powershell('$s=Get-AuthenticodeSignature '+quote(path)+
        ';@{status=$s.Status.ToString();signer=$s.SignerCertificate.Thumbprint;'
        'publisher=$s.SignerCertificate.Subject;timestampSigner=$s.TimeStamperCertificate.Thumbprint}|ConvertTo-Json -Compress')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True);p.add_argument('--input-sha256',required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--mode',choices=['research','release'],required=True)
    p.add_argument('--certificate-thumbprint');p.add_argument('--certificate-store',choices=['CurrentUser','LocalMachine'],default='CurrentUser')
    p.add_argument('--expected-publisher');p.add_argument('--signtool',type=Path)
    p.add_argument('--timestamp-url',default='https://timestamp.digicert.com')
    a=p.parse_args()
    if os.name!='nt':p.error('仅在目标 Windows 上执行')
    if not re.fullmatch(r'[a-fA-F0-9]{64}',a.input_sha256) or sha(a.input)!=a.input_sha256.lower():p.error('输入制品哈希不符')
    if a.mode=='release':
        if not a.certificate_thumbprint or not re.fullmatch(r'[a-fA-F0-9]{40}',a.certificate_thumbprint) or not a.expected_publisher or a.signtool is None:
            p.error('正式包须提供受信任证书指纹、预期发布者及已安装 SignTool；不会降级成研究包')
        url=urlsplit(a.timestamp_url)
        if url.scheme!='https' or not url.hostname or url.username or url.password:p.error('时间戳地址须为无凭据 HTTPS URL')
        certpath='Cert:\\'+a.certificate_store+'\\My\\'+a.certificate_thumbprint
        cert=powershell('$c=Get-Item '+quote(certpath)+
            ';$chain=New-Object Security.Cryptography.X509Certificates.X509Chain;'
            '$chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.3"));'
            '$chain.ChainPolicy.RevocationMode="Online";'
            '@{privateKey=$c.HasPrivateKey;publisher=$c.Subject;'
            'current=($c.NotBefore -le (Get-Date) -and $c.NotAfter -gt (Get-Date));'
            'codeSigning=(@($c.EnhancedKeyUsageList|Where-Object {$_.ObjectId.Value -eq "1.3.6.1.5.5.7.3.3"}).Count -gt 0);'
            'trusted=$chain.Build($c)}|ConvertTo-Json -Compress')
        if cert['publisher']!=a.expected_publisher or not all(cert[k] for k in ['privateKey','current','codeSigning','trusted']):
            raise RuntimeError('TRUSTED_CODE_SIGNING_CERTIFICATE_REQUIRED')
        tool_signature=signature(a.signtool.resolve())
        if tool_signature['status']!='Valid' or 'O=Microsoft Corporation' not in (tool_signature['publisher'] or ''):
            raise RuntimeError('TRUSTED_MICROSOFT_SIGNTOOL_REQUIRED')
    a.output.mkdir(parents=True,exist_ok=False)
    artifact=a.output/'guardlive.exe';shutil.copyfile(a.input,artifact)
    report=dict(version='windows-artifact-identity-v1',mode=a.mode,inputSha256=a.input_sha256.lower(),
        createdUtc=datetime.now(timezone.utc).isoformat(),productionAutoSupported=False,passed=False)
    try:
        if a.mode=='release':
            cmd=[str(a.signtool.resolve()),'sign','/sha1',a.certificate_thumbprint,'/s','My',
                 '/fd','SHA256','/tr',a.timestamp_url,'/td','SHA256']
            if a.certificate_store=='LocalMachine':cmd.append('/sm')
            subprocess.run(cmd+[str(artifact.resolve())],check=True,capture_output=True,timeout=90)
            subprocess.run([str(a.signtool.resolve()),'verify','/pa','/all',str(artifact.resolve())],
                           check=True,capture_output=True,timeout=60)
        report['signature']=signature(artifact.resolve())
        signed=report['signature']
        if a.mode=='release' and (signed['status']!='Valid' or signed['signer'].upper()!=a.certificate_thumbprint.upper()
            or signed['publisher']!=a.expected_publisher or not signed['timestampSigner']):
            raise RuntimeError('RELEASE_SIGNATURE_OR_TIMESTAMP_INVALID')
        if a.mode=='research' and signed['status'] not in ('NotSigned','Valid'):
            raise RuntimeError('INVALID_EXISTING_SIGNATURE')
        report['smartAppControl']=powershell('(Get-MpComputerStatus).SmartAppControlState|ConvertTo-Json -Compress')
        probe=subprocess.run([str(artifact.resolve()),'-h'],capture_output=True,text=True,timeout=10)
        report['launchExitCode']=probe.returncode
        if probe.returncode:raise RuntimeError('SYSTEM_LAUNCH_REJECTED')
        report.update(passed=True,sha256=sha(artifact),trustedPublisherSignature=signed['status']=='Valid',
                      distributionClass='signed_release_artifact' if a.mode=='release' else 'research_only')
    except BaseException as error:report['error']=type(error).__name__+':'+str(error)
    finally:
        (a.output/'identity.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
