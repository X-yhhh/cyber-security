#!/usr/bin/env python3
"""按冻结清单生成单一候选包并验证两端相同字节；收尾不拟合、不搜索阈值。

只打包清单列出的文件和清单本身；拒绝逃逸、符号链接及未绑定候选状态。
旧权重可复用已通过的 ONNX 证据，本入口只解决完整包身份差异。
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def safe_name(name):
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name or str(p)!=name:raise ValueError('制品路径逃逸')
    return p


def verify(root):
    checks=json.loads((root/'checksums.json').read_text())
    for name,expected in checks.items():
        safe_name(name);path=root/name
        if not path.is_file() or path.is_symlink() or sha(path)!=expected:raise ValueError('制品哈希/类型不符: '+name)
    manifest=json.loads((root/'candidate/model-manifest.json').read_text())
    policy=json.loads((root/'candidate/decision-policy.json').read_text())
    if manifest['candidateOnly'] is not True or manifest['finalEvaluationReportSha256'] is not None or policy['mode']!='alert_only':raise ValueError('候选边界不符')
    if policy['modelId']!=manifest['modelId']:raise ValueError('模型/策略绑定不符')
    return dict(filesVerified=len(checks),checksumsSha256=sha(root/'checksums.json'),
        modelSha256=sha(root/'candidate/model.onnx'),candidateOnly=True,newModelFits=0,newOnnxRuns=0)


def pack(root, output):
    result=verify(root)
    checks=json.loads((root/'checksums.json').read_text())
    # 使用 x 模式，不能覆盖既有交付组合。
    with tarfile.open(output,'x') as t:
        for name in sorted([*checks,'checksums.json']):
            safe_name(name);info=t.gettarinfo(str(root/name),arcname=name)
            info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0;info.mode=0o400
            with (root/name).open('rb') as f:t.addfile(info,f)
    return dict(result,packageSha256=sha(output),packageBytes=output.stat().st_size)


def unpack(package, output, expected):
    if sha(package)!=expected:raise ValueError('完整包哈希不符')
    output.mkdir(parents=True,exist_ok=False)
    with tarfile.open(package) as t:
        for info in t.getmembers():
            safe_name(info.name)
            if not info.isfile():raise ValueError('包只允许普通文件')
        t.extractall(output,filter='data')
    result=verify(output)
    expected_files=set(json.loads((output/'checksums.json').read_text()))|{'checksums.json'}
    actual={p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}
    if actual!=expected_files:raise ValueError('包内文件与清单不一致')
    return dict(result,packageSha256=expected)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['pack','unpack'])
    p.add_argument('--root',type=Path,required=True);p.add_argument('--package',type=Path,required=True)
    p.add_argument('--expected-sha256');a=p.parse_args()
    if a.mode=='unpack' and not a.expected_sha256:p.error('须指定同一完整包 SHA-256')
    print(json.dumps(pack(a.root,a.package) if a.mode=='pack' else unpack(a.package,a.root,a.expected_sha256)))
