#!/usr/bin/env python3
"""装配/接收已冻结数据补齐包；只写新目录，逐文件哈希验证，拒绝覆盖与路径逃逸。"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile

DATASET_ID = 'host-guard-p2-final-development-20261004'


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def pack(repo, dataset, output):
    freeze_path = repo / 'docs/p2/data-readiness/freeze-manifest.json'
    freeze = json.loads(freeze_path.read_text())
    output.mkdir()
    public, private = output / 'public', output / 'dataset'
    public.mkdir()
    private.mkdir()
    for name, expected in freeze['publicFiles'].items():
        source = repo / name
        if sha(source) != expected:
            raise ValueError('冻结公开文件变更: ' + name)
        target = public / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    shutil.copyfile(freeze_path, public / 'docs/p2/data-readiness/freeze-manifest.json')
    for name, expected in freeze['datasetFiles'].items():
        if sha(dataset / name) != expected:
            raise ValueError('冻结数据已变化: ' + name)
        shutil.copyfile(dataset / name, private / name)
    manifest = {p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob('*')) if p.is_file()}
    (output / 'transfer-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    with tarfile.open(output.with_suffix('.tar.gz'), 'w:gz') as tar:
        for name in sorted([*manifest, 'transfer-manifest.json']):
            tar.add(output / name, arcname=name, recursive=False)
    print(json.dumps(dict(status='packed', files=len(manifest), datasetId=DATASET_ID,
                         archiveSha256=sha(output.with_suffix('.tar.gz')), endpointsOrKeysIncluded=False)))


def install(repo, archive, expected):
    if sha(archive) != expected:
        raise ValueError('传输归档哈希不符')
    public = repo / 'contracts' / DATASET_ID
    private = repo / '.cache' / DATASET_ID
    if public.exists() or private.exists():
        raise FileExistsError('目标已经存在，拒绝覆盖')
    with tarfile.open(archive, 'r:gz') as tar:
        manifest = json.load(tar.extractfile('transfer-manifest.json'))
        members = tar.getmembers()
        if len(members) != len(manifest) + 1 or {m.name for m in members} != {*manifest, 'transfer-manifest.json'}:
            raise ValueError('交付成员集合不符')
        for member in members:
            name = PurePosixPath(member.name)
            if not member.isfile() or name.is_absolute() or '..' in name.parts:
                raise ValueError('不安全的归档成员')
            if member.name == 'transfer-manifest.json':
                continue
            if name.parts[0] not in ('public', 'dataset'):
                raise ValueError('成员超出交付范围')
            with tar.extractfile(member) as f:
                if hashlib.file_digest(f, 'sha256').hexdigest() != manifest[member.name]:
                    raise ValueError('交付成员哈希不符')
        public.mkdir(parents=True)
        private.mkdir(parents=True)
        for member in members:
            if member.name == 'transfer-manifest.json':
                continue
            name = PurePosixPath(member.name)
            target = (public if name.parts[0] == 'public' else private).joinpath(*name.parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)
            if sha(target) != manifest[member.name]:
                raise ValueError('接收端磁盘文件哈希不符')
    result = dict(status='passed', datasetId=DATASET_ID, filesHashVerified=len(manifest),
                  archiveSha256=expected, sourceBranchModified=False, trainingExecuted=False,
                  endpointLedgerIncluded=False, keyIncluded=False)
    with (private / 'delivery-verification.json').open('x', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('pack', 'install'))
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--dataset', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--archive', type=Path)
    p.add_argument('--expected-sha256')
    a = p.parse_args()
    if a.action == 'pack':
        pack(a.repo, a.dataset, a.output)
    else:
        install(a.repo, a.archive, a.expected_sha256)
