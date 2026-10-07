#!/usr/bin/env python3
"""P6 冻结测试访问入口：每次请求追加日志，最多三个已登记评价运行。

本工具不在 P3-A 运行。调用方先提供绑定当前候选/切分的 P6 计划，再以
stdin 收取 test；禁止导出到 train/validation。OS 权限是防误读措施，不能
阻止同账户主动绕过；任何直接 chmod/读取均不属于受支持的开发流程。
"""
import argparse
import json
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from multiclass_common import PLAN, digest, line, rows


@contextmanager
def evaluation_lock(root):
    """文件系统原子互斥覆盖登记到重封存；并发及崩溃残留均拒绝读取。"""
    lock = root / '.test-access-lock'
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        with (root / 'test-access.jsonl').open('a', encoding='utf-8') as stream:
            line(stream, {'event': 'access_denied_busy', 'at': datetime.now(timezone.utc).isoformat()})
        raise ValueError('已有 test 访问或崩溃残留锁，拒绝并发读取') from None
    try:
        yield
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--frozen', type=Path, required=True)
    parser.add_argument('--evaluation-plan', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--evaluation-id', required=True)
    args = parser.parse_args()
    root = args.frozen.resolve()
    with evaluation_lock(root):
        access(args, root)


def access(args, root):
    """仅接受绑定数据清单与当前候选的 P6 计划；失败亦保留请求记录。"""
    log = root / 'test-access.jsonl'
    event = {'at': datetime.now(timezone.utc).isoformat(), 'event': 'access_requested',
             'evaluationId': args.evaluation_id, 'stage': 'P6'}
    prior = list(rows(log))
    with log.open('a', encoding='utf-8') as stream:
        line(stream, event)
    manifest = json.loads((root / 'manifest.json').read_text())
    plan = json.loads(args.evaluation_plan.read_text())
    used = {row['evaluationId'] for row in prior if row['event'] == 'access_started'}
    ids = plan.get('evaluationIds', [])
    if (plan.get('plan') != PLAN or plan.get('stage') != 'P6'
            or plan.get('candidateSha256') != digest(args.candidate)['sha256']
            or plan.get('splitManifestSha256') != digest(root / 'manifest.json')['sha256']
            or not isinstance(ids, list) or not all(isinstance(value, str) for value in ids)
            or len(ids) != len(set(ids)) or args.evaluation_id not in ids
            or len(ids) > 3 or args.evaluation_id in used
            or len(used) >= 3):
        raise ValueError('未绑定合法 P6 计划/候选或已超过测试次数；请求已记录')
    folder, path = root / 'test', root / 'test/dataset.jsonl'
    if os.name != 'nt':
        os.chmod(folder, 0o700)
        os.chmod(path, 0o400)
    try:
        if digest(path)['sha256'] != manifest['datasetSha256']['test']:
            raise ValueError('test 哈希变化，拒绝读取')
        with log.open('a', encoding='utf-8') as stream:
            line(stream, event | {'event': 'access_started', 'candidateSha256': plan['candidateSha256']})
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b''):
                sys.stdout.buffer.write(chunk)
        with log.open('a', encoding='utf-8') as stream:
            line(stream, event | {'event': 'access_completed'})
    finally:
        if os.name != 'nt':
            os.chmod(path, 0)
            os.chmod(folder, 0)


if __name__ == '__main__':
    main()
