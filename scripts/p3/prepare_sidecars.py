"""仅按冻结开发集合观察 ID 匹配原始观测，不解码未入选记录。

旁路字段用于首次过阈值与来源汇总，绝不成为模型特征；不会打开 test/L3。
"""
import argparse
import hashlib
import json
import re
from pathlib import Path


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--frozen', type=Path, required=True)
    parser.add_argument('--extract', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    wanted, orders = {}, {}
    manifest = json.loads((args.frozen / 'manifest.json').read_text())
    for role in ('train', 'validation'):
        path = args.frozen / role / 'dataset.jsonl'
        if digest(path) != manifest['datasetSha256'][role]:
            raise ValueError('冻结哈希不符')
        orders[role] = []
        with path.open() as stream:
            for line in stream:
                row = json.loads(line)
                identifier = row['observationId']
                if identifier in wanted:
                    raise ValueError('观察 ID 重复')
                wanted[identifier.encode()] = (role, row)
                orders[role].append(identifier)
    # 原始记录只扫描字节索引；仅开发 ID 命中后才解码该观察。
    pattern = re.compile(rb'"observationId"\s*:\s*"([0-9a-f-]+)"')
    matched, sources = {}, {}
    fields = ('assetId', 'sensorId', 'bootId', 'captureScopeId', 'peerKey', 'keyEpoch',
              'asOf', 'firstSeenAt', 'servicePort', 'direction', 'transport')
    for path in sorted(args.extract.glob('*/observations.jsonl')):
        count = 0
        with path.open('rb') as stream:
            for line in stream:
                identifier = pattern.search(line)
                if identifier is None or identifier[1] not in wanted:
                    continue
                role, row = wanted[identifier[1]]
                observation = json.loads(line)
                if observation['parentConnectionId'] != row['parentConnectionId']:
                    raise ValueError('冻结 parent 与原始观察不符')
                if observation['features'] != row['input']['features'] or observation['contexts'] != row['input']['contexts']:
                    raise ValueError('冻结特征与原始观察不符')
                key = identifier[1].decode()
                if key in matched:
                    raise ValueError('原始观察重复')
                matched[key] = {'observationId': key, 'parentConnectionId': row['parentConnectionId'],
                                **{field: observation[field] for field in fields}}
                count += 1
        if count:
            sources[str(path)] = count
    if len(matched) != len(wanted):
        raise ValueError(f'旁路缺记录: {len(matched)}/{len(wanted)}')
    evidence = {'frozenManifestSha256': digest(args.frozen / 'manifest.json'),
                'datasetSha256': {role: manifest['datasetSha256'][role] for role in orders},
                'onlyDecodedSelectedDevelopmentObservations': True, 'testFilesOpened': False,
                'sourcesMatched': sources, 'sidecars': {}}
    for role, identifiers in orders.items():
        path = args.output / role / 'metadata.jsonl'
        path.parent.mkdir()
        with path.open('x') as stream:
            for identifier in identifiers:
                stream.write(json.dumps(matched[identifier], separators=(',', ':')) + '\n')
        evidence['sidecars'][role] = {'rows': len(identifiers), 'sha256': digest(path)}
    (args.output / 'sidecar-manifest.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'rows': len(matched), 'testFilesOpened': False}))


if __name__ == '__main__':
    main()
