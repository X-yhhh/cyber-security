#!/usr/bin/env python3
"""P3-A CIC2017 登记、CNS2022 关联与冻结；原件只读、输出排他创建。

只解析 CSV 的标识/时间/标签列。官方特征不进入数据集；不拟合、不读
冻结 test，不继承旧 prefix 候选。每个网站独立提取，避免合并主机上下文。
"""
import argparse
import ast
import collections
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import subprocess
import uuid
import zipfile
from pathlib import Path

from multiclass_common import (PLAN, LABEL_VERSION, CLASS_VERSION, CLASSES, MAPPING,
    SPLITS, SPLIT_VERSION, applicable, assign_splits, controlled_root, create, decide, defective,
    digest, endpoint, internal, line, micros, model_input, normal_split, rows,
    tuple_key, write_json, unique_connections)

DAYS = ('monday', 'tuesday', 'wednesday', 'thursday', 'friday')


def windows(source):
    """用 AST 读取发布脚本的常量时段与主机；不执行下载的 Python。"""
    result = {}
    for call in ast.walk(ast.parse(Path(source).read_text(encoding='utf-8'))):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != 'label_flows':
            continue
        if not call.args or not isinstance(call.args[0], ast.Name):
            continue
        day = call.args[0].id.removesuffix('_df')
        raw = ast.literal_eval(call.args[1])
        if 'Attempted' in raw:
            continue
        start, end = (ast.literal_eval(value) // 1000 for value in call.args[2:4])
        hosts = []
        for value in call.args[4:6]:
            hosts.extend(ast.literal_eval(value) or [])
        key = (day, raw, start, end)
        result[key] = {'day': day, 'rawLabel': raw, 'startUs': start, 'endUs': end,
                       'hosts': hosts, 'excluded': raw not in MAPPING,
                       'activityId': f'{day}:{raw}:{start}'}
    # Infiltration/Botnet 的 Attempted-only 时段也必须整体隔离。
    for call in ast.walk(ast.parse(Path(source).read_text(encoding='utf-8'))):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != 'label_flows':
            continue
        raw = ast.literal_eval(call.args[1])
        base = raw.removesuffix(' - Attempted')
        if base in MAPPING or 'Attempted' not in raw:
            continue
        day = call.args[0].id.removesuffix('_df')
        start, end = (ast.literal_eval(value) // 1000 for value in call.args[2:4])
        hosts = []
        for value in call.args[4:6]:
            hosts.extend(ast.literal_eval(value) or [])
        key = (day, base, start, end)
        result.setdefault(key, {'day': day, 'rawLabel': base, 'startUs': start,
            'endUs': end, 'hosts': hosts, 'excluded': True,
            'activityId': f'{day}:{base}:{start}'})
    return sorted(result.values(), key=lambda row: (row['day'], row['startUs'], row['rawLabel']))


def index(args):
    root = controlled_root(args.run)
    target = root / 'inputs' / 'cns.sqlite'
    target.parent.mkdir(exist_ok=True)
    if target.exists():
        raise ValueError('标签索引已存在')
    sources = []
    for day in DAYS:
        path = args.raw / f'{day.title()}-WorkingHours.pcap'
        checks = digest(path, ('sha256', 'md5'))
        md5_path = path.with_suffix('.md5')
        expected = re.search(r'\b[a-fA-F0-9]{32}\b', md5_path.read_text()).group().lower()
        if checks['md5'] != expected:
            raise ValueError('PCAP MD5 与下载记录不符: ' + day)
        sources.append({'day': day, 'path': str(path.resolve()), 'bytes': path.stat().st_size,
                        **checks, 'downloadMd5': expected, 'downloadRecord': str(md5_path),
                        'downloadRecordSha256': digest(md5_path)['sha256']})
        print(json.dumps({'registered': day, 'bytes': path.stat().st_size}), flush=True)
    archive = args.raw / 'improved' / 'CICIDS2017_improved.zip'
    archive_hash = digest(archive)['sha256']
    if archive_hash != '97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883':
        raise ValueError('CNS2022 原件哈希与下载记录不符')
    source = args.raw / 'improved' / 'label-source-readonly.txt'
    intervals = windows(source)
    write_json(root / 'inputs' / 'publisher-windows.json', intervals)
    conn = sqlite3.connect(target)
    os.chmod(target, 0o600)
    conn.execute('CREATE TABLE labels(day TEXT, tupleKey TEXT, startUs INTEGER, rawLabel TEXT, '
                 'src TEXT, sport INTEGER, dst TEXT, dport INTEGER, csvRow INTEGER, attempted TEXT)')
    distributions = {}
    with zipfile.ZipFile(archive) as zipped:
        for day in DAYS:
            member = next(name for name in zipped.namelist() if Path(name).name == day + '.csv')
            counts = collections.Counter()
            buffer = []
            with zipped.open(member) as stream:
                for number, record in enumerate(csv.DictReader(io.TextIOWrapper(stream, encoding='utf-8-sig')), 2):
                    if int(record['Protocol']) != 6:
                        counts['non_tcp'] += 1
                        continue
                    src, dst = record['Src IP'], record['Dst IP']
                    sport, dport = int(record['Src Port']), int(record['Dst Port'])
                    raw = record['Label']
                    buffer.append((day, tuple_key(6, (src, sport), (dst, dport)),
                        micros(record['Timestamp']), raw, src, sport, dst, dport,
                        number, record['Attempted Category']))
                    counts[raw] += 1
                    if len(buffer) == 10000:
                        conn.executemany('INSERT INTO labels VALUES(?,?,?,?,?,?,?,?,?,?)', buffer)
                        buffer.clear()
                conn.executemany('INSERT INTO labels VALUES(?,?,?,?,?,?,?,?,?,?)', buffer)
            conn.commit()
            distributions[day] = dict(counts)
            print(json.dumps({'indexed': day, 'counts': dict(counts)}), flush=True)
    conn.execute('CREATE INDEX association ON labels(day, tupleKey, startUs)')
    conn.commit()
    conn.close()
    registry = {'plan': PLAN, 'pcaps': sources, 'labels': {'path': str(archive.resolve()),
        'bytes': archive.stat().st_size, 'sha256': archive_hash, 'version': 'CNS2022-CICIDS2017-improved',
        'timezone': 'UTC', 'allowedColumns': ['Src IP', 'Src Port', 'Dst IP', 'Dst Port',
            'Protocol', 'Timestamp', 'Label', 'Attempted Category'],
        'counts': distributions, 'indexSha256': digest(target)['sha256'],
        'publisherScriptSha256': digest(source)['sha256']},
        'license': {'source': 'https://www.unb.ca/cic/datasets/ids-2017.html',
            'terms': 'Publicly available for researchers; cite Sharafaldin et al., ICISSP 2018',
            'correctedLabels': 'https://intrusion-detection.distrinet-research.be/CNS2022/',
            'correctedCitation': 'Engelen, Rimmer and Joosen, Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study, CNS 2021; corrected 2022 release'},
        'finalTestRead': False, 'modelFits': 0}
    write_json(root / 'inputs' / 'registry.json', registry)


def website_plan(args):
    root = Path(args.run)
    conn = sqlite3.connect(f'file:{root / "inputs/cns.sqlite"}?mode=ro', uri=True)
    intervals = json.loads((root / 'inputs/publisher-windows.json').read_text())
    plan = []
    for day in DAYS:
        counts = collections.Counter()
        for src, dst, first in conn.execute("SELECT src,dst,startUs FROM labels WHERE day=? AND rawLabel='BENIGN' AND dport IN (80,443)", (day,)):
            if not internal(src) or internal(dst) or dst.startswith(('172.16.', '192.168.', '10.')):
                continue
            if any(w['day'] == day and w['excluded'] and src in w['hosts']
                   and w['startUs'] - 30000000 <= first <= w['endUs'] + 30000000 for w in intervals):
                continue
            counts[dst] += 1
        for address, count in counts.most_common(args.servers):
            plan.append({'day': day, 'address': address, 'csvBenignConnections': count,
                'connectionCap': args.cap, 'mode': 'reviewed_website',
                'evidenceTier': 'analyst_reviewed',
                'reviewBasis': 'CNS BENIGN; internal initiator; server port 80/443; excluded host/time windows removed',
                'reviewer': 'Codex data preparation; not independent human sign-off'})
    write_json(root / 'inputs' / args.output, {'servers': plan, 'perDayMaximumServers': args.servers,
        'perServerConnectionCap': args.cap,
        'limitation': 'Client capture vantage: timing differs from a real server-side sensor; not release evidence'})
    print(json.dumps({'servers': len(plan), 'potentialConnections': sum(min(p['csvBenignConnections'], args.cap) for p in plan)}))


def extract(args):
    root = controlled_root(args.run)
    key_path = root / 'configs/peer-key.bin'
    if not key_path.exists() or key_path.stat().st_size != 32:
        raise ValueError('缺少受控 HMAC 密钥')
    output = root / 'extract' / f'{args.day}-{args.address.replace(".", "-")}'
    if output.exists():
        raise ValueError('视角输出已存在，不覆盖')
    output.mkdir(mode=0o700)
    config = root / 'configs' / (output.name + '.json')
    write_json(config, {**{key: str(uuid.uuid4()) for key in
        ('assetId', 'sensorId', 'bootId', 'captureScopeId')},
        'localAddresses': [args.address], 'secretFile': str(key_path), 'keyEpoch': 1})
    binary = root / 'bin/guardextract'
    pcap = args.raw / f'{args.day.title()}-WorkingHours.pcap'
    subprocess.run([str(binary), '-config', str(config), '-pcap', str(pcap),
        '-out', str(output / 'observations.jsonl'), '-ledger', str(output / 'ledger.jsonl'),
        '-report', str(output / 'extraction.json')], check=True)
    print(json.dumps({'extracted': output.name}), flush=True)


def associate(conn, day, key, first, tolerance):
    candidates = conn.execute('SELECT startUs,rawLabel,csvRow,src,sport,dst,dport FROM labels '
        'WHERE day=? AND tupleKey=? AND startUs BETWEEN ? AND ?',
        (day, key, first - tolerance, first + tolerance)).fetchall()
    return [{'startUs': row[0], 'rawLabel': row[1], 'csvRow': row[2], 'src': row[3],
        'sport': row[4], 'dst': row[5], 'dport': row[6], 'deltaUs': first - row[0]} for row in candidates]


def join(args):
    root = Path(args.run)
    view = root / 'extract' / args.view
    day = args.view.split('-', 1)[0]
    conn = sqlite3.connect(f'file:{root / "inputs/cns.sqlite"}?mode=ro', uri=True)
    intervals = json.loads((root / 'inputs/publisher-windows.json').read_text())
    extraction = json.loads((view / 'extraction.json').read_text())
    parents = {}
    for obs, entry in zip(rows(view / 'observations.jsonl'), rows(view / 'ledger.jsonl'), strict=True):
        if obs['observationId'] != entry['observationId']:
            raise ValueError('观察与旁路账本错位')
        if not applicable(obs):
            continue
        parent = obs['parentConnectionId']
        first = micros(entry['First'])
        local, peer = endpoint(entry['Endpoints']['Local']), endpoint(entry['Endpoints']['Peer'])
        item = parents.setdefault(parent, {'parentConnectionId': parent,
            'local': local, 'peer': peer, 'tupleKey': tuple_key(6, local, peer),
            'startUs': first, 'endUs': micros(entry['Last']), 'snapshots': 0, 'cleanSnapshots': 0,
            'qualityReasons': collections.Counter()})
        if item['tupleKey'] != tuple_key(6, local, peer):
            raise ValueError('同 parent 端点变化')
        item['startUs'] = min(item['startUs'], first)
        item['endUs'] = max(item['endUs'], micros(entry['Last']))
        item['snapshots'] += 1
        item['cleanSnapshots'] += not defective(obs)
        item['qualityReasons'].update(key for key, value in obs['quality'].items() if value is True)
    counts = collections.Counter()
    delta_counts = collections.Counter()
    unmatched = collections.Counter()
    matched_rows = set()
    labels = []
    for item in parents.values():
        matches = associate(conn, day, item['tupleKey'], item['startUs'], args.tolerance_us)
        local, peer = item['local'][0], item['peer'][0]
        intersect = [w for w in intervals if w['day'] == day and w['excluded'] and
            ({local, peer} & set(w['hosts'])) and item['startUs'] <= w['endUs'] + 30000000
            and item['endUs'] >= w['startUs'] - 30000000]
        reviewed = args.web and item['local'][1] in (80, 443)
        label, exclusion, tier = decide(matches, local, peer, bool(intersect), reviewed)
        activity = None
        raw = matches[0]['rawLabel'] if matches else None
        schedule = []
        if label and label != 'normal':
            schedule = [w for w in intervals if w['day'] == day and w['rawLabel'] == raw and
                        w['startUs'] - args.tolerance_us <= item['startUs'] <= w['endUs'] + args.tolerance_us]
            if len(schedule) != 1:
                label, exclusion, tier = None, 'attack_outside_publisher_window', 'ambiguous'
            else:
                activity = schedule[0]['activityId']
        if label == 'normal':
            activity = f'{day}:normal:' + ('website' if args.web else 'internal')
        if matches:
            counts['associated'] += 1
            delta_counts.update(str(abs(match['deltaUs'])) for match in matches)
            matched_rows.update(match['csvRow'] for match in matches)
        else:
            counts['unassociated'] += 1
            nearest = conn.execute('SELECT min(abs(startUs-?)) FROM labels WHERE day=? AND tupleKey=?',
                                  (item['startUs'], day, item['tupleKey'])).fetchone()[0]
            unmatched['tuple_absent' if nearest is None else 'first_time_outside_tolerance'] += 1
            item['nearestDeltaUs'] = nearest
        if not item['cleanSnapshots']:
            label, exclusion = None, 'all_snapshots_quality_defective'
        item.update({'day': day, 'label': label, 'exclusionReason': exclusion,
            'evidenceTier': tier, 'activityId': activity, 'originalScenario': raw,
            'association': matches, 'excludedWindows': [w['activityId'] for w in intersect],
            'labelRuleVersion': LABEL_VERSION, 'classMappingVersion': CLASS_VERSION,
            'sourceVersion': 'CNS2022-CICIDS2017-improved',
            'sourceHash': extraction['pcapSha256'], 'websiteSupplement': args.web,
            'physicalConnectionId': hashlib.sha256((extraction['pcapSha256'] + item['tupleKey']
                + ':' + str(item['startUs'])).encode()).hexdigest()})
        counts[label or exclusion] += 1
        counts['quality_defective_snapshots'] += item['snapshots'] - item['cleanSnapshots']
        labels.append(item)
    # 网页上限按连接哈希选样，先选 parent，再保留其所有合格快照。
    if args.web:
        retained = sorted((item for item in labels if item['label']), key=lambda item: item['physicalConnectionId'])
        for item in retained[args.web_cap:]:
            counts[item['label']] -= 1
            counts['website_server_cap'] += 1
            item.update(label=None, exclusionReason='website_server_cap')
    with create(view / 'labels.jsonl') as stream:
        for item in sorted(labels, key=lambda row: (row['startUs'], row['parentConnectionId'])):
            line(stream, item)
    address = json.loads((root / 'configs' / (args.view + '.json')).read_text())['localAddresses'][0]
    attack_rows = conn.execute("SELECT csvRow,rawLabel,startUs,tupleKey FROM labels WHERE day=? AND dst=? AND rawLabel NOT LIKE '%Attempted%' AND rawLabel != 'BENIGN'", (day, address)).fetchall()
    coverage = collections.Counter()
    parent_keys = {item['tupleKey'] for item in parents.values()}
    for number, raw, first, key in attack_rows:
        if raw in MAPPING:
            coverage[raw + ':totalCsv'] += 1
            if number in matched_rows:
                coverage[raw + ':associatedCsv'] += 1
            else:
                # 只统计原因，不把 CSV 未覆盖行制造为训练样本。
                coverage[raw + (':unmatched_first_time' if key in parent_keys else ':no_inbound_parent')] += 1
    report = {'plan': PLAN, 'view': args.view, 'toleranceUs': args.tolerance_us,
        'parentConnections': len(parents), 'counts': dict(counts), 'timeDeltaHistogramUs': dict(delta_counts),
        'unmatchedReasons': dict(unmatched), 'attackCsvCoverage': dict(coverage),
        'qualityPolicy': 'exclude defective snapshots; retain parent if at least one clean snapshot; no feature imputation',
        'labelsSha256': digest(view / 'labels.jsonl')['sha256'],
        'extractorReportSha256': digest(view / 'extraction.json')['sha256']}
    write_json(view / 'association.json', report)
    print(json.dumps({key: report[key] for key in ('view', 'parentConnections', 'counts', 'unmatchedReasons', 'attackCsvCoverage')}), flush=True)


def freeze(args):
    root = Path(args.run)
    review = json.loads((root / 'evidence/pre-freeze-review.json').read_text())
    signoff = json.loads((root / 'evidence/label-review-signoff.json').read_text())
    if review['status'] != 'passed' or signoff['status'] != 'reviewed':
        raise ValueError('冻结前核对/抽样审阅未完成')
    if signoff['samplesSha256'] != digest(root / 'evidence/label-review-samples.json')['sha256']:
        raise ValueError('审阅样本哈希变化')
    target = controlled_root(root / 'frozen')
    if (target / 'manifest.json').exists():
        raise ValueError('数据已冻结')
    labels, parent_lookup, eligible = {}, {}, []
    exclusions = collections.Counter()
    view_paths = sorted((root / 'extract').glob('*/labels.jsonl'))
    for path in view_paths:
        view = path.parent.name
        if (digest(path.parent / 'association.json')['sha256'] != review['viewHashes'][view]['association.json']
                or digest(path.parent / 'extraction.json')['sha256'] != review['viewHashes'][view]['extraction.json']):
            raise ValueError('已审阅视角变化')
        association = json.loads((path.parent / 'association.json').read_text())
        extraction = json.loads((path.parent / 'extraction.json').read_text())
        for name, expected in (('labels.jsonl', association['labelsSha256']),
                               ('observations.jsonl', extraction['observationsSha256'])):
            if digest(path.parent / name)['sha256'] != expected:
                raise ValueError('冻结输入哈希变化: ' + view + '/' + name)
        for item in rows(path):
            parent_lookup[item['parentConnectionId']] = item
            if not item['label']:
                exclusions[item['exclusionReason']] += 1
                continue
            eligible.append(item)
    labels, ambiguous = unique_connections(eligible)
    for item in ambiguous:
        item.update(label=None, exclusionReason='ambiguous_physical_identity')
        exclusions['ambiguous_physical_identity'] += 1
    # 每个网站跨五天累计最多 2000 连接，避免同一服务器主导补充数据。
    web_groups = collections.defaultdict(list)
    for item in labels.values():
        if item['websiteSupplement']:
            web_groups[item['local'][0]].append(item)
    for items in web_groups.values():
        for item in sorted(items, key=lambda row: row['physicalConnectionId'])[2000:]:
            labels.pop(item['physicalConnectionId'])
            item.update(label=None, exclusionReason='website_global_server_cap')
            exclusions['website_global_server_cap'] += 1
    if review.get('splitRuleVersion') != SPLIT_VERSION:
        raise ValueError('冻结前核对不是当前切分规则')
    assignments, scenarios = assign_splits(list(labels.values()))
    if scenarios != review['splitScenarios']:
        raise ValueError('场景切分与预核对不符')
    count = {split: collections.Counter() for split in SPLITS}
    sample_count = {split: collections.Counter() for split in SPLITS}
    supplement_count = {split: collections.Counter() for split in SPLITS}
    normal_sources = {split: collections.Counter() for split in SPLITS}
    for item in labels.values():
        split = assignments[item['physicalConnectionId']]
        if split:
            count[split][item['label']] += 1
            supplement_count[split]['website' if item['websiteSupplement'] else 'internal_or_attack'] += 1
            if item['label'] == 'normal':
                normal_sources[split]['website' if item['websiteSupplement'] else 'internal'] += 1
        else:
            exclusions['split_boundary_30s'] += 1
    for split in SPLITS:
        if set(count[split]) != set(CLASSES):
            raise ValueError('集合未覆盖五类: ' + split + str(count[split]))
    if count['test']['normal'] < 4000:
        raise ValueError('test normal 不足 4000: ' + str(count['test']['normal']))
    if ({key: dict(value) for key, value in count.items()} != review['connectionCounts']
            or {key: dict(value) for key, value in normal_sources.items()} != review['normalSourceCounts']):
        raise ValueError('独立预核对与最终切分数量不符')
    with create(target / 'split-ledger.jsonl') as stream:
        for item in sorted(labels.values(), key=lambda row: row['physicalConnectionId']):
            split = assignments[item['physicalConnectionId']]
            line(stream, {key: item[key] for key in ('physicalConnectionId', 'parentConnectionId',
                'label', 'activityId', 'startUs', 'sourceHash', 'websiteSupplement')} | {'split': split})
    streams = {}
    try:
        for split in SPLITS:
            folder = controlled_root(target / split)
            streams[split] = create(folder / 'dataset.jsonl')
        for path in view_paths:
            for obs in rows(path.parent / 'observations.jsonl'):
                item = parent_lookup.get(obs['parentConnectionId'])
                if not item or not item['label'] or not applicable(obs) or defective(obs):
                    continue
                split = assignments[item['physicalConnectionId']]
                if not split:
                    continue
                line(streams[split], {'parentConnectionId': item['parentConnectionId'],
                    'physicalConnectionId': item['physicalConnectionId'],
                    'observationId': obs['observationId'], 'profile': obs['profile'],
                    'label': item['label'], 'activityId': item['activityId'],
                    'evidenceTier': item['evidenceTier'], 'websiteSupplement': item['websiteSupplement'],
                    'input': model_input(obs)})
                sample_count[split][item['label']] += 1
    finally:
        for stream in streams.values():
            stream.close()
    files = {split: digest(target / split / 'dataset.jsonl')['sha256'] for split in SPLITS}
    manifest = {'plan': PLAN, 'stage': 'P3-A', 'labelRuleVersion': LABEL_VERSION,
        'classMappingVersion': CLASS_VERSION, 'classOrder': list(CLASSES),
        'contractVersion': 'host-guard/5.0.0-rc.2', 'candidateOnly': True, 'modelFits': 0,
        'finalTestRead': False, 'testAccess': 'P6 only through access_multiclass_test.py; sealed mode 000',
        'connectionCounts': {split: dict(value) for split, value in count.items()},
        'snapshotCounts': {split: dict(value) for split, value in sample_count.items()},
        'supplementCounts': {split: dict(value) for split, value in supplement_count.items()},
        'datasetSha256': files, 'splitLedgerSha256': digest(target / 'split-ledger.jsonl')['sha256'],
        'registrySha256': digest(root / 'inputs/registry.json')['sha256'],
        'splitRuleVersion': SPLIT_VERSION, 'splitScenarios': scenarios,
        'normalSourceCounts': {split: dict(value) for split, value in normal_sources.items()},
        'qualityCoverage': review['qualityCoverage'], 'exclusions': dict(exclusions),
        'guardSeconds': 30, 'normalBlockSeconds': 600,
        'websiteGlobalServerConnectionCap': 2000,
        'entireConnectionSpanGuard': True,
        'preFreezeReviewSha256': digest(root / 'evidence/pre-freeze-review.json')['sha256'],
        'labelReviewSignoffSha256': digest(root / 'evidence/label-review-signoff.json')['sha256'],
        'publisherCrosscheckSha256': digest(root / 'evidence/publisher-crosscheck.json')['sha256'],
        'unmatchedCsvReviewSha256': digest(root / 'evidence/unmatched-csv-review.json')['sha256'],
        'preparationSourceSha256': {path.name: digest(path)['sha256'] for path in Path(__file__).parent.glob('*multiclass*.py')},
        'normalBlockCycle': ['train'] * 6 + ['validation'] * 2 + ['test'] * 2,
        'associationReports': {str(path.parent.relative_to(root)): digest(path.parent / 'association.json')['sha256'] for path in view_paths},
        'limitations': ['Client-side capture timing for website supplement',
            'Same CIC2017 tools across splits; L2 is optional and not yet prepared',
            'Historical capture loss unknown; recorded defective snapshots excluded',
            'Quality exclusion (mostly offloadSuspected server responses) removes most Hulk/DDoS connections; see qualityCoverage',
            'No independent human label approval or deployed capability is implied']}
    write_json(target / 'manifest.json', manifest)
    with create(target / 'test-access.jsonl') as stream:
        line(stream, {'event': 'sealed_after_preparation', 'stage': 'P3-A',
            'testRead': False, 'sha256': files['test']})
    # 生成时完成哈希；封存后本阶段不再打开 test 的特征或标签。
    os.chmod(target / 'test/dataset.jsonl', 0)
    os.chmod(target / 'test', 0)
    print(json.dumps({'frozen': str(target), 'counts': manifest['connectionCounts'], 'sha256': files}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument('--raw', type=Path)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('index')
    web = commands.add_parser('website-plan')
    web.add_argument('--servers', type=int, default=15)
    web.add_argument('--cap', type=int, default=2000)
    web.add_argument('--output', default='website-plan.json')
    extraction = commands.add_parser('extract')
    extraction.add_argument('--day', choices=DAYS, required=True)
    extraction.add_argument('--address', required=True)
    labeling = commands.add_parser('join')
    labeling.add_argument('--view', required=True)
    labeling.add_argument('--tolerance-us', type=int, required=True)
    labeling.add_argument('--web', action='store_true')
    labeling.add_argument('--web-cap', type=int, default=2000)
    commands.add_parser('freeze')
    args = parser.parse_args()
    {'index': index, 'website-plan': website_plan, 'extract': extract, 'join': join, 'freeze': freeze}[args.command](args)


if __name__ == '__main__':
    main()
