#!/usr/bin/env python3
"""冻结前核对原件、提取/关联哈希、五类抽样和时间切分；不读冻结 test。

自动核对与审阅结论分开：本脚本生成可复查样本，不伪造人工批准。
"""
import argparse
import collections
import json
import sqlite3
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from multiclass_common import (CLASSES, MAPPING, SPLITS, SPLIT_VERSION, assign_splits, decide, digest,
    rows, write_json, unique_connections, internal)
from prepare_multiclass import associate


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def utc(value):
    return datetime.fromtimestamp(value / 1000000, timezone.utc).isoformat()


def publisher_check(root, page):
    parser = Text()
    parser.feed(page.read_text())
    content = ' '.join(' '.join(parser.parts).split())
    # 页面列出的当地时段；仅作独立交叉核对，CNS 精确修正窗口不被覆盖。
    schedule = {
        ('tuesday', 'FTP-Patator'): ('2017-07-04', '09:20', '10:20', 'FTP-Patator'),
        ('tuesday', 'SSH-Patator'): ('2017-07-04', '14:00', '15:00', 'SSH-Patator'),
        ('wednesday', 'DoS Slowloris'): ('2017-07-05', '09:47', '10:10', 'DoS slowloris'),
        ('wednesday', 'DoS Slowhttptest'): ('2017-07-05', '10:14', '10:35', 'DoS Slowhttptest'),
        ('wednesday', 'DoS Hulk'): ('2017-07-05', '10:43', '11:00', 'DoS Hulk'),
        ('wednesday', 'DoS GoldenEye'): ('2017-07-05', '11:10', '11:23', 'DoS GoldenEye'),
        ('friday', 'DDoS'): ('2017-07-07', '15:56', '16:16', 'DDoS LOIT'),
        ('friday', 'Portscan'): ('2017-07-07', '13:55', '15:29', 'Port Scan:'),
        ('thursday', 'Infiltration - Portscan'): ('2017-07-06', '14:19', '15:45', 'Second Step (Portscan + Nmap)')}
    windows = json.loads((root / 'inputs/publisher-windows.json').read_text())
    result = []
    for (day, label), (date, start, end, marker) in schedule.items():
        if marker not in content:
            raise ValueError('官方缓存未包含时段依据: ' + marker)
        starts, ends = [int(datetime.fromisoformat(f'{date}T{stamp}:00-03:00').timestamp() * 1000000)
                        for stamp in (start, end)]
        found = [window for window in windows if window['day'] == day and window['rawLabel'] == label]
        if not found:
            raise ValueError('缺少 CNS 修正窗口: ' + label)
        for window in found:
            result.append({'day': day, 'rawLabel': label, 'activityId': window['activityId'],
                'officialEnvelopeUtc': [utc(starts), utc(ends)],
                'correctedUtc': [utc(window['startUs']), utc(window['endUs'])],
                'startOffsetSeconds': (window['startUs'] - starts) / 1000000,
                'endOffsetSeconds': (window['endUs'] - ends) / 1000000,
                'overlapsOfficialEnvelope': window['startUs'] <= ends and window['endUs'] >= starts,
                'interpretation': 'Official minute schedule/envelope is approximate; CNS corrected per-flow and precise windows remain label authority'})
    write_json(root / 'evidence/publisher-crosscheck.json', {'pageSha256': digest(page)['sha256'],
        'timezone': 'America/Halifax, ADT UTC-03:00 in July 2017', 'comparisons': result,
        'notableDifferences': ['SSH corrected window ends approximately 64 minutes later',
            'Thursday internal scans include earlier probing than the broad infiltration narrative',
            'Friday scan envelopes include inactive gaps; not every minute is an attack'],
        'noLabelRewrite': True})


def review(root):
    complete = json.loads((root / 'evidence/full-extraction.json').read_text())
    if complete['status'] != 'completed' or len(complete['views']) != 95:
        raise ValueError('全量视角未完成')
    conn = sqlite3.connect(f'file:{root / "inputs/cns.sqlite"}?mode=ro', uri=True)
    registry = json.loads((root / 'inputs/registry.json').read_text())
    source_hashes = {item['day']: item['sha256'] for item in registry['pcaps']}
    labels, exclusions = [], collections.Counter()
    totals, quality = collections.Counter(), collections.Counter()
    coverage, misses, deltas = collections.Counter(), collections.Counter(), collections.Counter()
    view_hashes, sampled = {}, collections.defaultdict(list)
    for view in sorted(complete['views'], key=lambda row: row['view']):
        folder = root / 'extract' / view['view']
        report = json.loads((folder / 'extraction.json').read_text())
        joined = json.loads((folder / 'association.json').read_text())
        for name, expected in (('observations.jsonl', report['observationsSha256']),
                               ('ledger.jsonl', report['localLedgerSha256']),
                               ('labels.jsonl', joined['labelsSha256'])):
            if digest(folder / name)['sha256'] != expected:
                raise ValueError('产物哈希变化: ' + str(folder / name))
        if (report['status'] != 'completed' or report['pcapSha256'] != source_hashes[view['view'].split('-')[0]]
                or report['binarySha256'] != digest(root / 'bin/guardextract')['sha256']
                or digest(folder / 'association.json')['sha256'] != view['associationSha256']):
            raise ValueError('来源或执行状态变化')
        view_hashes[view['view']] = {name: digest(folder / name)['sha256'] for name in ('extraction.json', 'association.json')}
        totals.update(joined['counts'])
        coverage.update(joined['attackCsvCoverage'])
        deltas.update(joined['timeDeltaHistogramUs'])
        for item in rows(folder / 'labels.jsonl'):
            quality.update(item['qualityReasons'])
            if not item['label']:
                exclusions[item['exclusionReason']] += 1
                if 'nearestDeltaUs' in item:
                    delta = item['nearestDeltaUs']
                    misses['tuple_absent' if delta is None else
                        'delta_le_1s' if delta <= 1000000 else 'delta_le_30s' if delta <= 30000000 else 'delta_gt_30s'] += 1
                continue
            item['view'] = view['view']
            labels.append(item)
    physical, ambiguous = unique_connections(labels)
    exclusions['ambiguous_physical_identity'] += len(ambiguous)
    for item in physical.values():
        sampled[item['label']].append(item)
    examples = []
    for label in CLASSES:
        candidates = sampled[label]
        buckets = collections.defaultdict(list)
        for item in candidates:
            buckets[(item['originalScenario'], item['day'], item['websiteSupplement'])].append(item)
        selected = []
        queues = [sorted(items, key=lambda row: row['physicalConnectionId']) for _, items in sorted(buckets.items(), key=lambda row: str(row[0]))]
        while len(selected) < 50 and any(queues):
            for queue in queues:
                if queue and len(selected) < 50:
                    selected.append(queue.pop(0))
        if len(selected) < 50:
            raise ValueError('每类抽样不足 50: ' + label)
        for item in selected:
            matches = associate(conn, item['day'], item['tupleKey'], item['startUs'], 1000)
            actual = decide(matches, item['local'][0], item['peer'][0], bool(item['excludedWindows']),
                            item['websiteSupplement'] and item['local'][1] in (80, 443))[0]
            if actual != label or not item['cleanSnapshots']:
                raise ValueError('抽样重关联/质量不符')
            examples.append({key: item[key] for key in ('parentConnectionId', 'physicalConnectionId',
                'view', 'local', 'peer', 'label', 'originalScenario', 'startUs', 'endUs', 'activityId',
                'association', 'cleanSnapshots', 'snapshots', 'qualityReasons', 'evidenceTier', 'websiteSupplement')})
    write_json(root / 'evidence/label-review-samples.json', {'sampleCounts': {label: 50 for label in CLASSES},
        'selection': 'round-robin raw scenario/day/web/internal strata; deterministic hash order',
        'automatedChecksPassed': True, 'reviewStatus': 'awaiting_Codex_record_review',
        'independentHumanApproved': False, 'samples': examples})
    split = split_review(physical, exclusions)
    evidence = {'status': 'passed', 'views': len(view_hashes), 'viewHashes': view_hashes,
        'inputLabelSha256': registry['labels']['sha256'],
        'exclusions': dict(exclusions), 'associationTotals': dict(totals), 'qualityReasonCounts': dict(quality),
        'timeDeltaHistogramUs': dict(deltas), 'unmatchedParentNearestDeltaBuckets': dict(misses),
        'attackCsvCoverage': dict(coverage), 'entireConnectionSpanGuard': True,
        'qualityCoverage': quality_coverage(root),
        'ambiguousIdentityGroups': [{'view': item['view'], 'physicalConnectionId': item['physicalConnectionId'],
                                    'parentConnectionId': item['parentConnectionId']} for item in ambiguous],
        'labelSamplesSha256': digest(root / 'evidence/label-review-samples.json')['sha256']} | split
    write_json(root / 'evidence/pre-freeze-review.json', evidence)
    print(json.dumps({key: evidence[key] for key in ('status', 'views', 'connectionCounts', 'exclusions', 'unmatchedParentNearestDeltaBuckets')}))


def split_review(physical, exclusions):
    """独立预核对：网站全局上限后按 host-guard-split/2 切分并检查出口。"""
    groups = collections.defaultdict(list)
    for item in physical.values():
        if item['websiteSupplement']:
            groups[item['local'][0]].append(item)
    for items in groups.values():
        for item in sorted(items, key=lambda row: row['physicalConnectionId'])[2000:]:
            physical.pop(item['physicalConnectionId'])
            exclusions['website_global_server_cap'] += 1
    assignments, scenarios = assign_splits(list(physical.values()))
    counts = {split: collections.Counter() for split in SPLITS}
    sources = {split: collections.Counter() for split in SPLITS}
    for key, item in physical.items():
        if assignments[key]:
            counts[assignments[key]][item['label']] += 1
            if item['label'] == 'normal':
                sources[assignments[key]]['website' if item['websiteSupplement'] else 'internal'] += 1
        else:
            exclusions['split_boundary_30s'] += 1
    if any(set(counts[split]) != set(CLASSES) for split in SPLITS) or counts['test']['normal'] < 4000:
        raise ValueError('切分出口不满足: ' + str(counts))
    if any(sources[split]['internal'] < 1000 for split in SPLITS):
        raise ValueError('内部正常连接不足 1000: ' + str(sources))
    return {'splitRuleVersion': SPLIT_VERSION, 'splitScenarios': scenarios,
            'connectionCounts': {key: dict(value) for key, value in counts.items()},
            'normalSourceCounts': {key: dict(value) for key, value in sources.items()}}


def quality_coverage(root):
    """各类可判定覆盖率：至少一个合格快照的连接 / (合格 + 全快照质量不合格) 连接。

    质量不合格连接按其关联到的原始标签归类；Attempted、不纳入类型及无法归类的不计。
    """
    clean, defective = collections.Counter(), collections.Counter()
    for path in sorted((root / 'extract').glob('*/labels.jsonl')):
        for item in rows(path):
            if item['label']:
                clean[item['label']] += 1
                clean['scenario:' + item['originalScenario'] + ('/website' if item['websiteSupplement'] else '')] += 1
                continue
            if item['exclusionReason'] != 'all_snapshots_quality_defective':
                continue
            raws = {match['rawLabel'] for match in item.get('association') or []}
            if len(raws) != 1:
                continue
            raw = raws.pop()
            label = MAPPING.get(raw) or ('normal' if raw == 'BENIGN' and internal(item['local'][0])
                                         and internal(item['peer'][0]) else None)
            if label:
                defective[label] += 1
                defective['scenario:' + raw] += 1
    return {key: {'clean': clean[key], 'qualityDefective': defective[key],
                  'coverage': round(clean[key] / (clean[key] + defective[key]), 4)}
            for key in sorted(set(clean) | set(defective)) if clean[key] + defective[key]}


def resplit(root):
    """只重做切分预核对：保留已审阅的提取、关联和抽样证据，旧核对改名留档。"""
    old = json.loads((root / 'evidence/pre-freeze-review.json').read_text())
    labels, exclusions = [], collections.Counter()
    for view, hashes in sorted(old['viewHashes'].items()):
        folder = root / 'extract' / view
        if {name: digest(folder / name)['sha256'] for name in hashes} != hashes:
            raise ValueError('已审阅视角变化: ' + view)
        joined = json.loads((folder / 'association.json').read_text())
        if digest(folder / 'labels.jsonl')['sha256'] != joined['labelsSha256']:
            raise ValueError('标签文件变化: ' + view)
        for item in rows(folder / 'labels.jsonl'):
            if not item['label']:
                exclusions[item['exclusionReason']] += 1
                continue
            item['view'] = view
            labels.append(item)
    physical, ambiguous = unique_connections(labels)
    exclusions['ambiguous_physical_identity'] += len(ambiguous)
    split = split_review(physical, exclusions)
    (root / 'evidence/pre-freeze-review.json').rename(root / 'evidence/pre-freeze-review-split1.json')
    evidence = {key: value for key, value in old.items() if key not in
                ('connectionCounts', 'exclusions', 'splitActivityGroups')}
    evidence |= split | {'exclusions': dict(exclusions), 'qualityCoverage': quality_coverage(root),
        'supersedes': {'file': 'pre-freeze-review-split1.json',
                       'sha256': digest(root / 'evidence/pre-freeze-review-split1.json')['sha256'],
                       'reason': 'split/1 count-quantile bounds left Slowhttptest, Friday Portscan and Hulk segments without validation'}}
    write_json(root / 'evidence/pre-freeze-review.json', evidence)
    print(json.dumps({key: evidence[key] for key in ('splitRuleVersion', 'connectionCounts', 'normalSourceCounts', 'exclusions')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--official-page', type=Path)
    parser.add_argument('--resplit', action='store_true', help='保留已审阅证据，只按 host-guard-split/2 重做切分预核对')
    args = parser.parse_args()
    if args.resplit:
        resplit(args.run)
    elif args.official_page:
        publisher_check(args.run, args.official_page)
    else:
        review(args.run)


if __name__ == '__main__':
    main()
