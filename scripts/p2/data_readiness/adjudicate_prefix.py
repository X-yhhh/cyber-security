#!/usr/bin/env python3
"""逐条裁决已有 475 个 Slowloris 结构起点，限定发布者来源及真实 prefix 时刻。

这是 publisher_documented 的来源规则复核，不冒充两名人工 analyst_reviewed。
载荷规则和标签字段始终为旁路；独立选型/校准缺少 prefix 真值时仍禁止早期模型资格。
"""
import argparse
import collections
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/p2'))
from build_partition import lines, micros
from prepare_labels import sha

START, END = 1499258934539220, 1499260278500956
ARTIFACT_PORTS = {33358, 33360, 33362, 54114}


def adjudicate(label, joined):
    """纠正研究明确排除的启动/收尾、导航、无载荷、窗口和关联失败均不能批准。"""
    checks = dict(
        publisherLabel=label['label'] == 'DoS Slowloris',
        fullJoin=joined['join'] == 'matched' and joined['expected'] == joined['observed'],
        noOverlap=not label['overlaps'],
        synEpoch=joined['synStart'] and joined['distinctSynSequences'] == 1,
        cleanReview=not joined['reviewError'] and joined['timestampRegressions'] == 0 and joined['badHeaders'] == 0 and joined['offloadPackets'] == 0,
        incompleteHeaders=joined['headerCompleteUs'] is None,
        causalContinuation=joined['independentContinuations'] >= 1 and joined['onsetCandidateUs'] is not None,
        excludesPublisherArtifacts=int(label['origin'].rsplit(':', 1)[1]) not in ARTIFACT_PORTS,
        sourceService=label['responder'].endswith(':80'),
        nonemptyPayload=label['fwdPayload'] > 0,
        publisherWindow=joined['onsetCandidateUs'] is not None and START <= joined['onsetCandidateUs'] <= END,
        onsetWithinLabel=joined['onsetCandidateUs'] is not None and label['start'] <= joined['onsetCandidateUs'] <= label['end'])
    return dict(labelId=label['id'], checks=checks,
                decision='source_bound_onset_supported' if all(checks.values()) else 'rejected',
                onsetUs=joined['onsetCandidateUs'], windowEndUs=label['end'],
                evidenceTier='publisher_documented', humanSecondReviewClaimed=False,
                structuralCandidatePromotedUnconditionally=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    joins = {r['labelId']: r for r in lines(a.run / 'wednesday-joins.jsonl') if r['onsetStructuralChecksPassed']}
    if len(joins) != 475:
        raise ValueError('原始候选数量变化，须重新登记审查范围')
    labels = {r['id']: r for r in lines(a.run / 'wednesday-labels.jsonl') if r['id'] in joins}
    decisions = {ident: adjudicate(labels[ident], j) for ident, j in joins.items()}
    bykey = collections.defaultdict(list)
    for r in labels.values():
        bykey[tuple(sorted((r['origin'], r['responder'])))].append(r)
    kept = {r['parentConnectionId'] for r in lines(a.run / 'partition-index.jsonl') if r['split'] == 'train'}
    census = collections.Counter()
    snapshot_rows = []
    for o, ledger in zip(lines(a.run / 'train-observations.jsonl'), lines(a.run / 'train-ledger.jsonl'), strict=True):
        if o['observationId'] != ledger['observationId']:
            raise ValueError('观察与账本不一致')
        if o['profile'] != 'flow-prefix-v1':
            continue
        key = tuple(sorted((ledger['Endpoints']['Local'], ledger['Endpoints']['Peer'])))
        candidates = [r for r in bykey.get(key, []) if r['start'] - 1 <= micros(o['firstSeenAt']) and micros(o['lastPacketAt']) <= r['end'] + 1]
        if len(candidates) != 1:
            continue
        label = candidates[0]
        review = decisions[label['id']]
        reason = None
        if review['decision'] != 'source_bound_onset_supported':
            reason = 'onset_rejected'
        elif micros(o['asOf']) <= review['onsetUs']:
            reason = 'before_onset_unknown'
        elif micros(o['asOf']) > label['end']:
            reason = 'after_publisher_window_unknown'
        elif o['parentConnectionId'] not in kept:
            reason = 'parent_excluded_by_frozen_partition'
        elif (o['addressFamily'], o['transport'], o['direction'], o['servicePort']) != ('ipv4', 'tcp', 'inbound', 80):
            reason = 'outside_scope'
        elif any(v is True for k, v in o['quality'].items() if k != 'clockSkewMs'):
            reason = 'quality'
        census[reason or 'admissible_source_bound_prefix'] += 1
        if reason is None:
            snapshot_rows.append(dict(observationId=o['observationId'], parentConnectionId=o['parentConnectionId'],
                                      sourceLabelId=label['id'], asOf=o['asOf'], onsetUs=review['onsetUs'],
                                      label=1, trainingEnabled=False, role='train_candidate_diagnostic_only'))
    by_label = collections.Counter(r['sourceLabelId'] for r in snapshot_rows)
    for ident, review in decisions.items():
        review['admissiblePrefixSnapshots'] = by_label[ident]
    a.output.mkdir()
    with (a.output / 'decisions.jsonl').open('x') as f:
        for row in sorted(decisions.values(), key=lambda r: r['labelId']):
            f.write(json.dumps(row, separators=(',', ':')) + '\n')
    with (a.output / 'prefix-candidates.jsonl').open('x') as f:
        for row in snapshot_rows:
            f.write(json.dumps(row, separators=(',', ':')) + '\n')
    report = dict(version='p2-prefix-adjudication-v1', candidatesReviewed=len(decisions),
          decisions=dict(collections.Counter(r['decision'] for r in decisions.values())),
          candidatesWithAdmissiblePrefix=len(by_label), actualPrefixCensus=dict(census),
          admissiblePrefixSnapshots=len(snapshot_rows),
          admissibleParents=len({r['parentConnectionId'] for r in snapshot_rows}),
          independentPrefixValidationAvailable=False, independentPrefixCalibrationAvailable=False,
          prefixResearchReady=False, earlyBlockingQualified=False,
          permittedModelProfile='flow-final-v1', evidenceTier='publisher_documented',
          reason='onset evidence is source-bound; selection Slowhttptest and calibration 2018 Slowloris require their own causal onset reviews; diagnostic candidates are not part of the final dataset',
          ruleReference='https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html',
          publisherDocumentSha256=sha(ROOT / 'artifacts/p1/continuation-20261003/cns-2017.html'),
          labelSha256=sha(a.run / 'wednesday-labels.jsonl'), joinSha256=sha(a.run / 'wednesday-joins.jsonl'),
          decisionsSha256=sha(a.output / 'decisions.jsonl'), candidateIndexSha256=sha(a.output / 'prefix-candidates.jsonl'),
          payloadIsModelInput=False, humanSecondReviewClaimed=False)
    with (a.output / 'summary.json').open('x') as f:
        json.dump(report, f, indent=2)
        f.write('\n')
    print(json.dumps({k: report[k] for k in ('candidatesReviewed', 'decisions', 'candidatesWithAdmissiblePrefix', 'admissiblePrefixSnapshots', 'admissibleParents', 'prefixResearchReady')}))


if __name__ == '__main__':
    main()
