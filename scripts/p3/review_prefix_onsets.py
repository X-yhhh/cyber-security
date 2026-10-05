#!/usr/bin/env python3
"""P3-B 来源限定的完整连接抽查。只读既有PCAP，载荷仅驻留标签审查旁路。

两来源分别登记，拒绝把完整流标签反向赋给prefix。24个SYN起始候选并
额外保留4个失败样本；读取完整原件核验哈希，不截断下载或连接来凑预算。
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/p1'))
from pcap_reference import frames, tcp
from http_prefix_state import CausalHTTP, REQUEST_LINE

LABEL_RULE_VERSION = 'source-http-causal-v3'

RULES = {
    'cic2017_slowhttptest': dict(label='DoS Slowhttptest', start=1499260537936810, end=1499261869331517,
        sourceMode='source-bound HTTP extension method and declared incomplete body; later contiguous body progress required; zero-window RST is not slow-read evidence',
        approvedPattern='auto', excludedPorts=[33372, 37670]),
    'cic2018_slowloris': dict(label='DoS Slowloris', start=1518706812000000, end=1518709321000000,
        sourceMode='incomplete request header with later contiguous progress; numeric and literal X-a variants recorded',
        approvedPattern='slow_header', excludedPorts=[]),
}


def read_lines(path):
    with Path(path).open() as stream:
        for line in stream:
            yield json.loads(line)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def endpoint(text):
    import ipaddress
    host, port = text.rsplit(':', 1)
    return int(ipaddress.IPv4Address(host)), int(port)


def sample(labels, joins, rule):
    """先固定样本再读载荷：16条稳定hash、4条活动前界、4条后界、4条Attempted。"""
    positive = [r for r in labels if r['label'] == rule['label'] and joins[r['id']]['synStart'] and
                joins[r['id']]['join'] == 'matched']
    chosen, used = [], set()
    def add(rows, count, stratum):
        n = 0
        for row in rows:
            key = tuple(sorted((row['origin'], row['responder'])))
            if key in used:
                continue
            used.add(key); chosen.append(dict(row, stratum=stratum)); n += 1
            if n == count:
                break
        if n != count:
            raise ValueError('独立完整连接不足，不能重复样本补足: ' + stratum)
    add(sorted(positive, key=lambda r: (r['start'], r['id'])), 4, 'activity_start_boundary')
    add(sorted(positive, key=lambda r: (-r['end'], r['id'])), 4, 'activity_end_boundary')
    add(sorted(positive, key=lambda r: r['id']), 16, 'positive_hash_order')
    failures = [r for r in labels if r['label'].startswith(rule['label']) and r['label'] != rule['label'] and joins[r['id']]['synStart']]
    add(sorted(failures, key=lambda r: r['id']), 4, 'attempted_failure')
    return chosen


class Review:
    """SYN起始有界重组；只在新连续载荷到来时产生起点，重传不增加证据。"""
    def __init__(self, mode):
        self.mode = mode
        self.expected = None
        self.request = bytearray()
        self.invalid = None
        self.onset = None
        self.complete = None
        self.continuations = 0
        self.first_payload = None
        self.payload_shapes = Counter()

    def add(self, packet, payload):
        if self.invalid:
            return
        if packet['flags'] & 2 and not packet['flags'] & 16:
            if self.expected is None:
                self.expected = packet['seq'] + 1
            return
        if not payload:
            return
        if self.expected is None or not packet['payloadFullyCaptured']:
            self.invalid = 'missing_syn_or_truncated_payload'; return
        if packet['seq'] > self.expected:
            self.invalid = 'sequence_gap'; return
        skip = self.expected - packet['seq']
        if skip >= len(payload):
            return
        novel = payload[skip:]
        if self.expected + len(novel) >= 2**32 or len(self.request) + len(novel) > 32768:
            self.invalid = 'review_bound_or_sequence_wrap'; return
        previous = len(self.request)
        self.expected += len(novel)
        self.request.extend(novel)
        if self.first_payload is None:
            self.first_payload = packet['ts']
        shape = ('get_request' if novel.startswith(b'GET ') else 'post_request' if novel.startswith(b'POST ') else
                 'numeric_x_a' if re.fullmatch(rb'X-a: [0-9]+\r\n', novel) else
                 'literal_b_x_a' if novel == b'X-a: b\r\n' else 'other')
        self.payload_shapes[shape] += 1
        if self.complete is not None:
            return
        if b'\r\n\r\n' in self.request:
            self.complete = packet['ts']; return
        if previous and re.match(rb'GET [^\r\n]+ HTTP/1\.[01]\r\n', self.request) and shape == self.mode:
            value = int(novel.split(b':',1)[1]) if shape == 'numeric_x_a' else None
            if shape == 'numeric_x_a' and not 1 <= value <= 5000:
                return
            self.continuations += 1
            if self.onset is None:
                self.onset = packet['ts']


def prefix_label(asof, onset, end, supported):
    """严格晚于已满足起点且不超发布窗口；Unknown从不映射成正常。"""
    return 1 if supported and onset is not None and onset < asof <= end else None


def audit(args):
    rule = RULES[args.scenario]
    output = args.output
    output.mkdir(parents=True, exist_ok=False)
    joins = {r['labelId']: r for r in read_lines(args.joins)}
    labels = list(read_lines(args.labels))
    excluded_shared=0
    if args.all_syn_epochs:
        grouped=defaultdict(list)
        for r in labels:
            if r['label'].startswith(rule['label']) and joins[r['id']]['synStart'] and joins[r['id']]['join']=='matched':
                grouped[tuple(sorted((r['origin'],r['responder'])))].append(r)
        # 同五元组多 SYN epoch 需独立重组能力；首版全部明确排除，不覆盖字典或挑容易的一个。
        selected=[dict(rows[0],stratum='all_unique_syn_epochs') for rows in grouped.values() if len(rows)==1]
        excluded_shared=sum(len(rows) for rows in grouped.values() if len(rows)>1)
    else:
        selected = sample(labels, joins, rule)
    with (output / 'sample-registration.json').open('x') as f:
        json.dump({'scenario': args.scenario, 'rule': rule, 'pcapExpectedSha256': args.expected_sha256,
                   'labelSha256': sha(args.labels), 'joinSha256': sha(args.joins),
                   'sourceDocumentSha256': sha(args.publisher), 'scriptSha256': sha(__file__),
                   'selected': [{'labelId': r['id'], 'stratum': r['stratum']} for r in selected],
                   'sampleCount': len(selected), 'labelRuleVersion': LABEL_RULE_VERSION, 'fullLabelsApproved': False}, f, indent=2)
    lookup = {}
    for row in selected:
        origin, responder = endpoint(row['origin']), endpoint(row['responder'])
        lookup[tuple(sorted((origin, responder)))] = dict(label=row, origin=origin, review=CausalHTTP(rule['approvedPattern']),
            started=False, ended=False, first=None, last=None, packets=0, forward=0, reverse=0,
            labelCounts=[0,0,0,0], regressions=0, offload=0, incomplete=0, closed=False, synSequence=None)
        lookup[tuple(sorted((origin,responder)))]['readState']={'clientWindowMin':None,'zeroWindowTimes':[],
            'responsePayloadBytes':0,'responsePackets':0,'responseHttpStatusSeen':False,'resetZeroWindowPackets':0}
    capture, quality = {}, Counter()
    for ts, data, wire, link in frames(args.pcap, capture):
        packet = tcp(ts, data, wire, link, quality)
        if packet is None or packet['key'] not in lookup:
            continue
        item = lookup[packet['key']]; label = item['label']
        forward = packet['src'] == item['origin']
        syn = forward and packet['flags'] & 2 and not packet['flags'] & 16
        if not item['started']:
            if abs(ts-label['start']) > 1 or not syn:
                continue
            item['started'] = True; item['first'] = ts; item['synSequence'] = packet['seq']
        elif syn and packet['seq'] != item['synSequence']:
            item['ended'] = True
        if item['ended']:
            continue
        item['regressions'] += item['last'] is not None and ts < item['last']
        item['last'] = ts; item['packets'] += 1
        item['forward' if forward else 'reverse'] += 1
        item['offload'] += packet['offloadSized']; item['incomplete'] += not packet['payloadFullyCaptured']
        item['closed'] |= bool(packet['flags'] & 5)
        if label['start']-1 <= ts <= label['end']+1:
            item['labelCounts'][0 if forward else 1] += 1
            item['labelCounts'][2 if forward else 3] += packet['payloadBytes']
        if forward:
            payload = data[packet['payloadOffset']:packet['payloadOffset']+packet['payloadBytes']]
            item['review'].add(packet, payload)
            state=item['readState'];window=packet['tcpWindow']
            state['clientWindowMin']=window if state['clientWindowMin'] is None else min(window,state['clientWindowMin'])
            # RST 的 Window 字段没有接收窗口通告语义，不能据此推断慢读取。
            if window==0 and packet['flags']&4:state['resetZeroWindowPackets']+=1
            if window==0 and packet['flags']&16 and not packet['flags']&6:state['zeroWindowTimes'].append(ts)
        else:
            state=item['readState'];state['responsePayloadBytes']+=packet['payloadBytes'];state['responsePackets']+=packet['payloadBytes']>0
            state['responseHttpStatusSeen'] |= data[packet['payloadOffset']:packet['payloadOffset']+5]==b'HTTP/'
    if capture['sha256'] != args.expected_sha256 or not capture['completeContainer']:
        raise ValueError('完整原件或已登记派生件哈希不符，拒绝发布审查结果')
    reviews = []
    for item in lookup.values():
        r, v = item['label'], item['review']
        full_join = item['labelCounts'] == [r['fwdPackets'],r['bwdPackets'],r['fwdPayload'],r['bwdPayload']]
        checks = dict(publisherLabel=r['label']==rule['label'], sourceRuleDefined=rule['approvedPattern'] is not None,
            fullLabelJoin=full_join and not r['overlaps'], synStart=item['started'],
            causalContinuation=bool(v.evidence),
            publisherWindow=v.onset is not None and rule['start'] <= v.onset <= rule['end'],
            excludesArtifacts=endpoint(r['origin'])[1] not in rule['excludedPorts'])
        supported = all(checks.values())
        end = min(item['last'] or r['end'], rule['end'])
        on = v.onset
        reviews.append(dict(labelId=r['id'], stratum=r['stratum'], checks=checks,
            decision='source_bound_evidence_supported' if supported else 'unknown',
            reasons=[k for k,vv in checks.items() if not vv], packets=item['packets'],
            firstUs=item['first'], lastUs=item['last'], onsetUs=on, headerCompleteUs=v.complete,
            attackStartUs=r['start'], attackStartIntervalUs=[r['start'],v.first_payload or r['start']],
            attackStartBasis='corrected publisher-labelled SYN used as conservative bound; exact attack-intent time not independently known',
            evidenceAvailableAtUs=on, detectedMode=v.detected_mode, causalEvidence=v.evidence,
            connectionProvenance={'closedObserved':item['closed'], 'futureOrWholeConnectionIssue':v.invalid,
                'regressions':item['regressions'], 'offload':item['offload'], 'incomplete':item['incomplete']},
            slowReadDiagnostic=item['readState'],slowReadOnsetQualified=False,
            fullConnectionDurationUs=(item['last']-item['first']) if item['started'] else None,
            timestampRegressions=item['regressions'], offloadPackets=item['offload'], truncatedPayloads=item['incomplete'],
            requestMethod=(match.group(1).decode('ascii') if (match:=REQUEST_LINE.match(bytes(v.request))) else 'unrecognized'),
            labelSegmentDurationUs=r['end']-r['start'], firstPayloadUs=v.first_payload,
            payloadShapes=dict(v.payload_shapes), invalidReason=v.invalid, continuations=v.continuations,
            boundaryLabels={'before': prefix_label(on-1,on,end,supported) if on else None,
                            'equal': prefix_label(on,on,end,supported) if on else None,
                            'after': prefix_label(on+1,on,end,supported) if on else None},
            labelRuleVersion=LABEL_RULE_VERSION, evidenceTier='publisher_documented', humanSecondReviewClaimed=False, fullLabelsApproved=False))
    with (output/'reviews.jsonl').open('x') as f:
        for row in reviews:f.write(json.dumps(row)+'\n')
    summary=dict(scenario=args.scenario, status='sample_review_complete', connectionsReviewed=len(reviews),
        reviewScope='all_unique_syn_epochs' if args.all_syn_epochs else 'registered_sample',excludedSharedTupleLabelRows=excluded_shared,
        completeConnections=sum(r['connectionProvenance']['closedObserved'] for r in reviews),
        decisions=dict(Counter(r['decision'] for r in reviews)),
        reasons=dict(Counter(reason for r in reviews for reason in r['reasons'])),
        payloadShapes=dict(sum((Counter(r['payloadShapes']) for r in reviews),Counter())),
        sourceMode=rule['sourceMode'], labelRuleVersion=LABEL_RULE_VERSION,
        modes=dict(Counter(r['detectedMode'] or 'unknown' for r in reviews)),
        sourceDocumentSha256=sha(args.publisher), captureSha256=capture['sha256'],
        reviewsSha256=sha(output/'reviews.jsonl'), registrationSha256=sha(output/'sample-registration.json'),
        fullLabelsApproved=False, prefixResearchReady=False, finalTestRead=False,
        limitation='sample feasibility only; new dataset roles and independent activities not qualified')
    with (output/'summary.json').open('x') as f:json.dump(summary,f,indent=2)
    print(json.dumps(summary))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario',choices=RULES,required=True)
    for name in ('pcap','labels','joins','publisher','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--expected-sha256',required=True)
    parser.add_argument('--all-syn-epochs',action='store_true',help='版本化审查全部唯一且已关联的来源 SYN epoch；多 epoch 五元组单列排除')
    audit(parser.parse_args())
