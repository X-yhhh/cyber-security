#!/usr/bin/env python3
"""对已关联 Slowloris 候选补充有界、只读的攻击起点审查依据。

载荷仅用于标签旁路，绝不加入头部模型输入。要求 SYN 起始、连续序号、
未结束的 GET 请求及后续独立 X-a 头片段；仅 GET、重传或缺包不能得到起点。
工具输出可审查候选，最终 prefix 批准必须结合发布者活动和关联结果另作裁决。
"""
import argparse
import collections
import csv
import hashlib
import json
import re
from pathlib import Path

from cic_probe import choose, compact, endpoints, timestamp, sha
from pcap_reference import frames, tcp


class SlowHeaderReview:
    """最多保留32KiB初始请求，拒绝缺口、截断或序号回绕歧义，忽略完整重传。"""
    def __init__(self):
        self.expected=None
        self.request=bytearray()
        self.invalid=None
        self.first_payload_ts=None
        self.onset=None
        self.continuations=0
        self.complete=None

    def add(self, packet, payload):
        if self.invalid:
            return
        flags=packet['flags']
        if flags&2 and not flags&16:
            if self.expected is None:
                self.expected=(packet['seq']+1)%2**32
            elif packet['seq']+1>self.expected:
                self.invalid='new_syn_epoch'
            return
        if not payload:
            return
        if self.expected is None:
            self.invalid='missing_syn'
            return
        if not packet['payloadFullyCaptured']:
            self.invalid='payload_truncated'
            return
        seq=packet['seq']
        if seq>self.expected:
            self.invalid='sequence_gap'
            return
        overlap=self.expected-seq
        if overlap>=len(payload):
            return
        novel=payload[overlap:]
        if self.expected+len(novel)>=2**32 or len(self.request)+len(novel)>32768:
            self.invalid='review_bound_or_sequence_wrap'
            return
        previous=len(self.request)
        self.expected+=len(novel)
        self.request.extend(novel)
        if self.first_payload_ts is None:
            self.first_payload_ts=packet['ts']
        if self.complete is not None:
            return
        end=self.request.find(b'\r\n\r\n')
        if end>=0:
            self.complete=packet['ts']
            return
        # 只接受初始请求后的独立、连续序号片段，拒绝初次 GET 中已有的同名头。
        if previous and re.match(rb'GET [^\r\n]+ HTTP/1\.[01]\r\n',self.request):
            # CICIDS2017 发布者描述及实包均为字面 b；不能套用 2018 的随机整数头值。
            if novel==b'X-a: b\r\n':
                self.continuations+=1
                if self.onset is None:
                    self.onset=packet['ts']

    def report(self, start):
        return {'initialRequestBytesReviewed':len(self.request),
                'requestPrefixSha256':hashlib.sha256(self.request).hexdigest() if self.request else None,
                'independentHeaderContinuations':self.continuations,
                'onsetCandidateDeltaUs':None if self.onset is None else self.onset-start,
                'headerCompletionDeltaUs':None if self.complete is None else self.complete-start,
                'invalidReason':self.invalid,
                'payloadIsModelInput':False,'prefixSupervisionApproved':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pcap',type=Path,required=True)
    p.add_argument('--labels',type=Path,required=True)
    p.add_argument('--expected-md5',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():
        raise FileExistsError('保留历史起点审查')
    sampled,_,_=choose(a.labels,'wednesday')
    selected={r['id']:r for r in sampled if r['label']=='DoS Slowloris'}
    additional=[]
    with a.labels.open() as f:
        for r in csv.DictReader(f):
            if r['Label']=='DoS Slowloris' and int(r['SYN Flag Count'])>0:
                item=compact(r,'wednesday','slow_header_onset_syn_candidate')
                if item['id'] not in selected:
                    additional.append(item)
    for item in sorted(additional,key=lambda x:x['id'])[:10]:
        selected[item['id']]=item
    windows=collections.defaultdict(list)
    wanted={c['key'] for c in selected.values()}
    with a.labels.open() as f:
        for row in csv.DictReader(f):
            if row['Protocol']!='6':
                continue
            key=tuple(sorted(endpoints(row)))
            if key in wanted:
                start=timestamp(row['Timestamp'])
                windows[key].append((start,start+int(row['Flow Duration']),row['id']))
    lookup=collections.defaultdict(list)
    for c in selected.values():
        c['review']=SlowHeaderReview()
        c['counts']=collections.Counter()
        c['synSequences']=set()
        c['firstPacket']=None
        c['lastTimestamp']=None
        c['timestampRegressions']=0
        lookup[c['key']].append(c)
    audit={};quality=collections.Counter()
    for ts,data,wire,link in frames(a.pcap,audit):
        packet=tcp(ts,data,wire,link,quality)
        if packet is None or packet['key'] not in lookup:
            continue
        for c in lookup[packet['key']]:
            if not c['start']-1<=ts<=c['end']+1:
                continue
            forward=packet['src']==c['origin']
            if c['firstPacket'] is None:
                c['firstPacket']=packet
            c['timestampRegressions']+=c['lastTimestamp'] is not None and ts<c['lastTimestamp']
            c['lastTimestamp']=ts
            c['counts']['offloadSizedPackets']+=packet['offloadSized']
            tag='fwd' if forward else 'bwd'
            c['counts'][tag+'Packets']+=1
            c['counts'][tag+'Payload']+=packet['payloadBytes']
            if forward:
                if packet['flags']&2 and not packet['flags']&16:
                    c['synSequences'].add(packet['seq'])
                payload=data[packet['payloadOffset']:packet['payloadOffset']+packet['payloadBytes']]
                c['review'].add(packet,payload)
    if audit['md5']!=a.expected_md5:
        raise ValueError('完整原件校验失败')
    rows=[]
    for c in selected.values():
        mismatches=[n for n in ('fwdPackets','bwdPackets','fwdPayload','bwdPayload') if c[n]!=c['counts'][n]]
        overlaps=sum(rid!=c['rowId'] and start<=c['end']+1 and end>=c['start']-1
                     for start,end,rid in windows[c['key']])
        first=c['firstPacket']
        syn_start=first is not None and first['src']==c['origin'] and bool(first['flags']&2) and not first['flags']&16
        rows.append({'connectionDigest':c['id'],'selection':c['selection'],
                     'countPayloadJoinPassed':not mismatches,'mismatchedFields':mismatches,
                     'overlappingLabelRows':overlaps,
                     'expected':{n:c[n] for n in ('fwdPackets','bwdPackets','fwdPayload','bwdPayload')},
                     'observed':dict(c['counts']),'synStartObserved':syn_start,
                     'timestampRegressions':c['timestampRegressions'],
                     'distinctSynSequences':len(c['synSequences']),**c['review'].report(c['start'])})
    result={'version':'p1-slow-header-onset-review-v2','pcap':audit,'samples':rows,
            'sourceSpecificSignature':'cicids2017_incomplete_get_then_literal_x_a_b',
            'codeSha256':sha(Path(__file__)),
            'referenceCodeSha256':sha(Path(__file__).with_name('pcap_reference.py')),
            'labelSha256':sha(a.labels),
            'policy':'original 10 Slowloris samples plus 10 disjoint label-SYN-positive stable hashes; all failures retained',
            'labelSideChannelOnly':True,'trainingExecuted':False,'approval':'requires_separate_analyst_adjudication'}
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'samples':len(rows),'onsetCandidates':sum(r['onsetCandidateDeltaUs'] is not None for r in rows)}))


if __name__=='__main__':
    main()
