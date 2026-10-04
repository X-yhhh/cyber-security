#!/usr/bin/env python3
"""把已审查起点映射到候选快照时刻，仅证明时间方案可解释，不批准训练标签。

发布者 Flow Duration 止于其窗口最后包，不是实时连接结束真值。
超出该窗口的定时快照须由 P2 的 FIN/RST、idle、Tick 和续段规则验证。
"""
import argparse
import csv
import json
from pathlib import Path
from cic_probe import compact, sha


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--labels',type=Path,required=True)
    parser.add_argument('--onset',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError('保留既有时间审查')
    onset=json.loads(args.onset.read_text())
    selected={r['connectionDigest']:r for r in onset['samples']
              if r['onsetCandidateDeltaUs'] is not None and r['invalidReason'] is None
              and r['countPayloadJoinPassed'] and r['overlappingLabelRows']==0
              and r['synStartObserved'] and r['distinctSynSequences']==1
              and r['timestampRegressions']==0 and not r['observed'].get('offloadSizedPackets',0)}
    rows=[]
    with args.labels.open() as source:
        for raw in csv.DictReader(source):
            if raw['Label']!='DoS Slowloris':continue
            label=compact(raw,'wednesday','')
            if label['id'] not in selected:continue
            start=selected[label['id']]['onsetCandidateDeltaUs']
            seconds=1 if start<1000000 else (start//5000000+1)*5
            rows.append({'connectionDigest':label['id'],'onsetDeltaUs':start,
                         'publisherWindowDurationUs':label['end']-label['start'],
                         'firstScheduleAfterOnsetSeconds':seconds,
                         'scheduleWithinPublisherWindow':seconds*1000000<label['end']-label['start']})
    if len(rows)!=len(selected):raise ValueError('起点与标签摘要不能完整关联')
    report={'version':'p1-onset-schedule-reference-v2','codeSha256':sha(Path(__file__)),
            'sourceAuditSha256':sha(args.onset),'labelSha256':sha(args.labels),'samples':rows,
            'actualV5SnapshotEmissionVerified':False,'prefixSupervisionApproved':False,
            'windowEndMeaning':'last publisher-window packet, not a causal TCP close event',
            'outsideWindowHandling':'P2 must evaluate timer, idle, close and continuation without reading future'}
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'candidates':len(rows),'schedulesWithinObservedWindow':sum(r['scheduleWithinPublisherWindow'] for r in rows)}))


if __name__=='__main__':main()
