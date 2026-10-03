#!/usr/bin/env python3
"""只读核验 CIC 修正表的布局、标签、缺失、非有限值及重复；不拟合或造值。"""
import argparse
import collections
import csv
import hashlib
import json
import math
from pathlib import Path

from cic_probe import timestamp, sha


def audit(path):
    ids=set();rows_seen=set();without_id=set();flow_ids=collections.Counter()
    labels=collections.Counter();empty=collections.Counter();nonfinite=collections.Counter()
    duplicates=collections.Counter();rows=0;negative_duration=zero_packets=0
    minimum=maximum=None
    with path.open() as f:
        reader=csv.DictReader(f);columns=reader.fieldnames
        if columns is None or len(set(columns))!=len(columns):
            raise ValueError('表头为空或有重复字段')
        for row in reader:
            rows+=1
            if None in row or any(v is None for v in row.values()):
                raise ValueError(f'第 {rows} 条记录宽度与表头不一致')
            labels[row['Label']]+=1;flow_ids[row['Flow ID']]+=1
            for name,value in row.items():
                if not value.strip():empty[name]+=1
                try:
                    if not math.isfinite(float(value)):nonfinite[name]+=1
                except ValueError:
                    pass
            duplicates['id']+=row['id'] in ids;ids.add(row['id'])
            digest=hashlib.sha256('\0'.join(row[c] for c in columns).encode()).digest()
            digest_without_id=hashlib.sha256('\0'.join(row[c] for c in columns if c!='id').encode()).digest()
            duplicates['exactIncludingId']+=digest in rows_seen;rows_seen.add(digest)
            duplicates['exactExcludingId']+=digest_without_id in without_id;without_id.add(digest_without_id)
            negative_duration+=int(row['Flow Duration'])<0
            zero_packets+=(int(row['Total Fwd Packet'])+int(row['Total Bwd packets']))==0
            instant=timestamp(row['Timestamp'])
            minimum=instant if minimum is None else min(minimum,instant)
            maximum=instant if maximum is None else max(maximum,instant)
    return {'name':path.name,'bytes':path.stat().st_size,'sha256':sha(path),'rows':rows,
            'columns':columns,'labels':dict(labels),'emptyByColumn':dict(empty),
            'nonFiniteByColumn':dict(nonfinite),'duplicateRows':dict(duplicates),
            'reusedFlowIdValues':sum(v>1 for v in flow_ids.values()),
            'reusedFlowIdIsNotAutomaticallyDuplicate':'same tuple may contain separate epochs or 120s continuation segments',
            'negativeDurationRows':negative_duration,'zeroPacketRows':zero_packets,
            'timestampRangeUtcUs':[minimum,maximum],
            'numericFeaturesImportedForTraining':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--labels',nargs='+',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise FileExistsError('保留历史表格审计')
    result={'version':'p1-corrected-table-audit-v1','codeSha256':sha(Path(__file__)),
            'tables':[audit(x) for x in a.labels],'preprocessingFit':False,'splitAssigned':False}
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps([{k:t[k] for k in ('name','rows','duplicateRows','nonFiniteByColumn')} for t in result['tables']]))


if __name__=='__main__':main()
