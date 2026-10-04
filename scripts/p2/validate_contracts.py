#!/usr/bin/env python3
"""离线校验冻结 Schema、格式检查器、正反例和 v5 观察时序；不加载任何业务服务。"""
import argparse
import copy
import datetime as dt
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT=Path(__file__).resolve().parents[2]

def invariant(o):
    times={k:dt.datetime.fromisoformat(o[k].replace('Z','+00:00')) for k in ('firstSeenAt','lastPacketAt','asOf','emittedAt')}
    assert times['firstSeenAt']<=times['lastPacketAt']<=times['asOf']<=times['emittedAt']
    f=o['features'];assert abs(f['elapsedMs']-(times['asOf']-times['firstSeenAt']).total_seconds()*1000)<1e-6
    assert f['packetsOutbound']+f['packetsInbound']>=1
    assert f['lengthMin']<=f['lengthMean']<=f['lengthMax']
    assert (f['iatMeanUs'] is None)==(f['packetsOutbound']+f['packetsInbound']==1)
    assert (f['iatStdUs'] is None)==(f['iatMeanUs'] is None)
    assert [v['windowSeconds'] for v in o['contexts']]==[1,5,30]
    if o['targetRef'] is not None:
        expiry=dt.datetime.fromisoformat(o['targetExpiresAt'].replace('Z','+00:00'))
        assert times['asOf']<expiry<=times['lastPacketAt']+dt.timedelta(seconds=15)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--observations',type=Path,action='append',default=[]);a=p.parse_args()
    checker=FormatChecker()
    @checker.checks('date-time',raises=(ValueError,TypeError))
    def rfc3339(value):
        if not isinstance(value,str):return True
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})',value):return False
        return dt.datetime.fromisoformat(value.replace('Z','+00:00')).tzinfo is not None
    for fmt,value in [('date-time','2026-13-40T00:00:00Z'),('date-time','2026-02-30T00:00:00Z'),('uuid','not-a-uuid')]:
        assert not checker.conforms(value,fmt),f'{fmt} checker unavailable'
    contracts=ROOT/'docs/contracts';validators={}
    for path in contracts.glob('*.schema.json'):
        schema=json.loads(path.read_text());Draft202012Validator.check_schema(schema)
        name=path.name.removesuffix('.schema.json');v=Draft202012Validator(schema,format_checker=checker);validators[name]=v
        v.validate(json.loads((contracts/'examples'/f'{name}.json').read_text()))
    v=validators['observation'];base=json.loads((contracts/'examples/observation.json').read_text())
    negatives=[]
    for key,value in [('contractVersion','host-guard/5.0.0-rc.1'),('asOf','2026-02-30T00:00:00Z'),('observationId','invalid'),('unknown',1),('targetRef','00000000-0000-4000-8000-000000000001')]:
        row=copy.deepcopy(base);row[key]=value;negatives.append(row)
    row=copy.deepcopy(base);row['contexts'].reverse();negatives.append(row)
    row=copy.deepcopy(base);row['features']['synCount']=None;negatives.append(row)
    row=copy.deepcopy(base);row['contexts'][0]['coverageMs']=1001;negatives.append(row)
    for row in negatives:assert list(v.iter_errors(row)),'negative schema example accepted'
    profile=json.loads((contracts/'feature-profile.json').read_text())
    go=(ROOT/'sensor/internal/hostguard/vector.go').read_text()
    base_order=re.findall(r'"(features\.[^"]+)"',go)
    context_order=re.findall(r'"(coverageMs|peerFlowStarts|peerSynCount|peerRstCount|peerDistinctServicePorts|hostFlowStarts|hostDistinctPeers|peerBytesOutbound|peerBytesInbound)"',go)
    assert profile['numericFeatures']==base_order+[f'contexts.{w}.{name}' for w in (1,5,30) for name in context_order]
    assert len(profile['numericFeatures'])==43 and len(profile['categoricalFeatures'])==3
    count=0
    for path in [ROOT/'sensor/testdata/hostguard-v5/observations.jsonl',*a.observations]:
        with path.open() as f:
            for line in f:
                o=json.loads(line);o=o.get('observation',o);v.validate(o);invariant(o);count+=1
    print(json.dumps(dict(schemas=len(validators),negativeCases=len(negatives),observations=count,status='passed')))

if __name__=='__main__':main()
