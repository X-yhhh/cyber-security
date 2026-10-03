#!/usr/bin/env python3
"""核对关联账本并产出可复算分区索引；不训练，不读取 final_test，不批准 prefix 起点。"""
import argparse
import bisect
import collections
import datetime as dt
import hashlib
import json
from pathlib import Path

from prepare_labels import sha

def lines(path):
    with path.open() as f:
        for line in f:
            yield json.loads(line)

def micros(text):
    value = dt.datetime.fromisoformat(text.replace('Z', '+00:00'))
    delta = value - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return (delta.days*86400+delta.seconds)*1_000_000+delta.microseconds

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def signature(o):
    f = dict(o['features'])
    f['elapsedMs'] = round(f['elapsedMs']/100)
    for n in ('iatMeanUs', 'iatStdUs'):
        f[n] = None if f[n] is None else round(f[n]/1000)
    for n in ('lengthMean', 'lengthStd'):
        f[n] = round(f[n])
    return digest([o['transport'], o['direction'], o['serviceClass'], f])

def build(root, plan_path, output):
    plan=json.loads(plan_path.read_text()); joins={r['labelId']:r for r in lines(root/'wednesday-joins.jsonl')}
    configs={s:json.loads((root/f'{s}-config.json').read_text()) for s in ('train','validation')}
    if configs['train']['bootId']==configs['validation']['bootId']:raise ValueError('partition engines must use distinct boot identities')
    for split in ('train','validation'):
        report=json.loads((root/f'{split}-extraction.json').read_text())
        expected_start=plan['development']['validationStart'] if split=='validation' else ''
        expected_end=plan['development']['trainEnd'] if split=='train' else ''
        if report['status']!='completed' or report['partitionStart']!=expected_start or report['partitionEnd']!=expected_end:raise ValueError('partition extraction range mismatch')
        for field,name in [('configSha256',f'{split}-config.json'),('observationsSha256',f'{split}-observations.jsonl'),('localLedgerSha256',f'{split}-ledger.jsonl')]:
            if sha(root/name)!=report[field]:raise ValueError('partition input hash mismatch')
    bykey=collections.defaultdict(list); label_counts=collections.Counter(); onset=collections.Counter()
    for row in lines(root/'wednesday-labels.jsonl'):
        bykey[tuple(sorted((row['origin'],row['responder'])))].append(row)
        j=joins[row['id']];label_counts[row['label']+'/'+j['join']]+=1
        if j['onsetStructuralChecksPassed']:onset[row['label']]+=1
    for rows in bykey.values():rows.sort(key=lambda r:r['start'])
    starts={k:[r['start'] for r in v] for k,v in bykey.items()}
    selected=[];excluded=collections.Counter();census=collections.Counter();parent_groups=collections.defaultdict(set);rejected_parents=set();scope_census=collections.Counter()
    split_limits={'train':(None,micros(plan['development']['trainEnd'])),
                  'validation':(micros(plan['development']['validationStart']),None)}
    for split,(begin,end) in split_limits.items():
        for o,ledger in zip(lines(root/f'{split}-observations.jsonl'),lines(root/f'{split}-ledger.jsonl'),strict=True):
            if o['observationId']!=ledger['observationId']:raise ValueError('ledger order mismatch')
            if o['bootId']!=configs[split]['bootId']:raise ValueError('observation boot differs from extraction configuration')
            census[split+'/'+o['transport']+'/'+o['direction']+'/'+o['profile']]+=1
            def reject(reason):excluded[split+'/'+reason]+=1
            if o['transport']!='tcp':reject('unsupported_protocol');continue
            endpoint=ledger['Endpoints'];key=tuple(sorted((endpoint['Local'],endpoint['Peer'])))
            first,last=micros(o['firstSeenAt']),micros(o['lastPacketAt'])
            candidates=[r for r in bykey.get(key,[])[:bisect.bisect_right(starts.get(key,[]),first+1)] if r['end']+1>=last]
            parent=(split,o['parentConnectionId'])
            if len(candidates)!=1:reject('no_unique_covering_label');rejected_parents.add(parent);continue
            row=candidates[0];j=joins[row['id']];label=row['label']
            if j['join']!='matched':reject('label_join');rejected_parents.add(parent);continue
            if begin is not None and row['start']<begin or end is not None and row['end']>end:reject('label_crosses_partition');rejected_parents.add(parent);continue
            if label=='BENIGN':activity='benign-background-'+str(row['start']//900_000_000);binary_label=0
            elif label in ('DoS Slowloris','DoS Slowhttptest'):activity=label;binary_label=1
            else:reject('attempted' if 'Attempted' in label else 'unsupported_family');rejected_parents.add(parent);continue
            parent_groups[(split,o['parentConnectionId'])].add((activity,binary_label))
            if o['direction']=='unknown':reject('unknown_direction');continue
            if any(v is True for k,v in o['quality'].items() if k!='clockSkewMs'):reject('quality');continue
            if o['profile']!='flow-final-v1':reject('prefix_pending_onset_adjudication');continue
            if o['closeReason'] in ('eof','new_syn'):reject('incomplete_or_replaced_connection');continue
            scope_census[f"{split}/{binary_label}/{o['direction']}/{o['serviceClass']}"]+=1
            if o['addressFamily']!='ipv4' or o['direction']!='inbound' or o['servicePort']!=80:reject('outside_candidate_scope');continue
            selected.append(dict(observationId=o['observationId'],parentConnectionId=o['parentConnectionId'],
                                 split=split,activityId=digest(activity),label=binary_label,family='connection_abuse' if binary_label else None,
                                 evidenceTier='publisher_documented',sourceLabelId=row['id'],duplicateGroup=signature(o),
                                 firstSeenAt=o['firstSeenAt'],asOf=o['asOf']))
    # 同一 parent 跨标签活动则整体排除，不保留其中容易分类的那一段。
    mixed={key for key,groups in parent_groups.items() if len(groups)>1}
    selected=[r for r in selected if (r['split'],r['parentConnectionId']) not in mixed|rejected_parents]
    duplicate_splits=collections.defaultdict(set)
    for r in selected:duplicate_splits[r['duplicateGroup']].add(r['split'])
    duplicate_groups={k for k,v in duplicate_splits.items() if len(v)>1}
    duplicate_parents={(r['split'],r['parentConnectionId']) for r in selected if r['duplicateGroup'] in duplicate_groups}
    selected=[r for r in selected if (r['split'],r['parentConnectionId']) not in duplicate_parents]
    parent_counts=collections.Counter((r['split'],r['parentConnectionId']) for r in selected)
    activities=collections.defaultdict(set);counts=collections.Counter();parents=collections.defaultdict(set)
    for r in selected:
        r['sampleWeight']=1/parent_counts[(r['split'],r['parentConnectionId'])]
        counts[r['split']+'/'+str(r['label'])]+=1;parents[r['split']+'/'+str(r['label'])].add(r['parentConnectionId']);activities[r['activityId']].add(r['split'])
    if any(len(v)>1 for v in activities.values()):raise ValueError('activity crosses split')
    if set(r['parentConnectionId'] for r in selected if r['split']=='train')&set(r['parentConnectionId'] for r in selected if r['split']=='validation'):raise ValueError('parent crosses split')
    index=root/'partition-index.jsonl'
    with index.open('x') as f:
        index.chmod(0o600)
        for r in selected:f.write(json.dumps(r,separators=(',',':'))+'\n')
    result=dict(version='p2-partition-manifest-v1',planSha256=sha(plan_path),indexSha256=sha(index),
                source='CICIDS2017 Wednesday registered target TCP full pilot',sourceLabelCounts=dict(label_counts),
                structuralOnsetCandidates=dict(onset),prefixLabelsApproved=False,
                observationCensus=dict(census),broadDiagnosticFinalScopeCensus=dict(scope_census),exclusions=dict(excluded),mixedParentsExcluded=len(mixed),rejectedWholeParents=len(rejected_parents),
                crossSplitDuplicateGroups=len(duplicate_groups),crossSplitDuplicateParentsExcluded=len(duplicate_parents),
                retainedSnapshots=dict(counts),retainedParents={k:len(v) for k,v in parents.items()},
                partitionIsolationSeconds=300,enginesReset=True,parentAndActivityDisjoint=True,
                profile='flow-final-v1',developmentPositiveAndNegativeReady=all(counts[k]>0 for k in ('train/0','train/1','validation/0','validation/1')),
                candidateScope='ipv4/tcp/inbound/servicePort80; other services only diagnostic',
                sampleAdequacy='prototype_only_not_sufficient_for_model_or_policy_selection',
                prefixDevelopmentReady=False,finalTestAllocated=False,finalAcceptanceEligible=False,
                independentValidationCalibrationGroupsAvailable=False,
                inputs={name:sha(root/name) for name in ['wednesday-labels.jsonl','wednesday-joins.jsonl','train-observations.jsonl','validation-observations.jsonl','train-ledger.jsonl','validation-ledger.jsonl']})
    with output.open('x') as f:json.dump(result,f,indent=2,ensure_ascii=False);f.write('\n')
    print(json.dumps(dict(retainedSnapshots=dict(counts),developmentReady=result['developmentPositiveAndNegativeReady'])))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--plan',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.root,a.plan,a.output)
