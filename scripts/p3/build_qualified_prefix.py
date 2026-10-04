#!/usr/bin/env python3
"""把全量来源限定起点证据接入 rc.2 prefix 观察；只生成开发待分区材料，不批准训练。

重新核验来源/观察/账本/审查哈希；Unknown 不映射正常，标签时间线与观察分开，
无观察 episode 仍保留。输出为新版本，不覆盖旧 final 数据或冻结清单。
"""
import argparse,bisect
from collections import Counter,defaultdict
from datetime import datetime
import hashlib,json
from pathlib import Path


def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def lines(p):
    with p.open() as f:
        for line in f:yield json.loads(line)
def us(s):return round(datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()*1e6)
def target_key(asset,local,peer):
    # 稳定处置目标旁路，剥除临时客户端端口；不使用 boot/epoch/HMAC身份重置预算。
    return hashlib.sha256(json.dumps([asset,local,peer.rsplit(':',1)[0],'ipv4','tcp']).encode()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ['source','labels','reviews','review_summary','observations','ledger','extraction','output']:p.add_argument('--'+n.replace('_','-'),type=Path,required=True)
    a=p.parse_args();ex=json.loads(a.extraction.read_text());review_summary=json.loads(a.review_summary.read_text())
    expected={'pcapSha256':a.source,'observationsSha256':a.observations,'localLedgerSha256':a.ledger}
    if any(sha(path)!=ex[key] for key,path in expected.items()):raise ValueError('提取原件/观察/账本哈希不符')
    if ex['status']!='completed' or ex['mode']!='research_offline' or ex['version']!='host-guard/5.0.0-rc.2':raise ValueError('提取器版本/状态不符')
    if sha(a.reviews)!=review_summary['reviewsSha256'] or ex['pcapSha256']!=review_summary['captureSha256'] or review_summary['reviewScope']!='all_unique_syn_epochs':raise ValueError('全量审查/提取原件不一致')
    registration=json.loads((a.reviews.parent/'sample-registration.json').read_text())
    if sha(a.labels)!=registration['labelSha256']:raise ValueError('审查标签被修改')
    reviews={r['labelId']:r for r in lines(a.reviews)};labels={r['id']:r for r in lines(a.labels)}
    supported={k:r for k,r in reviews.items() if r['decision']=='source_bound_evidence_supported'}
    bykey=defaultdict(list)
    for key,r in supported.items():
        lab=labels[key];bykey[tuple(sorted((lab['origin'],lab['responder'])))].append(lab)
    counts=Counter();rows=[];observations=[];timeline={};seen=set();asset=None
    for o,l in zip(lines(a.observations),lines(a.ledger),strict=True):
        if o['observationId']!=l['observationId'] or o['parentConnectionId']!=l['parentConnectionId']:raise ValueError('观察/账本顺序或身份不符')
        if o['observationId'] in seen:raise ValueError('重复观察身份')
        seen.add(o['observationId']);asset=o['assetId'] if asset is None else asset
        if o['assetId']!=asset:raise ValueError('混合资产捕获')
        ep=l['Endpoints'];key=tuple(sorted((ep['Local'],ep['Peer'])))
        candidates=[r for r in bykey.get(key,[]) if abs(r['start']-us(o['firstSeenAt']))<=1 and us(o['lastPacketAt'])<=r['end']+1]
        if len(candidates)!=1:counts['no_unique_qualified_source_connection']+=1;continue
        lab=candidates[0];r=supported[lab['id']];asof=us(o['asOf']);end=min(lab['end'],registration['rule']['end'])
        target=target_key(asset,ep['Local'],ep['Peer'])
        if lab['id'] not in timeline:timeline[lab['id']]=dict(episodeId=lab['id'],targetId=target,startMs=r['attackStartUs']/1000,endMs=end/1000,label=1,hasObservation=False,attackStartIntervalUs=r['attackStartIntervalUs'],evidenceAvailableAtUs=r['evidenceAvailableAtUs'],sourceLabelId=lab['id'])
        if (o['profile'],o['addressFamily'],o['transport'],o['direction'],o['servicePort'])!=('flow-prefix-v1','ipv4','tcp','inbound',80):counts['profile_or_scope']+=1;continue
        if any(v is True for v in o['quality'].values()):counts['quality']+=1;continue
        if not r['evidenceAvailableAtUs']<asof<=end:counts['unknown_before_evidence_or_after_window']+=1;continue
        if r['invalidReason'] is not None and asof>max(e['evidenceAvailableAtUs'] for e in r['causalEvidence']):counts['after_last_verified_causal_evidence']+=1;continue
        timeline[lab['id']]['hasObservation']=True
        rows.append(dict(observationId=o['observationId'],parentConnectionId=o['parentConnectionId'],activityId='cic2018-thursday-slowloris',associationGroup='cic2018-thursday-slowloris',split='development_unassigned',label=1,family='connection_abuse',scenario='cic2018_slowloris',sourceId='cic2018_corrected',sourceLabelId=lab['id'],evidenceTier='publisher_documented',labelRuleVersion=r['labelRuleVersion'],firstSeenAt=o['firstSeenAt'],asOf=o['asOf'],budgetTargetId=target));observations.append(o)
    # 未输出观察的合格源连接仍是时间线分母，不能因提取失败/质量剔除就消失。
    for key,r in supported.items():
        if key in timeline:continue
        lab=labels[key];local=lab['responder'];peer=lab['origin'];end=min(lab['end'],registration['rule']['end'])
        timeline[key]=dict(episodeId=key,targetId=target_key(asset,local,peer),startMs=r['attackStartUs']/1000,endMs=end/1000,label=1,hasObservation=False,attackStartIntervalUs=r['attackStartIntervalUs'],evidenceAvailableAtUs=r['evidenceAvailableAtUs'],sourceLabelId=key)
    # 同目标重叠连接只组成一个攻击区间，不能把数百 parent 当作数百独立活动。
    target_spans=defaultdict(list)
    for row in timeline.values():target_spans[row['targetId']].append(row)
    episodes=[]
    for target,spans in target_spans.items():
        merged=[]
        for row in sorted(spans,key=lambda r:r['startMs']):
            if merged and row['startMs']<=merged[-1]['endMs']:
                merged[-1]['endMs']=max(merged[-1]['endMs'],row['endMs'])
                merged[-1]['hasObservation']|=row['hasObservation']
                merged[-1]['sourceLabelIds'].append(row['sourceLabelId'])
            else:merged.append(dict(targetId=target,startMs=row['startMs'],endMs=row['endMs'],label=1,hasObservation=row['hasObservation'],sourceLabelIds=[row['sourceLabelId']]))
        for ordinal,row in enumerate(merged):
            row['episodeId']=hashlib.sha256(json.dumps([target,row['startMs'],row['endMs'],ordinal]).encode()).hexdigest()
            row['basis']='union_of_qualified_source_connection_intervals; conservative onset bounds'
            row['activityId']='cic2018-thursday-slowloris';episodes.append(row)
    a.output.mkdir(parents=True,exist_ok=False)
    for name,values in [('index.jsonl',rows),('observations.jsonl',observations),('label-connection-timeline.jsonl',timeline.values()),('label-timeline.jsonl',episodes)]:
        with (a.output/name).open('x') as f:
            for row in values:f.write(json.dumps(row)+'\n')
    result=dict(version='qualified-prefix-development-v2',status='blocked',profile='flow-prefix-v1',observations=len(rows),parents=len({r['parentConnectionId'] for r in rows}),sourceConnectionSegments=len(timeline),sourceConnectionSegmentsWithoutQualifiedObservation=sum(not r['hasObservation'] for r in timeline.values()),targetAttackIntervals=len(episodes),independentActivities=1,excludedObservationReasons=dict(counts),inputHashes={str(path.name):sha(path) for path in [a.labels,a.reviews,a.review_summary,a.extraction]},outputHashes={name:sha(a.output/name) for name in ['index.jsonl','observations.jsonl','label-connection-timeline.jsonl','label-timeline.jsonl']},rolesFrozen=False,trainingAllowed=False,modelFits=0,finalRead=False,blockers=['CIC2017_SLOWHTTPTEST_ONSET_UNQUALIFIED','INDEPENDENT_ATTACK_ACTIVITIES_INSUFFICIENT','ROLES_AND_NEAR_DUPLICATE_GROUPS_NOT_FROZEN'])
    (a.output/'readiness.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
