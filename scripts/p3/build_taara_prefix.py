#!/usr/bin/env python3
"""把已来源资格化的 TAARA 开发连接接入真实 Go rc.2 提取器，不读取封存捕获。

每个捕获单独重置引擎；同来源日/关联组身份保留给正式分区。Unknown、坏质量及
证据出现前的 prefix 不进入模型材料；完整来源连接仍作为时间线分母。
"""
import argparse
from prefix_contract import metadata
from collections import Counter,defaultdict
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import uuid

from build_qualified_prefix import sha,lines,us,target_key,source_connection


def endpoint(value):
    return str(ipaddress.IPv4Address(value[0]))+':'+str(value[1])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['sources','qualification','labels','extractor','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();q=json.loads(a.qualification.read_text());summary=json.loads((a.labels.parent/'summary.json').read_text())
    registration=json.loads((a.labels.parent/'registration.json').read_text())
    if sha(a.labels)!=summary['labelsSha256'] or sha(a.qualification)!=registration['qualificationSha256']:
        raise ValueError('来源资格化文件哈希不符')
    captures={r['sha256']:r for r in q['captures'] if r['source']=='taara' and r['role']=='development_unassigned' and r['featureRead']}
    source_rows=defaultdict(list)
    for row in lines(a.labels):
        if row['captureSha256'] not in captures:raise ValueError('标签指向封存或未知捕获')
        source_rows[row['captureSha256']].append(row)
    a.output.mkdir(parents=True,exist_ok=False,mode=0o700)
    secret=a.output/'peer-key.bin';secret.write_bytes(os.urandom(32));secret.chmod(0o600)
    identity={k:str(uuid.uuid4()) for k in ['assetId','sensorId']};indices=[];observations=[];timeline=[];counts=Counter();runs=[]
    for ordinal,(digest,meta) in enumerate(sorted(captures.items())):
        source=a.sources/'taara'/meta['member']
        if not meta['containerComplete'] or sha(source)!=digest:raise ValueError('开发捕获不完整或被修改')
        work=a.output/f'capture-{ordinal:02d}';work.mkdir()
        cfg=dict(identity,bootId=str(uuid.uuid4()),captureScopeId=str(uuid.uuid4()),
                 localAddresses=['192.168.1.8'],secretFile=str(secret.resolve()),keyEpoch=1)
        (work/'config.json').write_text(json.dumps(cfg)+'\n')
        args=[str(a.extractor.resolve()),'-config',str(work/'config.json'),'-pcap',str(source),
              '-out',str(work/'observations.jsonl'),'-ledger',str(work/'ledger.jsonl'),'-report',str(work/'extraction.json')]
        result=subprocess.run(args,capture_output=True,text=True,timeout=120)
        if result.returncode:raise RuntimeError('GO_SOURCE_EXTRACTION_FAILED:'+result.stderr[-300:])
        ex=json.loads((work/'extraction.json').read_text())
        if ex['status']!='completed' or ex['version']!='host-guard/5.0.0-rc.2' or ex['pcapSha256']!=digest:
            raise ValueError('提取器版本或捕获身份不符')
        for key,name in [('observationsSha256','observations.jsonl'),('localLedgerSha256','ledger.jsonl')]:
            if sha(work/name)!=ex[key]:raise ValueError('Go 输出哈希不符')
        lookup=defaultdict(list);byid={}
        for r in source_rows[digest]:
            if r['label'] is None:continue
            end=r['lastUs'];onset=r['evidenceAvailableAtUs'] if r['label']==1 else r['completeAtUs']
            if r['futureConnectionIssue'] is not None:
                if not r['causalEvidence']:continue
                end=min(end,max(e['evidenceAvailableAtUs'] for e in r['causalEvidence']))
            if r['label']==1 and r['completeAtUs'] is not None:end=min(end,r['completeAtUs'])
            if onset is None or end<=onset:continue
            local,peer=endpoint(r['destination']),endpoint(r['origin'])
            lab=dict(id=r['sourceConnectionId'],origin=peer,responder=local,start=r['firstUs'],end=end)
            lookup[tuple(sorted((local,peer)))].append(lab);byid[lab['id']]=(r,onset)
            timeline.append(dict(sourceConnectionId=lab['id'],activityId='taara:'+meta['associationGroup'],
                sourceDayCluster=meta['cluster'],captureSha256=digest,label=r['label'],startMs=r['firstUs']/1000,
                endMs=end/1000,evidenceAvailableAtUs=onset,targetId=target_key(identity['assetId'],local,peer)))
        parents={};seen=set();kept=Counter()
        for o,l in zip(lines(work/'observations.jsonl'),lines(work/'ledger.jsonl'),strict=True):
            if o['observationId']!=l['observationId'] or o['parentConnectionId']!=l['parentConnectionId'] or o['observationId'] in seen:
                raise ValueError('观察/账本身份或顺序不符')
            seen.add(o['observationId']);lab=source_connection(o,l,lookup,parents)
            if lab is None:counts['no_unique_source_connection']+=1;continue
            r,onset=byid[lab['id']]
            if (o['profile'],o['direction'],o['transport'],o['addressFamily'],o['servicePort'])!=('flow-prefix-v1','inbound','tcp','ipv4',80):
                counts['profile_or_scope']+=1;continue
            if any(v is True for v in o['quality'].values()):counts['quality']+=1;continue
            if not onset<us(o['asOf'])<=lab['end']:counts['outside_causal_interval']+=1;continue
            ep=l['Endpoints'];indices.append(dict(observationId=o['observationId'],parentConnectionId=o['parentConnectionId'],
                activityId='taara:'+meta['associationGroup'],associationGroup='taara:'+meta['associationGroup'],
                sourceDayCluster=meta['cluster'],sourceId='taara_publisher',scenario='taara_slowloris',
                captureSha256=digest,split='development_unassigned',label=r['label'],family='connection_abuse' if r['label']==1 else 'benign',
                sourceLabelId=lab['id'],evidenceTier='publisher_documented',labelRuleVersion=r['labelRuleVersion'],
                firstSeenAt=o['firstSeenAt'],asOf=o['asOf'],budgetTargetId=target_key(identity['assetId'],ep['Local'],ep['Peer'])))
            observations.append(o);kept[str(r['label'])]+=1
        runs.append(dict(captureSha256=digest,associationGroup=meta['associationGroup'],sourceDayCluster=meta['cluster'],
                         extractionSha256=sha(work/'extraction.json'),prefixCounts=dict(kept)))
    indices=[metadata(dict(r,plannedRole='independent_development')) for r in indices]
    timeline=[metadata(dict(r,plannedRole='independent_development',scenario='taara_slowloris',sourceId='taara_publisher')) for r in timeline]
    for name,rows in [('index.jsonl',indices),('observations.jsonl',observations),('label-connection-timeline.jsonl',timeline)]:
        with (a.output/name).open('x') as f:
            for r in rows:f.write(json.dumps(r)+'\n')
    report=dict(version='taara-qualified-prefix-v1',captures=runs,observations=len(indices),
        labels=dict(Counter(str(r['label']) for r in indices)),parents=len({r['parentConnectionId'] for r in indices}),
        sourceQualifiedAttackGroups=len({r['associationGroup'] for r in indices if r['label']==1}),
        sourceDayClusters=len({r['sourceDayCluster'] for r in indices}),excluded=dict(counts),
        sourceLabelsSha256=sha(a.labels),extractorSha256=sha(a.extractor),
        outputHashes={n:sha(a.output/n) for n in ['index.jsonl','observations.jsonl','label-connection-timeline.jsonl']},
        trainingAllowed=False,rolesFrozen=False,finalRead=False,modelFits=0)
    (a.output/'readiness.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))


if __name__=='__main__':main()
