#!/usr/bin/env python3
"""汇总完整 P1 数据审计，公开输出只含摘要、谱系哈希和失败。

不从下载成功自动决定出口，不训练或计算分类成绩；包关联、起点、
平台正常任务和独立活动可获取性分别报告，供阶段裁决引用。
"""
import argparse
import collections
import hashlib
import json
import statistics
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def verify_audit_code(audit, script, reference=True):
    """拒绝把旧算法产物绑定到当前代码，参考实现变动后须保留旧报告并重算。"""
    if audit['codeSha256'] != record(ROOT/'scripts/p1'/script)['sha256']:
        raise ValueError(f'{script} 审计代码哈希不一致，须重新生成独立报告')
    if reference and audit['referenceCodeSha256'] != record(ROOT/'scripts/p1/pcap_reference.py')['sha256']:
        raise ValueError('头部参考实现已变化，须重新计算审计')


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def record(path):
    return {'path':path.relative_to(ROOT).as_posix(),'bytes':path.stat().st_size,
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}


def group_summary(rows):
    result={}
    for label in sorted({r['publisherLabel'] for r in rows}):
        group=[r for r in rows if r['publisherLabel']==label]
        result[label]={'sampled':len(group),'joinCounts':dict(collections.Counter(r['join'] for r in group)),
                      'singleSynEpochObserved':sum(r['singleSynEpochObserved'] for r in group),
                      'sameAttackTargetService':sum(r['sameAttackTargetService'] for r in group),
                      'offloadAffected':sum(r['observed'].get('offloadSizedPackets',0)>0 for r in group),
                      'singleEpochWithoutOffloadOrReorder':sum(r['singleSynEpochObserved']
                          and not r['observed'].get('offloadSizedPackets',0)
                          and not r['finalFeatures']['timestampReordered'] for r in group),
                      'prefixReferences':{}}
        for sec in ('1','5'):
            references=[r['prefixes'][sec]['features'] for r in group
                        if r['join']=='matched' and r['prefixes'][sec]['hasPacketAtOrAfterDeadline']]
            result[label]['prefixReferences'][sec]={'observedSpansNotAutoQualification':len(references),
                'median':{name:statistics.median(values) if (values:=[r[name] for r in references if r[name] is not None]) else None
                          for name in ('packetsInbound','packetsOutbound','lengthMean','iatMeanUs')}}
    return result


def build(base,raw):
    days={};evidence=[];pcaps=[]
    for day,name in [('wednesday','Wednesday-workingHours.pcap'),('friday','Friday-WorkingHours.pcap')]:
        report_path=base/f'cic-{day}-audit.json'
        ledger_path=raw/(name+'.partial.json')
        audit=read(report_path);ledger=read(ledger_path)
        verify_audit_code(audit,'cic_probe.py')
        if ledger.get('status')!='complete' or not audit['pcap']['completeContainer']:
            raise ValueError('未完成原件不能生成阶段数据报告')
        if sorted(ledger['done'])!=list(range(0,ledger['size'],ledger['blockBytes'])):
            raise ValueError('完成账本的分段覆盖不完整或重复')
        if (raw/name).stat().st_size!=ledger['size'] or audit['pcap']['bytes']!=ledger['size']:
            raise ValueError('原件、下载账本与审计大小不同')
        if ledger['md5']!=audit['pcap']['md5'] or ledger['sha256']!=audit['pcap']['sha256']:
            raise ValueError('下载与容器审计哈希不同')
        checksum_path=raw/'Wednesday-workingHours.md5' if day=='wednesday' else raw/'kaggle/Friday-WorkingHours.md5'
        if checksum_path.read_text().split()[0]!=ledger['md5']:
            raise ValueError('下载账本未匹配已归档的校验文件')
        evidence += [report_path,ledger_path]
        pcaps.append({'name':name,**audit['pcap'],
                      'transferMirror':'https://www.kaggle.com/datasets/congyuanxu/cicids2017',
                      'checksumSource':ledger['checksumSource'],
                      'officialChecksumVerified':ledger['officialChecksumVerified']})
        days[day]={'labelSha256':audit['labelSha256'],'labelCensus':audit['labelCensus'],
                   'sampled':len(audit['samples']),'joinCounts':audit['joinCounts'],
                   'sameTargetBenignRowsAvailable':audit['sameTargetBenignRowsAvailable'],
                   'packetQuality':audit['packetQuality'],'labels':group_summary(audit['samples']),
                   'samples':audit['samples']}
    onset_path=base/'cic-slow-header-onset-v2.json'
    onset=read(onset_path);evidence.append(onset_path)
    verify_audit_code(onset,'review_slow_headers.py')
    # 来源附加字段不参与容器比对；起点审查必须来自相同完整原件。
    for key in ('sha256','md5','bytes','frames'):
        if onset['pcap'][key]!=pcaps[0][key]:
            raise ValueError('起点审查未绑定相同周三原件')
    if onset['labelSha256']!=days['wednesday']['labelSha256']:
        raise ValueError('起点审查与关联审计的标签版本不同')
    candidates=[]
    for row in onset['samples']:
        if (row['countPayloadJoinPassed'] and row['overlappingLabelRows']==0 and row['synStartObserved']
                and row['distinctSynSequences']==1 and row['invalidReason'] is None
                and row['timestampRegressions']==0 and row['observed'].get('offloadSizedPackets',0)==0
                and row['onsetCandidateDeltaUs'] is not None):
            candidates.append(row['connectionDigest'])
    diagnosis=read(base/'label-diagnosis.json')
    ddos=next(x for x in diagnosis['scenarios'] if x['scenario']=='CTU-IoT-Malware-Capture-34-1')
    torii={}
    for name in ('torii20','torii21'):
        path=base/(name+'-audit.json');a=read(path);evidence.append(path)
        torii[name]=a
    controlled_path=base/'benign-http-capture-audit-v3.json'
    controlled=read(controlled_path)
    verify_audit_code(controlled,'audit_controlled_capture.py')
    table_path=base/'cic-tables-audit.json';tables=read(table_path)
    verify_audit_code(tables,'audit_cic_tables.py',reference=False)
    for day in days:
        table=next(t for t in tables['tables'] if t['name']==day+'.csv')
        if table['sha256']!=days[day]['labelSha256'] or table['labels']!=days[day]['labelCensus']:
            raise ValueError('表格审计与关联审计的标签来源不同')
    available=read(base/'independent-activity-availability.json')
    schedule_path=base/'onset-schedule-reference-v2.json';schedule=read(schedule_path)
    verify_audit_code(schedule,'audit_onset_schedule.py',reference=False)
    if schedule['sourceAuditSha256']!=record(onset_path)['sha256'] or schedule['labelSha256']!=onset['labelSha256']:
        raise ValueError('快照时刻审查未绑定相同起点和标签版本')
    for expected in available['evidence']:
        if record(ROOT/expected['path'])!=expected:
            raise ValueError('独立活动来源的存档证据已变化')
    evidence += [base/'label-diagnosis.json',base/'supplement-manifest.json',
                 base/'cic-supplement-manifest.json',controlled_path,table_path,
                 base/'independent-activity-availability.json',base/'cns-labelling.ipynb']
    evidence += [raw/'Wednesday-workingHours.md5',raw/'kaggle/Friday-WorkingHours.md5']
    evidence += [base/'cic-slow-header-onset.json',base/'review_slow_headers-v1.py',
                 base/'slow-header-shape-diagnosis.json',base/'diagnose_slow_header_shape.py',schedule_path]
    return {'version':'p1-data-continuation-v2','status':'audited_feasibility_evidence',
            'candidateTask':'inbound HTTP connection/request abuse on one authorized service',
            'pcaps':pcaps,'correctedLabels':read(base/'cic-supplement-manifest.json')['files'],
            'correctedTableAudit':tables,
            'cicDays':days,
            'slowHeaderOnset':{'review':onset,'candidatesPassingStructuralChecks':candidates,
                               'scheduleReference':schedule,
                               'prefixSupervisionApproved':False,'payloadIsModelInput':False},
            'iot23':{'completeCaptures':5,'publisherLabelRows':196146,'sampledRows':150,
                     'originalDdosDiagnostics':ddos['ddosSampleDiagnostics'],
                     'originalDdosIssueResolved':False,'additionalToriiAudits':torii,
                     'selectedForInboundHttpTask':False},
            'controlledBenign':controlled,'independentActivityAvailability':available,
            'limits':['all CICIDS2017 inspected activities are development-exposed',
                      'same-target BENIGN count is small; source/host confounding remains',
                      'Attempted rows remain separate; no automatic benign/attack relabelling',
                      'offline header references are not the P2 production extractor',
                      '1/5/30s context engine and parent-connection continuation not implemented',
                      'no classification, blocking precision or model-versus-rule benefit measured',
                      'public checksum transport and independent origin verification are distinct'],
            'trainingExecuted':False,'finalTestAllocated':False,'finalTestEvaluated':False,
            'provenance':{'codeFiles':[record(p) for p in sorted((ROOT/'scripts/p1').glob('*.py'))],
                          'policy':record(ROOT/'docs/p1/continuation-label-policy.md'),
                          'budget':record(ROOT/'docs/p1/continuation-budget.md'),
                          'evidence':[record(p) for p in evidence]}}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts',type=Path,default=ROOT/'artifacts/p1/continuation-20261003')
    p.add_argument('--raw',type=Path,default=ROOT/'data/raw/p1/cic2017')
    p.add_argument('--output',type=Path,default=ROOT/'docs/p1/continuation-data.json')
    p.add_argument('--check',action='store_true');a=p.parse_args()
    result=build(a.artifacts.resolve(),a.raw.resolve())
    text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if a.check:
        if a.output.read_text()!=text:raise SystemExit('数据报告与证据/代码不一致')
    else:a.output.write_text(text)
    print(json.dumps({'pcaps':len(result['pcaps']),'sampled':sum(x['sampled'] for x in result['cicDays'].values()),
                      'structuralOnsetCandidates':len(result['slowHeaderOnset']['candidatesPassingStructuralChecks'])}))


if __name__=='__main__':
    main()
