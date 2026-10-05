#!/usr/bin/env python3
"""冻结新 prefix 开发语料的保守分区与 P6 原件预留；准入不足仍产出明确的拒绝裁决。

不读取 final_reserved 的载荷、标签或特征。parent/活动/来源日/上下文/近重复的
连通分量只能进入一个明确登记角色；缺失或冲突即拒绝，不看模型分数或调换困难样本。
近重复按完整 parent 的有序、去身份、粗粒度特征序列登记，可能多合并但不拆活动。
"""
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path

from build_qualified_prefix import sha,lines,us,target_key
from verify_prefix_corpus import context_sources, group_admission, grouping_summary
from prefix_contract import metadata, early_edges, sole_role, MAPPING_VERSION, EARLY_WINDOWS
from capture_health import HealthChain, IDENTITY, VERSION as HEALTH_VERSION, stamp

VERSION='prefix-corpus-partition-v5'
# 增加谱系和诊断不重洗既有分区；固定原来的排序种子及组 ID 算法。
ASSIGNMENT_SEED_VERSION='prefix-corpus-partition-v3'
ADMISSION_VERSION='prefix-independent-development-v1'
ROLES=('train','validation_selection','validation_calibration','independent_development')
CONTROLLED_DOMAIN='controlled_windows_http_cde'


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def near_vector(features):
    """时长1秒、字节32、长度8字节分箱；丢弃端点/身份/绝对时刻/标签及IAT抖动。

    至少两个prefix的完整有序序列相同才构成跨活动近重复边；这是显式的保守判据，
    不能由无此类边推断跨域泛化。所有原有精确重复parent排除仍生效。
    """
    fields=[('elapsedMs',1000),('bytesInbound',32),('bytesOutbound',32),
            ('packetsInbound',1),('packetsOutbound',1),('lengthMin',8),('lengthMax',8),
            ('lengthMean',8),('synCount',1),('synAckCount',1),('rstCount',1),('finCount',1)]
    return [None if features[k] is None else round(features[k]/bucket) for k,bucket in fields]+[features['handshakeSeen']]


def health_binding(registry_path, authorization_path, rows, timelines):
    """仅为本轮真实受控目标生成可信绑定；公共来源不能继承回环健康旁证。"""
    registry_path=Path(registry_path)
    root=registry_path.parent
    registry=json.loads(registry_path.read_text(encoding='utf-8'))
    binding_path=root/'observer-binding.json'
    records_path=root/'health-records.jsonl'
    ledger_path=root/'activity-ledger.jsonl'
    binding_doc=json.loads(binding_path.read_text(encoding='utf-8'))
    authorization=json.loads(Path(authorization_path).read_text(encoding='utf-8'))
    binding=binding_doc['binding']
    if registry_path.name!='health-registry.json' or registry.get('version')!='p3-capture-health-registry-v1' or registry.get('modelFits')!=0:
        raise ValueError('健康登记版本或拟合状态不符')
    if (registry.get('healthVersion')!=HEALTH_VERSION or binding_doc.get('healthVersion')!=HEALTH_VERSION
            or registry.get('recordsFile')!=records_path.name or registry.get('recordsSha256')!=sha(records_path)
            or registry.get('records')!=sum(1 for _ in lines(records_path))
            or registry.get('bindingSha256')!=sha(binding_path)
            or registry.get('observerBindings')!=[binding] or registry.get('targetBindings')!={}):
        raise ValueError('观察器绑定、原始记录或哈希不符')
    config_sha=hashlib.sha256(json.dumps(binding_doc['config'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if (binding.get('configSha256')!=config_sha
            or binding.get('buildSha256')!=sha(Path(__file__).with_name('capture_health_observer.py'))):
        raise ValueError('观察器配置或采集代码身份不符')
    if (authorization.get('status')!='authorized_active' or authorization.get('executionAuthorized') is not True
            or binding_doc.get('authorizationId')!=authorization.get('authorizationId')
            or binding_doc.get('authorizedUntil')!=authorization.get('validUntil')
            or registry.get('authenticatedCollectionRef')!=authorization['authorizationId']+':'+sha(binding_path)):
        raise ValueError('受控采集授权与观察器登记不符')
    scope=authorization['scope'];config=binding_doc['config']
    if (scope.get('host')!='win-dev' or scope.get('environment')!='isolated_loopback_research'
            or scope.get('interface')!=config.get('interface') or scope.get('local')!='127.0.0.1'
            or scope.get('peer')!='127.0.0.2' or scope.get('servicePort')!=80
            or scope.get('maxConcurrentConnections',0)>4 or scope.get('firewallChanges') is not False
            or scope.get('externalTrafficAllowed') is not False
            or config.get('filter')!='ip and tcp and host 127.0.0.1 and host 127.0.0.2 and port 80'):
        raise ValueError('观察器配置超出登记回环范围')
    valid_from=stamp(authorization['validFrom']);valid_until=stamp(authorization['validUntil'])
    if not valid_from<=stamp(binding_doc['startedAt'])<valid_until or stamp(registry['stoppedAt'])>valid_until+5000:
        raise ValueError('观察器会话不在授权时段')
    if registry.get('stopReason') not in ('stop_file','authorization_expired'):
        raise ValueError('健康观察器异常停止')
    controlled=[r for r in rows if r['sourceDomainId']==CONTROLLED_DOMAIN]
    if not controlled:
        raise ValueError('本轮没有可绑定的受控活动')
    activities={r['activityId'] for r in controlled}
    public_targets={r['budgetTargetId'] for r in rows if r['sourceDomainId']!=CONTROLLED_DOMAIN}
    targets={r['budgetTargetId'] for r in controlled}
    expected_target=target_key(binding['assetId'],'127.0.0.1:80','127.0.0.2:0')
    if targets!={expected_target} or targets & public_targets:
        raise ValueError('受控稳定目标缺失、与公共来源冲突或跨目标')
    ledger=list(lines(ledger_path))
    by_activity={r['activityId']:r for r in ledger}
    if len(by_activity)!=len(ledger) or set(by_activity)!=activities:
        raise ValueError('受控活动与完成账本不一致')
    chain=HealthChain([binding]);last=None
    for record in lines(records_path):
        last=chain.accept(record)
        if last['reason'] is not None:
            raise ValueError('健康链存在不合格区间: '+last['reason'])
    if last is None:
        raise ValueError('健康链为空')
    for row in controlled:
        entry=by_activity[row['activityId']]
        if (entry.get('success') is not True or entry.get('plannedRole')!=row['split']
                or entry.get('kind')!=('attack' if row['label']==1 else 'benign')
                or not valid_from<=stamp(row['firstSeenAt'])<=stamp(row['asOf'])<=entry['endedAt']*1000<=valid_until):
            raise ValueError('受控观察与授权、角色或完成账本冲突')
    controlled_timeline=[r for r in timelines if r['activityId'] in activities]
    if {r['activityId'] for r in controlled_timeline}!=activities:
        raise ValueError('受控活动标签时间线缺失')
    for episode in controlled_timeline:
        if (episode['targetId'] not in targets or not valid_from<=episode['startMs']<episode['endMs']<=valid_until
                or episode['endMs']>by_activity[episode['activityId']]['endedAt']*1000
                or chain.proof(binding,episode['startMs'],episode['endMs']) is None):
            raise ValueError('受控活动时间线缺少授权范围内的连续健康证明')
    if last['end']<max(r['endMs'] for r in controlled_timeline)+180000:
        raise ValueError('最后活动后缺少规则到期及冷却旁证')
    derived=dict(registry, targetBindings={target:{k:binding[k] for k in IDENTITY} for target in targets},
                 sourceRegistrySha256=sha(registry_path),authorizationSha256=sha(authorization_path),
                 activityLedgerSha256=sha(ledger_path))
    return derived,records_path,binding_path,ledger_path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qualified',type=Path,action='append',required=True)
    p.add_argument('--benign-root',type=Path)
    p.add_argument('--health-registry',type=Path,default=None,
                   help='capture_health_observer 产出的 health-registry.json；'
                        '提供后将受控活动的 budgetTargetId 绑定到观察器会话，'
                        '原始记录及派生登记写入冻结输出。不提供则跳过绑定。')
    p.add_argument('--authorization',type=Path,
                   help='本轮受控回环执行授权；指定健康登记时必填')
    for name in ['qualification','reservation','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();q=json.loads(a.qualification.read_text());reservation=json.loads(a.reservation.read_text())
    if q['reservationSha256']!=sha(a.reservation) or reservation['modelScoresRead'] or reservation['finalFeaturesRead']:
        raise ValueError('预留角色身份或封存边界不符')
    sealed={r['sha256']:r for r in q['captures'] if r['role']=='final_reserved'}
    rows=[];observations={};input_hashes={};cohorts={};parents={};parent_rows=defaultdict(list);files=[];timelines=[]
    def add(index,obs,origin):
        if index['split'] not in ('development_unassigned',)+ROLES:raise ValueError('禁止未知或最终评估角色输入')
        if index.get('captureSha256') in sealed:raise ValueError('封存捕获禁止进入开发集合')
        ident=index['observationId'];parent=index['parentConnectionId']
        if ident in observations or ident!=obs['observationId'] or parent!=obs['parentConnectionId']:
            raise ValueError('重复或错配的观察身份')
        if obs['profile']!='flow-prefix-v1' or obs['contractVersion']!='host-guard/5.0.0-rc.2':raise ValueError('特征契约不符')
        if any(v is True for v in obs['quality'].values()) or index['label'] not in (0,1):raise ValueError('坏质量或Unknown混入语料')
        cohort=index.get('sourceDayCluster') or index['activityId']
        previous=parents.setdefault(parent,cohort)
        if previous!=cohort:raise ValueError('parent跨来源活动')
        index=metadata(index)
        index=dict(index,sourceId=index['sourceId'],scenario=index['scenario'],
                   cohortId=cohort,priorPlannedRole=index['split'])
        c=cohorts.setdefault(cohort,dict(activities=set(),sources=set(),first=us(index['firstSeenAt']),last=us(index['asOf'])))
        c['activities'].add(index['activityId']);c['sources'].update(context_sources(index))
        c['first']=min(c['first'],us(index['firstSeenAt']));c['last']=max(c['last'],us(index['asOf']))
        observations[ident]=obs;rows.append(index);parent_rows[parent].append((us(index['asOf']),near_vector(obs['features'])))
    for folder in a.qualified:
        report=json.loads((folder/'readiness.json').read_text())
        if report['finalRead'] or report['modelFits']!=0:raise ValueError('该新语料已读取最终数据或进行拟合')
        for name in report['outputHashes']:
            if name not in ('index.jsonl','observations.jsonl','label-timeline.jsonl','label-connection-timeline.jsonl'):
                raise ValueError('未知的资格化输出文件')
            if sha(folder/name)!=report['outputHashes'][name]:raise ValueError('资格化输出哈希不符')
            input_hashes[str(folder/name)]=sha(folder/name)
        for index,obs in zip(lines(folder/'index.jsonl'),lines(folder/'observations.jsonl'),strict=True):add(index,obs,'publisher')
        files.append(dict(kind='qualified',name=folder.name,readinessSha256=sha(folder/'readiness.json')))
        name='label-timeline.jsonl' if 'label-timeline.jsonl' in report['outputHashes'] else 'label-connection-timeline.jsonl'
        for ordinal,ep in enumerate(lines(folder/name)):
            # 时间线保留发布/任务起点，绝不从首个高分观察反推分母。
            ep=metadata(ep)
            ep.setdefault('activityId',report.get('activityId'))
            ep.setdefault('scenario',report.get('scenario','taara_slowloris'))
            ep.setdefault('episodeId',digest([folder.name,ep.get('sourceConnectionId'),ordinal]))
            ep.setdefault('attackStartIntervalMs',[ep['startMs'],ep.get('evidenceAvailableAtUs',ep['startMs']*1000)/1000] if ep['label']==1 else None)
            ep.setdefault('basis','source_bound_connection_interval_with_causal_evidence; onset_bounds_preserved')
            timelines.append(ep)
    audit_path=a.benign_root/'group-audit-eight' if a.benign_root else None
    audit=json.loads((audit_path/'summary.json').read_text()) if audit_path else None
    if audit and sha(audit_path/'prefix-index.jsonl')!=audit['indexSha256']:raise ValueError('受控任务去重复索引哈希不符')
    safe={r['observationId']:r for r in lines(audit_path/'prefix-index.jsonl')} if audit else {};found=set()
    for batch in sorted(a.benign_root.glob('batch-*')) if a.benign_root else []:
        path=batch/'extraction-stable-v1/observations.jsonl'
        if not path.exists():continue
        ex=json.loads((path.parent/'extraction.json').read_text())
        if sha(path)!=ex['observationsSha256'] or ex['pcapSha256']!=audit['captureHashes'][batch.name]:
            raise ValueError('受控任务提取身份不符')
        for obs in lines(path):
            ident=obs['observationId']
            if ident in safe:add(safe[ident],obs,'controlled_windows_http');found.add(ident)
        # 旧受控任务的完整连接旁路已由PCAP核验，保留无prefix的正常连接分母。
        connections=list(lines(batch/'audit-stable-v1/connections.jsonl'))
        bound={r['parentConnectionId']:r for r in safe.values() if r['activityId']==json.loads((batch/'task.json').read_text())['activityId']}
        for parent,row in bound.items():
            obs=observations[row['observationId']]
            port=int(next(l for l in lines(path.parent/'ledger.jsonl') if l['observationId']==row['observationId'])['Endpoints']['Peer'].rsplit(':',1)[1])
            matches=[c for c in connections if c['peerPort']==port and abs(c['firstUs']-us(obs['firstSeenAt']))<=1]
            if len(matches)!=1:raise ValueError('旧正常连接时间线未唯一对应')
            c=matches[0]
            timelines.append(dict(episodeId=digest([row['activityId'],parent]),parentConnectionId=parent,
                activityId=row['activityId'],scenario='controlled_benign',label=0,targetId=row['budgetTargetId'],
                startMs=c['firstUs']/1000,endMs=c['lastUs']/1000,hasObservation=True,basis='verified_controlled_task_connection'))
        input_hashes[str(path)]=sha(path)
    if found!=set(safe):raise ValueError('受控prefix缺少真实Go观察')
    if audit_path:input_hashes[str(audit_path/'prefix-index.jsonl')]=sha(audit_path/'prefix-index.jsonl')
    union={key:key for key in cohorts};edges=[]
    def find(key):
        while union[key]!=key:union[key]=union[union[key]];key=union[key]
        return key
    def merge(left,right,reason):
        if find(left)!=find(right):
            x,y=sorted((find(left),find(right)));union[y]=x;edges.append(dict(left=left,right=right,reason=reason))
    activities={}
    for key,c in cohorts.items():
        for activity in c['activities']:
            if activity in activities:merge(key,activities[activity],'shared_activity')
            else:activities[activity]=key
    keys=sorted(cohorts)
    for i,key in enumerate(keys):
        c=cohorts[key]
        for other in keys[:i]:
            d=cohorts[other]
            if c['sources']&d['sources'] and c['first']<d['last']+150000000 and d['first']<c['last']+150000000:
                merge(key,other,'shared_source_context_150s')
    signatures={};near_matches=0
    for parent,sequence in parent_rows.items():
        if len(sequence)<2:continue
        sig=digest([v for _,v in sorted(sequence,key=lambda item:item[0])]);cohort=parents[parent]
        if sig in signatures and signatures[sig]!=cohort:
            near_matches+=1;merge(cohort,signatures[sig],'whole_parent_quantized_sequence')
        else:signatures[sig]=cohort
    early_matches=early_edges(parent_rows,parents)
    for left,right,window in early_matches:
        merge(left,right,'common_early_prefix_trajectory_'+str(window)+'s')
    components=defaultdict(list)
    for key in keys:components[find(key)].append(key)
    assigned={};groups=[];component_labels=defaultdict(Counter)
    for row in rows:component_labels[find(row['cohortId'])][str(row['label'])]+=1
    ordered=sorted(components.values(),key=lambda members:(
        -int(component_labels[find(members[0])]['1']>0),
        -len(component_labels[find(members[0])]),digest([ASSIGNMENT_SEED_VERSION,members])))
    covered={role:set() for role in ROLES};role_sizes=Counter();evaluation_groups=Counter();covered_scenes={role:set() for role in ROLES}
    for members in ordered:
        group=digest([ASSIGNMENT_SEED_VERSION,members]);labels=component_labels[find(members[0])]
        scenes={r['scenario'] for r in rows if r['cohortId'] in members and r['label']==1}
        role=sole_role(r for r in rows if r['cohortId'] in members)
        covered[role].update(labels);role_sizes[role]+=sum(labels.values())
        covered_scenes[role].update(scenes)
        if role=='independent_development':evaluation_groups.update(labels.keys())
        for member in members:assigned[member]=(group,role)
        groups.append(dict(groupId=group,role=role,cohorts=members,
                           activities=sorted({v for m in members for v in cohorts[m]['activities']})))
    for row in rows:row['leakageGroupId'],row['split']=assigned[row['cohortId']]
    scenario_groups=defaultdict(set);classes=defaultdict(set);role_classes=Counter();role_groups=defaultdict(set)
    for row in rows:
        classes[str(row['label'])].add(row['leakageGroupId']);role_classes[(row['split'],str(row['label']))]+=1
        role_groups[(row['split'],str(row['label']))].add(row['leakageGroupId'])
        if row['label']==1:scenario_groups[row['scenario']].add(row['leakageGroupId'])
    admission=group_admission(rows);blockers=admission['blockers']
    activity_binding={activity:(g['groupId'],g['role']) for g in groups for activity in g['activities']}
    qualified_timeline=[]
    for ep in timelines:
        if ep['activityId'] not in activity_binding:
            raise ValueError('时间线活动没有完整来源/分区绑定；禁止丢弃无观察分母后冻结')
        group,role=activity_binding[ep['activityId']]
        if ep.get('plannedRole') != role:
            raise ValueError('标签时间线 plannedRole 与冻结组冲突')
        if ep['endMs']<=ep['startMs']:raise ValueError('非法标签时间线')
        qualified_timeline.append(dict(ep,leakageGroupId=group,split=role))
    if bool(a.health_registry)!=bool(a.authorization):
        raise ValueError('健康登记与执行授权必须同时提供')
    health=None
    if a.health_registry:
        health=health_binding(a.health_registry,a.authorization,rows,qualified_timeline)

    # 独立开发最少组数是下限；真实训练入口仍须使用完整实验计划，不由此脚本放宽。
    a.output.mkdir(parents=True,exist_ok=False,mode=0o700)
    for name,values in [('index.jsonl',rows),('observations.jsonl',[observations[r['observationId']] for r in rows]),('label-timeline.jsonl',qualified_timeline)]:
        with (a.output/name).open('x') as f:
            for row in values:f.write(json.dumps(row)+'\n')
    development_days={r.get('sourceDayCluster') for r in rows if r.get('sourceDayCluster')}
    sealed_rows=[]
    for r in sealed.values():
        row={k:r[k] for k in ['source','member','sha256','bytes','containerComplete','associationGroup','cluster']}
        row['eligibility']='quarantined_shared_development_source_day' if r['cluster'] in development_days else 'sealed_provenance_pending'
        sealed_rows.append(row)
    seal=dict(version='p6-raw-reservation-v3',priorReservationSha256=sha(a.reservation),
              qualificationSha256=sha(a.qualification),allowedRead='integrity_only',featuresRead=False,
              labelsRead=False,modelScoresRead=False,evaluationAllowed=False,
              captures=sealed_rows,
              reason='immutable reservation only; final provenance and candidate admission must be reviewed separately')
    (a.output/'p6-sealed-manifest.json').write_text(json.dumps(seal,indent=2)+'\n')
    health_outputs=[]
    if health:
        registry,records_path,binding_path,ledger_path=health
        for path in (records_path,binding_path,ledger_path):
            (a.output/path.name).write_bytes(path.read_bytes())
            health_outputs.append(path.name)
        (a.output/'health-registry.json').write_text(json.dumps(registry,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        health_outputs.append('health-registry.json')
    partition=dict(version=VERSION,assignment='explicit plannedRole; merged role conflict rejected before output',
                   assignmentSeedVersion=ASSIGNMENT_SEED_VERSION,
                   scenarioMappingVersion=MAPPING_VERSION,earlyTrajectoryWindowsSeconds=list(EARLY_WINDOWS),
                   earlyTrajectoryMatches=len(early_matches),
                   contextGapSeconds=150,nearDuplicateRule=near_vector.__doc__,nearDuplicateMatches=near_matches,
                   edges=edges,groups=groups,sourceIdentityPreserved=True)
    (a.output/'partitions.json').write_text(json.dumps(partition,indent=2)+'\n')
    report=dict(version=VERSION,admissionVersion=ADMISSION_VERSION,observations=len(rows),parents=len(parents),activities=len({r['activityId'] for r in rows}),
        leakageGroups=len(groups),classGroups={k:len(v) for k,v in classes.items()},
        sceneAttackGroups={k:len(v) for k,v in scenario_groups.items()},
        roleCounts={role:{label:role_classes[(role,label)] for label in ('0','1')} for role in ROLES},
        roleClassGroups={role:{label:len(role_groups[(role,label)]) for label in ('0','1')} for role in ROLES},
        sceneRoleAttackGroups=admission['sceneRoleAttackGroups'],labelTimelineEntries=len(qualified_timeline),
        groupingSummary=grouping_summary(rows,partition),
        nearDuplicateMatches=near_matches,rolesFrozen=True,finalReservationFrozen=True,sealedCaptures=len(sealed),
        finalRead=False,p6Ready=False,trainingAllowed=not blockers,modelFits=0,blockers=blockers,
        inputs=files,inputHashes=input_hashes,scriptSha256=sha(Path(__file__)),
        outputHashes={name:sha(a.output/name) for name in ['index.jsonl','observations.jsonl','label-timeline.jsonl','partitions.json','p6-sealed-manifest.json',*health_outputs]})
    (a.output/'readiness.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('inputHashes','inputs')}))


if __name__=='__main__':main()
