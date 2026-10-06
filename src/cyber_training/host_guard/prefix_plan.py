"""P3 新运行计划准入；check 与 run 共用，设计 JSON 不能直接当训练配置。"""
import hashlib
import itertools
import json
from pathlib import Path
from collections import defaultdict

from .data import read, sha
from .prefix_corpus import verify


def subject_sha256(plan):
    """诊断 subject 排除其输出引用，避免清单自引用；规则/时效/代码仍逐项绑定。"""
    subject={k:v for k,v in plan.items() if k not in ('planSha256','_health','preFitDiagnostics')}
    subject['preFitParameters']=plan['preFitDiagnostics']['parameters']
    return hashlib.sha256(json.dumps(subject,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


def parameter_grid(plan):
    """在评分前固定完整网格；每个实际候选必须进入所属试验臂账本。"""
    d = plan['decision']
    return [dict(threshold=t, min_flows=n, span_ms=s, min_starts=p, ttl=ttl)
            for t,n,s,p,ttl in itertools.product(d['thresholds'],d['minDistinctFlows'],
                d['minEvidenceSpanMs'],d['minPeerFlowStarts'],d['ttlSeconds']) if n != 1 or s == 0]


def compatibility(plan, dataset, contracts):
    """真实文件、代码、资源边界分别检查；数据门槛失败也必须给非零退出。"""
    required = {'versions','scope','scenarios','budget','decision','evaluation','maximumPolicyTrials',
                'datasetFreezeSha256','softwareFreezeSha256','featureProfileSha256','codeFiles',
                'offlineSimulation','preFitDiagnostics','sourceScope'}
    if not required <= plan.keys(): raise ValueError('运行计划字段不全，不能直接使用设计登记')
    if plan.get('candidateOnly') is not True or plan.get('finalTestRead') is not False:
        raise ValueError('候选或 P6 访问边界不符')
    if plan['scope']['profile'] != 'flow-prefix-v1' or set(plan['scenarios']) != {'slowloris','slowhttptest'}:
        raise ValueError('本轮只允许 prefix 两行为')
    from .prefix_evaluation import ACTION_HORIZON, VERSION as EVALUATION_VERSION
    from .prefix_replay import VERSION as DECISION_VERSION
    expected = dict(observation='host-guard/5.0.0-rc.2',decision=DECISION_VERSION,
                    evaluation=EVALUATION_VERSION,captureHealth='host-guard-capture-health/1.0.0',
                    scenarioMapping='host-guard-behavior-map/1')
    if plan['versions'] != expected: raise ValueError('运行计划版本组合不符')
    budget = plan['budget']
    for field, cap in [('maximumFullFits',10),('maximumSmokeFits',3),('maxSecondsPerFit',300),
                       ('maxTotalSeconds',14400),('maxGpuSeconds',14400),('maximumPolicyTrials',256)]:
        if type(budget.get(field)) is not int or not 0 < budget[field] <= cap: raise ValueError('运行预算不符: '+field)
    if budget['algorithms'] != ['lightgbm','xgboost'] or budget['featureSets'] != ['base','peer_context']:
        raise ValueError('未登记算法或特征矩阵')
    if budget['policyTrialAllocation'] != dict(model_selection=64,rules=64,model=64,model_and_policy=64):
        raise ValueError('三臂及选型预算不符')
    grid = parameter_grid(plan)
    if len(grid) != plan['maximumPolicyTrials'] or len(grid)>64: raise ValueError('完整策略网格数不符')
    d=plan['decision']
    for field,value in [('maxEvidenceAgeMs',10000),('targetLastPacketLeaseMs',15000),
                        ('maxContinuousBlockSeconds',120),('maxActiveRulesPerAsset',10),('maxNewActionsPerMinute',5)]:
        if d[field] != value: raise ValueError('不得放宽硬安全约束: '+field)
    if any(type(t) is not int or not 5<=t<=60 for t in d['ttlSeconds']): raise ValueError('TTL 网格越界')
    if d.get('onContinuousBudgetExhausted') != 'escalate_manual':
        raise ValueError('连续预算耗尽必须登记为转人工输出')
    if plan['evaluation'].get('actionHorizon') != ACTION_HORIZON or max(d['ttlSeconds']) > ACTION_HORIZON['maxTtlMs']//1000:
        raise ValueError('自动处置期/人工移交期登记与评价代码不符')
    for path,digest in [(dataset/'readiness.json',plan['datasetFreezeSha256']),
        (contracts/'docs/p2/freeze-manifest.json',plan['softwareFreezeSha256']),
        (contracts/'docs/contracts/feature-profile.json',plan['featureProfileSha256'])]:
        if sha(path)!=digest: raise ValueError('运行输入哈希不符: '+path.name)
    for name,digest in read(contracts/'docs/p2/freeze-manifest.json')['files'].items():
        target=(contracts/name).resolve()
        if contracts.resolve() not in target.parents or sha(target)!=digest: raise ValueError('历史契约包被修改')
    code_root=Path(__file__).parent
    actual={p.name:sha(p) for p in code_root.glob('*.py')}
    if plan['codeFiles'] != actual: raise ValueError('当前训练代码与计划哈希不符')
    verified=verify(dataset,plan['scenarios'])
    blockers=list(verified['blockers'])
    preflight=plan['preFitDiagnostics']
    if not preflight.get('file') or not preflight.get('sha256'):
        blockers.append('PREFIT_DIAGNOSTICS_NOT_BOUND')
    else:
        path=(dataset/preflight['file']).resolve()
        if sha(path)!=preflight['sha256']: raise ValueError('拟合前诊断被修改')
        report=read(path)
        if report.get('status')!='passed' or report.get('modelFits')!=0:
            blockers.append('PREFIT_STRUCTURAL_REACHABILITY_FAILED')
        if report.get('datasetFreezeSha256')!=plan['datasetFreezeSha256'] or report.get('decisionVersion')!=expected['decision']:
            raise ValueError('诊断数据或决策版本未绑定')
        if report.get('runtimeSubjectSha256')!=subject_sha256(plan):
            raise ValueError('诊断规则/时效/代码与当前运行计划不符')
    registrations=plan['evaluation'].get('latencyRegistrations',[])
    if not registrations: blockers.append('LATENCY_REGISTRATION_MISSING')
    if not plan.get('captureHealth'):
        blockers.append('CONTINUOUS_CAPTURE_HEALTH_NOT_BOUND')
    else:
        from .capture_health import HealthChain, IDENTITY, stamp
        health=load_health(plan,dataset)
        chain=HealthChain(health['bindings'])
        for record in health['records']:
            state=chain.accept(record)
            if state['reason'] is not None: blockers.append('CAPTURE_HEALTH_INVALID:'+state['reason'])
        if not health['records'] or not health['targets']: blockers.append('CAPTURE_HEALTH_EMPTY')
    scope={r['sourceDomainId']:r['role'] for r in plan['sourceScope']}
    declared={(r['behaviorScenario'],r['sourceDomainId']) for r in registrations}
    if len(declared)!=len(registrations):raise ValueError('重复时效登记')
    for record in registrations:
        if (record['startToActionLimitMs']<2000 or record.get('eligibility')!='alert_only'
                or record.get('automaticApprovalRef') is not None):
            raise ValueError('时效登记越过候选权限')
    target_roles=defaultdict(lambda:defaultdict(list))
    from .data import time_ms
    for line in (dataset/'index.jsonl').open(encoding='utf-8'):
        row=json.loads(line)
        target_roles[row['budgetTargetId']][row['split']].append(time_ms(row['asOf']))
        if row['label']!=1:continue
        from .prefix_contract import BEHAVIORS
        domain=row.get('sourceDomainId',row['sourceId'])
        behavior=row.get('behaviorScenario',BEHAVIORS.get(row['scenario']))
        if domain not in scope: blockers.append('SOURCE_SCOPE_NOT_REGISTERED:'+domain)
        if (behavior,domain) not in declared:blockers.append('SOURCE_LATENCY_NOT_REGISTERED:'+domain)
    # 调参时可读取的角色必须是该目标的真实时间前缀；否则不能用空预算代替
    # 尚未开放角色的历史证据，也不能提前读取独立开发特征来修补预算。
    roles=('train','validation_selection','validation_calibration','independent_development')
    for periods in target_roles.values():
        last=-float('inf')
        for role in roles:
            if role not in periods:continue
            if min(periods[role])<=last:blockers.append('ROLE_ACCESS_ORDER_BREAKS_CONTINUOUS_BUDGET')
            last=max(periods[role])
    return dict(runtimeCompatible=True,trainingAllowed=not blockers,blockers=sorted(set(blockers)),
                dataset=verified,policyGridTrials=len(grid),modelFits=0,finalTestRead=False,
                codeSha256=hashlib.sha256(json.dumps(actual,sort_keys=True).encode()).hexdigest())


def load_health(plan, dataset):
    """旁证与可信采集登记分别绑定；空链只可诊断，不能隐式视为健康。"""
    binding=plan.get('captureHealth')
    if not binding: return dict(records=[],bindings=[],targets={})
    manifest=dataset/binding['manifest']
    if sha(manifest)!=binding['sha256']: raise ValueError('健康登记哈希不符')
    registry=read(manifest)
    if registry['version']=='p3-capture-health-registry-v1':
        records=dataset/registry['recordsFile']
        if sha(records)!=registry['recordsSha256']: raise ValueError('原始健康旁证被修改')
        if registry['authenticatedCollectionRef'] != binding['authenticatedCollectionRef']:
            raise ValueError('缺少可信采集来源绑定')
        return dict(records=[json.loads(line) for line in records.open(encoding='utf-8')],
                    bindings=registry['observerBindings'],targets=registry['targetBindings'])
    if registry['version']!='p3-capture-health-registry-v2' or registry.get('crossSessionContinuity') is not False:
        raise ValueError('未知健康会话版本或跨会话连续性声明')
    sessions=registry['sessions']
    if len(sessions)<2 or binding['authenticatedCollectionRef'] != [s['authenticatedCollectionRef'] for s in sessions]:
        raise ValueError('健康会话来源绑定不符')
    from .capture_health import IDENTITY, stamp
    records=[]; identities=[]; seen_activities=set(); previous_stop=None
    for session in sessions:
        relative=Path(session['directory'])
        directory=(dataset/relative).resolve()
        if relative.is_absolute() or dataset.resolve() not in directory.parents:
            raise ValueError('健康会话路径越界')
        source=directory/'health-registry.json'
        observed=directory/'health-records.jsonl'
        observer=directory/'observer-binding.json'
        ledger=directory/'activity-ledger.jsonl'
        authorization=directory/'authorization.json'
        for path,key in ((source,'sourceRegistrySha256'),(observed,'recordsSha256'),
                         (observer,'bindingSha256'),(ledger,'activityLedgerSha256'),
                         (authorization,'authorizationSha256')):
            if sha(path)!=session[key]: raise ValueError('健康会话原件哈希不符: '+path.name)
        raw=read(source); documented=read(observer); approved=read(authorization)
        if (raw.get('version')!='p3-capture-health-registry-v1'
                or raw['observerBindings']!=[session['observerBinding']]
                or raw['recordsSha256']!=session['recordsSha256']
                or raw['bindingSha256']!=session['bindingSha256']
                or raw['authenticatedCollectionRef']!=session['authenticatedCollectionRef']
                or approved.get('authorizationId')!=documented['authorizationId']
                or approved.get('status')!='authorized_active'
                or approved.get('executionAuthorized') is not True
                or documented['binding']!=session['observerBinding']
                or documented['startedAt']!=session['startedAt']
                or raw['stoppedAt']!=session['stoppedAt']):
            raise ValueError('健康会话登记与原件不一致')
        if previous_stop is not None and stamp(previous_stop)>=stamp(session['startedAt']):
            raise ValueError('健康会话重叠或倒序')
        previous_stop=session['stoppedAt']
        activity_ids=[json.loads(line)['activityId'] for line in ledger.open(encoding='utf-8')]
        if (len(activity_ids)!=len(set(activity_ids)) or set(activity_ids)!=set(session['activityIds'])
                or seen_activities & set(activity_ids)):
            raise ValueError('健康会话活动归属重复或被修改')
        seen_activities.update(activity_ids)
        identity=tuple(session['observerBinding'][k] for k in IDENTITY)
        if identity in identities: raise ValueError('健康会话身份重复')
        identities.append(identity)
        records.extend(json.loads(line) for line in observed.open(encoding='utf-8'))
    if registry['observerBindings']!=[s['observerBinding'] for s in sessions]:
        raise ValueError('健康观察器列表与会话不符')
    if any(tuple(target[k] for k in IDENTITY)!=identities[0]
           for target in registry['targetBindings'].values()):
        raise ValueError('跨会话预算目标必须保守绑定首个会话')
    target_sessions={target:[dict(identity=session['observerBinding'],
                                  activityIds=session['activityIds']) for session in sessions]
                     for target in registry['targetBindings']}
    return dict(records=sorted(records,key=lambda r:(stamp(r['intervalEnd']),r['sequence'])),
                bindings=registry['observerBindings'],targets=registry['targetBindings'],
                targetSessions=target_sessions)
