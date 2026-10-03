#!/usr/bin/env python3
"""按已取得证据输出 P1 出口裁决；不把可行性、测试通过或报告生成当运行授权。"""
import argparse
import json
from pathlib import Path
from summarize_data import ROOT, read, record


def build(data_path,platform_path,wfp_path=None):
    data=read(data_path);platform=read(platform_path)
    wfp=read(wfp_path) if wfp_path else None
    day=data['cicDays']['wednesday'];rows=day['samples']
    attack=[r for r in rows if r['publisherLabel']=='DoS Slowloris' and r['join']=='matched']
    benign=[r for r in rows if r['publisherLabel']=='BENIGN' and r['join']=='matched']
    onset=data['slowHeaderOnset'];schedule=onset['scheduleReference']['samples']
    checks={
        'completeOfficiallyChecksummedDevelopmentCapture':data['pcaps'][0]['completeContainer']
            and data['pcaps'][0]['officialChecksumVerified'],
        'atLeast30AuditedWith10PositiveAnd10Negative':len(rows)>=30 and len(attack)>=10 and len(benign)>=10,
        'causalHeaderInputsAvailable':all(r['finalFeatures']['packets']>0
            and r['finalFeatures']['lengthMean'] is not None for r in attack+benign),
        'sourceSpecificOnsetPlanDemonstrated':bool(onset['candidatesPassingStructuralChecks'])
            and any(r['scheduleWithinPublisherWindow'] for r in schedule),
        'controlledHardNegativesAvailable':data['controlledBenign']['scopeVerified']
            and data['controlledBenign']['successfulClientTasks']>0
            and data['controlledBenign']['legitimateTimeoutsRetained'],
        'separateActivityAvailableAtMetadataLevel':data['independentActivityAvailability']['publicObjectHeadStatus']==200,
    }
    data_pass=all(checks.values())
    cleanup=platform['cleanup'];reboot=platform['reboot']
    platform_pass=(platform['status']=='feasibility_demonstrated_with_limits'
                   and reboot['secondBootCleanupVerified'] and reboot['strictTtlAcrossRebootPassed']
                   and cleanup['ownedRulesRemaining']==0 and cleanup['ownedTasksRemaining']==0)
    if wfp:
        platform_pass=(wfp['strictRebootTtlPassed'] and all(r['passed'] for r in wfp['cases'])
                       and wfp['cleanup']['rules']==0 and wfp['cleanup']['tasks']==0
                       and wfp['cleanup']['probeProcesses']==0
                       and wfp['cleanup']['wfp']=={'sublayerPresent':False,'filters':[]})
    blockers=[]
    if not data_pass:blockers.append('DATA_FEASIBILITY_CHECK_FAILED')
    if wfp and not wfp['strictRebootTtlPassed']:
        blockers.extend(wfp['reboot']['blockers'])
    elif not wfp and not reboot['strictTtlAcrossRebootPassed']:
        blockers.append('WINDOWS_REBOOT_TTL_DEADLINE_MISSED')
    if not platform_pass and not any('DEADLINE' in b or 'OBSERVER' in b for b in blockers):
        blockers.append('PLATFORM_EXIT_NOT_VERIFIED')
    return {
        'version':'p1-stage-exit-v2','evidenceDate':'2026-10-04','phase':'P1',
        'status':'passed' if data_pass and platform_pass else 'blocked',
        'exitPassed':data_pass and platform_pass,
        'dataExit':{'status':'passed_feasibility_only' if data_pass else 'failed',
                    'checks':checks,'candidateFamily':'connection_abuse',
                    'task':'IPv4/TCP inbound slow incomplete HTTP requests to one protected service',
                    'developmentPositiveSamples':len(attack),'developmentBenignSamples':len(benign),
                    'structuralOnsetCandidates':len(onset['candidatesPassingStructuralChecks']),
                    'scheduledReferencesWithinPublisherWindow':sum(r['scheduleWithinPublisherWindow'] for r in schedule),
                    'fullDatasetPrefixLabelsApproved':False,
                    'modelBenefitOrBlockingPrecisionMeasured':False},
        'platformExit':{'status':'passed' if platform_pass else 'not_passed',
                        'windowsNarrowRuleFeasibilityDemonstrated':platform['status']=='feasibility_demonstrated_with_limits',
                        'strictRebootTtlPassed':wfp['strictRebootTtlPassed'] if wfp else reboot['strictTtlAcrossRebootPassed'],
                        'legacyPersistentStoreRebootDeletionMinusExpirySeconds':reboot['blockDeletionMinusExpirySeconds'],
                        'dynamicSessionProbe':{'status':wfp['status'],'nonRebootCasesPassed':sum(r['passed'] for r in wfp['cases']),
                                               'rebootExecuted':wfp['rebootExecuted'],'reboot':wfp['reboot']} if wfp else None,
                        'macOS':wfp['macOS'] if wfp else platform['macOS']['status'],
                        'macOSAutoSupported':False,'productionAutoSupported':False},
        'blockingReasons':blockers,
        'nextWork':[
            'P2 可独立实现已具数据依据的因果提取器；需另按阶段授权，不依赖前端',
            '全量重建 parentConnection、时间水位和起点旁路；原 20 条起点审查及失败全部保留',
            'WFP 已完成六项非重启和一次授权重启；须补关机截止观察与自动启动失败诊断，本次不追加重启',
            'Mac 按用户要求暂缓实测，持续排除自动能力',
            'P3 再验证来源混淆、困难负例、模型相对规则收益；独立评估原件未读取或分配',
        ],
        'trainingExecuted':False,'phase2Executed':False,'finalTestAllocated':False,
        'runtimeChanged':False,'automaticExecutionAuthorizedByReport':False,
        'provenance':{'code':record(Path(__file__).resolve()),
                      'dataReport':record(data_path),'platformReport':record(platform_path),
                      'coverage':record(ROOT/'docs/p1/continuation-coverage.md'),
                      'dynamicSessionReport':record(wfp_path) if wfp_path else None},
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data',type=Path,default=ROOT/'docs/p1/continuation-data.json')
    parser.add_argument('--platform',type=Path,default=ROOT/'docs/p1/continuation-platform.json')
    parser.add_argument('--wfp',type=Path,default=ROOT/'docs/p1/wfp-dynamic-probe.json')
    parser.add_argument('--output',type=Path,default=ROOT/'docs/p1/stage-exit.json')
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    report=build(args.data.resolve(),args.platform.resolve(),args.wfp.resolve())
    serialized=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if args.check:
        if args.output.read_text()!=serialized:raise SystemExit('阶段裁决与证据不一致')
    else:args.output.write_text(serialized)
    print(json.dumps({'status':report['status'],'dataExit':report['dataExit']['status'],
                      'blockingReasons':report['blockingReasons']}))


if __name__=='__main__':main()
