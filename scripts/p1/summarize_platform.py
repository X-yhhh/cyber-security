#!/usr/bin/env python3
"""从已归档 P1 证据生成去敏平台报告；不连接主机或修改防火墙。

实际删除事件用于计算清理时效，连接失败始终保留。此报告只判定有界探针，
不会将启动后最终清理冒充严格 TTL 或完整生产恢复器验收。
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from connection_probe import evaluate

ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def record(path):
    return {'path':path.relative_to(ROOT).as_posix(), 'bytes':path.stat().st_size,
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}


def delta(later, earlier):
    return round((dt.datetime.fromisoformat(later) - dt.datetime.fromisoformat(earlier)).total_seconds(), 6)


def event_values(event):
    return {x.attrib['Name']:x.text for x in ET.fromstring(event['xml']).iter()
            if x.tag.endswith('Data') and 'Name' in x.attrib}


def build(base):
    first = base/'windows/host-guard-p1-continuation-20261003'
    boot = base/'boot-evidence/boot-final'
    evidence = [base/'all-owned-final-events.json', boot/'after.json', boot/'before.json',
                boot/'firewall-events.json', boot/'final-cleanup.json', boot/'lease.json',
                boot/'restart-request.json', first/'preflight-after-npcap.json',
                first/'reboot-firewall-events.json', first/'reboot-verification.json',
                base/'capture-audit.json', base/'benign-http-capture-audit.json',
                base/'benign-http-task-v2.json', base/'http-evidence/http2/capture.jsonl',
                base/'execution-files.json', first/'round2/windows-rule-probe.ps1']
    all_events = read(base/'all-owned-final-events.json')
    removed = {}
    for event in all_events['events']:
        if event['id'] != 2052:
            continue
        values = event_values(event)
        if values.get('ErrorCode') == '0':
            removed[values['RuleName']] = event['utc']
    cases = []
    for name in ('ttl', 'process-exit', 'channel-loss', 'channel-loss-retry', 'post-reboot-ttl'):
        path = base/(name+'.json')
        evidence.append(path)
        data = read(path)
        deleted = removed.get(data['lease']['name'])
        cases.append({'case':name, 'connections':{p:data[p] for p in ('before','during','after')},
                      'evaluation':evaluate(data), 'leaseSeconds':30,
                      'deletedUtc':deleted,
                      'deletionMinusExpirySeconds':None if deleted is None else delta(deleted,data['lease']['expiresUtc']),
                      'remainingBlockRules':data['remainingBlockRules'],
                      'processModel':'dedicated_probe_powershell_not_production_detector' if name=='process-exit' else None,
                      'timeoutSeconds':3 if name in ('channel-loss-retry','post-reboot-ttl') else 1.5})
    before = read(boot/'before.json')
    after = read(boot/'after.json')
    cleanup = read(boot/'final-cleanup.json')
    lease = read(boot/'lease.json')
    reboot_deletes = []
    for event in read(boot/'firewall-events.json'):
        values = event_values(event)
        if event['id']==2052 and values.get('ErrorCode')=='0':
            reboot_deletes.append({'ruleRole':values['RuleName'].removeprefix(before['group']+'.'),
                'secondsAfterBoot':round(event['secondsAfterBoot'],6), 'deletedUtc':event['utc']})
    expected = {r['name'].removeprefix(before['group']+'.') for r in before['rules']}
    actual = {r['ruleRole'] for r in reboot_deletes}
    boot_cleaned = expected==actual and not after['remainingRules']
    block_delete = removed[lease['name']]
    preflight = read(first/'preflight-after-npcap.json')
    controlled = read(base/'benign-http-capture-audit.json')
    capture_logs = [json.loads(line) for line in (base/'http-evidence/http2/capture.jsonl').read_text().splitlines() if line.strip()]
    old = read(ROOT/'docs/p1/platform-capability-probe.json')
    source_paths = sorted((ROOT/'scripts/p1').glob('*.py')) + sorted((ROOT/'scripts/p1').glob('*.ps1'))
    source_paths += sorted((ROOT/'sensor/cmd/p1httpcanary').glob('*.go'))
    source_paths += sorted((ROOT/'sensor/cmd/p1canary').glob('*.go'))
    final_clean = all_events['ownedRules']==0 and all_events['ownedTasks']==0 and cleanup['ownedRules']==0 and cleanup['ownedTasks']==0
    return {
        'version':'p1-platform-continuation-v2', 'observedUtc':cleanup['observedUtc'],
        'status':'feasibility_demonstrated_with_limits' if boot_cleaned and final_clean else 'failed',
        'scope':{'platform':'Windows','addressFamily':'ipv4','transport':'tcp','direction':'inbound',
                 'action':'peer_and_local_service_block','productionAutoCapabilityGranted':False},
        'environment':{'os':preflight['os'], 'elevated':preflight['elevated'],
                       'windowsTrainingBranch':cleanup['branch'],'windowsTrainingHead':cleanup['head'],
                       'preexistingTrainingWorktreePreserved':cleanup['gitStatus']==[
                           '?? scripts/phase2_finish_cic2017.py','?? scripts/phase2_prepare_cic2017.py',
                           '?? src/cyber_training/phase2/','?? tests/test_phase2_baseline.py',
                           '?? tests/test_phase2_labels.py','?? tests/test_phase2_review.py',
                           '?? tests/test_phase2_split.py','?? tests/test_phase2_transfer.py']},
        'startup':{'canary':preflight['canary'], 'historical4551Reproduced':False,
                   'historical4551Cause':'unknown','smartAppControlFinal':cleanup['sac'],
                   'securityPolicyWeakened':False},
        'capture':{'npcapVersion':'1.89','library':'libpcap 1.10.7, 64-bit time_t',
                   'installerSha256':'8aed85e900d783d1308506e919587d3e540451947af8a82f2d04f819e44305cc',
                   'installerAuthenticode':'Valid, Nmap Software LLC','adminOnly':True,
                   'liveDatalink':12,'tcpEcho':read(base/'capture-audit.json'),
                   'controlledHTTP':{k:v for k,v in controlled.items() if k!='flows'},
                   'nativeStatistics':capture_logs[-1],
                   'firstHttpAttemptStatsAccepted':False},
        'isolation':{'mechanism':'program-scoped egress block and inbound peer/port restrictions',
                     'managementExecutablesExcluded':True,
                     'deniedThirdPortProbe':'timed_out_with_live_listener_verified_during_trial',
                     'lateSavedListenerSnapshot':'taken_after_lifetime_expiry_not_independent_listener_proof'},
        'connectionCases':cases,
        'reboot':{'count':2,'firstRun':'rules_eventually_removed_but_about_593s_after_boot_failed_timeliness',
                  'repair':'separate expiry and startup tasks; signed native netsh; startup delay 15s',
                  'secondBootUtc':after['bootUtc'],'secondRuleDeletionEvents':reboot_deletes,
                  'secondBootCleanupVerified':boot_cleaned,
                  'blockDeletionMinusExpirySeconds':delta(block_delete,lease['expiresUtc']),
                  'strictTtlAcrossRebootPassed':False,'furtherRebootPlanned':False},
        'cleanup':{'ownedNamespaces':len(all_events['groups']),'ownedRulesRemaining':all_events['ownedRules'],
                   'ownedTasksRemaining':all_events['ownedTasks'],'testProcessesRemaining':len(cleanup['testProcesses']),
                   'services':cleanup['services'],'firewallProfiles':cleanup['profiles'],
                   'completeFirewallEqualityClaimed':False,
                   'nonOwnedRulesNote':'first reboot snapshots had 10 additions and 14 removals; not attributed to probe'},
        'macOS':old['macOS'],
        'limits':['P1 stand-in processes, not production detector/executor',
                  'one control echo timeout retained; later retry passed; root cause unproven',
                  '7 of 8 legitimate HTTP tasks passed; one concurrent timeout retained',
                  'no outbound/IPv6/platform-wide blocking qualification',
                  'startup cleanup succeeded but exceeded original expiry by about 19.7s',
                  'no clock rollback, signed-command or full recovery state-machine qualification'],
        'provenance':{'codeFiles':[record(p) for p in source_paths],
                      'executedWindowsFiles':read(base/'execution-files.json')['files'],
                      'initialRecoveryScript':record(first/'round2/windows-rule-probe.ps1'),
                      'contractBaseline':old['provenance']['contractsSha256'],
                      'policy':record(ROOT/'docs/p1/continuation-label-policy.md'),
                      'budget':record(ROOT/'docs/p1/continuation-budget.md'),
                      'evidence':[record(p) for p in evidence]}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts',type=Path,default=ROOT/'artifacts/p1/continuation-20261003')
    parser.add_argument('--output',type=Path,default=ROOT/'docs/p1/continuation-platform.json')
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    data=build(args.artifacts.resolve())
    text=json.dumps(data,ensure_ascii=False,indent=2)+'\n'
    if args.check:
        if args.output.read_text()!=text:
            raise SystemExit('平台报告与证据/代码不一致')
    else:
        args.output.write_text(text)
    print(json.dumps({'status':data['status'],'ownedRulesRemaining':data['cleanup']['ownedRulesRemaining'],
                      'rebootCleanupVerified':data['reboot']['secondBootCleanupVerified']}))


if __name__=='__main__':
    main()
