#!/usr/bin/env python3
"""复算动态会话非重启探针报告；拒绝缺项，保留早期失败，不扩大平台资格。"""
import argparse
import hashlib
import json
from pathlib import Path

from run_wfp_probe import evaluate
from summarize_wfp_reboot import build_reboot

ROOT = Path(__file__).resolve().parents[2]
CASES = {'ttl':'ttl-03','close-session':'close-01','kill':'kill-01','hang':'hang-01',
         'detector-exit':'detector-02','channel-loss':'channel-01'}


def read(p):
    return json.loads(p.read_text(encoding='utf-8-sig'))


def record(p):
    return {'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,
            'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}


def build(base):
    evidence = []; results = []
    for case, name in CASES.items():
        path = base/(name+'.json'); r = read(path); evidence.append(path)
        evaluation = evaluate(r)
        if evaluation != r['evaluation']:
            raise ValueError('CASE_EVALUATION_MISMATCH')
        revision = 'round2' if case in ('detector-exit','channel-loss') else 'round1'
        folder = base/'remote'/revision/name
        for artifact in ('owner.jsonl','watchdog.jsonl','ready.json','applied.json','final.json','command.json'):
            evidence.append(folder/artifact)
        final = read(folder/'final.json')
        if final != r['final'] or read(folder/'applied.json') != r['applied']:
            raise ValueError('REMOTE_EVIDENCE_MISMATCH')
        owner = [json.loads(x) for x in (folder/'owner.jsonl').read_text().splitlines()]
        events = [x['event'] for x in owner]
        if 'reconciled' not in events or 'lease_accepted' not in events or 'applied' not in events:
            raise ValueError('AUDIT_INCOMPLETE')
        if case == 'hang' and final['reason'] != 'heartbeat_timeout':
            raise ValueError('HANG_NOT_DETECTED')
        if case == 'kill' and final['reason'] != 'owner_forced_exit':
            raise ValueError('OWNER_NOT_TERMINATED')
        if case == 'detector-exit' and not r.get('detectorFault',{}).get('exited'):
            raise ValueError('DETECTOR_NOT_TERMINATED')
        if case == 'channel-loss' and not r.get('controlChannelTerminated'):
            raise ValueError('CHANNEL_NOT_TERMINATED')
        expired = [e for e in owner if e['event']=='removed_verified' and e['reason']=='ttl_expired']
        if case in ('ttl','detector-exit','channel-loss') and (len(expired)!=1 or not 0 <= expired[0]['delaySeconds'] <= 1):
            raise ValueError('MONOTONIC_EXPIRY_NOT_PROVEN')
        results.append({'case':case,'passed':evaluation['passed'],'failedChecks':evaluation['failedChecks'],
                        'sourceRevision':revision,
                        'connections':{p:{k:v['ok'] for k,v in r[p].items()} for p in ('before','during','after')},
                        'deniedThirdPort':not r['isolationDeniedPort']['ok'],
                        'managementAfter':r['managementAfter'],
                        'dynamicFilterCount':len(r['applied']['filterIds']),
                        'cleanupReason':final['reason'],'remainingFilters':len(final['inventory']['filters']),
                        'sublayerRemaining':final['inventory']['sublayerPresent'],
                        'externalVerificationMinusDeadlineSeconds':round(final['delaySeconds'],6),
                        'ownerDeletionMinusDeadlineSeconds':round(expired[0]['delaySeconds'],6) if expired else None})
    cleanup_path=base/'cleanup.json'; cleanup=read(cleanup_path);evidence.append(cleanup_path)
    official_path=base/'friday-official-check.json';official=read(official_path);evidence.append(official_path)
    evidence += [base/'isolation-before.json',base/'setup.json',base/'final-environment.json',base/'execution-hashes.json']
    source = [ROOT/'scripts/p1'/n for n in ('wfp_native.py','wfp_probe.py','run_wfp_probe.py','test_wfp_probe.py','summarize_wfp.py',
                                          'run_wfp_reboot.py','wfp_reboot_observer.py','summarize_wfp_reboot.py')]
    executed=read(base/'execution-hashes.json')
    for revision in ('round1','round2','round3','round4'):
        for name in ('wfp_native.py','wfp_probe.py'):
            path=base/'remote'/revision/name; evidence.append(path)
            if executed[revision][name] != record(path)['sha256']:
                raise ValueError('EXECUTED_SOURCE_SNAPSHOT_MISMATCH')
    for name in ('wfp_native.py','wfp_probe.py'):
        if executed['round4'][name] != record(ROOT/'scripts/p1'/name)['sha256']:
            raise ValueError('CURRENT_SOURCE_NOT_TESTED')
    reboot,reboot_evidence=build_reboot(base);evidence+=reboot_evidence
    evidence += [base/'remote/round3/stale-boot-01/owner.jsonl',base/'observer-diagnostic-result.json',
                 base/'automatic-observer-events.json',base/'post-reboot-traffic.json',
                 base/'reboot-task.xml',base/'reboot-isolation.json',base/'post-reboot-traffic-setup.json',
                 base/'remote/round3/revision2/wfp_probe.py',base/'remote/round3/wfp_reboot_observer.py']
    failures=[]
    for name, reason in (('ttl-01','SSH_STARTER_WAITED_FOR_CHILD_NO_BLOCK_INSTALLED'),
                        ('ttl-02','NONATOMIC_COMMAND_FILE_PERMISSION_RACE_NO_BLOCK_INSTALLED'),
                        ('detector-01','AUTHORIZATION_ENDS_BEFORE_REQUESTED_TTL_REJECTED')):
        path=base/(name+'.json');evidence.append(path)
        failures.append({'attempt':name,'passed':False,'cause':reason,'originalEvidence':record(path)})
    failures.append({'attempt':'stale-boot-01','passed':False,
                     'cause':'STALE_BOOT_REJECTED_FINAL_AUDIT_MISSING_PIPE_CLOSURE_GUARD_ADDED',
                     'fixedAndRetestedAs':'stale-boot-02',
                     'originalEvidence':record(base/'remote/round3/stale-boot-01/owner.jsonl')})
    clean=(cleanup['rules']==0 and cleanup['tasks']==0 and cleanup['probeProcesses']==0
           and cleanup['wfp']=={'sublayerPresent':False,'filters':[]})
    return {'version':'p1-wfp-dynamic-v1','evidenceDate':'2026-10-04',
            'status':('passed_bounded_probe' if reboot['strictRebootTtlPassed'] else 'passed_non_reboot_probe_reboot_deadline_unverified') if all(r['passed'] for r in results) and clean else 'failed',
            'scope':{'platform':'Windows','addressFamily':'ipv4','transport':'tcp','direction':'inbound',
                     'target':'one_authorized_peer_and_local_high_service_port','ttlSeconds':30,'expiryVerificationBudgetSeconds':1},
            'implementation':{'dynamicSession':True,'persistentBlockFilters':False,'bootTimeFilters':False,
                              'independentMonotonicRecovery':True,'independentWatchdog':True,
                              'startupReconciliationGate':True,'staleBootExecutorOrLateCommandRejected':True,
                              'networkIsolationIndependentOfDynamicSession':True},
            'cases':results,'retainedFailedAttempts':failures,
            'cleanup':cleanup,'environment':read(base/'final-environment.json'),
            'reboot':reboot,'strictRebootTtlPassed':reboot['strictRebootTtlPassed'],
            'rebootExecuted':reboot['rebootExecuted'],'macOS':'deferred_by_user',
            'macOSAutoSupported':False,'productionAutoSupported':False,
            'fridayOfficialChecksum':{'status':official.get('status'),'error':official.get('error'),
                                      'officialChecksumVerified':official['officialChecksumVerified'],
                                      'checksumSource':official['checksumSource']},
            'limits':['one actual reboot performed; shutdown deadline observation missing; automatic observer exited 1',
                      'six original cases retain their executed source hashes; later closed-pipe audit fix verified by Windows stale-boot retry and 14 unit tests',
                      'post-reboot manual observer success does not replace failed automatic startup observation',
                      'detector test uses a dedicated harmless stub; production detector is not integrated',
                      'control loss terminates a dedicated SSH channel; management recovery SSH remains available',
                      'local ACL bounded probe has no production command signatures or policy engine',
                      'clock rollback logic is implemented but changing the OS clock was not tested',
                      'P2 implementation, training, runtime rollout and release approval are outside this probe'],
            'provenance':{'code':[record(p) for p in source],'executedWindowsSourceSha256':executed,
                          'evidence':[record(p) for p in evidence],
                          'microsoftObjectLifetime':'https://learn.microsoft.com/en-us/windows/win32/fwp/object-management'}}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts',type=Path,default=ROOT/'artifacts/p1/wfp-20261004-01')
    p.add_argument('--output',type=Path,default=ROOT/'docs/p1/wfp-dynamic-probe.json')
    p.add_argument('--check',action='store_true');a=p.parse_args()
    report=build(a.artifacts.resolve());text=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if a.check:
        if a.output.read_text()!=text:raise SystemExit('动态探针报告与证据不一致')
    else:a.output.write_text(text)
    print(json.dumps({'status':report['status'],'cases':len(report['cases']),'strictRebootTtlPassed':report['strictRebootTtlPassed']}))


if __name__=='__main__':main()
