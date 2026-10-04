#!/usr/bin/env python3
"""从实跑证据重建去敏 P2 出口；软件验证与后续模型/平台资格分别报告。"""
import argparse
import collections
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def build(run):
    read=lambda name:json.loads((run/name).read_text())
    whole=read('wednesday-final-extraction.json');controlled=read('controlled-final-extraction.json')
    partitions=read('partition-manifest.json');windows=read('windows-verification.json');schema=read('schema-validation.json')
    tests=collections.Counter();skips=[]
    for line in (run/'go-tests-final.jsonl').open():
        row=json.loads(line)
        if row.get('Test') and row['Action'] in ('pass','fail','skip'):tests[row['Action']]+=1
        if row['Action']=='fail':raise ValueError('Go test failure')
        if row.get('Test') and row['Action']=='skip':skips.append(row['Test'])
    golden=[json.loads(s) for s in (ROOT/'sensor/testdata/hostguard-v5/observations.jsonl').open()]
    joins=collections.Counter();onsets=0
    for line in (run/'wednesday-joins.jsonl').open():
        row=json.loads(line);joins[row['join']]+=1;onsets+=row['onsetStructuralChecksPassed']
    checks=dict(goTests=tests['pass']>0 and tests['fail']==0,
                race='ok ' in (run/'go-race-final.log').read_text(),
                vet=(run/'go-vet-final.log').read_text()=='',
                schema=schema['status']=='passed',
                javaReference='status=passed' in (run/'java-reference.log').read_text(),
                windowsActualExecution=windows['status']=='passed' and windows['extractorExecuted'] and windows['goldenExecuted'],
                crossPlatformByteParity=windows['observationSha256']==controlled['observationsSha256'],
                fullPilotJoin=joins['matched']==180765 and sum(joins.values())==180765,
                partitionIntegrity=partitions['parentAndActivityDisjoint'] and partitions['enginesReset'] and partitions['partitionIsolationSeconds']>=150,
                developmentPositiveNegativeAvailable=partitions['developmentPositiveAndNegativeReady'],
                windowsDeliveryHashVerified=read('windows-delivery-verification.json')['status']=='passed')
    result=dict(version='p2-stage-exit-v1',phase='P2',evidenceDate='2026-10-04',status='passed' if all(checks.values()) else 'blocked',
                scope='causal extractor and frozen research contract; no model/policy/platform release qualification',
                contractVersion=whole['version'],checks=checks,
                fullPilot=dict(frames=whole['stats']['frames'],observations=whole['stats']['observations'],tcpLabels=sum(joins.values()),joins=dict(joins),structuralOnsetCandidates=onsets),
                controlledBenign=dict(frames=controlled['stats']['frames'],observations=controlled['stats']['observations'],distribution=controlled['distribution'],observationSha256=controlled['observationsSha256']),
                validation=dict(goTests=dict(tests),skippedTests=skips,goldenScenarios=len({v['scenario'] for v in golden}),goldenObservations=len(golden),
                                schema=schema,java=(run/'java-reference.log').read_text().strip(),windows=windows),
                development=dict(profile='flow-final-v1',scope=partitions['candidateScope'],retainedSnapshots=partitions['retainedSnapshots'],
                                 retainedParents=partitions['retainedParents'],prefixDevelopmentReady=False,adequateForModelSelection=False),
                retainedLimits=[
                    'same-service benign support is only train 1 / validation 4 snapshots; other services do not count',
                    '475 structural onset candidates are not approved prefix supervision',
                    'one positive validation activity does not provide independent calibration groups',
                    'final_test remains unallocated and unread; independent final acceptance unavailable',
                    'PCAP/live parity uses deterministic input fixtures; no new physical live-capture qualification',
                    'P1 Windows strict reboot TTL remains unverified and Mac action tests remain deferred',
                    'target IPC is an ephemeral prototype without firewall execution or persistent recovery'],
                initialFailures=[
                    'same boot was initially reused for partition resets; integrity check rejected overlap; separate boot configurations fixed it',
                    'RAW IP controlled capture was initially rejected; explicit Ethernet/RAW adapter added and parity tested',
                    'first Windows test launcher was rejected by App Control 4551; later normal verification succeeded; no system policy changed and cause remains unknown',
                    'ARM fused multiply-add caused last-bit standard-deviation differences; explicit float64 rounding fixed exact JSON parity'],
                trainingExecuted=False,databaseMigrated=False,activeRuntimeChanged=False,firewallModified=False,gitCommitted=False,gitPushed=False,
                evidenceHashes={name:sha(run/name) for name in ['wednesday-final-extraction.json','controlled-final-extraction.json','partition-manifest.json','windows-verification.json','windows-delivery-verification.json','schema-validation.json','go-tests-final.jsonl','go-race-final.log','go-vet-final.log','java-reference.log']},
                freezeManifestSha256=sha(ROOT/'docs/p2/freeze-manifest.json'))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--check',action='store_true');a=p.parse_args()
    result=build(a.run);text=json.dumps(result,ensure_ascii=False,indent=2)+'\n';out=ROOT/'docs/p2/stage-exit.json'
    if a.check:
        if out.read_text()!=text:raise SystemExit('P2 report does not match evidence')
    else:
        with out.open('x') as f:f.write(text)
    print(json.dumps(dict(phase='P2',status=result['status'],checks=result['checks'])))

if __name__=='__main__':main()
