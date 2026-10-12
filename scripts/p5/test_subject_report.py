"""联合报告合成夹具：使用真实工具的输出结构，不产生正式报告。"""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from executor.common import Rejected, canonical
from scripts.p5 import subject_report as report

class SubjectReportTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.subject={k:'a'*64 for k in ('manifestSha256','policySha256','featureProfileSha256','extractorSha256','evaluationPlanSha256')}
        self.subject.update(contractVersion='host-guard/5.0.0-rc.3',protocolVersions={'observation':'host-guard/5.0.0-rc.2'},modelId='model',policyId='policy',capabilityIds=['a','b'],environment='lab')
        self.binding=dict(bundleId='00000000-0000-4000-8000-000000000001',subject=self.subject,subjectSha256=report.digest(self.subject))
        self.runtime=dict(subjectSha256=self.binding['subjectSha256'],bundleId=self.binding['bundleId'],policySha256=self.subject['policySha256'],capabilityIds=['a','b'],verifiedBeforeExecution=True)
        self.launches=[];self.summaries=[]
        for scope in ('peer_service','peer_inbound'):
            parent=self.root/scope;parent.mkdir()
            rows=[]
            for scenario in ('revoke','disconnect','receipt_loss'):
                directory=parent/('root-'+scenario);(directory/'evidence').mkdir(parents=True)
                self.dump(directory/'launch-record.json',dict(task='e3-executor',exitCode=0,scope=scope,scenario=scenario,rendezvous=str(parent/(scope+'-'+scenario)),commit='fixture',subjectBinding=self.binding))
                self.dump(directory/'evidence/result.json',dict(scope=scope,scenario=scenario,realPF=True,passed=True,runtimeSubjectBinding=self.runtime))
                self.launches.append(directory);rows.append(dict(scope=scope,scenario=scenario,passed=True))
            summary=parent/'summary.json';self.dump(summary,dict(realPF=True,scenarios=rows,sourceSha256={'executor/engine.py':'b'*64},subjectBinding=self.binding));self.summaries.append(summary)
        self.key=Ed25519PrivateKey.generate();self.keypath=self.root/'key.der'
        self.keypath.write_bytes(self.key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));self.keypath.chmod(0o600)
        self.trust={'fixture':base64.b64encode(self.key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode()}

    def tearDown(self):self.temp.cleanup()
    def dump(self,path,value):path.write_bytes(canonical(value))
    def collect(self,summaries=None,launches=None,kind='platform'):
        return report.collect(self.summaries if summaries is None else summaries,self.launches if launches is None else launches,kind,self.binding)
    def payload(self):return report.build('platform',self.subject,self.collect())

    def test_jcs_subject_sign_verify(self):
        p=self.payload();e=report.sign(p,self.keypath,'fixture')
        self.assertTrue(report.verify(e,self.trust,p)['signatureVerified'])
        self.assertEqual(p['subjectSha256'],report.digest(self.subject))
        changed=copy.deepcopy(self.subject);changed['policySha256']='c'*64
        with self.assertRaisesRegex(Rejected,'REPORT_SUBJECT_MISMATCH'):
            report.build('platform',changed,self.collect())

    def test_hash_only_or_wrong_claim_is_rejected(self):
        for value in ({'subjectSha256':'a'*64},{'subject':self.subject,'subjectSha256':'b'*64}):
            with self.assertRaises(Rejected):report.subject_hash(value)

    def test_missing_root_synthetic_nonzero_and_other_run(self):
        with self.assertRaises(Rejected):self.collect(launches=[])
        path=self.launches[0]/'launch-record.json';original=report.load(path)
        for change in ({'exitCode':1},{'exitCode':None},{'task':'unrelated'},{'rendezvous':str(self.root/'elsewhere'/'round')}):
            self.dump(path,dict(original,**change))
            with self.assertRaises(Rejected):self.collect()
        self.dump(path,original)
        p=self.summaries[0];value=report.load(p);value['realPF']=False;self.dump(p,value)
        with self.assertRaisesRegex(Rejected,'REPORT_EVIDENCE_NOT_REAL'):self.collect()

    def test_partial_scope_is_rejected(self):
        with self.assertRaisesRegex(Rejected,'REPORT_E3_INCOMPLETE'):self.collect(summaries=self.summaries[:1])

    def test_canary_requires_real_root_results_and_cleanup(self):
        d=self.root/'canary';(d/'evidence/ttl').mkdir(parents=True)
        self.dump(d/'launch-record.json',dict(task='e1e2-lab',exitCode=0,commit='fixture',subjectBinding=self.binding))
        self.dump(d/'evidence/summary.json',dict(passed=True,cleanup={'empty':True},unknownRule={'passed':True},scenarios=[{'scenario':'ttl'}],subjectBinding=self.binding))
        r=dict(kind='pf_engine_canary',realPF=True,passed=True,fixtureResolver=False,cleanupVerified=True,executorSha256='a'*64,runtimeSubjectBinding=self.runtime)
        self.dump(d/'evidence/ttl/result.json',r)
        self.assertEqual(self.collect([],[d],'canary')['executorSha256'],'a'*64)
        r['cleanupVerified']=False;self.dump(d/'evidence/ttl/result.json',r)
        with self.assertRaises(Rejected):self.collect([],[d],'canary')

    def test_old_or_unrelated_runtime_cannot_be_attached_to_subject(self):
        path=self.launches[0]/'evidence/result.json';row=report.load(path)
        for binding in (None,dict(self.runtime,policySha256='f'*64),dict(self.runtime,capabilityIds=['elsewhere'])):
            self.dump(path,dict(row,runtimeSubjectBinding=binding or {}))
            with self.assertRaisesRegex(Rejected,'REPORT_RUNTIME_SUBJECT_MISMATCH'):self.collect()

    def test_cli_generate_sign_verify(self):
        subject=self.root/'subject.json';self.dump(subject,self.binding)
        trust=self.root/'trust.json';self.dump(trust,self.trust)
        raw=self.root/'raw.json';signed=self.root/'signed.json'
        common=['--kind','platform','--subject',str(subject)]
        for p in self.summaries:common+=['--e3-summary',str(p)]
        for p in self.launches:common+=['--root-launch',str(p)]
        base=[sys.executable,'-B',str(report.ROOT/'scripts/p5/subject_report.py')]
        for args in (['generate',*common,'--output',str(raw)],['sign','--input',str(raw),'--output',str(signed),'--private-key',str(self.keypath),'--runner-identity','fixture'],['verify',*common,'--input',str(signed),'--trust',str(trust)]):
            result=subprocess.run(base+args,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
