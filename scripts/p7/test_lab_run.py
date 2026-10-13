"""编排器输入冻结、签名和恢复边界；不访问业务库或真实 PF。"""
import base64
import copy
import json
import io
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import struct
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.p7 import lab_run as runner


class LabRunTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        (self.root/'a.pcap').write_bytes(b'fixture-a');(self.root/'b.pcap').write_bytes(b'fixture-b')
        self.source=dict(schema='g3-scenario/1',plannedM2=['brute_force'],segments=[dict(segmentId='a',family='brute_force',
             pcapRef='a.pcap',pcapSha256=runner.sha(self.root/'a.pcap'),captureStartUs=1000000,scoringFirstUs=31000000,scoringLastUs=60000000),
             dict(segmentId='b',family='normal',pcapRef='b.pcap',pcapSha256=runner.sha(self.root/'b.pcap'),captureStartUs=86401000000,
             scoringFirstUs=86431000000,scoringLastUs=86460000000)])
    def tearDown(self):self.temp.cleanup()
    def test_frozen_pcaps_are_verified_without_rewriting(self):
        rows=runner.freeze_scenarios(self.source,self.root)
        self.assertEqual([r['trialAutoEligible'] for r in rows],[True,False])
        (self.root/'a.pcap').write_bytes(b'tamper')
        with self.assertRaisesRegex(ValueError,'LAB_PCAP_MISMATCH'):runner.freeze_scenarios(self.source,self.root)
    def test_rejects_duplicate_or_escaping_input(self):
        source=copy.deepcopy(self.source);source['segments'].append(source['segments'][0])
        with self.assertRaisesRegex(ValueError,'LAB_SCENARIO_DUPLICATE'):runner.freeze_scenarios(source,self.root)
        source=copy.deepcopy(self.source);source['segments'][0]['pcapRef']='../outside.pcap'
        with self.assertRaisesRegex(ValueError,'LAB_PCAP_MISMATCH'):runner.freeze_scenarios(source,self.root)
    def test_scenario_clocks_preserve_warmup_and_intervals(self):
        rows=runner.freeze_scenarios(self.source,self.root);start=datetime(2030,1,1,tzinfo=timezone.utc)
        plan=runner.clock_plan(rows,start)
        self.assertEqual(set(plan['scenarioOffsets']),{'a','b'})
        self.assertEqual(abs(plan['scenarioOffsets']['a']-plan['scenarioOffsets']['b']),86400000000)
        for row in rows:
            delta=timedelta(microseconds=plan['scenarioOffsets'][row['scenarioId']])
            self.assertEqual(runner.lab_report.timestamp(row['sourceStart'])+delta,start)
            self.assertEqual(runner.lab_report.timestamp(row['captureStart'])+delta,start-timedelta(seconds=30))
    def test_staggered_g3_clocks_preserve_each_frozen_interval(self):
        source=datetime(2017,7,3,tzinfo=timezone.utc)
        rows=[]
        for family,count,length in [('port_scan',3,2),('brute_force',3,90),('dos_slow',3,95),('dos_flood',3,35),('normal',6,510)]:
            for index in range(count):
                rows.append(dict(scenarioId=f'{family}-{index+1}',family=family,
                                 captureStart=runner.lab_report.iso(source-timedelta(seconds=30)),
                                 sourceStart=runner.lab_report.iso(source),
                                 sourceEnd=runner.lab_report.iso(source+timedelta(seconds=length))))
        start=datetime(2030,1,1,tzinfo=timezone.utc)
        plan=runner.clock_plan(rows,start,staggered=True)
        expected={'port_scan':[0,20,40],'brute_force':[120,140,160],
                  'dos_slow':[300,320,340],'dos_flood':[480,500,520],
                  'normal':[0,60,120,180,240,300]}
        for row in rows:
            family,index=row['scenarioId'].rsplit('-',1)
            shift=timedelta(microseconds=plan['scenarioOffsets'][row['scenarioId']])
            actual=runner.lab_report.timestamp(row['sourceStart'])+shift
            self.assertEqual(actual,start+timedelta(seconds=expected[family][int(index)-1]))
            self.assertEqual(runner.lab_report.timestamp(row['captureStart'])+shift,actual-timedelta(seconds=30))
            self.assertEqual((runner.lab_report.timestamp(row['sourceEnd'])+shift-actual).total_seconds(),
                             (runner.lab_report.timestamp(row['sourceEnd'])-runner.lab_report.timestamp(row['sourceStart'])).total_seconds())
    def test_signature_covers_immutable_input(self):
        value=dict(sessionId='fixture',time={'scenarioOffsets':{'a':123}});key=Ed25519PrivateKey.generate()
        obj=runner.Runner(SimpleNamespace(directory=self.root/'run',artifacts=self.root,mode='dry-run',scenario=self.root/'a.pcap'))
        obj.artifact_dir=self.root;obj.key=key;obj.runner_name='fixture'
        ref=obj.signed('session',value);envelope=runner.load(self.root/'session.json')
        signature=envelope['signature'];raw=base64.urlsafe_b64decode(signature+'='*(-len(signature)%4))
        key.public_key().verify(raw,runner.canonical(value))
        self.assertEqual(ref['sha256'],runner.sha(self.root/'session.json'))
        value['time']['scenarioOffsets']['a']=124
        with self.assertRaises(Exception):key.public_key().verify(raw,runner.canonical(value))
    def test_resume_requires_complete_capture_and_unchanged_files(self):
        path=self.root/'a.pcap';state=dict(schema='guard-lab-run/1',scenarioSha256='s',captureComplete=True,
                                        frozenFiles={str(path):runner.sha(path)},sessionId='frozen')
        self.assertEqual(runner.check_resume(state,self.root,'s')['sessionId'],'frozen')
        with self.assertRaisesRegex(ValueError,'CONTINUITY_LOST'):runner.check_resume(dict(state,captureComplete=False),self.root,'s')
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'FILE_MISMATCH'):runner.check_resume(state,self.root,'s')

    def formal_db(self, evidence='real_pf', active=True, subject_sha=runner.R4_SUBJECT_SHA256):
        bundle_id='c313b44e-e835-441a-9e50-ada7e92fdf0a'
        refs=[{'evaluationId':str(__import__('uuid').uuid4()),'reportSha256':str(i)*64}
              for i in (1,2,3)]
        sealed={'subjectSha256':subject_sha,'reports':refs}
        snapshot={'guard_release_bundle':{'rows':1,'sha256':'a'*64}}
        context=dict(cloneSchema='cyber_guard_fixture_1',bootstrapReports=[
            {'sha256':'a'*64,'keyId':'e3-bootstrap-test'},
            {'sha256':'b'*64,'keyId':'e3-bootstrap-test'}],
            businessBefore=snapshot,businessAfter=snapshot,
            sourceBundle={'bundleId':bundle_id,'subjectSha256':subject_sha},
            cloneBundle={'bundleId':bundle_id,'subjectSha256':subject_sha},subjectMatchesSource=True)
        bundle=dict(status='active' if active else 'candidate',environment='lab',subjectSha256=subject_sha,
                    approvedBy=12,sealedSha256=runner.digest(sealed),sealed=sealed)
        reports={ref['evaluationId']:dict(kind=kind,status='passed',reportSha256=ref['reportSha256'],
                 payload=dict(runKind=kind,reportVersion='host-guard-subject-report/1.0',passed=True,
                              evidenceKind=evidence,subjectSha256=subject_sha,executionContext=context))
                 for ref,kind in zip(refs,('final','platform','canary'))}
        class Db:
            def query(self, sql, schema):
                assert schema=='cyber_security'
                if 'FROM guard_release_bundle' in sql and 'FROM guard_evaluation_run' not in sql:
                    return json.dumps(bundle).encode()+b'\n'
                for key,value in reports.items():
                    if "public_id='"+key+"'" in sql:return json.dumps(value).encode()+b'\n'
                return b''
        return Db(),bundle_id,bundle,reports

    def test_pf_preflight_binds_explicit_subject_and_preserves_r4_default(self):
        expected='a'*64
        db,bundle_id,_,_=self.formal_db(subject_sha=expected)
        self.assertEqual(runner.formal_r4_preflight(db,bundle_id,expected)['subjectSha256'],expected)
        with self.assertRaisesRegex(ValueError,'LAB_PF_R4_NOT_ACTIVE'):
            runner.formal_r4_preflight(db,bundle_id)
        with self.assertRaisesRegex(ValueError,'LAB_PF_R4_NOT_ACTIVE'):
            runner.formal_r4_preflight(db,bundle_id,'b'*64)

    def test_subject_cli_parsing_and_forwarding(self):
        for expected in (runner.R4_SUBJECT_SHA256,'a'*64):
            argv=['lab_run.py','--directory',str(self.root/'run')]
            if expected!=runner.R4_SUBJECT_SHA256:argv+=['--subject-sha256',expected]
            with patch('sys.argv',argv),patch.object(runner,'Runner',return_value=Mock()) as constructor:
                runner.main()
            self.assertEqual(constructor.call_args.args[0].subject_sha256,expected)
        for value in ('short','A'*64,'g'*64):
            with patch('sys.argv',['lab_run.py','--directory',str(self.root/'run'),'--subject-sha256',value]), \
                 patch('sys.stderr',new=io.StringIO()),patch.object(runner,'Runner') as constructor:
                with self.assertRaises(SystemExit):runner.main()
                constructor.assert_not_called()

    def test_pf_preflight_accepts_only_active_r4_with_formal_sealed_reports(self):
        db,bundle_id,bundle,reports=self.formal_db()
        self.assertEqual(runner.formal_r4_preflight(db,bundle_id)['formalKinds'],['canary','platform'])
        bundle['status']='approved'
        with self.assertRaisesRegex(ValueError,'LAB_PF_R4_NOT_ACTIVE'):runner.formal_r4_preflight(db,bundle_id)
        bundle['status']='active';bundle['sealedSha256']='0'*64
        with self.assertRaisesRegex(ValueError,'LAB_PF_R4_NOT_ACTIVE'):runner.formal_r4_preflight(db,bundle_id)
        bundle['sealedSha256']=runner.digest(bundle['sealed'])
        platform=next(row for row in reports.values() if row['kind']=='platform')
        platform['payload']['evidenceKind']='synthetic'
        with self.assertRaisesRegex(ValueError,'LAB_PF_R4_NOT_ACTIVE'):runner.formal_r4_preflight(db,bundle_id)
        platform['payload']['evidenceKind']='real_pf'
        platform['payload']['executionContext']['businessAfter']={}
        with self.assertRaisesRegex(ValueError,'LAB_PF_R4_NOT_ACTIVE'):runner.formal_r4_preflight(db,bundle_id)

    def test_blocked_pf_mode_has_no_side_effects(self):
        """业务库 r4 未正式激活时，在目录或服务创建前拒绝。"""
        from unittest.mock import patch
        output=self.root/'must-not-exist'
        with patch('sys.argv',['lab_run.py','--mode','pf','--directory',str(output)]), \
             patch.object(runner.j1_run,'Database',side_effect=AssertionError('unexpected database access')), \
             patch.object(runner.subprocess,'Popen',side_effect=AssertionError('unexpected process')):
            with self.assertRaisesRegex(ValueError,'LAB_PF_R4_NOT_ACTIVE'):runner.main()
        db,bundle_id,_,_=self.formal_db(active=False)
        with patch('sys.argv',['lab_run.py','--mode','pf','--directory',str(output),
                               '--r4-bundle-id',bundle_id,'--authorization-reference','A6-test']), \
             patch.object(runner.j1_run,'Database',return_value=db), \
             patch.object(runner.subprocess,'Popen',side_effect=AssertionError('unexpected process')):
            with self.assertRaisesRegex(ValueError,'LAB_PF_R4_NOT_ACTIVE'):runner.main()
        self.assertFalse(output.exists())

    def test_substitute_cleanup_requires_original_successful_terminal_record(self):
        """捕获后的报告收尾不能忽略执行器失败，也不能只凭一条空规则快照放行。"""
        from unittest.mock import Mock
        obj=runner.Runner(SimpleNamespace(directory=self.root,artifacts=self.root,mode='rehearse',scenario=self.root/'a.pcap'))
        obj.substitute=Mock();obj.substitute.poll.return_value=None;obj.substitute.returncode=0
        path=self.root/'substitute.jsonl'
        def records(rows):path.write_text(''.join(__import__('json').dumps(r)+'\n' for r in rows))
        empty=dict(kind='observation',installedRules=[],commandIds=[])
        stopped=dict(kind='stopped',installedRules=[])
        records([empty,stopped]);obj.stop_substitute()
        obj.substitute.terminate.assert_called_once()
        obj.substitute.wait.assert_called_once_with(timeout=10)
        for rows in ([empty],[empty,dict(kind='failure',code='CONTROL_PLANE_UNAVAILABLE'),stopped],
                     [empty,dict(stopped,installedRules=['unremoved'])]):
            records(rows)
            with self.assertRaisesRegex(ValueError,'LAB_SUBSTITUTE_CLEANUP_UNVERIFIED'):obj.verify_substitute_cleanup()

    def test_mapping_includes_unscored_warmup_peers(self):
        """评分连接清单不能裁掉预热包；正常段保留该对端，攻击段拒绝额外来源。"""
        import ipaddress
        def packet(peer, seconds):
            ethernet=b'\x00'*12+b'\x08\x00'
            ipv4=struct.pack('!BBHHHBBH4s4s',69,0,40,0,0,64,6,0,
                             ipaddress.ip_address(peer).packed,ipaddress.ip_address('192.0.2.10').packed)
            tcp=struct.pack('!HHIIBBHHH',50000,443,0,0,80,2,65535,0,0)
            data=ethernet+ipv4+tcp
            return struct.pack('<IIII',seconds,0,len(data),len(data))+data
        data=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
        data+=packet('192.0.2.21',1)+packet('192.0.2.20',31)+packet('192.0.2.22',61)
        path=self.root/'warmup.pcap';path.write_bytes(data)
        row=dict(family='normal',pcapRef=path.name,pcapSha256=runner.sha(path),
                 captureStart=runner.at(1_000_000),sourceStart=runner.at(31_000_000),sourceEnd=runner.at(60_000_000))
        selection=dict(host='192.0.2.10',peer='192.0.2.20')
        mapping=runner.original_mapping(row,selection,self.root)
        self.assertEqual(mapping['peers'],['192.0.2.20','192.0.2.21'])
        self.assertEqual(mapping['ports'],[443])
        with self.assertRaisesRegex(ValueError,'LAB_ORIGINAL_MAPPING_MISMATCH'):
            runner.original_mapping(dict(row,family='brute_force'),selection,self.root)
        with self.assertRaisesRegex(ValueError,'LAB_PCAP_MISMATCH'):
            runner.original_mapping(dict(row,pcapSha256='0'*64),selection,self.root)

    def test_dry_run_uses_only_substitutes_and_verifies_report(self):
        from unittest.mock import patch
        source=self.root/'scenario.json';source.write_text(__import__('json').dumps(self.source))
        obj=runner.Runner(SimpleNamespace(directory=self.root/'run',artifacts=self.root,mode='dry-run',scenario=source))
        with patch.object(runner.j1_run,'Database',side_effect=AssertionError('dry run must not access MySQL')):
            obj.run()
        self.assertTrue(runner.load(obj.work/'verification.json')['signatureVerified'])
        state=runner.load(obj.work/'state.json');self.assertTrue(state['dryRunComplete'])
        self.assertFalse(state['captureComplete']);self.assertFalse(state['reportImported'])
        self.assertEqual(runner.load(obj.work/'report.json')['status'],'unverified')
        trace=runner.load(obj.work/'dry-run-trace.json')
        self.assertEqual(sum(s.startswith('scenario.completed:') for s in trace['steps']),2)
        self.assertEqual(trace['rulesAfter'],[])


if __name__=='__main__':unittest.main()
