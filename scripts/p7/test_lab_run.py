"""编排器输入冻结、签名和恢复边界；不访问业务库或真实 PF。"""
import base64
import copy
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import struct
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

    def test_blocked_pf_mode_has_no_side_effects(self):
        """r4 E3 前置条件未解环时，正式入口必须在目录或服务创建前拒绝。"""
        from unittest.mock import patch
        output=self.root/'must-not-exist'
        with patch('sys.argv',['lab_run.py','--mode','pf','--directory',str(output)]), \
             patch.object(runner.j1_run,'Database',side_effect=AssertionError('unexpected database access')), \
             patch.object(runner.subprocess,'Popen',side_effect=AssertionError('unexpected process')):
            with self.assertRaisesRegex(ValueError,'LAB_PF_BLOCKED_BY_R4_E3_PRECONDITION'):runner.main()
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
