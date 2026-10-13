"""正式编排与克隆门禁预演的边界；替换数据库、服务和进程，不执行 PF。"""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.p7 import lab_formal as formal


class LabFormalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.artifacts = self.root / 'artifacts'
        self.artifacts.mkdir()
        self.official = self.root / 'official-trust.json'
        self.trust = self.root / 'clone-trust.json'
        self.official.write_text('{}')
        self.trust.write_text('{}')
        self.addCleanup(patch.stopall)
        patch.object(formal, 'OFFICIAL_TRUST', self.official).start()
        (self.artifacts / 'fixture.pcap').write_bytes(b'not a real capture')
        self.source = dict(schema='g3-scenario/1', plannedM2=['brute_force'], bindings={'modelSha256': 'm' * 64},
                           segments=[dict(segmentId='brute_force-1', family='brute_force', pcapRef='fixture.pcap',
                                          pcapSha256=formal.sha(self.artifacts / 'fixture.pcap'), captureStartUs=1_000_000,
                                          scoringFirstUs=31_000_000, scoringLastUs=60_000_000)])
        self.scenario = self.root / 'scenario.json'
        self.scenario.write_text(json.dumps(self.source))
        self.selection = self.root / 'selection.json'
        self.selection.write_text(json.dumps([{'segmentId': 'brute_force-1'}]))
        self.jar = self.root / 'backend.jar'
        self.jar.write_bytes(b'fixture jar')

    def argv(self):
        return ['--target', 'clone', '--admission-probe', '--directory', str(self.root / 'run'),
                '--artifacts', str(self.artifacts), '--scenario', str(self.scenario),
                '--selection', str(self.selection), '--backend-jar', str(self.jar), '--report-trust', str(self.trust)]

    def arguments(self, **changes):
        args = formal.parse_args(self.argv())
        for name, value in changes.items():
            setattr(args, name, value)
        return args

    def runner(self, **changes):
        with patch.object(formal, 'Rabbit') as rabbit:
            rabbit.return_value.name = 'fixture-vhost'
            return formal.Formal(self.arguments(**changes))

    def proof_fixture(self, runner):
        runner.subject_sha = 'a' * 64
        runner.plan_sha = 'b' * 64
        runner.versions = {'health': 'host-guard-capture-health/1.1.0'}
        return dict(keyId='fixture-runner', payload=dict(runKind='platform', passed=True, evidenceKind='real_pf',
                    subjectSha256=runner.subject_sha, evaluationPlanSha256=runner.plan_sha, protocolVersions=runner.versions))

    def test_cli_defaults_and_explicit_r5_bindings(self):
        args = formal.parse_args(self.argv())
        self.assertEqual(args.subject_sha256, formal.lab_run.R4_SUBJECT_SHA256)
        self.assertEqual(args.bundle_id, formal.R4_BUNDLE)
        self.assertIsNone(args.final_ref)
        args = formal.parse_args(self.argv() + ['--subject-sha256', 'a' * 64, '--bundle-id', formal.uid(),
                    '--final-ref', 'r5/final.json', '--platform-ref', 'r5/platform.json', '--import-plan', 'r5/plan.json'])
        self.assertEqual(args.subject_sha256, 'a' * 64)
        self.assertEqual(args.final_ref, 'r5/final.json')
        self.assertEqual(args.platform_ref, 'r5/platform.json')
        self.assertEqual(args.import_plan, Path('r5/plan.json'))
        for value in ('short', 'A' * 64, 'g' * 64):
            with self.subTest(value=value), patch('sys.stderr', new=io.StringIO()), patch.object(formal, 'Formal') as constructor:
                with self.assertRaises(SystemExit):
                    formal.parse_args(self.argv() + ['--subject-sha256', value])
                constructor.assert_not_called()

    def test_invalid_arguments_rejected_before_constructor_effects(self):
        cases = [({'target': 'business'}, 'LAB_PROBE_CLONE_ONLY'),
                 ({'probe_seconds': 0}, 'LAB_PROBE_DURATION_INVALID'),
                 ({'gate_rehearsal': True, 'admission_probe': False}, 'LAB_GATE_CLONE_PROBE_ONLY'),
                 ({'gate_rehearsal': True}, 'LAB_GATE_SOURCE_INVALID'),
                 ({'source_schema': 'cyber_guard_test'}, 'LAB_FORMAL_SOURCE_MUST_BE_BUSINESS'),
                 ({'admission_probe': False}, 'LAB_ROOT_ARGUMENTS_REQUIRED'),
                 ({'subject_sha256': 'a' * 64}, 'LAB_FINAL_REF_REQUIRED'),
                 ({'bundle_id': 'bad'}, 'LAB_BUNDLE_ID_INVALID')]
        for changes, code in cases:
            with self.subTest(code=code), patch.object(formal, 'Rabbit') as rabbit, patch.object(formal, 'keychain') as secret:
                with self.assertRaisesRegex(ValueError, code):
                    formal.Formal(self.arguments(**changes))
                rabbit.assert_not_called()
                secret.assert_not_called()
                self.assertFalse((self.root / 'run').exists())

    def test_gate_trust_rejects_official_symlink_and_hard_link(self):
        symbolic = self.root / 'symbolic.json'
        symbolic.symlink_to(self.official)
        hard = self.root / 'hard.json'
        os.link(self.official, hard)
        changes = dict(gate_rehearsal=True, source_schema='cyber_guard_gate_test')
        for trust in (self.official, symbolic, hard, self.root / 'missing.json'):
            with self.subTest(trust=trust), patch.object(formal, 'Rabbit') as rabbit:
                with self.assertRaisesRegex(ValueError, 'LAB_GATE_CLONE_TRUST_REQUIRED'):
                    formal.Formal(self.arguments(**changes, report_trust=trust))
                rabbit.assert_not_called()
        obj = self.runner(**changes)
        self.assertNotEqual(obj.schema, formal.BUSINESS)
        self.assertTrue(obj.schema.startswith('cyber_guard_g3pf_'))

    def test_proof_binds_kind_subject_version_plan_and_original_bytes(self):
        obj = self.runner()
        envelope = self.proof_fixture(obj)
        path = self.artifacts / 'platform.json'
        path.write_text(json.dumps(envelope))
        original = path.read_bytes()
        ref, payload = obj.read_proof(path.name, 'platform')
        self.assertEqual(ref['sha256'], formal.sha(path))
        self.assertEqual(payload, envelope['payload'])
        self.assertEqual(path.read_bytes(), original)
        for field, value in [('runKind', 'final'), ('passed', False), ('subjectSha256', 'c' * 64),
                             ('evaluationPlanSha256', 'c' * 64), ('protocolVersions', {'health': 'old'})]:
            changed = copy.deepcopy(envelope)
            changed['payload'][field] = value
            path.write_text(json.dumps(changed))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'LAB_P5_PROOF_INVALID'):
                obj.read_proof(path.name, 'platform')
        for ref in (str(path), '../official-trust.json'):
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, 'LAB_P5_PROOF_INVALID'):
                obj.read_proof(ref, 'platform')

    def test_formal_proof_rejects_bootstrap_and_synthetic(self):
        obj = self.runner()
        envelope = self.proof_fixture(obj)
        path = self.artifacts / 'proof.json'
        for kind in ('platform', 'final'):
            envelope['payload']['runKind'] = kind
            for evidence in ('bootstrap', 'synthetic'):
                envelope['payload']['evidenceKind'] = evidence
                path.write_text(json.dumps(envelope))
                with self.subTest(kind=kind, evidence=evidence), self.assertRaisesRegex(ValueError, 'LAB_P[56]_PROOF_INVALID'):
                    obj.read_proof(path.name, kind)
                obj.args.gate_rehearsal = True
                self.assertEqual(obj.read_proof(path.name, kind)[1]['evidenceKind'], evidence)
                obj.args.gate_rehearsal = False

    def test_prepare_bundle_rejects_import_plan_drift_before_using_reports(self):
        policy = {'evaluationPlanSha256': 'b' * 64}
        versions = {'health': 'host-guard-capture-health/1.1.0'}
        subject = dict(protocolVersions=versions, policySha256=formal.digest(policy),
                       extractorSha256='c' * 64, evaluationPlanSha256='b' * 64)
        subject_sha = formal.digest(subject)
        obj = self.runner(subject_sha256=subject_sha, final_ref='final.json', platform_ref='platform.json')
        obj.source = self.source
        obj.op, obj.db = Mock(), Mock()
        obj.op.v2.return_value = dict(status='approved', subjectSha256=subject_sha, environment='lab', revision=1)
        obj.db.query.return_value = json.dumps(subject).encode()
        obj.args.import_plan = self.root / 'plan.json'
        plan = dict(decisionPolicy=policy, releaseBundle=dict(protocolVersions=versions, extractorSha256='c' * 64))
        payload = dict(passed=True, subjectSha256=subject_sha, evaluationPlanSha256='b' * 64,
                       protocolVersions=versions, evidenceKind='real_pf')
        platform = dict(payload, runKind='platform', executorSha256='e' * 64)
        final = dict(payload, runKind='final', provenance={k: 'f' * 64 for k in
                     ('datasetSha256', 'splitSha256', 'labelRulesSha256', 'codeSha256')})
        for name, value in [('platform', platform), ('final', final)]:
            (self.artifacts / (name + '.json')).write_text(json.dumps(dict(keyId='fixture-runner', payload=value)))
        original = {name: (self.artifacts / name).read_bytes() for name in ('platform.json', 'final.json')}
        obj.args.import_plan.write_text(json.dumps(plan))
        with patch.object(formal.lab_run, 'executor_digest', return_value='e' * 64):
            obj.prepare_bundle()
        self.assertEqual(obj.state['subjectSha256'], subject_sha)
        self.assertEqual(obj.versions, versions)
        for name, value in original.items():
            self.assertEqual((self.artifacts / name).read_bytes(), value)
        for section, field, value in [('releaseBundle', 'protocolVersions', {'health': 'host-guard-capture-health/1.0.0'}),
                                     ('releaseBundle', 'extractorSha256', 'd' * 64),
                                     ('decisionPolicy', 'evaluationPlanSha256', 'd' * 64)]:
            changed = copy.deepcopy(plan)
            changed[section][field] = value
            obj.args.import_plan.write_text(json.dumps(changed))
            with self.subTest(field=field), patch.object(obj, 'read_proof') as proof:
                with self.assertRaisesRegex(ValueError, 'LAB_IMPORT_PLAN_MISMATCH'):
                    obj.prepare_bundle()
                proof.assert_not_called()

    def test_probe_isolation_evidence_describes_heartbeat_only_operation(self):
        obj = self.runner(gate_rehearsal=True, source_schema='cyber_guard_gate_test')
        obj.work.mkdir()
        (obj.work / 'private').mkdir()
        (obj.work / 'bin').mkdir()
        for name in ('guardlive', 'guardtargets', 'backend.jar'):
            (obj.work / 'bin' / name).write_bytes(b'fixture executable')
        obj.artifact_dir = self.artifacts / 'g3/run'
        obj.artifact_dir.mkdir(parents=True)
        obj.source = self.source
        obj.rows = formal.freeze_scenarios(self.source, self.artifacts)
        obj.asset, obj.bundle, obj.auth, obj.sensor, obj.boot, obj.executor, obj.executor_boot, obj.scope = [formal.uid() for _ in range(8)]
        obj.auth_revision = 1
        obj.runner_name = 'fixture-runner'
        obj.valid_from = formal.datetime.now(formal.UTC)
        obj.valid_until = obj.valid_from + formal.timedelta(hours=2)
        obj.versions = {'health': 'host-guard-capture-health/1.1.0'}
        obj.subject_sha, obj.plan_sha = 'a' * 64, 'b' * 64
        obj.provenance = dict(modelSha256='m' * 64, extractorSha256='e' * 64)
        obj.proofs = dict(platform={'ref': 'platform.json'}, final={'ref': 'final.json'})
        obj.initial, obj.local_entries = [], []
        obj.original = {'brute_force-1': {'host': '192.0.2.2'}}
        obj.base, obj.target_port = 'https://127.0.0.1:19643', 19644
        obj.op, obj.rev = Mock(), Mock()
        obj.op.v2.return_value = obj.rev.v2.return_value = {'revision': 1}
        signed = {}
        def sign(name, payload, isolation=False):
            signed[name] = copy.deepcopy(payload)
            path = obj.artifact_dir / (name + '.json')
            formal.write(path, dict(payload=payload, keyId='fixture-runner'))
            return dict(ref=str(path.relative_to(self.artifacts)), sha256=formal.sha(path), runnerIdentity='fixture-runner')
        obj.signed = sign
        real_sha = formal.sha
        closeout = formal.ROOT / '.cache/j1v9-20261011/closeout.json'
        with patch.object(formal, 'sha', side_effect=lambda p: 'f' * 64 if p == closeout else real_sha(p)):
            obj.freeze_session()
        isolation = signed['isolation']
        self.assertIn('heartbeats only; no command claims or PF rules', isolation['mechanism'])
        self.assertIn('no PF execution', isolation['verifiedBy'])
        self.assertEqual(signed['session']['protocolVersions'], obj.versions)
        runtime = formal.load(obj.work / 'runtime.json')
        self.assertTrue(runtime['gateRehearsal'])
        self.assertFalse(runtime['realPF'])
        self.assertFalse(runtime['formalG3Eligible'])
        self.assertFalse(runtime['packetInjection'])

    def test_sensor_config_uses_subject_health_version(self):
        obj = self.runner()
        (obj.work / 'private').mkdir(parents=True)
        (obj.work / 'bin').mkdir()
        (obj.work / 'bin/guardlive').write_bytes(b'fixture sensor')
        obj.artifact_dir = self.artifacts / 'g3/run'
        obj.bundle = formal.R4_BUNDLE
        obj.versions = {'health': 'host-guard-capture-health/1.1.0'}
        obj.rows = [{'scenarioId': 'brute_force-1', 'family': 'brute_force'}]
        obj.original = {'brute_force-1': {'port': 443}}
        obj.op, obj.rev = Mock(), Mock()
        obj.op.v2.return_value = {'id': formal.uid(), 'revision': 1, 'credential': 'fixture-only'}
        obj.rev.v2.return_value = {'revision': 2}
        obj.save_state = Mock()
        plan = {'releaseBundle': {'featureProfileSha256': 'f' * 64},
                'existingCapabilities': [{'id': formal.uid(), 'payload': {'family': 'brute_force'}}]}
        with patch.object(formal, 'load', return_value=plan):
            obj.prepare_identities()
        configs = [call.args[1] for call in obj.op.v2.call_args_list if call.args[0].endswith('/configs')]
        self.assertEqual(len(configs), 1)
        self.assertEqual(configs[0]['captureHealthVersion'], obj.versions['health'])

    def test_probe_shutdown_precedes_cleanup_and_refuses_live_thread(self):
        obj = self.runner()
        obj.probe_stop, obj.probe_thread = Mock(), Mock()
        obj.probe_thread.is_alive.return_value = True
        obj.rabbit_created = True
        process = Mock()
        process.poll.return_value = None
        obj.processes = [process]
        with self.assertRaisesRegex(ValueError, 'LAB_PROBE_HEARTBEAT_STOP_TIMEOUT'):
            obj.finish()
        obj.probe_stop.set.assert_called_once()
        obj.probe_thread.join.assert_called_once_with(timeout=65)
        process.terminate.assert_not_called()
        obj.rabbit.delete.assert_not_called()
        obj.probe_thread.is_alive.return_value = False
        events = []
        obj.probe_thread.join.side_effect = lambda **kw: events.append('heartbeat-stopped')
        process.terminate.side_effect = lambda: events.append('process-stopped')
        obj.rabbit.delete.side_effect = lambda: events.append('vhost-deleted')
        obj.probe_latency = [['2026-10-13T00:00:00Z', 0.12]]
        obj.finish()
        self.assertEqual(events, ['heartbeat-stopped', 'process-stopped', 'vhost-deleted'])
        self.assertTrue(obj.state['probeHeartbeatStopped'])
        self.assertEqual(formal.load(obj.work / 'probe-latency.json'), obj.probe_latency)

    def test_probe_run_completion_timeout_and_failure_use_local_clone_and_identities(self):
        """走真实 run/finish 控制流，所有外部副作用用替身；预演不进入报告收尾。"""
        for outcome in ('completed', 'timeout', 'failed'):
            with self.subTest(outcome=outcome):
                obj = self.runner(gate_rehearsal=True, source_schema='cyber_guard_gate_test',
                                  directory=self.root / outcome, probe_seconds=1)
                database = Mock()
                database.clone.return_value = {}
                database.query.return_value = b'1'
                obj.snapshot = Mock(return_value={'fixture': {'rows': 1, 'sha256': 'a' * 64}})
                obj.operator = Mock()
                obj.start_backend = Mock()
                obj.prepare_bundle = Mock()
                obj.prepare_identities = Mock()
                obj.prepare_targets = Mock()
                obj.freeze_session = Mock()
                obj.drain, obj.collect = Mock(), Mock()
                obj.sensor = formal.uid()
                obj.backend, obj.targets = Mock(), Mock()
                obj.backend.poll.return_value = obj.targets.poll.return_value = None
                obj.op = Mock()
                obj.op.call.return_value = {'data': {'state': {'runnable': True}}}
                sensor = Mock()
                sensor.poll.return_value = None if outcome == 'timeout' else 0
                sensor.returncode = 2 if outcome == 'failed' else 0
                obj.start_process = Mock(return_value=sensor)
                def start_executor():
                    obj.root_dir = obj.work / 'private/probe-executor'
                    obj.root_dir.mkdir()
                    obj.probe_stop, obj.probe_thread = Mock(), Mock()
                    obj.probe_thread.is_alive.return_value = False
                    obj.probe_latency = []
                obj.start_executor = start_executor
                def prepare_identities():
                    (obj.work / 'private/sensor.credential').write_text('fixture-only')
                obj.prepare_identities.side_effect = prepare_identities
                with patch.object(formal, 'ensure_identity') as identity, patch.object(formal.j1_run, 'Database', return_value=database), \
                     patch.object(formal.subprocess, 'run'), patch.object(formal, 'original_mapping', return_value={}), \
                     patch.object(formal.time, 'monotonic', side_effect=[0, 2]), patch.object(formal.os, 'umask'):
                    try:
                        if outcome == 'failed':
                            with self.assertRaisesRegex(ValueError, 'LAB_SENSOR_FAILED'):
                                obj.run()
                        else:
                            obj.run()
                    finally:
                        obj.finish()
                database.clone.assert_called_once()
                self.assertEqual(database.clone.call_args.args[:2], ('cyber_guard_gate_test', obj.schema))
                for call in identity.call_args_list:
                    self.assertEqual(call.args[0], self.trust)
                    self.assertTrue(call.args[2].is_relative_to(obj.work / 'private'))
                    self.assertTrue(call.args[1].startswith('g3-gate-'))
                self.assertEqual(self.official.read_text(), '{}')
                self.assertTrue(obj.state['probeHeartbeatStopped'])
                self.assertTrue(obj.state['cloneDropped'])
                self.assertTrue(obj.state['businessUnchanged'])
                self.assertFalse(obj.state.get('reportImported', False))
                self.assertFalse(obj.state['realPF'])
                self.assertFalse(obj.state['formalG3Eligible'])
                obj.drain.assert_not_called()
                obj.collect.assert_not_called()
                if outcome == 'timeout':
                    sensor.terminate.assert_called_once()
                    sensor.wait.assert_called_once_with(30)
                if outcome != 'failed':
                    self.assertEqual(formal.load(obj.work / 'probe-latency.json'), [])


if __name__ == '__main__':
    unittest.main()
