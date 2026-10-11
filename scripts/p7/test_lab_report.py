"""G3 报告纯函数、签名与篡改回归；仅使用合成事实和临时密钥。"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from lab_report import generate, digest, sign, verify, load, InvalidReport, Rejected

ROOT = Path(__file__).resolve().parents[2]


class LabReportTest(unittest.TestCase):
    def fixture(self, live=False):
        value = load(ROOT / 'docs/contracts/examples/lab-report-input.json')
        if live:
            value['session']['evidenceKind'] = 'lab'
            value['sessionSha256'] = digest(value['session'])
        return value

    def test_shared_golden(self):
        result = generate(self.fixture())
        self.assertEqual(result, load(ROOT / 'docs/contracts/examples/lab-report-expected.json'))
        self.assertFalse(result['passed'])
        self.assertEqual(result['computedStatus'], 'passed')

    def test_duration_and_delays(self):
        result = generate(self.fixture(True))
        self.assertTrue(result['passed'])
        self.assertEqual(result['normal']['cumulativeMs'], 1800000)
        self.assertEqual(result['normal']['singleAssetUnionMs'], 900000)
        self.assertEqual(result['scenarios'][0]['alertLatencyMs'], 30000)

    def test_half_hour_one_false_block_fails_without_double_count(self):
        value = self.fixture(True); sid = value['scenarios'][4]['scenarioId']
        applied = dict(scenarioId=sid, commandId='synthetic-command', kind='verified_receipt', verification='verified', status='applied', occurredAt='2026-10-11T00:00:10Z')
        value['events'] += [applied, applied, dict(applied, status='expired', occurredAt='2026-10-11T00:00:20Z')]
        result = generate(value)
        self.assertFalse(result['passed']); self.assertEqual(result['normal']['perHour'], 2)
        self.assertEqual(result['normal']['verifiedFalseBlocks'], 1)

    def test_unknown_apply_and_unverified_receipts(self):
        for mode in ('remove', 'unverified'):
            value = self.fixture(True)
            if mode == 'remove':
                value['events'] = [e for e in value['events'] if e.get('status') != 'applied']
            else:
                for event in value['events']:
                    if event.get('status') == 'applied': event['verification'] = 'unverified'
            self.assertEqual(generate(value)['status'], 'unverified')

    def test_missing_and_late_are_not_fabricated(self):
        value = self.fixture(True); value['events'].reverse()
        self.assertTrue(generate(value)['passed'])
        value['events'] = [e for e in value['events'] if e.get('kind') != 'scenario_result']
        self.assertFalse(generate(value)['passed'])
        self.assertIsNone(generate(value)['normal']['perHour'])

    def test_one_millisecond_below_threshold(self):
        value = self.fixture(True); value['scenarios'][4]['sourceEnd'] = '2020-01-01T00:14:59.999Z'
        self.assertFalse(generate(value)['normal']['passed'])

    def test_manual_cleanup_is_not_proof_of_ttl_recovery(self):
        value = self.fixture(True)
        for s in value['scenarios'][4:]: s['sourceEnd'] = '2020-01-01T00:30:00Z'
        sid = value['scenarios'][4]['scenarioId']
        value['events'] += [dict(scenarioId=sid, commandId='false-block', kind='command', occurredAt='2026-10-11T00:00:01Z'),
                            dict(scenarioId=sid, commandId='false-block', kind='verified_receipt', verification='verified', status='applied', occurredAt='2026-10-11T00:00:02Z'),
                            dict(scenarioId=sid, commandId='false-block', kind='verified_receipt', verification='verified', status='revoked', occurredAt='2026-10-11T00:00:03Z')]
        result = generate(value)
        self.assertEqual(result['normal']['perHour'], 1)
        self.assertFalse(result['normal']['falseBlocksTtlRestored'])
        self.assertFalse(result['passed'])

    def test_incomplete_population(self):
        value = self.fixture(True); value['unlinkedCommandIds'] = ['missing-command']
        self.assertEqual(generate(value)['status'], 'unverified')
        value = self.fixture(True); value['scenarios'] = value['scenarios'][1:]
        self.assertIn('port_scan', generate(value)['missingClasses'])

    def test_missing_targets_do_not_turn_capture_quality_into_execution_evidence(self):
        value = self.fixture(True)
        value['scenarios'][0]['quality'].update(executionQualified=0, missingTargetRef=10, nonExecutable=10)
        result = generate(value)
        self.assertEqual(result['scenarios'][0]['qualifiedCoverage'], 1)
        self.assertEqual(result['scenarios'][0]['executionQualifiedCoverage'], 0)
        self.assertFalse(result['passed'])

    def test_per_class_results_timeline_and_unverified_items(self):
        self.assertEqual(generate(self.fixture(True))['unverifiedItems'], [])
        value = self.fixture(True); value['scenarios'] = value['scenarios'][1:]
        result = generate(value)
        self.assertEqual([c['family'] for c in result['classes']], ['brute_force', 'dos_flood', 'dos_slow', 'port_scan'])
        classes = {c['family']: c for c in result['classes']}
        self.assertEqual(classes['port_scan']['status'], 'not_evaluated')
        self.assertEqual(classes['port_scan']['scenarioIds'], [])
        self.assertEqual(classes['brute_force']['firstApplicationLatencyMs'], 32000)
        self.assertIn('class:port_scan:no_scenario', result['unverifiedItems'])
        row = result['scenarios'][0]
        self.assertEqual((row['labStart'], row['firstAlertAt'], row['firstIssuedAt'], row['firstAppliedAt'], row['lastClearedAt']),
                         ('2026-10-11T00:00:00Z', '2026-10-11T00:00:30Z', '2026-10-11T00:00:31Z', '2026-10-11T00:00:32Z', '2026-10-11T00:01:02Z'))
        self.assertEqual((row['issueLatencyMs'], row['cleanupLatencyMs']), (31000, 62000))
        value = self.fixture(True); value['runStatus'] = 'interrupted'
        self.assertIn('run:interrupted', generate(value)['unverifiedItems'])

    def test_signing_reuses_platform_report_key_rules(self):
        key = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'loose.der'
            path.write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            path.chmod(0o644)
            with self.assertRaises(Rejected):
                sign(generate(self.fixture()), path, 'fixture-runner')

    def test_signature_and_cross_session_tamper(self):
        value = self.fixture(); key = Ed25519PrivateKey.generate()
        trust = {'fixture-runner': base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'test.der'; path.write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); path.chmod(0o600)
            envelope = sign(generate(value), path, 'fixture-runner')
            self.assertTrue(verify(envelope, trust, value)['signatureVerified'])
            changed = copy.deepcopy(value); changed['session']['sessionId'] = '00000000-0000-4000-8000-000000009999'; changed['sessionSha256'] = digest(changed['session'])
            with self.assertRaises(InvalidReport): verify(envelope, trust, changed)
            envelope['payload']['passed'] = True
            with self.assertRaises(Exception): verify(envelope, trust, value)

    def test_raw_hash_and_jcs_are_different_purposes(self):
        import hashlib
        value = self.fixture()
        a = json.dumps(value, indent=2).encode(); b = json.dumps(value, separators=(',', ':')).encode()
        self.assertNotEqual(hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
        self.assertEqual(digest(json.loads(a)), digest(json.loads(b)))

    def test_duplicate_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bad.json'; path.write_text('{"passed":false,"passed":true}')
            with self.assertRaises(InvalidReport): load(path)


if __name__ == '__main__':
    unittest.main()
