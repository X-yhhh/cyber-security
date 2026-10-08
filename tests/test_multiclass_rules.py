"""T3.5a：独立规则统计、零拟合迁移、输入拒绝与当前 P7 接口对拍。"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np

from cyber_training.host_guard import multiclass_audit as a


def fixture():
    """所有身份与分数为合成；两正常来源和四攻击类别均有连接。"""
    labels = np.array([0, 0, 1, 2, 2, 3, 4, 4])
    ports = [80, 22, 9999, 21, 8080, 8080, 80, 443]
    metadata = [dict(servicePort=port, asOf=f'2026-01-01T00:00:0{i}Z') for i, port in enumerate(ports)]
    values = np.zeros((8, len(a.NUMERIC)), dtype=np.float32)
    values[:, 0] = [0, 0, 0, 0, 0, 0, 5000, 10000]
    values[:, a.NUMERIC.index('contexts.5.peerDistinctServicePorts')] = [0, 0, 10, 0, 0, 0, 0, 0]
    values[:, a.NUMERIC.index('contexts.30.peerFlowStarts')] = [0, 5, 0, 5, 5, 0, 20, 20]
    values[:, a.NUMERIC.index('contexts.1.peerBytesInbound')] = [100, 0, 0, 0, 0, 100, 0, 0]
    data = SimpleNamespace(labels=labels, parent_ids=np.array(list('abcdefgh')),
                           source_ids=np.array(['internal', 'website'] * 4), metadata=metadata,
                           rows=[{'originalScenario': 'synthetic'}] * 8,
                           values=values, missing=np.zeros_like(values))
    baseline = {'rules': [dict(family=family, field=field, threshold=threshold,
                               servicePorts=ports, minElapsedMs=elapsed, validationFpr=0, automatic=False)
                          for (_, family, field, ports, elapsed), threshold in zip(a.RULE_DEFINITIONS, [10, 5, 100, 20])]}
    scores = np.zeros((8, 5), dtype=np.float32)
    return data, scores, baseline


class RulesAudit(unittest.TestCase):
    def compare(self):
        data, scores, baseline = fixture()
        return a.compare_rules(data, a.Connections(data), scores, .5, baseline)

    def test_exact_rc4_fields_and_frozen_thresholds(self):
        result = self.compare()
        self.assertEqual(len(result['rules']), 4)
        for rule, threshold in zip(result['rules'], [10, 5, 100, 20]):
            self.assertEqual(set(rule), {'ruleId', 'family', 'field', 'operator', 'threshold', 'automatic'})
            self.assertEqual(rule['operator'], 'gte')
            self.assertEqual(rule['threshold'], threshold)
            self.assertIs(rule['automatic'], False)
        self.assertEqual(result['newFits'], 0)
        self.assertFalse(result['newThresholdSearch'])
        self.assertFalse(result['finalTestRead'])

    def test_each_rule_counts_other_attacks_as_false_positives(self):
        metric = self.compare()['ruleMetrics']['brute-starts']
        self.assertEqual((metric['before']['truePositives'], metric['before']['falsePositives']), (1, 1))
        self.assertEqual((metric['after']['truePositives'], metric['after']['falsePositives']), (2, 3))
        self.assertEqual(metric['after']['precision'], .4)
        self.assertEqual(metric['after']['recall'], 1)
        self.assertEqual(metric['after']['validationFpr'], .5)

    def test_removes_both_port_and_elapsed_conditions(self):
        metrics = self.compare()['ruleMetrics']
        self.assertEqual(metrics['flood-bytes']['before']['recall'], 0)
        self.assertEqual(metrics['flood-bytes']['after']['recall'], 1)
        self.assertEqual(metrics['slow-starts']['before']['recall'], .5)
        self.assertEqual(metrics['slow-starts']['after']['recall'], 1)
        self.assertEqual(self.compare()['precisionBelow90RuleIds'], ['brute-starts', 'flood-bytes'])

    def test_missing_and_nonfinite_fields_never_match(self):
        data, scores, baseline = fixture()
        offset = a.NUMERIC.index('contexts.30.peerFlowStarts')
        data.missing[3, offset] = 1
        data.values[4, offset] = np.nan
        result = a.compare_rules(data, a.Connections(data), scores, .5, baseline)
        self.assertEqual(result['ruleMetrics']['brute-starts']['after']['truePositives'], 0)
        self.assertEqual(result['ruleMetrics']['brute-starts']['notApplicableSnapshots'], 2)

    def test_parent_snapshots_count_once(self):
        data, scores, baseline = fixture()
        data.parent_ids[4] = data.parent_ids[3]
        result = a.compare_rules(data, a.Connections(data), scores, .5, baseline)
        self.assertEqual(result['ruleMetrics']['brute-starts']['after']['truePositives'], 1)

    def test_unknown_or_ambiguous_legacy_rules_rejected(self):
        _, _, baseline = fixture()
        for edit in [lambda r: r.update(threshold=True), lambda r: r.update(threshold=float('inf')),
                     lambda r: r.update(threshold=-1), lambda r: r.update(automatic=True),
                     lambda r: r.update(operator='gt'), lambda r: r.update(servicePorts=[8080]),
                     lambda r: r.update(field='unknown'), lambda r: r.update(minElapsedMs=42)]:
            broken = copy.deepcopy(baseline)
            edit(broken['rules'][1])
            with self.assertRaises(ValueError):
                a.legacy_rules(broken)
        baseline['rules'][1]['family'] = 'port_scan'
        with self.assertRaises(ValueError):
            a.legacy_rules(baseline)

    def test_test_or_l3_rejected_before_any_file_read(self):
        for root in ('test', 'l3', 'test-scores'):
            with patch.object(a, 'sha256', side_effect=AssertionError('must not open')):
                with self.assertRaises(ValueError):
                    a.load_development(Path(root), Path('sidecars'), 'validation')
                with self.assertRaises(ValueError):
                    a.load_development(Path('frozen'), Path(root), 'validation')
        with patch.object(a, 'sha256', side_effect=AssertionError('must not open')):
            with self.assertRaises(ValueError):
                a.load_development(Path('frozen'), Path('sidecars'), 'test')

    def test_cli_requires_explicit_binding(self):
        with patch('sys.argv', ['audit', '--mode', 'rules', '--frozen', 'frozen',
                                '--sidecars', 'sidecars', '--output', 'output']):
            with self.assertRaises(SystemExit) as error:
                a.main()
            self.assertEqual(error.exception.code, 2)

    def test_cli_rejects_hash_mismatch_without_loading_dataset(self):
        with tempfile.TemporaryDirectory(prefix='rc4-') as folder:
            source = Path(folder) / 'baseline.json'
            source.write_text('{}')
            with patch('sys.argv', ['audit', '--mode', 'rules', '--frozen', 'frozen', '--sidecars', 'sidecars',
                       '--output', str(Path(folder) / 'output'), '--baseline-rules', str(source),
                       '--baseline-rules-sha256', '0' * 64, '--validation-output', str(source),
                       '--validation-output-sha256', '0' * 64, '--alert-threshold', '.5']), \
                 patch.object(a, 'load_development', side_effect=AssertionError('must not load')):
                with self.assertRaisesRegex(ValueError, '哈希不符'):
                    a.main()
            self.assertFalse((Path(folder) / 'output').exists())

    @unittest.skipUnless(os.environ.get('P7_COMPOSER_ROOT'), 'requires current main P7 composer')
    def test_current_p7_accepts_generated_comparison_and_rejects_old_format(self):
        root = Path(os.environ['P7_COMPOSER_ROOT'])
        spec = importlib.util.spec_from_file_location('p7_compose', root / 'scripts/p7/compose_policy.py')
        c = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(c)
        comparison_path = os.environ.get('RC4_VALIDATION_COMPARISON')
        comparison = c.load(comparison_path) if comparison_path else self.compare()
        fixture_root = root / 'scripts/p7/testdata'
        layer = c.load(fixture_root / 'candidate-alert.json')
        layer['rulePolicies'] = [{key: rule[key] for key in c.RULE_FIELDS} | {'autoRequested': False}
                                 for rule in comparison['rules']]
        policy = c.compose(layer, c.load(fixture_root / 'policy-preview.json'), comparison,
                           c.load(fixture_root / 'deployment-binding.json'))
        self.assertEqual(policy['mode'], 'alert_only')
        self.assertFalse(any(rule['autoEligible'] for rule in policy['rulePolicies']))
        self.assertEqual(len(policy['rulePolicies']), 4)
        # 部署/计划为 P7 合成夹具，只证明真实 CLI 消费格式，不生成正式策略或授权。
        with tempfile.TemporaryDirectory(prefix='rc4-compose-') as folder:
            folder = Path(folder)
            for path in fixture_root.glob('*.json'):
                shutil.copyfile(path, folder / path.name)
            (folder / 'rules-comparison.json').write_text(json.dumps(comparison, allow_nan=False), encoding='utf-8')
            layer['sourceSha256']['rulesComparison'] = c.digest((folder / 'rules-comparison.json').read_bytes())
            (folder / 'candidate-alert.json').write_text(json.dumps(layer), encoding='utf-8')
            command = [sys.executable, str(root / 'scripts/p7/compose_policy.py'), 'compose']
            for option, name in [('candidate-layer', 'candidate-alert.json'), ('policy-preview', 'policy-preview.json'),
                                 ('rules-comparison', 'rules-comparison.json'), ('deployment-binding', 'deployment-binding.json'),
                                 ('evaluation-plan', 'evaluation-plan.json'), ('protection-set', 'protection-set.json')]:
                command.extend(['--' + option, str(folder / name)])
            command.extend(['--output', str(folder / 'output.json')])
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(c.load(folder / 'output.json'), policy)
            repeated = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(repeated.returncode, 2)
        for extra in ('servicePorts', 'minElapsedMs', 'validationFpr'):
            broken = copy.deepcopy(comparison)
            broken['rules'][0][extra] = 0
            with self.assertRaises(c.PolicyError):
                c.compose(layer, c.load(fixture_root / 'policy-preview.json'), broken,
                          c.load(fixture_root / 'deployment-binding.json'))
        _, _, baseline = fixture()
        with self.assertRaises(c.PolicyError):
            c.compare_rules(layer['rulePolicies'], baseline)


if __name__ == '__main__':
    unittest.main()
