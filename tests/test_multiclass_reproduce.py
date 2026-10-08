"""验证累计拟合台账与输出布局；不拟合模型，不读取冻结数据。"""
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch
import sys
from pathlib import Path

import numpy as np

try:
    from cyber_training.host_guard.multiclass_reproduce import (framework_output, initialize_ledger, ledger_count,
                                                                reserve_fit, checked_round, parser, sha256, reference_outputs)
except ModuleNotFoundError:
    from multiclass_reproduce import framework_output, initialize_ledger, ledger_count, reserve_fit, checked_round, parser, sha256, reference_outputs


def inventory(folder, fits):
    path = Path(folder) / 'fit-inventory.json'
    runs = [{'run': f'run-{i}', 'completedFits': n, 'eventSha256': None} for i, n in enumerate(fits)]
    path.write_text(json.dumps({'runs': runs, 'provenFitLowerBound': sum(fits)}), encoding='utf-8')
    return path


class Reproduce(unittest.TestCase):
    def test_ablation_split_names_follow_frozen_feature_indices(self):
        module = sys.modules[reference_outputs.__module__]
        indices = module.Preprocessor('no_host_context', True).indices
        width = len(indices)
        attributes = {'nodes_featureids': [16, width + 16, 2 * width, 2 * width + 2],
                      'nodes_modes': [b'BRANCH_LEQ'] * 4}
        tree = SimpleNamespace(op_type='TreeEnsembleClassifier', attribute=[
            SimpleNamespace(name=name, value=value) for name, value in attributes.items()])
        onnx = SimpleNamespace(load=lambda _: SimpleNamespace(graph=SimpleNamespace(node=[tree])),
                               helper=SimpleNamespace(get_attribute_value=lambda item: item.value))
        with patch.dict('sys.modules', {'onnx': onnx}):
            result = module.split_counts(Path('synthetic'), indices)
        self.assertEqual([item['feature'] for item in result['splitCounts']],
                         [module.NUMERIC[indices[16]], 'missing:' + module.NUMERIC[indices[16]],
                          'transport', 'serviceClass'])
        self.assertTrue(all('hostFlowStarts' not in item['feature'] and 'hostDistinctPeers' not in item['feature']
                            for item in result['splitCounts']))

    def test_ledger_allows_exactly_one_authorized_fit(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger = Path(folder) / 'fit-ledger.jsonl'
            initialize_ledger(ledger, inventory(folder, [13, 1, 13, 5, 0]))
            self.assertEqual(ledger_count(ledger), 32)
            self.assertEqual(reserve_fit(ledger, 'run-reproduce', 33, 'target', {'scope': 'synthetic'}), 33)
            with self.assertRaises(RuntimeError):
                reserve_fit(ledger, 'run-again', 33, 'target', {'scope': 'synthetic'})
            self.assertEqual(ledger_count(ledger), 33)

    def test_reserved_fit_counts_even_without_completion(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger = Path(folder) / 'fit-ledger.jsonl'
            initialize_ledger(ledger, inventory(folder, [2]))
            reserve_fit(ledger, 'run-crashed', 4, 'target', {'scope': 'synthetic'})
            self.assertEqual(ledger_count(ledger), 3)

    def test_existing_ledger_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger = Path(folder) / 'fit-ledger.jsonl'
            initialize_ledger(ledger, inventory(folder, [2]))
            reserve_fit(ledger, 'run-a', 10, 'target', {'scope': 'synthetic'})
            before = ledger.read_bytes()
            initialize_ledger(ledger, inventory(folder, [0]))
            self.assertEqual(ledger.read_bytes(), before)

    def test_inventory_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = inventory(folder, [3])
            value = json.loads(path.read_text())
            value['provenFitLowerBound'] = 4
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                initialize_ledger(Path(folder) / 'fit-ledger.jsonl', path)

    def test_framework_output_matches_onnx_layout(self):
        probabilities = np.asarray([[.7, .1, .1, .05, .05]])
        output = framework_output(probabilities)
        self.assertEqual(output.dtype, np.float32)
        np.testing.assert_allclose(output, [[.3, .1, .1, .05, .05]], rtol=0, atol=1e-7)

    def test_new_round_preserves_33_fit_history_and_binding(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old, new = root / 'history.jsonl', root / 'round2.jsonl'
            initialize_ledger(old, inventory(folder, [33]))
            before = old.read_bytes()
            auth = root / 'authorization.json'
            auth.write_text(json.dumps({'budget': 1, 'target': 'ablation-no-host-context',
                'featureSet': 'no_host_context', 'seed': 42, 'date': 'synthetic', 'by': 'test',
                'scope': 'synthetic only', 'countingRule': 'reservation counts', 'roundId': 'round-2'}))
            args = SimpleNamespace(ledger=new, historical_ledger=old, historical_ledger_sha256=sha256(old),
                authorization=auth, budget=1, target='ablation-no-host-context', feature_set='no_host_context', seed=42)
            authorization = checked_round(args)
            self.assertEqual(ledger_count(new), 0)
            reserve_fit(new, 'synthetic', 1, args.target, authorization)
            with self.assertRaises(RuntimeError):
                reserve_fit(new, 'retry', 1, args.target, authorization)
            checked_round(args)
            args.seed = 43
            with self.assertRaises(ValueError):
                checked_round(args)
            args.seed, args.ledger = 42, old
            with self.assertRaises(ValueError):
                checked_round(args)
            self.assertEqual(old.read_bytes(), before)

    def test_fit_cli_requires_every_explicit_parameter(self):
        options = {'run': 'run', 'reference-run': 'ref', 'reference-outputs': 'out', 'ledger': 'new',
            'target': 'ablation', 'feature-set': 'no_host_context', 'seed': '42', 'reference-model-sha256': 'a',
            'reference-train-sha256': 'b', 'reference-validation-sha256': 'c', 'historical-ledger-sha256': 'd',
            'budget': '1', 'authorization': 'auth', 'historical-ledger': 'old', 'frozen': 'frozen', 'sidecars': 'sidecars'}
        for omitted in options:
            argv = ['fit'] + [item for key, value in options.items() if key != omitted for item in ('--' + key, value)]
            with self.subTest(omitted=omitted), redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                parser().parse_args(argv)

    def test_reference_refuses_path_traversal_before_reading(self):
        with self.assertRaises(ValueError):
            reference_outputs(SimpleNamespace(target='../test'))

    def test_reference_zero_fit_roles_bindings_and_no_overwrite(self):
        module = sys.modules[reference_outputs.__module__]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'ref/models/ablation'
            target.mkdir(parents=True)
            (target / 'model.onnx').write_bytes(b'synthetic')
            (target / 'preprocessing.json').write_text('{}')
            (root / 'ref/run-summary.json').write_text(json.dumps({'status': 'completed', 'finalTestRead': False,
                'fits': [{'name': 'ablation', 'export': 'passed', 'featureSet': 'no_host_context', 'seed': 42,
                          'artifactSha256': sha256(target / 'model.onnx')}]}))
            args = SimpleNamespace(target='ablation', reference_run=root / 'ref',
                reference_model_sha256=sha256(target / 'model.onnx'), frozen=root / 'frozen',
                sidecars=root / 'sidecars', output=root / 'outputs')
            actual = np.tile([.8, .2, .2, .2, .2], (3, 1)).astype(np.float32)
            with patch.object(module.Preprocessor, 'restore', return_value=SimpleNamespace(
                    feature_set='no_host_context', include_service_class=True)), \
                 patch.object(module, 'load_development', return_value=SimpleNamespace(rows=[{}, {}, {}])) as loader, \
                 patch.object(module, 'session', return_value=object()), \
                 patch.object(module, 'feed_for', return_value={}), \
                 patch.object(module, 'predict', return_value=actual), \
                 patch.object(module, 'code_manifest', return_value={'synthetic': True}), \
                 patch.object(module, 'fit_model', side_effect=AssertionError('不能拟合')), \
                 redirect_stderr(StringIO()):
                from contextlib import redirect_stdout
                with redirect_stdout(StringIO()):
                    reference_outputs(args)
                self.assertEqual([call.args[2] for call in loader.call_args_list], ['train', 'validation'])
                result = json.loads((args.output / 'reference-bindings.json').read_text())
                self.assertEqual(result['newFits'], 0)
                self.assertFalse(result['testRead'])
                for role in ('train', 'validation'):
                    np.testing.assert_array_equal(np.load(args.output / f'{role}-onnx.npy', allow_pickle=False), actual)
                    self.assertEqual(result['outputs'][role], sha256(args.output / f'{role}-onnx.npy'))
                with self.assertRaises(ValueError):
                    reference_outputs(args)


if __name__ == '__main__':
    unittest.main()
