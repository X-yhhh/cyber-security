"""验证累计拟合台账与输出布局；不拟合模型，不读取冻结数据。"""
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

try:
    from cyber_training.host_guard.multiclass_reproduce import (framework_output, initialize_ledger, ledger_count,
                                                                reserve_fit)
except ModuleNotFoundError:
    from multiclass_reproduce import framework_output, initialize_ledger, ledger_count, reserve_fit


def inventory(folder, fits):
    path = Path(folder) / 'fit-inventory.json'
    runs = [{'run': f'run-{i}', 'completedFits': n, 'eventSha256': None} for i, n in enumerate(fits)]
    path.write_text(json.dumps({'runs': runs, 'provenFitLowerBound': sum(fits)}), encoding='utf-8')
    return path


class Reproduce(unittest.TestCase):
    def test_ledger_allows_exactly_one_authorized_fit(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger = Path(folder) / 'fit-ledger.jsonl'
            initialize_ledger(ledger, inventory(folder, [13, 1, 13, 5, 0]))
            self.assertEqual(ledger_count(ledger), 32)
            self.assertEqual(reserve_fit(ledger, 'run-reproduce', 33), 33)
            with self.assertRaises(RuntimeError):
                reserve_fit(ledger, 'run-again', 33)
            self.assertEqual(ledger_count(ledger), 33)

    def test_reserved_fit_counts_even_without_completion(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger = Path(folder) / 'fit-ledger.jsonl'
            initialize_ledger(ledger, inventory(folder, [2]))
            reserve_fit(ledger, 'run-crashed', 4)
            self.assertEqual(ledger_count(ledger), 3)

    def test_existing_ledger_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger = Path(folder) / 'fit-ledger.jsonl'
            initialize_ledger(ledger, inventory(folder, [2]))
            reserve_fit(ledger, 'run-a', 10)
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


if __name__ == '__main__':
    unittest.main()
