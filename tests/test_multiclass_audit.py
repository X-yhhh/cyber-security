"""验证检出/分类分离与真实来源最新证据语义，不需要真实网络。"""
import unittest
from types import SimpleNamespace
import numpy as np

try:
    from cyber_training.host_guard.multiclass_audit import report_predictions, simulate_sources, compare_outputs
except ModuleNotFoundError:
    from multiclass_audit import report_predictions, simulate_sources, compare_outputs


def sample(parents, seconds, peers=None, epochs=None, ports=None):
    n = len(parents)
    metadata = []
    for i in range(n):
        metadata.append(dict(assetId='asset', sensorId='sensor', bootId='boot', captureScopeId='scope',
                             peerKey=(peers or ['p'] * n)[i], keyEpoch=(epochs or ['e'] * n)[i],
                             direction='inbound', transport='tcp', servicePort=(ports or [80] * n)[i],
                             asOf=f'2026-01-01T00:00:{seconds[i]:02d}Z'))
    return SimpleNamespace(metadata=metadata, parent_ids=np.asarray(parents), labels=np.full(n, 4))


class Audit(unittest.TestCase):
    def test_wrong_attack_class_still_detected(self):
        labels = np.array([0, 0, 1, 2, 3, 4])
        predicted = np.array([0, 0, 2, 3, 4, 1])
        result = report_predictions(labels, predicted, np.array(['internal', 'website'] * 3), np.array(['s'] * 6))
        self.assertEqual(result['attackDetection'], 1.0)
        self.assertEqual(result['recall']['dos_slow'], 0.0)

    def test_latest_low_score_replaces_high(self):
        data = sample(['a', 'a', 'b'], [0, 1, 2])
        out = np.array([[.99, 0, 0, 0, .99], [.1, 0, 0, 0, .1], [.99, 0, 0, 0, .99]])
        self.assertEqual(simulate_sources(data, out, .9, 4, 2)['coveredAttackOpportunities'], 0)

    def test_same_parent_never_double_counts(self):
        data = sample(['a', 'a'], [0, 1])
        out = np.array([[.99, 0, 0, 0, .99]] * 2)
        self.assertEqual(simulate_sources(data, out, .9, 4, 2)['coveredAttackOpportunities'], 0)

    def test_expiry_and_scope_separation(self):
        out = np.array([[.99, 0, 0, 0, .99]] * 2)
        for data in [sample(['a', 'b'], [0, 11]), sample(['a', 'b'], [0, 1], peers=['p', 'q']),
                     sample(['a', 'b'], [0, 1], epochs=['e', 'f']), sample(['a', 'b'], [0, 1], ports=[80, 443])]:
            self.assertEqual(simulate_sources(data, out, .9, 4, 2)['coveredAttackOpportunities'], 0)
        self.assertEqual(simulate_sources(sample(['a', 'b'], [0, 10]), out, .9, 4, 2)['coveredAttackOpportunities'], 1)

    def test_boundary_threshold_flip_is_not_tolerated(self):
        a = np.array([[.5, .5, 0, 0, 0]], dtype=np.float32)
        b = a.copy()
        b[0, 0] = np.nextafter(np.float32(.5), np.float32(0))
        self.assertEqual(compare_outputs(a, b, .5)['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
