"""单对端反事实与连接检出边界；只使用合成样本。"""
import unittest
import numpy as np

from single_peer_check import CLASSES, _connection_decisions, _rates, passed, rewrite


class SinglePeerTest(unittest.TestCase):
    def test_later_hit_counts_once_and_wrong_attack_family_is_detection(self):
        rows = [{"parentConnectionId": "p", "label": "dos_slow"}] * 3
        scores = np.array([[.1, .1, 0, 0, 0], [.9, 0, .9, 0, 0], [1, 0, 0, 1, 0]])
        labels, predicted = _connection_decisions(rows, scores, {"alertThreshold": .8})
        self.assertEqual(predicted.tolist(), [2])
        self.assertEqual(_rates(labels, predicted)["dos_slow"], 1)

    def test_conflicting_parent_label_rejected(self):
        rows = [{"parentConnectionId": "p", "label": name} for name in ("normal", "port_scan")]
        with self.assertRaises(ValueError):
            _connection_decisions(rows, np.zeros((2, 5)), {"alertThreshold": .8})

    def test_exactly_twenty_percentage_points_passes_and_missing_class_fails(self):
        drops = {name: .20 for name in CLASSES[1:]}
        self.assertTrue(passed(drops))
        self.assertFalse(passed(drops | {"dos_slow": .20001}))
        self.assertFalse(passed({"dos_slow": 0}))

    def test_rewrite_preserves_peer_null_and_other_fields(self):
        rows = [{"input": {"contexts": [{"windowSeconds": w, "hostDistinctPeers": 20,
                    "hostFlowStarts": 90, "peerFlowStarts": None if w == 1 else 7,
                    "peerSynCount": 3} for w in (1, 5, 30)]}, "label": "normal"}]
        changed = rewrite(rows)
        self.assertEqual(rows[0]["input"]["contexts"][0]["hostDistinctPeers"], 20)
        for item in changed[0]["input"]["contexts"]:
            self.assertEqual(item["hostDistinctPeers"], 1)
            self.assertEqual(item["hostFlowStarts"], item["peerFlowStarts"])
            self.assertEqual(item["peerSynCount"], 3)


if __name__ == "__main__":
    unittest.main()
