"""R4 因果连接计数回归；只用合成 validation，不访问真实 test。"""
from datetime import datetime, timedelta, timezone
import unittest

import numpy as np

from select_dos_slow import analyze


def sample(parent, second, label="dos_slow", score=1.0, peer="slow", port=80, epoch=1):
    """旁路身份只用于证据汇总，分数由合成夹具提供。"""
    stamp = (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)).isoformat()
    identifier = f"{parent}-{second}-{score}-{peer}-{port}-{epoch}"
    row = {"observationId": identifier, "parentConnectionId": parent, "label": label,
           "websiteSupplement": False, "input": {"serviceClass": "web"}}
    meta = {"observationId": identifier, "parentConnectionId": parent, "assetId": "asset",
            "sensorId": "sensor", "bootId": "boot", "captureScopeId": "capture", "peerKey": peer,
            "keyEpoch": epoch, "direction": "inbound", "transport": "tcp", "servicePort": port, "asOf": stamp}
    return row, meta, [score, 0, 0, 0, score]


def run(samples):
    samples = [sample(f"baseline-{i}", i / 100) for i in range(5)] + samples
    samples.append(sample("normal", 100, label="normal", score=0, peer="benign"))
    rows, metas, scores = zip(*samples)
    return analyze(list(rows), list(metas), np.array(scores, dtype=np.float32), .9)


class SlowSelectionTest(unittest.TestCase):
    def test_r4_rejects_low_concurrency_but_retains_comparisons(self):
        result = run([sample("low-1", 60), sample("low-2", 61)])
        self.assertEqual(result["selected"]["minDistinctFlows"], 5)
        self.assertEqual(result["selected"]["coveredAttackOpportunities"], 1)
        self.assertEqual(result["alternatives"][0]["coveredAttackOpportunities"], 2)
        self.assertFalse(result["outsideCoverage"]["excludedFromEvaluation"])

    def test_parent_snapshots_do_not_inflate_distinct_count(self):
        result = run([sample("repeated", 60 + i) for i in range(8)])
        self.assertEqual(result["slowOpportunityMaxDistinctFlows"]["histogram"], {"1": 1, "5": 1})

    def test_new_lower_score_invalidates_old_evidence(self):
        result = run([sample("a", 60), sample("b", 61), sample("a", 62, score=0), sample("c", 63)])
        self.assertEqual(result["slowOpportunityMaxDistinctFlows"]["histogram"], {"2": 1, "5": 1})

    def test_ten_seconds_inclusive_then_expires(self):
        result = run([sample("a", 60), sample("b", 70), sample("c", 80.001)])
        self.assertEqual(result["slowOpportunityMaxDistinctFlows"]["histogram"], {"2": 1, "5": 1})

    def test_peers_epochs_and_services_cannot_pool(self):
        samples = [sample(f"a-{i}", 60 + i, peer=f"peer-{i}") for i in range(4)]
        samples += [sample("epoch-a", 65, epoch=2), sample("epoch-b", 66, epoch=3)]
        samples += [sample("service-a", 67, port=443), sample("service-b", 68, port=443)]
        result = run(samples)
        self.assertEqual(result["selected"]["coveredAttackSources"], 1)
        self.assertEqual(result["slowOutOfHttpScopeSnapshots"], 2)

    def test_normal_mixed_opportunity_counts_false_positive(self):
        # 无下限可满足 FPR 时拒绝，不能把混合正常从分母剔除。
        with self.assertRaisesRegex(ValueError, "没有具备正覆盖"):
            run([sample("mixed", 1, label="normal", score=0)])

    def test_alignment_and_label_conflicts_fail_closed(self):
        samples = [sample(f"s-{i}", i) for i in range(5)]
        samples += [sample("normal", 100, label="normal", score=0, peer="benign")]
        rows, metas, scores = zip(*samples)
        metas = [dict(m) for m in metas]
        metas[0]["observationId"] = "wrong"
        with self.assertRaisesRegex(ValueError, "对齐"):
            analyze(list(rows), metas, np.array(scores), .9)
        with self.assertRaisesRegex(ValueError, "冲突"):
            run([sample("baseline-0", 2, label="normal", score=0)])


if __name__ == "__main__":
    unittest.main()
