"""K2 诊断单位与嵌套计时契约，不读取 PCAP 或模型。"""
import unittest

from k2_profile import seconds, summarize


class ProfileTest(unittest.TestCase):
    def test_duration_units_and_invalid_values(self):
        self.assertEqual(seconds("PT1M0.125S"), 60.125)
        self.assertEqual(seconds("PT0.000001S"), .000001)
        for value in ("", "PT", "12ms", "PT-1S"):
            with self.assertRaises(ValueError):
                seconds(value)

    def test_inference_aggregates_within_batch_without_merging_parent_phase(self):
        events = [dict(type="cyber.guard.BatchPhase", values=dict(batchId="b", phase=phase, duration=duration, committed=ok))
                  for phase, duration, ok in (("onnx_inference", "PT0.1S", False),
                                              ("onnx_inference", "PT0.2S", False),
                                              ("t2_consume", "PT1S", False),
                                              ("t2_commit", "PT0.01S", False))]
        result = summarize(events)
        self.assertAlmostEqual(result["phases"]["onnx_inference"]["p95PerBatchSeconds"], .3)
        self.assertEqual(result["phases"]["t2_consume"]["totalSeconds"], 1)
        self.assertEqual(result["rolledBackTransactions"], 1)


if __name__ == "__main__":
    unittest.main()
