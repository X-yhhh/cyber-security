import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

try:
    from cyber_training.host_guard.multiclass_train import (CLASSES, Dataset, Preprocessor, connection_scores,
        connection_scores_at, metrics, sample_weights, select_alert_threshold)
except ModuleNotFoundError:
    from multiclass_train import (CLASSES, Dataset, Preprocessor, connection_scores,
        connection_scores_at, metrics, sample_weights, select_alert_threshold)


def row(parent, label, activity="source-a"):
    features = {name.split(".")[1]: 1.0 for name in ["features." + x for x in ("elapsedMs", "bytesOutbound", "bytesInbound", "packetsOutbound", "packetsInbound", "lengthMin", "lengthMax", "lengthMean", "lengthStd", "iatMeanUs", "iatStdUs", "synCount", "synAckCount", "rstCount", "finCount", "handshakeSeen")]}
    contexts = [{"windowSeconds": window, "coverageMs": 1.0, "peerFlowStarts": 1.0, "peerSynCount": 1.0, "peerRstCount": 0.0, "peerDistinctServicePorts": 1.0, "hostFlowStarts": 1.0, "hostDistinctPeers": 1.0, "peerBytesOutbound": 1.0, "peerBytesInbound": 1.0} for window in (1, 5, 30)]
    return {"observationId": f"obs-{parent}-{activity}", "parentConnectionId": parent,
            "activityId": activity, "label": label,
            "input": {"features": features, "contexts": contexts, "transport": "tcp", "direction": "inbound", "serviceClass": "web"}}


class MultiClass(unittest.TestCase):
    def test_load_and_feature_ablation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dataset.jsonl"
            path.write_text("\n".join(json.dumps(row(str(i), CLASSES[i % 5])) for i in range(10)) + "\n")
            dataset = Dataset.load(path)
            full = Preprocessor().fit(dataset)
            self.assertEqual(full.transform(dataset).shape[1], 43 * 2 + 3)
            self.assertEqual(Preprocessor("base").fit(dataset).transform(dataset).shape[1], 16 * 2 + 3)
            self.assertEqual(Preprocessor(include_service_class=False).fit(dataset).transform(dataset).shape[1], 43 * 2 + 2)

    def test_parent_weight_sum_and_alert_threshold(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dataset.jsonl"
            path.write_text("\n".join(json.dumps(row("same", "normal")) for _ in range(2)) + "\n" + json.dumps(row("attack", "dos_flood")) + "\n")
            dataset = Dataset.load(path)
            weights, factors = sample_weights(dataset)
            self.assertAlmostEqual(float(weights[:2].sum() / factors["normal"]), 1.0, places=5)
            self.assertAlmostEqual(float(weights[2] / factors["dos_flood"]), 1.0, places=5)
            probabilities = np.asarray([[.99, .0025, .0025, .0025, .0025], [.98, .005, .005, .005, .005], [.1, .1, .1, .7, .0]], dtype=np.float32)
            self.assertGreaterEqual(select_alert_threshold(dataset, probabilities), 0.0)
            self.assertEqual(connection_scores(dataset, probabilities)[0].shape, (2, 5))
            self.assertEqual(set(connection_scores(dataset, probabilities)[2].tolist()), {"internal"})

    def test_first_threshold_snapshot_and_normal_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rows = [row("same", "dos_flood", "early"), row("same", "dos_flood", "late")]
            rows[0]["observationId"], rows[1]["observationId"] = "obs-early", "obs-late"
            dataset_path = root / "dataset.jsonl"
            dataset_path.write_text("\n".join(json.dumps(value) for value in rows) + "\n")
            metadata_path = root / "metadata.jsonl"
            metadata_path.write_text("\n".join(json.dumps({"observationId": value, "parentConnectionId": "same", "asOf": timestamp})
                                     for value, timestamp in (("obs-early", "2026-01-01T00:00:02Z"),
                                                               ("obs-late", "2026-01-01T00:00:01Z"))) + "\n")
            dataset = Dataset.load(dataset_path, metadata_path=metadata_path)
            probabilities = np.asarray([[.01, .0, .0, 1.0, .0], [.4, .0, .0, 1.0, .0]], dtype=np.float32)
            scores, *_ = connection_scores_at(dataset, probabilities, .5)
            self.assertAlmostEqual(float(scores[0, 0]), .6, places=5)
            fallback, *_ = connection_scores_at(dataset, probabilities, 1.0)
            self.assertEqual(float(fallback[0, 0]), 0.0)

    def test_source_false_positive_rate_is_equal_weighted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dataset.jsonl"
            rows = [row(f"internal-{i}", "normal") for i in range(3)]
            rows.append(row("website-0", "normal"))
            for value in rows[-1:]:
                value["websiteSupplement"] = True
            path.write_text("\n".join(json.dumps(value) for value in rows) + "\n")
            dataset = Dataset.load(path)
            probabilities = np.asarray([[.9, .025, .025, .025, .025]] * 3 +
                                       [[.1, .225, .225, .225, .225]], dtype=np.float32)
            report = metrics(dataset, probabilities, .5)
            self.assertAlmostEqual(report["falsePositiveRate"], .5, places=5)
            self.assertEqual(report["falsePositiveWeighting"], "equal-source-internal-website")


if __name__ == "__main__":
    unittest.main()
