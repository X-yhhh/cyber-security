"""阶段 2 门禁回归：完整关联、切段、Unknown 和字段失败关闭；不读取真实 holdout。"""
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cyber_training import feature_pilot as p


def label(duration="2.000000", packets=2, candidate="Attack_candidate"):
    row = {"uid": "public-fixture", "ts": "1700000000", "duration": duration,
           "id.orig_h": "192.0.2.1", "id.orig_p": "1234", "id.resp_h": "192.0.2.2", "id.resp_p": "80",
           "orig_pkts": str(packets), "resp_pkts": "1", "orig_ip_bytes": str(packets * 40),
           "resp_ip_bytes": "40", "proto": "tcp", "missed_bytes": "0",
           "label": "Malicious", "detailed-label": "Attack"}
    return p.Label(0, row, p.endpoints("tcp", "192.0.2.1", 1234, "192.0.2.2", 80),
                   1700000000000000, 1700000002000000, candidate)


def flow(start="2023-11-14T22:13:20Z", end="2023-11-14T22:13:22Z", packets=2, reverse=1):
    return {"exportSeq": 1, "flowStartAt": start, "flowEndAt": end,
            "initiator": "192.0.2.1", "responder": "192.0.2.2", "initiatorPort": 1234,
            "responderPort": 80, "protocol": 6, "closeReason": "idle_timeout",
            "lengths": {"initiatorRawPackets": packets, "responderRawPackets": reverse,
                        "initiatorRawIPBytes": packets * 40, "responderRawIPBytes": reverse * 40,
                        "rawIPBytesReliable": True}}


def contract_and_record():
    numeric = ["dur", "sbytes", "dbytes", "sload", "dload", "tcprtt", "ackdat", "synack", "smean", "dmean",
               "spkts", "dpkts", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm"]
    values = [2, 80, 40, 160, 0, .2, .1, .1, 40, 40, 2, 1, 1, 1, 1, 1, 1]
    contract = {"numericFields": [{"name": name, "unit": "fixture", "min": 0, "integer": False} for name in numeric],
                "categoricalFields": [{"name": "proto"}, {"name": "service"}],
                "serviceRules": {"portMap": {"tcp/80": "http"}}}
    record = {"recordKey": "fixture:1", "exportSeq": 1, "flowStartAt": "2023-11-14T22:13:20Z",
              "flowEndAt": "2023-11-14T22:13:22Z", "status": "ready", "closeReason": "idle_timeout",
              "addressFamily": "ipv4", "viewpoint": "responder", "handshakeSeen": True,
              "features": {**dict(zip(numeric, values)), "proto": "tcp", "service": "http"}}
    return contract, record


def write_labels(path, rows):
    fields = list(rows[0])
    path.write_text("#fields\t" + "\t".join(fields) + "\n" +
                    "".join("\t".join(row[name] for name in fields) + "\n" for row in rows), encoding="utf-8")


class FeaturePilotTest(unittest.TestCase):
    def test_microseconds_are_exact(self):
        self.assertEqual(p.microseconds("1.000001"), 1000001)
        for value in ["NaN", "Infinity", "-1", "1.0000001", "-"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                p.microseconds(value)

    def test_timestamp_requires_timezone(self):
        self.assertEqual(p.timestamp("2023-11-14T22:13:20Z"), 1700000000000000)
        with self.assertRaises(ValueError):
            p.timestamp("2023-11-14T22:13:20")

    def test_partial_packet_match_is_not_a_full_connection(self):
        self.assertEqual(p.full_connection_reason(label(), [flow(packets=1)]), "connection_packet_or_ip_byte_mismatch")

    def test_missing_ip_bytes_rejects_even_matching_packets(self):
        sample = flow()
        sample["lengths"].pop("rawIPBytesReliable")
        self.assertEqual(p.full_connection_reason(label(), [sample]), "raw_ip_length_unobservable")

    def test_segmented_connection_can_be_proved_by_aggregate(self):
        first = flow(end="2023-11-14T22:13:21Z", packets=1, reverse=0)
        second = flow(start="2023-11-14T22:13:21.000001Z", packets=1)
        self.assertIsNone(p.full_connection_reason(label(), [first, second]))

    def test_partial_duration_rejects_even_matching_counts(self):
        self.assertEqual(p.full_connection_reason(label(), [flow(end="2023-11-14T22:13:21Z")]),
                         "connection_interval_incomplete")

    def test_missing_labels_never_propagate_across_tuple(self):
        sample = flow(start="2023-11-14T22:13:23Z", end="2023-11-14T22:13:24Z")
        row = label()
        found, reason = p.find_label(sample, {row.key: [row]}, {row.key: [row.start]})
        self.assertIsNone(found)
        self.assertEqual(reason, "no_unique_full_interval_label")

    def test_reverse_direction_is_explicitly_excluded(self):
        sample = flow()
        sample["initiator"], sample["responder"] = sample["responder"], sample["initiator"]
        sample["initiatorPort"], sample["responderPort"] = sample["responderPort"], sample["initiatorPort"]
        row = label()
        self.assertEqual(p.find_label(sample, {row.key: [row]}, {row.key: [row.start]})[1],
                         "publisher_sensor_direction_mismatch")

    def test_overlap_and_conflict_stay_unknown(self):
        row = label()
        second = deepcopy(row)
        second.ordinal = 1
        self.assertEqual(p.find_label(flow(), {row.key: [row, second]}, {row.key: [row.start, row.start]})[1],
                         "no_unique_full_interval_label")

    def test_model_scope_is_not_the_contract_scope(self):
        record = {"addressFamily": "ipv4", "viewpoint": "initiator", "handshakeSeen": True}
        self.assertEqual(p.model_scope_reasons(record, flow()), ["viewpoint_initiator"])

    def test_nonready_never_has_synthetic_features(self):
        self.assertEqual(p.check_features({"status": "window_not_ready", "features": None}, flow(), {}),
                         ["window_not_ready"])

    def test_ready_requires_all_nineteen_fields_in_order(self):
        contract = {"numericFields": [{"name": "dur"}], "categoricalFields": [{"name": "proto"}]}
        self.assertEqual(p.check_features({"status": "ready", "features": {"proto": "tcp", "dur": 2}}, flow(), contract),
                         ["feature_names_or_order"])

    def test_jsonl_duplicate_or_nonfinite_data_not_silently_normalized(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "records.jsonl"
            path.write_text('{"value":NaN}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                p.read_jsonl(path)

    def test_output_is_never_overwritten(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            p.save_json(path, {"trainingAuthorized": False})
            with self.assertRaises(FileExistsError):
                p.save_json(path, {"trainingAuthorized": True})

    def test_no_full_join_without_segments(self):
        self.assertEqual(p.full_connection_reason(label(), []), "no_unique_complete_sensor_connection")

    def test_missed_bytes_poison_the_complete_connection(self):
        row = label()
        row.problem = "publisher_missed_bytes"
        self.assertEqual(p.full_connection_reason(row, [flow()]), "publisher_missed_bytes")

    def test_single_packet_missing_duration_is_bounded(self):
        row = label(duration="-", packets=1)
        row.row["resp_pkts"], row.row["resp_ip_bytes"] = "0", "0"
        row.end = row.start
        self.assertIsNone(p.full_connection_reason(row, [flow(end="2023-11-14T22:13:20Z", packets=1, reverse=0)]))

    def test_bad_load_formula_is_rejected(self):
        contract, record = contract_and_record()
        self.assertEqual(p.check_features(record, flow(), contract), [])
        record["features"]["sload"] *= 2
        self.assertEqual(p.check_features(record, flow(), contract), ["sload|formula"])

    def test_unobservable_field_is_not_defaulted_to_zero(self):
        contract, record = contract_and_record()
        record["features"]["ackdat"] = None
        self.assertEqual(p.check_features(record, flow(), contract), ["ackdat|nonfinite_or_missing"])

    def test_service_uses_responder_port_not_publisher_service(self):
        contract, record = contract_and_record()
        record["features"]["service"] = "ssl"
        self.assertEqual(p.check_features(record, flow(), contract), ["service|frozen_responder_port"])

    def test_near_duplicates_keep_protocol_and_packet_evidence(self):
        _, record = contract_and_record()
        changed = deepcopy(record["features"])
        changed["dur"] += .0001
        self.assertEqual(p.near_feature_signature(record["features"]), p.near_feature_signature(changed))
        changed["spkts"] += 1
        self.assertNotEqual(p.near_feature_signature(record["features"]), p.near_feature_signature(changed))

    def test_near_duplicate_audit_does_not_mutate_features(self):
        _, record = contract_and_record()
        before = deepcopy(record["features"])
        p.near_feature_signature(record["features"])
        self.assertEqual(before, record["features"])

    def test_feature_groups_do_not_claim_independent_partitions(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            write_labels(directory / "conn.log", [label().row])
            contract, record = contract_and_record()
            (directory / "records.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
            (directory / "flows.label-audit.jsonl").write_text(json.dumps(flow()) + "\n", encoding="utf-8")
            (directory / "diagnostics.json").write_text(json.dumps({"feature": {"records_by_status": {"ready": 1}}}), encoding="utf-8")
            report = p.audit_profile(directory / "conn.log", "documented_malware_capture", directory, contract, directory / "decisions")
            self.assertEqual(report["groupingAudit"]["partitionedRows"], 0)
            self.assertEqual(report["groupingAudit"]["crossPartitionLeakageStatus"], "NOT_EVALUABLE_NO_PARTITIONS")

    def test_load_labels_missing_multi_packet_duration_is_unknown(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "conn.log"
            write_labels(path, [label(duration="-").row])
            rows, _ = p.load_labels(path, "documented_malware_capture", p.time.monotonic() + 10)
            self.assertEqual(rows[0].problem, "missing_multi_packet_duration")
            self.assertIsNone(rows[0].end)

    def test_background_in_malware_capture_stays_unknown(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "conn.log"
            row = label().row
            row["label"], row["detailed-label"] = "Benign", "-"
            write_labels(path, [row])
            rows, _ = p.load_labels(path, "documented_malware_capture", p.time.monotonic() + 10)
            self.assertEqual(rows[0].candidate, "Unknown")

    def test_label_file_duplicate_uid_is_unknown(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "conn.log"
            first, second = label().row, label().row
            second["ts"] = "1700000010"
            write_labels(path, [first, second])
            rows, _ = p.load_labels(path, "documented_malware_capture", p.time.monotonic() + 10)
            self.assertTrue(all(row.problem == "duplicate_publisher_uid" for row in rows))

    def test_every_accepted_or_excluded_flow_has_ledger_decision(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "conn.log"
            write_labels(source, [label().row])
            contract, record = contract_and_record()
            excluded = flow()
            excluded["exportSeq"], excluded["excludedReason"] = 2, "no_local_endpoint"
            (directory / "records.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
            (directory / "flows.label-audit.jsonl").write_text(json.dumps(flow()) + "\n" + json.dumps(excluded) + "\n", encoding="utf-8")
            (directory / "diagnostics.json").write_text(json.dumps({"feature": {"records_by_status": {"ready": 1}}}), encoding="utf-8")
            report = p.audit_profile(source, "documented_malware_capture", directory, contract, directory / "decisions")
            ledger = p.read_jsonl(directory / "decisions/flow-decisions.jsonl")
            self.assertEqual(len(ledger), 2)
            self.assertEqual(ledger[1]["exclusionReasons"][0], "no_local_endpoint")
            self.assertTrue(all(row["trainingEligible"] is False for row in ledger))
            self.assertNotIn("192.0.2.", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
