"""整改阶段 2 的公开 PCAP 完整连接标签关联与冻结 v4 审计。

特征只能来自已登记的 Go sensor extract；本模块只检查字段并关联发布方标签。
逐流决定账本包含公开端点的哈希，留在 Git 忽略目录。它不训练、不评分、
不读取 holdout，不把候选或 Unknown 变成可信训练标签。
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import ipaddress
import json
import math
from pathlib import Path
import platform
import struct
import subprocess
import time

from cyber_training.source_screening import (
    MAX_PACKETS, MAX_PILOT_BYTES, MAX_ROWS, MAX_SECONDS, PCAP_MAGIC,
    digest, fingerprint, read_zeek, save_json, verify_license,
)

CONTRACT = "unsw-nb15-flow-v4"
SPEC_SHA256 = "dbba110432c2c381ec291e2ec373601256c7ca990efa3e7bdad405c25120c6f1"
MAX_OUTPUT_BYTES = 512 << 20
PROFILES = (
    ("somfy-lan", 0, "192.168.1.158", "192.168.1.0/24"),
    ("somfy-setup", 0, "192.168.4.2", "192.168.4.0/24"),
    ("muhstik", 1, "192.168.2.5", "192.168.2.0/24"),
)


def microseconds(value: str) -> int:
    """十进制秒精确转换微秒；非有限值、负值和亚微秒输入不得被静默舍入。"""
    try:
        result = Decimal(value) * 1_000_000
        if not result.is_finite() or result < 0 or result != result.to_integral_value():
            raise ValueError("invalid_time_precision")
        return int(result)
    except InvalidOperation as error:
        raise ValueError("invalid_time_precision") from error


def timestamp(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp_requires_timezone")
    delta = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    if delta.days < 0:
        raise ValueError("negative_timestamp")
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def endpoints(proto, source, sport, destination, dport):
    pair = ((str(ipaddress.ip_address(source)), int(sport)),
            (str(ipaddress.ip_address(destination)), int(dport)))
    if any(not 0 <= port <= 65535 for _, port in pair):
        raise ValueError("invalid_port")
    return proto, tuple(sorted(pair))


@dataclass
class Label:
    ordinal: int
    row: dict
    key: tuple
    start: int
    end: int | None
    candidate: str
    problem: str | None = None


def load_labels(path: Path, role: str, deadline: float):
    """完整连接要求时间区间、方向、包数/IP 字节与 missed_bytes，不按日程传播标签。"""
    labels = []
    by_key = defaultdict(list)
    uids = defaultdict(list)
    required = {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
                "duration", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
                "missed_bytes", "label", "detailed-label"}
    for index, row in enumerate(read_zeek(path, deadline)):
        if not required <= row.keys():
            raise ValueError("incomplete_label_schema")
        try:
            key = endpoints(row["proto"], row["id.orig_h"], row["id.orig_p"], row["id.resp_h"], row["id.resp_p"])
            start = microseconds(row["ts"])
        except ValueError:
            # 不能建立端点/时间索引的源行也保留明确排除决定。
            label = Label(index, row, ("invalid", index), 0, None, "Unknown", "invalid_label_key")
            labels.append(label)
            continue
        coarse = row["label"].casefold()
        candidate = "Unknown"
        if role == "dedicated_benign_device" and coarse == "benign" and row["detailed-label"] == "-":
            candidate = "Normal_candidate"
        elif role == "documented_malware_capture" and coarse == "malicious" and row["detailed-label"] != "-":
            candidate = "Attack_candidate"
        problem = None
        end = None
        try:
            counts = [int(row[name]) for name in ["orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"]]
            if any(value < 0 for value in counts):
                raise ValueError("negative_label_counter")
            if row["duration"] == "-":
                # Zeek 单包连接的 duration 可为空；仅用精确起点与完整包/字节计数证明单包。
                if sum(counts[:2]) != 1:
                    problem = "missing_multi_packet_duration"
                else:
                    end = start
            else:
                end = start + microseconds(row["duration"])
            if counts[-1] != 0:
                problem = "publisher_missed_bytes"
        except ValueError:
            problem = "invalid_label_counter_or_duration"
        label = Label(index, row, key, start, end, candidate, problem)
        labels.append(label)
        by_key[key].append(label)
        uids[row["uid"]].append(label)
    for rows in uids.values():
        if len(rows) > 1:
            for row in rows:
                row.problem = "duplicate_publisher_uid"
    for rows in by_key.values():
        rows.sort(key=lambda row: (row.start, row.ordinal))
        previous = None
        furthest = -1
        for label in rows:
            if previous is not None and label.start <= furthest + 1:
                previous.problem = label.problem = "overlapping_or_conflicting_label_intervals"
            if label.end is not None and label.end >= furthest:
                previous, furthest = label, label.end
    return labels, by_key


def find_label(flow: dict, index: dict, starts: dict):
    """允许最多一微秒的发布方时间舍入差，整个 sensor 切段必须落在唯一标签区间。"""
    proto = {6: "tcp", 17: "udp", 1: "icmp", 58: "ipv6-icmp"}.get(flow["protocol"], "other")
    key = endpoints(proto, flow["initiator"], flow["initiatorPort"], flow["responder"], flow["responderPort"])
    start, end = timestamp(flow["flowStartAt"]), timestamp(flow["flowEndAt"])
    candidates = index.get(key, [])
    position = bisect_right(starts.get(key, []), start + 1)
    found = []
    # 有重叠的源行不能被选择；前一完整区间包含该段才允许关联。
    for label in candidates[max(0, position - 2):position]:
        if label.end is not None and label.start - 1 <= start and end <= label.end + 1:
            found.append(label)
    if len(found) != 1:
        return None, "no_unique_full_interval_label"
    label = found[0]
    if label.problem:
        return None, label.problem
    if (flow["initiator"], flow["initiatorPort"], flow["responder"], flow["responderPort"]) != (
            label.row["id.orig_h"], int(label.row["id.orig_p"]), label.row["id.resp_h"], int(label.row["id.resp_p"])):
        return None, "publisher_sensor_direction_mismatch"
    return label, None


def full_connection_reason(label: Label, segments: list[dict]) -> str | None:
    """所有切段合并后与发布方双向原始包数、IP 字节、区间逐项一致，才称完整关联。"""
    if label.problem:
        return label.problem
    if not segments:
        return "no_unique_complete_sensor_connection"
    starts = [timestamp(flow["flowStartAt"]) for flow in segments]
    ends = [timestamp(flow["flowEndAt"]) for flow in segments]
    if abs(min(starts) - label.start) > 1 or label.end is None or abs(max(ends) - label.end) > 1:
        return "connection_interval_incomplete"
    totals = Counter()
    for flow in segments:
        length = flow.get("lengths")
        if not length or length.get("rawIPBytesReliable") is not True:
            return "raw_ip_length_unobservable"
        for key in ["initiatorRawPackets", "responderRawPackets", "initiatorRawIPBytes", "responderRawIPBytes"]:
            value = length.get(key)
            if type(value) is not int or value < 0:
                return "raw_packet_counter_invalid"
            totals[key] += value
    fields = {"initiatorRawPackets": "orig_pkts", "responderRawPackets": "resp_pkts",
              "initiatorRawIPBytes": "orig_ip_bytes", "responderRawIPBytes": "resp_ip_bytes"}
    if any(totals[key] != int(label.row[source]) for key, source in fields.items()):
        return "connection_packet_or_ip_byte_mismatch"
    return None


def read_jsonl(path: Path):
    if not path.is_file() or path.stat().st_size > MAX_OUTPUT_BYTES:
        raise ValueError("output_size_budget")
    out = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if len(line) > 65536 or len(out) >= MAX_ROWS:
                raise ValueError("output_row_budget")
            out.append(json.loads(line, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value))))
    return out


def pcap_quality(path: Path) -> dict:
    """只遍历经典 Ethernet 容器和最多 128 字节头部；内核丢包未知，不能报告零。"""
    result = Counter()
    first = last = None
    deadline = time.monotonic() + MAX_SECONDS
    with path.open("rb") as f:
        header = f.read(24)
        if len(header) != 24 or header[:4] not in PCAP_MAGIC:
            raise ValueError("unsupported_pcap_container")
        endian, scale = PCAP_MAGIC[header[:4]]
        major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or link != 1 or not 0 < snaplen <= (16 << 20):
            raise ValueError("unsupported_pcap_header")
        size = path.stat().st_size
        while raw := f.read(16):
            if len(raw) != 16 or result["frames"] >= MAX_PACKETS or time.monotonic() > deadline:
                raise ValueError("pcap_truncated_or_budget")
            sec, frac, cap, wire = struct.unpack(endian + "IIII", raw)
            if cap > wire or cap > snaplen or f.tell() + cap > size or frac * scale >= 1_000_000_000:
                raise ValueError("pcap_length_or_timestamp_invalid")
            tick = sec * 1_000_000_000 + frac * scale
            result["frames"] += 1
            result["snaplenShortenedFrames"] += cap < wire
            result["timestampReversals"] += last is not None and tick < last
            first = tick if first is None else min(first, tick)
            last = tick
            f.seek(cap, 1)
    if not result["frames"]:
        raise ValueError("empty_pcap")
    return {**dict(result), "containerTruncated": False, "kernelDrops": None,
            "kernelDropsEvidence": "Classic PCAP does not provide independently verified capture drop counters."}


def check_features(record: dict, flow: dict, contract: dict) -> list[str]:
    """字段顺序、有限数、窗口、公式、单位及端口类别按冻结文件检查；不产生特征。"""
    features = record.get("features")
    if record["status"] != "ready":
        return [record["status"]]
    names = [field["name"] for field in contract["numericFields"] + contract["categoricalFields"]]
    if not isinstance(features, dict) or list(features) != names:
        return ["feature_names_or_order"]
    errors = []
    for field in contract["numericFields"]:
        value = features[field["name"]]
        if type(value) not in (int, float) or not math.isfinite(value):
            errors.append(field["name"] + "|nonfinite_or_missing")
        elif value < field["min"] or value > field.get("max", math.inf) or (field["integer"] and value != int(value)):
            errors.append(field["name"] + "|range")
    if errors:
        return errors
    duration = (timestamp(flow["flowEndAt"]) - timestamp(flow["flowStartAt"])) / 1_000_000
    if duration < 0 or duration >= 60 or features["dur"] != duration:
        errors.append("dur|microsecond_interval_or_lifetime")
    for prefix in ["s", "d"]:
        packets, byte_count = features[prefix + "pkts"], features[prefix + "bytes"]
        expected = byte_count * 8 * (packets - 1) / packets / duration if packets > 1 and duration > 0 else 0
        if not math.isclose(features[prefix + "load"], expected, rel_tol=1e-12, abs_tol=1e-9):
            errors.append(prefix + "load|formula")
        mean = (2 * byte_count + packets) // (2 * packets) if packets else 0
        if features[prefix + "mean"] != mean or (packets == 0 and byte_count != 0):
            errors.append(prefix + "mean|packet_byte_consistency")
    proto = {6: "tcp", 17: "udp", 1: "icmp", 58: "ipv6-icmp"}.get(flow["protocol"])
    if proto is not None and features["proto"] != proto:
        errors.append("proto|iana_mapping")
    service = contract["serviceRules"]["portMap"].get(features["proto"] + "/" + str(flow["responderPort"]), "-")
    if features["service"] != service:
        errors.append("service|frozen_responder_port")
    if features["tcprtt"] != features["synack"] + features["ackdat"]:
        errors.append("tcprtt|sum")
    if features["proto"] != "tcp" and any(features[field] != 0 for field in ["tcprtt", "synack", "ackdat"]):
        errors.append("handshake|non_tcp")
    return errors


def model_scope_reasons(record: dict, flow: dict) -> list[str]:
    """复核 2026.10.2 的 IPv4/responder/TCP/首包 SYN 范围，不执行推理或改范围。"""
    reasons = []
    if record["addressFamily"] != "ipv4":
        reasons.append("address_family")
    if record["viewpoint"] != "responder":
        reasons.append("viewpoint_initiator")
    if flow["protocol"] != 6:
        reasons.append("protocol_not_tcp")
    if record["handshakeSeen"] is not True:
        reasons.append("handshake_not_seen")
    return reasons


def near_feature_signature(features: dict) -> str:
    """粗粒度近重复索引：时长 1 ms、握手 1 us、字节 64 B、均值 4 B、load 5% 对数桶。

    协议/service、包数和窗口计数保持精确。桶边界可能漏掉相近对；此索引只供复核，
    不能宣称不存在近重复，也不据此自动删行、造标签或建立独立分区。
    """
    values = {}
    for name, value in features.items():
        if name == "dur":
            values[name] = math.floor(value * 1000)
        elif name in ["tcprtt", "synack", "ackdat"]:
            values[name] = math.floor(value * 1_000_000)
        elif name in ["sbytes", "dbytes"]:
            values[name] = value // 64
        elif name in ["smean", "dmean"]:
            values[name] = value // 4
        elif name in ["sload", "dload"]:
            values[name] = "zero" if value == 0 else math.floor(math.log1p(value) / math.log(1.05))
        else:
            values[name] = value
    return fingerprint(values)


def audit_profile(labels_path: Path, role: str, directory: Path, contract: dict, output: Path) -> dict:
    """每条标签和 sensor 流均形成决定；完整关联、v4 ready、当前模型范围分别报告。"""
    labels, index = load_labels(labels_path, role, time.monotonic() + MAX_SECONDS)
    starts = {key: [label.start for label in rows] for key, rows in index.items()}
    flows = read_jsonl(directory / "flows.label-audit.jsonl")
    records = read_jsonl(directory / "records.jsonl")
    by_seq = {flow["exportSeq"]: flow for flow in flows}
    if len(by_seq) != len(flows) or len({row["exportSeq"] for row in records}) != len(records):
        raise ValueError("duplicate_sensor_export_sequence")
    attached = defaultdict(list)
    matches = {}
    for flow in flows:
        label, problem = find_label(flow, index, starts)
        matches[flow["exportSeq"]] = (label, problem)
        if label is not None:
            attached[label.ordinal].append(flow)
    label_reasons = {label.ordinal: full_connection_reason(label, attached[label.ordinal]) for label in labels}
    counts = Counter()
    label_decisions = Counter()
    details = Counter()
    protocols = Counter()
    scope = Counter()
    fields = {f["name"]: {"unit": f.get("unit", "categorical"), "missing": 0, "invalid": 0}
              for f in contract["numericFields"] + contract["categoricalFields"]}
    samples = []
    exact_features = Counter()
    near_features = Counter()
    exact_labels = defaultdict(set)
    connection_segments = Counter()
    dates = Counter()
    output.mkdir(parents=True, exist_ok=False)
    with (output / "label-decisions.jsonl").open("x", encoding="utf-8", newline="\n") as writer:
        for label in labels:
            reason = label_reasons[label.ordinal]
            target = label.candidate if reason is None else "Unknown"
            if target == "Unknown" and reason is None:
                reason = "background_or_unconfirmed_label"
            label_decisions[target + "|" + (reason or "complete_connection_verified")] += 1
            if label_reasons[label.ordinal] is None:
                counts["fullyJoinedPublisherConnections"] += 1
            writer.write(json.dumps({"labelOrdinal": label.ordinal, "publisherUidSha256": fingerprint(label.row["uid"]),
                                    "connectionGroupSha256": fingerprint([label.key, label.start, label.end]),
                                    "connectionLabelCandidate": target, "reason": reason,
                                    "sensorSegments": len(attached[label.ordinal]), "trainingEligible": False}) + "\n")
    flow_decisions = {}
    with (output / "flow-decisions.jsonl").open("x", encoding="utf-8", newline="\n") as writer:
        previous = None
        for record in records:
            seq = record["exportSeq"]
            flow = by_seq.get(seq)
            if flow is None or any(record[field] != flow[field] for field in ["flowStartAt", "flowEndAt", "closeReason"]):
                raise ValueError("record_audit_link_mismatch")
            order = (timestamp(record["flowEndAt"]), timestamp(record["flowStartAt"]), seq)
            if previous is not None and order <= previous:
                raise ValueError("nonmonotonic_feature_window")
            previous = order
            label, join_problem = matches[seq]
            feature_problems = check_features(record, flow, contract)
            reasons = [join_problem] if join_problem else []
            if label is not None:
                if label_reasons[label.ordinal]:
                    reasons.append(label_reasons[label.ordinal])
                if label.candidate == "Unknown":
                    reasons.append("background_or_unconfirmed_label")
            reasons += feature_problems
            accepted = not reasons and label is not None
            candidate = label.candidate if accepted else "Unknown"
            counts["records"] += 1
            counts["v4ReadyRecords"] += record["status"] == "ready"
            counts["v4InvalidReadyRecords"] += record["status"] == "ready" and bool(feature_problems)
            counts[candidate] += 1
            protocols[candidate + "|" + str(flow["protocol"])] += 1
            if label is not None and label_reasons[label.ordinal] is None:
                counts["fullyJoinedSensorSegments"] += 1
            for reason in reasons:
                details[reason] += 1
            for name, stats in fields.items():
                value = (record.get("features") or {}).get(name)
                stats["missing"] += value is None
                stats["invalid"] += any(problem.startswith(name + "|") for problem in feature_problems)
            model_reasons = model_scope_reasons(record, flow)
            if accepted:
                counts["currentModelScopeCandidates"] += not model_reasons
                for reason in model_reasons:
                    scope[reason] += 1
                exact_key = fingerprint(record["features"])
                near_key = near_feature_signature(record["features"])
                exact_features[exact_key] += 1
                near_features[near_key] += 1
                exact_labels[exact_key].add(label.candidate)
                connection_segments[label.ordinal] += 1
                day = datetime.fromisoformat(record["flowStartAt"].replace("Z", "+00:00")).astimezone(timezone.utc).date().isoformat()
                dates[day] += 1
            decision = {"exportSeq": seq, "recordKey": record["recordKey"],
                        "flowKeySha256": fingerprint([flow["initiator"], flow["responder"], flow["initiatorPort"],
                                                      flow["responderPort"], flow["protocol"], flow["flowStartAt"], flow["flowEndAt"]]),
                        "publisherLabelOrdinal": label.ordinal if label else None,
                        "connectionGroupSha256": fingerprint([label.key, label.start, label.end]) if label else None,
                        "candidate": candidate, "exclusionReasons": reasons,
                        "currentModelScopeExclusions": model_reasons, "trainingEligible": False}
            if accepted:
                decision.update({"exactFeatureSignature": exact_key, "nearFeatureSignature": near_key,
                                 "captureDayUtc": day})
            flow_decisions[seq] = decision
            if accepted and len(samples) < 8:
                samples.append(decision)
        for flow in flows:
            seq = flow["exportSeq"]
            if seq not in flow_decisions:
                exclusion = flow.get("excludedReason")
                if not exclusion:
                    raise ValueError("sensor_flow_disappeared_without_exclusion")
                label, problem = matches[seq]
                reasons = [exclusion]
                if problem:
                    reasons.append(problem)
                if label and label_reasons[label.ordinal]:
                    reasons.append(label_reasons[label.ordinal])
                flow_decisions[seq] = {"exportSeq": seq, "candidate": "Unknown", "exclusionReasons": reasons,
                                       "publisherLabelOrdinal": label.ordinal if label else None,
                                       "connectionGroupSha256": fingerprint([label.key, label.start, label.end]) if label else None,
                                       "trainingEligible": False}
                for reason in reasons:
                    details["address_excluded|" + reason] += 1
            writer.write(json.dumps(flow_decisions[seq], separators=(",", ":")) + "\n")
    counts["completedFlowsIncludingAddressExcluded"] = len(flows)
    counts["addressExcludedFlows"] = len(flows) - len(records)
    diag = json.loads((directory / "diagnostics.json").read_text())
    if sum(diag["feature"]["records_by_status"].values()) != len(records):
        raise ValueError("diagnostic_record_count_mismatch")
    return {"counts": dict(counts), "publisherLabelRows": len(labels), "labelDecisions": dict(label_decisions),
            "flowExclusionReasons": dict(details), "candidateProtocols": dict(protocols),
            "currentModelScopeExclusions": dict(scope), "fieldAvailability": fields,
            "diagnostics": diag, "samples": samples,
            "groupingAudit": {"candidateConnections": len(connection_segments),
                              "multiSegmentCandidateConnections": sum(value > 1 for value in connection_segments.values()),
                              "exactDuplicateFeatureRowsBeyondFirst": sum(value - 1 for value in exact_features.values()),
                              "nearDuplicateFeatureRowsBeyondFirst": sum(value - 1 for value in near_features.values()),
                              "conflictingLabelsOnExactFeatures": sum(len(value) > 1 for value in exact_labels.values()),
                              "captureDatesUtc": dict(dates), "verifiedIndependentActivities": 0,
                              "partitionedRows": 0, "crossPartitionLeakageStatus": "NOT_EVALUABLE_NO_PARTITIONS",
                              "nearDuplicateMethod": "duration_ms/handshake_us/bytes_64B/mean_4B/load_log_5pct; packet/window/category exact",
                              "limits": "Coarse candidate signature may miss boundary pairs; no rows removed and no independence or zero-leakage claim."},
            "ledgerChecksums": {name: digest(output / name) for name in ["label-decisions.jsonl", "flow-decisions.jsonl"]},
            "inputChecksums": {name: digest(directory / name) for name in ["records.jsonl", "flows.label-audit.jsonl", "diagnostics.json"]}}


def verify_source(data: Path, evidence: Path, metadata: Path) -> list[dict]:
    """复核阶段 1 的许可与官方单成员快照；不接受另一个相似文件名或可编辑布尔值。"""
    verify_license(evidence / "license-review-v1.json", metadata)
    pilot = json.loads((evidence / "source-screening-pilot-v2.json").read_text(encoding="utf-8"))
    spec = json.loads((evidence / "scenario-spec-v1.json").read_text(encoding="utf-8"))
    if pilot["sourceId"] != "IoT-23/1.0.0" or pilot["scenarioSpecSha256"] != digest(evidence / "scenario-spec-v1.json"):
        raise ValueError("source_identity_mismatch")
    if pilot["licenseReviewSha256"] != digest(evidence / "license-review-v1.json"):
        raise ValueError("license_binding_mismatch")
    if len(spec["scenarios"]) != 2 or len(pilot["scenarios"]) != 2:
        raise ValueError("pilot_scope_changed")
    total = 0
    for config, frozen in zip(spec["scenarios"], pilot["scenarios"]):
        if config["scenarioId"] != frozen["scenarioId"] or config["role"] != frozen["role"]:
            raise ValueError("scenario_identity_changed")
        for key, size_key in [("pcap", "pcapBytes"), ("labels", "labelBytes")]:
            name = config[key]
            if Path(name).name != name or "\\" in name:
                raise ValueError("source_path_escape")
            member = data / name
            if member.stat().st_size != frozen[size_key] or digest(member) != frozen[key + "Sha256"]:
                raise ValueError("source_content_changed")
            total += member.stat().st_size
    if total > MAX_PILOT_BYTES:
        raise ValueError("pilot_byte_budget")
    return spec["scenarios"]


def run(data: Path, evidence: Path, metadata: Path, contract_path: Path, spec_path: Path,
        extractor: Path, output: Path, expected_extractor_sha: str, application_head: str,
        imported_extraction: Path | None = None, bundle_sha256: str | None = None) -> dict:
    """只执行哈希已登记的传感器 extract；新建输出、不联网、不接生产 API。"""
    if output.exists():
        raise FileExistsError("output_already_exists")
    scenarios = verify_source(data, evidence, metadata)
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    if contract["version"] != CONTRACT or contract["specSha256"] != SPEC_SHA256 or digest(spec_path) != SPEC_SHA256:
        raise ValueError("frozen_contract_mismatch")
    if digest(extractor) != expected_extractor_sha:
        raise ValueError("extractor_content_changed")
    extraction_context = {"runtime": platform.system().lower() + "/" + platform.machine().lower(),
                          "extractorSha256": digest(extractor),
                          "windowsNativeExtractionVerified": platform.system() == "Windows"}
    if imported_extraction is not None:
        manifest_path = imported_extraction / "provenance.json"
        if not bundle_sha256 or digest(manifest_path) != bundle_sha256:
            raise ValueError("extraction_bundle_manifest_changed")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_paths = {profile + "/" + name for profile, *_ in PROFILES
                          for name in ["records.jsonl", "flows.label-audit.jsonl", "diagnostics.json"]}
        if (manifest.get("version") != "remediation-phase2-extraction-bundle-v1"
                or set(manifest["files"]) != expected_paths or manifest["specSha256"] != SPEC_SHA256
                or manifest["contractSha256"] != digest(contract_path)
                or manifest["stage1PilotSha256"] != digest(evidence / "source-screening-pilot-v2.json")
                or manifest["runtime"] != "darwin/arm64"):
            raise ValueError("extraction_bundle_identity_mismatch")
        for scenario in scenarios:
            for kind in ["pcap", "labels"]:
                if manifest["sourceHashes"].get(scenario[kind]) != digest(data / scenario[kind]):
                    raise ValueError("extraction_bundle_source_mismatch")
        for name, expected in manifest["files"].items():
            if digest(imported_extraction / name) != expected:
                raise ValueError("extraction_bundle_output_changed")
        extraction_context = {"runtime": manifest["runtime"], "extractorSha256": manifest["extractorSha256"],
                              "applicationSourceHashes": manifest["applicationSourceHashes"],
                              "bundleManifestSha256": bundle_sha256, "windowsNativeExtractionVerified": False,
                              "windowsBlockedReason": "OS application control rejected native extractor with WinError 4551.",
                              "attemptedWindowsExtractorSha256": digest(extractor)}
    quality = {s["scenarioId"]: pcap_quality(data / s["pcap"]) for s in scenarios}
    if any(report["timestampReversals"] for report in quality.values()):
        raise ValueError("pcap_must_be_time_ordered")
    output.mkdir(parents=True, exist_ok=False)
    reports = []
    for profile, scenario_index, host, subnet in PROFILES:
        scenario = scenarios[scenario_index]
        if imported_extraction is None:
            directory = output / profile
            directory.mkdir()
            command = [str(extractor.resolve()), "extract", "-pcap", str((data / scenario["pcap"]).resolve()),
                       "-local-addr", host, "-subnet", subnet, "-key-base", profile,
                       "-out", str(directory / "records.jsonl"), "-diagnostics", str(directory / "diagnostics.json"),
                       "-label-audit", str(directory / "flows.label-audit.jsonl")]
            subprocess.run(command, check=True, timeout=MAX_SECONDS, capture_output=True)
        else:
            directory = imported_extraction / profile
        report = audit_profile(data / scenario["labels"], scenario["role"], directory, contract,
                               output / profile / "decisions")
        report.update({"profile": profile, "scenarioId": scenario["scenarioId"],
                       "localHostSha256": fingerprint(host), "localHostCount": 1,
                       "subnetBasis": "Explicit offline /24 private-subnet parameter; publisher interface mask not independently verified.",
                       "grouping": "scenario/capture/day/local-host/publisher-connection; all sensor segments share connectionGroupSha256",
                       "activityEvidence": "Publisher labeled conn.log and scenario description only; no independent host-event log accepted."})
        reports.append(report)
    counts = Counter()
    for report in reports:
        counts.update(report["counts"])
    # 同一 Somfy capture 按两台独立主机提取，不把其完整连接重复计为独立样本。
    per_capture = {}
    for report in reports:
        per_capture.setdefault(report["scenarioId"], report["counts"]["fullyJoinedPublisherConnections"])
    counts["fullyJoinedPublisherConnections"] = sum(per_capture.values())
    blockers = []
    if counts["Normal_candidate"] == 0:
        blockers.append("No uniquely joined v4-ready Normal; Somfy per-host windows never reach 100 flows.")
    if counts["currentModelScopeCandidates"] == 0:
        blockers.append("No accepted candidate in current IPv4/responder/TCP/handshake model scope.")
    blockers.append("Independent activity/event evidence, second-person labels and partitions are not accepted.")
    if not extraction_context["windowsNativeExtractionVerified"]:
        blockers.append("Native Windows extractor/runtime parity remains unverified: OS application control.")
    result = {"version": "remediation-phase2-feature-pilot-v1", "phase": "remediation-phase2",
              "sourceId": "IoT-23/1.0.0", "phase2AuditComplete": True,
              "sourceAcceptedForPhase3": not blockers, "nextPhase": "phase1_find_independent_benign_source",
              "contract": CONTRACT, "contractSha256": digest(contract_path), "specSha256": SPEC_SHA256,
              "auditorSha256": digest(Path(__file__)), "extractionContext": extraction_context,
              "extractorApplicationBaseHead": application_head,
              "sourceStage1ReportSha256": digest(evidence / "source-screening-pilot-v2.json"),
              "licenseReviewSha256": digest(evidence / "license-review-v1.json"),
              "pcapQuality": quality, "profiles": reports, "aggregateCounts": dict(counts),
              "trainingEligibleRows": 0, "trustedLabelsHumanReviewed": False,
              "independentActivityLogJoinVerified": False, "independentPartitionsFrozen": False,
              "readinessStatus": "BLOCKED", "trainingAuthorized": False,
              "trainingExecuted": False, "predictionsExecuted": 0, "holdoutRead": False,
              "modelExportExecuted": False, "actionsExecuted": 0,
              "routeBlockers": blockers,
              "limits": ["Classical PCAP capture drop counters and publisher subnet masks are not independently verified.",
                         "Complete join is conservative: time, direction, packet/IP bytes must all match; ambiguous connections remain Unknown.",
                         "Candidate counts are not trusted training labels; no split, threshold, prediction or model was generated."]}
    save_json(output / "report.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["data", "evidence", "metadata", "contract", "spec", "extractor", "out"]:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--extractor-sha256", required=True)
    parser.add_argument("--application-head", required=True)
    parser.add_argument("--imported-extraction", type=Path, help="仅使用已绑定来源/文件哈希的 Mac 离线输出，不宣称 Windows 原生提取已验证")
    parser.add_argument("--bundle-sha256", help="独立登记的 provenance.json SHA-256")
    args = parser.parse_args()
    result = run(args.data, args.evidence, args.metadata, args.contract, args.spec, args.extractor,
                 args.out, args.extractor_sha256, args.application_head, args.imported_extraction, args.bundle_sha256)
    print(json.dumps({key: result[key] for key in ["phase2AuditComplete", "sourceAcceptedForPhase3",
                                                 "aggregateCounts", "trainingEligibleRows", "trainingAuthorized"]}))


if __name__ == "__main__":
    main()
