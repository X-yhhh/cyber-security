#!/usr/bin/env python3
"""从 lab report-input 生成、签名或核验 G3 报告。纯文件工具，无网络、数据库或防火墙副作用。

签名复用 P5 平台报告的同一封装与私钥规则（scripts/p5/platform_report.py：Ed25519 签 RFC8785 JCS，
私钥 PKCS8 DER、仓库外、权限 0600）；验签沿用后端 GuardSignatures.report 的 report-trust-file 格式
`{keyId: base64(X509-DER 公钥)}`，不新造信任根。只用合成会话数据测试，不产生正式成绩。
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "p5"))
import platform_report  # noqa: E402  复用既有报告签名与私钥检查；该模块同时把仓库根加入 sys.path
from executor.common import Rejected, canonical  # noqa: E402

VERSION_1_0 = "host-guard-lab/1.0"
VERSION_1_1 = "host-guard-lab/1.1"
VERSION = VERSION_1_0
REPORT = "host-guard-g3-report/1.0"
FAMILIES = {"port_scan", "brute_force", "dos_flood", "dos_slow"}
LIMITATIONS = [
    "L3 slow attacks detected 0/29; difficult benign false alerts 0/42; historical results unchanged",
    "L2 not evaluated; L1 shares dataset and tools across splits",
    "Cumulative concurrent scenario time is not continuous single-host time",
    "No class qualification, release approval or activation is granted by this report",
]


class InvalidReport(ValueError):
    """输入或完整性失败，调用方须保留未验证状态。"""


def require(condition, code):
    if not condition:
        raise InvalidReport(code)


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def timestamp(value):
    require(isinstance(value, str) and value.endswith("Z"), "LAB_TIME_INVALID")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def iso(value):
    if value is None:
        return None
    # 与 java.time.Instant 一致，分数秒按三位一组输出。
    precision = "seconds" if value.microsecond == 0 else "milliseconds" if value.microsecond % 1000 == 0 else "microseconds"
    return value.isoformat(timespec=precision).replace("+00:00", "Z")


def millis(start, end):
    if end is None:
        return None
    delta = end - start
    micros = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
    return (1 if micros >= 0 else -1) * (abs(micros) // 1000)


def first(events, predicate):
    values = [timestamp(e["occurredAt"]) for e in events if predicate(e) and isinstance(e.get("occurredAt"), str)]
    return min(values) if values else None


def verified(event, *statuses):
    return event.get("kind") == "verified_receipt" and event.get("verification") == "verified" and event.get("status") in statuses


def scenario_offsets(session, scenarios):
    """v1.1 为每个场景冻结独立平移；v1.0 保持会话单一偏移。"""
    value = session["time"].get("offsetMicros")
    require(type(value) is int and -9007199254740991 <= value <= 9007199254740991, "LAB_OFFSET_INVALID")
    base = timedelta(microseconds=value)
    require(timestamp(session["time"]["sourceStart"]) + base == timestamp(session["time"]["labStart"]), "LAB_OFFSET_INVALID")
    version = session["contractVersion"]
    if version == VERSION_1_0:
        require("scenarioOffsets" not in session["time"], "LAB_CONTRACT_INVALID")
        return {s["scenarioId"]: base for s in scenarios}
    require(version == VERSION_1_1, "LAB_CONTRACT_INVALID")
    offsets = session["time"].get("scenarioOffsets")
    require(isinstance(offsets, dict) and offsets and set(offsets) == {s["scenarioId"] for s in scenarios}, "LAB_OFFSET_INVALID")
    result = {}
    for sid, raw in offsets.items():
        require(type(raw) is int and -9007199254740991 <= raw <= 9007199254740991, "LAB_OFFSET_INVALID")
        result[sid] = timedelta(microseconds=raw)
    return result


def generate(data):
    """与 GuardLabReport 对拍；缺失 applied/cleanup 从不由 TTL 或完成状态补齐。"""
    require(set(data) == {"contractVersion", "session", "sessionSha256", "runStatus", "scenarios", "events", "unlinkedCommandIds", "unlinkedDecisionIds", "outsideScoringDecisionIds"}, "LAB_INPUT_INVALID")
    p = data["session"]
    require(data["contractVersion"] in {VERSION_1_0, VERSION_1_1} and p["contractVersion"] == data["contractVersion"] and p["environment"] == "lab", "LAB_CONTRACT_INVALID")
    require(digest(p) == data["sessionSha256"], "LAB_REPORT_MISMATCH")
    require(p["evidenceKind"] in {"synthetic", "lab"} and p["speed"] == 1, "LAB_CONTRACT_INVALID")
    require(isinstance(data["scenarios"], list) and 0 < len(data["scenarios"]) <= 64 and len(data["events"]) <= 20000, "LAB_INPUT_INVALID")
    for key in ("unlinkedCommandIds", "unlinkedDecisionIds", "outsideScoringDecisionIds"):
        require(isinstance(data[key], list) and all(isinstance(item, str) for item in data[key]), "LAB_INPUT_INVALID")
    ids = [s["scenarioId"] for s in data["scenarios"]]
    require(len(ids) == len(set(ids)), "LAB_SCENARIO_INVALID")
    offsets = scenario_offsets(p, data["scenarios"])
    rows, represented, normal_commands, normal_expired, intervals = [], set(), set(), set(), []
    normal_ms = 0
    uncertain, failed, not_evaluated = bool(data["unlinkedCommandIds"] or data["unlinkedDecisionIds"]), False, False
    for s in data["scenarios"]:
        sid, family = s["scenarioId"], s["family"]
        require(family in FAMILIES | {"normal"}, "LAB_SCENARIO_INVALID")
        normal = family == "normal"
        events = [e for e in data["events"] if e.get("scenarioId") == sid]
        complete = any(e.get("kind") == "scenario_result" and e.get("completed") is True for e in events)
        offset = offsets[sid]
        start, end = timestamp(s["sourceStart"]) + offset, timestamp(s["sourceEnd"]) + offset
        require(end > start, "LAB_TIME_INVALID")
        alert = first(events, lambda e: e.get("kind") == "decision" and e.get("decision") in {"alert", "block_candidate"})
        for e in events:
            if isinstance(e.get("decisionAt"), str) and e.get("decision") in {"alert", "block_candidate"}:
                at = timestamp(e["decisionAt"])
                alert = at if alert is None else min(alert, at)
        command_ids = sorted({e["commandId"] for e in events if isinstance(e.get("commandId"), str)})
        commands, applied_times, cleared_times, issued_times = [], [], [], []
        cleanup_missing, unknown_install, has_applied = False, False, False
        for command_id in command_ids:
            ce = [e for e in events if e.get("commandId") == command_id]
            issued = first(ce, lambda e: e.get("kind") == "command")
            for e in ce:
                if isinstance(e.get("issuedAt"), str):
                    at = timestamp(e["issuedAt"])
                    issued = at if issued is None else min(issued, at)
            if issued is not None:
                issued_times.append(issued)
            applied = first(ce, lambda e: verified(e, "applied"))
            cleared = first(ce, lambda e: verified(e, "expired", "revoked", "rejected"))
            rejected = any(verified(e, "rejected") for e in ce)
            if applied is not None:
                has_applied = True
                applied_times.append(applied)
                if normal:
                    normal_commands.add(command_id)
            if normal and any(verified(e, "expired") for e in ce):
                normal_expired.add(command_id)
            if cleared is None or issued is None:
                cleanup_missing = True
            if applied is None and not rejected:
                unknown_install = True
            if cleared is not None:
                cleared_times.append(cleared)
            if (issued is not None and applied is not None and applied < issued) or (applied is not None and cleared is not None and cleared < applied):
                cleanup_missing = True
            commands.append(dict(commandId=command_id, issuedAt=iso(issued), appliedAt=iso(applied), clearedAt=iso(cleared),
                                 installation="verified" if applied is not None else "rejected" if rejected else "unverified",
                                 cleanup="unverified" if cleared is None else "verified"))
        first_applied = min(applied_times) if applied_times else None
        final_cleared = max(cleared_times) if cleared_times else None
        first_issued = min(issued_times) if issued_times else None
        q = s["quality"]
        require(type(q["snapshots"]) is int and 0 <= q["snapshots"] <= 100000, "LAB_QUALITY_INVALID")
        for key in ("qualified", "offloadSuspected", "unknown", "indeterminate"):
            require(type(q[key]) is int and 0 <= q[key] <= q["snapshots"], "LAB_QUALITY_INVALID")
        require(type(q['executionQualified']) is int and 0 <= q['executionQualified'] <= q['qualified'], 'LAB_QUALITY_INVALID')
        quality_unknown = q["snapshots"] == 0
        quality_blocks = s["trialAutoEligible"] and q["executionQualified"] == 0
        if cleanup_missing or unknown_install or quality_unknown:
            status = "unverified"
        elif not complete:
            status = "not_evaluated"
        elif not normal and (alert is None or (s["trialAutoEligible"] and not has_applied) or quality_blocks):
            status = "failed"
        else:
            status = "passed"
        if not normal:
            represented.add(family)
        if normal and complete:
            normal_ms += millis(start, end)
            intervals.append((start, end))
        reasons = sorted({e["reasonCode"] for e in events if isinstance(e.get("reasonCode"), str)})
        missing = []
        if not complete:
            missing.append("scenario_result")
        if not normal and alert is None:
            missing.append("qualified_alert")
        if s["trialAutoEligible"] and not has_applied:
            missing.append("verified_application")
        if quality_blocks:
            missing.append("executable_observation")
        if cleanup_missing:
            missing.append("verified_cleanup")
        if unknown_install:
            missing.append("installation_history")
        if quality_unknown:
            missing.append("quality_population")
        rows.append(dict(scenarioId=sid, family=family, source=s["source"], ruleId=s["ruleId"], trialAutoEligible=s["trialAutoEligible"],
                         autoIneligibleReason=s["autoIneligibleReason"], status=status, completed=complete, originalStart=s["sourceStart"], labStart=iso(start),
                         firstAlertAt=iso(alert), firstIssuedAt=iso(first_issued), firstAppliedAt=iso(first_applied), lastClearedAt=iso(final_cleared),
                         alertLatencyMs=millis(start, alert), issueLatencyMs=millis(start, first_issued), applicationLatencyMs=millis(start, first_applied),
                         cleanupLatencyMs=millis(start, final_cleared), commands=commands, quality=q,
                         qualifiedCoverage=None if q["snapshots"] == 0 else q["qualified"] / q["snapshots"],
                         executionQualifiedCoverage=None if q["snapshots"] == 0 else q["executionQualified"] / q["snapshots"],
                         missing=missing, rejectionReasons=reasons))
        uncertain |= status == "unverified"
        failed |= status == "failed"
        not_evaluated |= status == "not_evaluated"
    missing_classes = sorted(FAMILIES - represented)
    not_evaluated |= bool(missing_classes)
    union_ms, start, end = 0, None, None
    for left, right in sorted(intervals):
        if start is None:
            start, end = left, right
        elif left <= end:
            end = max(end, right)
        else:
            union_ms += millis(start, end)
            start, end = left, right
    if start is not None:
        union_ms += millis(start, end)
    false_blocks = len(normal_commands)
    ttl_restored = normal_commands.issubset(normal_expired)
    normal_passed = normal_ms >= 1800000 and false_blocks * 3600000 <= normal_ms and ttl_restored
    if normal_ms > 0 and not normal_passed:
        failed = True
    elif normal_ms == 0:
        not_evaluated = True
    if data["runStatus"] != "completed":
        not_evaluated = True
    computed = "failed" if failed else "unverified" if uncertain else "not_evaluated" if not_evaluated else "passed"
    status = "unverified" if p["evidenceKind"] == "synthetic" else computed
    # 第 9 节逐类结果：四个攻击类按名称排序，状态取该类场景最差结果；与 GuardLabReport 同序同口径。
    classes = []
    for family in sorted(FAMILIES):
        members = [r for r in rows if r["family"] == family]
        alerts = [r["alertLatencyMs"] for r in members if r["alertLatencyMs"] is not None]
        applies = [r["applicationLatencyMs"] for r in members if r["applicationLatencyMs"] is not None]
        classes.append(dict(family=family, scenarioIds=[r["scenarioId"] for r in members],
                            sources=sorted({f"rule:{r['ruleId']}" if r["source"] == "rule" else "model" for r in members}),
                            status=aggregate({r["status"] for r in members}), trialAutoEligible=any(r["trialAutoEligible"] for r in members),
                            firstAlertLatencyMs=min(alerts) if alerts else None, firstApplicationLatencyMs=min(applies) if applies else None))
    # 第 9 节未验证项：只汇总已计算的缺口，顺序固定。
    unverified_items = [f"scenario:{r['scenarioId']}:{m}" for r in rows for m in r["missing"]]
    unverified_items += [f"class:{c}:no_scenario" for c in missing_classes]
    unverified_items += [f"command:{c}:unlinked" for c in data["unlinkedCommandIds"]]
    unverified_items += [f"decision:{d}:unlinked" for d in data["unlinkedDecisionIds"]]
    if normal_ms == 0:
        unverified_items.append("normal:not_evaluated")
    if data["runStatus"] != "completed":
        unverified_items.append(f"run:{data['runStatus']}")
    if p["evidenceKind"] == "synthetic":
        unverified_items.append("evidence:synthetic")
    return dict(reportVersion=REPORT, runKind="canary", protocolVersions=p["protocolVersions"], subjectSha256=p["subjectSha256"],
                evaluationPlanSha256=p["evaluationPlanSha256"], sessionId=p["sessionId"], sessionSha256=data["sessionSha256"], inputSha256=digest(data),
                evidenceKind=p["evidenceKind"], runStatus=data["runStatus"], provenance=p["provenance"], mappingSha256=p["mappingSha256"],
                scenarioSha256=p["scenarioSha256"], time=p["time"], scenarios=rows, classes=classes, unverifiedItems=unverified_items,
                missingClasses=missing_classes,
                unlinkedCommandIds=data["unlinkedCommandIds"], unlinkedDecisionIds=data["unlinkedDecisionIds"],
                outsideScoringDecisionIds=data['outsideScoringDecisionIds'],
                normal=dict(cumulativeMs=normal_ms, singleAssetUnionMs=union_ms, verifiedFalseBlocks=false_blocks,
                            perHour=None if normal_ms == 0 else false_blocks * 3600000 / normal_ms, falseBlocksTtlRestored=ttl_restored, passed=normal_passed),
                computedStatus=computed, status=status, passed=status == "passed", latencyIsReportOnly=True, limitations=LIMITATIONS)


def aggregate(statuses):
    """类别状态取最差：failed > unverified > not_evaluated > passed；无场景为 not_evaluated。"""
    if not statuses:
        return "not_evaluated"
    for value in ("failed", "unverified", "not_evaluated"):
        if value in statuses:
            return value
    return "passed"


def sign(payload, key_path, key_id):
    """显式调用才签名；复用 platform_report 的私钥检查（仓库外、0600）与签名封装，不打印密钥。"""
    key = platform_report.private_key(key_path)
    require(isinstance(key, Ed25519PrivateKey), "SIGNING_KEY_INVALID")
    return platform_report.sign(payload, key, key_id)


def verify(envelope, trust, expected):
    """与后端 GuardSignatures.report 相同：封装字段、Ed25519、trust 按 keyId 取 X509-DER 公钥、签 payload 的 JCS。"""
    require(set(envelope) == {"payload", "keyId", "algorithm", "signature"} and envelope["algorithm"] == "Ed25519", "SIGNATURE_INVALID")
    require(envelope["keyId"] in trust, "REPORT_IDENTITY_UNTRUSTED")
    key = serialization.load_der_public_key(base64.b64decode(trust[envelope["keyId"]], validate=True))
    require(isinstance(key, Ed25519PublicKey), "SIGNATURE_INVALID")
    value = envelope["signature"]
    key.verify(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), canonical(envelope["payload"]))
    require(digest(envelope["payload"]) == digest(generate(expected)), "LAB_REPORT_MISMATCH")
    require(envelope["keyId"] == expected["session"]["runnerIdentity"], "REPORT_IDENTITY_UNTRUSTED")
    return {"signatureVerified": True, "contentSha256": digest(envelope["payload"]), "status": envelope["payload"]["status"]}


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def load(path):
    require(path.stat().st_size <= 32 * 1024 * 1024, "LAB_INPUT_TOO_LARGE")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(InvalidReport("INVALID_JSON_NUMBER")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate"); gen.add_argument("--input", type=Path, required=True); gen.add_argument("--output", type=Path, required=True)
    signing = sub.add_parser("sign"); signing.add_argument("--input", type=Path, required=True); signing.add_argument("--key", type=Path, required=True)
    signing.add_argument("--key-id", required=True); signing.add_argument("--output", type=Path, required=True)
    check = sub.add_parser("verify"); check.add_argument("--input", type=Path, required=True); check.add_argument("--trust", type=Path, required=True)
    check.add_argument("--expected-input", type=Path, required=True); check.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            value = generate(load(args.input))
        elif args.command == "sign":
            value = sign(load(args.input), args.key, args.key_id)
        else:
            require(hashlib.sha256(args.input.read_bytes()).hexdigest() == args.sha256, "ARTIFACT_HASH_MISMATCH")
            value = verify(load(args.input), load(args.trust), load(args.expected_input))
            print(json.dumps(value, ensure_ascii=False)); return 0
        # 只创建新文件，不覆盖用户已有报告或签名封装。
        with args.output.open("xb") as stream:
            stream.write(canonical(value) + b"\n")
        print(json.dumps({"output": str(args.output), "rawSha256": hashlib.sha256(args.output.read_bytes()).hexdigest(), "contentSha256": digest(value)}))
        return 0
    except Exception as exc:
        # 不回显解析到的秘密、私钥路径或原始 payload。
        print(str(exc) if isinstance(exc, (InvalidReport, Rejected)) else "LAB_REPORT_OPERATION_FAILED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
