#!/usr/bin/env python3
"""从真实 P5 证据生成绑定 release subject 的联合评价报告。

只读文件。generate、sign、verify 分离；JCS 重算完整 subject，签名沿用
report-trust。platform 接受 orchestrate 汇总和对应 root e3-executor 记录；
canary 接受 root e1e2-lab 下 pf_engine_canary 的结果。缺证据直接拒绝。
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from executor.common import Rejected, canonical, require
from scripts.p5 import platform_report
from executor.subject_binding import SUBJECT_FIELDS, validate as validate_binding

REPORT_VERSION = "host-guard-subject-report/1.0"


def load(path):
    return json.loads(Path(path).read_bytes())


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def subject_hash(value):
    """与 GuardCatalog/J2-3 相同的完整 JCS；拒绝只有摘要而无 subject 的输入。"""
    subject = value.get("subject", value)
    require(isinstance(subject, dict) and set(subject) == SUBJECT_FIELDS, "REPORT_SUBJECT_INVALID")
    require(subject["capabilityIds"] == sorted(set(subject["capabilityIds"])) and subject["capabilityIds"], "REPORT_SUBJECT_INVALID")
    result = digest(subject)
    require("subjectSha256" not in value or value["subjectSha256"] == result, "REPORT_SUBJECT_MISMATCH")
    return result, subject


def collect(summaries, launches, kind, binding):
    """证据路径必须由调用方显式提供；不信任摘要中的任意外部引用。"""
    require(kind in {"platform", "canary"}, "REPORT_KIND_INVALID")
    require(launches, "REPORT_E3_ROOT_EVIDENCE_MISSING")
    validate_binding(binding)
    def matched(record, execution=None):
        require(record.get('subjectBinding')==binding,'REPORT_SUBJECT_MISMATCH')
        if execution is not None:
            actual=execution.get('runtimeSubjectBinding',{})
            require(actual.get('verifiedBeforeExecution') is True
                    and actual.get('subjectSha256')==binding['subjectSha256']
                    and actual.get('bundleId')==binding['bundleId']
                    and actual.get('policySha256')==binding['subject']['policySha256']
                    and actual.get('capabilityIds') and set(actual['capabilityIds'])<=set(binding['subject']['capabilityIds']),
                    'REPORT_RUNTIME_SUBJECT_MISMATCH')
    if kind == "platform":
        rounds = platform_report.e3_rounds(launches)
        for directory in map(Path,launches):
            matched(load(directory/'launch-record.json'),load(directory/'evidence/result.json'))
        items = [platform_report.e3_evidence(Path(p).resolve(), rounds) for p in summaries]
        require(items, "REPORT_EVIDENCE_EMPTY")
        for scope in ("peer_service", "peer_inbound"):
            covered = {s for item in items if item["scope"] == scope for s in item["scenarios"]}
            require(platform_report.E3_SCENARIOS <= covered, "REPORT_E3_INCOMPLETE")
        executor_hashes = set()
        for path in summaries:
            summary=load(path);matched(summary)
            source = summary.get("sourceSha256", {})
            files = {k: v for k, v in source.items() if k.startswith("executor/") and k.endswith(".py")}
            require(files, "REPORT_EXECUTOR_HASH_MISSING")
            executor_hashes.add(digest(files))
    else:
        require(not summaries, "REPORT_CANARY_INPUT_INVALID")
        items, executor_hashes = [], set()
        for directory in map(Path, launches):
            record = load(directory / "launch-record.json")
            matched(record)
            require(record.get("task") == "e1e2-lab" and type(record.get("exitCode")) is int and record["exitCode"] == 0,
                    "REPORT_EVIDENCE_NOT_REAL")
            # 复用已有 E1/E2 清理和未知规则核验规则。
            item = platform_report.lab_evidence(directory)
            matched(load(directory/'evidence/summary.json'))
            results = sorted((directory / "evidence").glob("*/result.json"))
            require(results, "REPORT_CANARY_ENGINE_INVALID")
            hashes = []
            for path in results:
                row = load(path)
                matched(record,row)
                require(row.get("kind") == "pf_engine_canary" and row.get("realPF") is True and row.get("passed") is True
                        and row.get("cleanupVerified") is True and row.get("fixtureResolver") is False,
                        "REPORT_EVIDENCE_NOT_REAL")
                require(row.get("executorSha256"), "REPORT_EXECUTOR_HASH_MISSING")
                executor_hashes.add(row["executorSha256"])
                hashes.append(sha(path))
            item["canaryResultSha256"] = hashes
            items.append(item)
    require(len(executor_hashes) == 1, "REPORT_EXECUTOR_HASH_MISMATCH")
    return {"items": items, "executorSha256": executor_hashes.pop(),"subjectBinding":binding}


def build(kind, subject_value, evidence):
    hashed, subject = subject_hash(subject_value)
    require(kind in {"platform", "canary"} and evidence.get("items"), "REPORT_EVIDENCE_EMPTY")
    binding=validate_binding(evidence['subjectBinding'])
    require(hashed==binding['subjectSha256'] and subject==binding['subject'],'REPORT_SUBJECT_MISMATCH')
    return {"reportVersion": REPORT_VERSION, "runKind": kind, "passed": True, "evidenceKind": "real_pf",
            "subjectSha256": hashed, "evaluationPlanSha256": subject["evaluationPlanSha256"],
            "protocolVersions": subject["protocolVersions"], "executorSha256": evidence["executorSha256"],
            "evidence": evidence["items"], "limitations": ["P5 joint execution evidence; no G3 category qualification"]}


def sign(payload, key, runner):
    return platform_report.sign(payload, platform_report.private_key(key), runner)


def verify(envelope, trust, expected):
    require(set(envelope) == {"payload", "keyId", "algorithm", "signature"} and envelope["algorithm"] == "Ed25519", "SIGNATURE_INVALID")
    require(envelope["keyId"] in trust, "REPORT_IDENTITY_UNTRUSTED")
    try:
        public = serialization.load_der_public_key(base64.b64decode(trust[envelope["keyId"]], validate=True))
        require(isinstance(public, Ed25519PublicKey), "SIGNATURE_INVALID")
        sig = envelope["signature"]
        public.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), canonical(envelope["payload"]))
    except (ValueError, InvalidSignature, TypeError) as error:
        raise Rejected("SIGNATURE_INVALID") from error
    require(digest(envelope["payload"]) == digest(expected), "REPORT_CONTENT_MISMATCH")
    return {"signatureVerified": True, "contentSha256": digest(expected), "subjectSha256": expected["subjectSha256"]}


def write(path, value):
    with Path(path).open("xb") as stream:
        stream.write(canonical(value) + b"\n")
    Path(path).chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("generate", "verify"):
        p = sub.add_parser(command)
        p.add_argument("--kind", choices=("platform", "canary"), required=True)
        p.add_argument("--subject", type=Path, required=True)
        p.add_argument("--e3-summary", type=Path, action="append", default=[])
        p.add_argument("--root-launch", type=Path, action="append", default=[])
        if command == "generate":
            p.add_argument("--output", type=Path, required=True)
        else:
            p.add_argument("--input", type=Path, required=True)
            p.add_argument("--trust", type=Path, required=True)
    p = sub.add_parser("sign")
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--runner-identity", required=True)
    args = parser.parse_args()
    if args.command == "sign":
        payload = load(args.input)
        require(payload.get("reportVersion") == REPORT_VERSION and payload.get("evidenceKind") == "real_pf", "REPORT_KIND_INVALID")
        write(args.output, sign(payload, args.private_key, args.runner_identity))
    else:
        binding=validate_binding(load(args.subject))
        payload = build(args.kind, binding, collect(args.e3_summary, args.root_launch, args.kind,binding))
        if args.command == "verify":
            print(json.dumps(verify(load(args.input), load(args.trust), payload)))
        else:
            write(args.output, payload)


if __name__ == "__main__":
    try:
        main()
    except (Rejected, OSError, ValueError, KeyError) as exc:
        print(str(exc) if isinstance(exc, Rejected) else "REPORT_INPUT_INVALID", file=sys.stderr)
        raise SystemExit(2)
