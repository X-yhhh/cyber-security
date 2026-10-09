"""由真实 PF 运行证据生成 P4 可验的签名平台/豁免报告；任何合成或失败证据都拒绝。

- platform：capability 为登记请求体去掉 evidenceRef/evidenceSha256/runnerIdentity/exemptionEvidenceRef，
  P4 `GuardCatalog.capability` 要求逐字段相等。
- exemption：peer_inbound 专用，platform=macos-pf、scope=peer_inbound、protectionSetSha256 与能力一致。
证据只接受 root 启动器记录（lab_root_launch.py）对应的 pf_lab 汇总，以及 orchestrate.py --mode pf 汇总
（realPF=true）；演练、dry-run 或夹具报告一律拒绝。私钥须在仓库外且权限 0600。
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from executor.common import Rejected, canonical, require  # noqa: E402

E3_SCENARIOS = {"revoke", "disconnect", "receipt_loss"}
WITHOUT_EVIDENCE = ("evidenceRef", "evidenceSha256", "runnerIdentity", "exemptionEvidenceRef")


def load(path):
    return json.loads(Path(path).read_bytes())


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def lab_evidence(directory):
    """pf_lab 证据：root 启动记录 exitCode=0 且汇总 passed、清理全部为真。"""
    directory = Path(directory)
    record, summary = load(directory / "launch-record.json"), load(directory / "evidence/summary.json")
    require(record["task"] == "e1e2-lab" and record["exitCode"] == 0, "REPORT_EVIDENCE_NOT_REAL")
    require(summary["passed"] is True and summary["cleanup"] and all(summary["cleanup"].values()),
            "REPORT_EVIDENCE_FAILED")
    require(summary.get("unknownRule", {}).get("passed") is True, "REPORT_EVIDENCE_FAILED")
    return {"kind": "e1e2-lab", "scope": "peer_inbound", "commit": record["commit"],
            "launchRecordSha256": file_digest(directory / "launch-record.json"),
            "summarySha256": file_digest(directory / "evidence/summary.json"),
            "scenarios": sorted(s["scenario"] for s in summary["scenarios"])}


def e3_evidence(path):
    """E3 证据：orchestrate --mode pf 汇总，realPF=true、每轮通过；同作用域三场景须齐备。"""
    summary = load(path)
    require(summary.get("realPF") is True, "REPORT_EVIDENCE_NOT_REAL")
    rows = summary["scenarios"]
    require(rows and all(r["passed"] is True for r in rows), "REPORT_EVIDENCE_FAILED")
    scopes = {r["scope"] for r in rows}
    require(len(scopes) == 1, "REPORT_EVIDENCE_SCOPE_MIXED")
    return {"kind": "e3-joint", "scope": scopes.pop(), "summarySha256": file_digest(path),
            "scenarios": sorted(r["scenario"] for r in rows)}


def collect(labs, e3s, scope):
    items = [lab_evidence(p) for p in labs] + [e3_evidence(p) for p in e3s]
    covered = {s for item in items if item["kind"] == "e3-joint" and item["scope"] == scope for s in item["scenarios"]}
    require(E3_SCENARIOS <= covered, "REPORT_E3_INCOMPLETE")
    require(any(item["kind"] == "e1e2-lab" for item in items), "REPORT_E1E2_MISSING")
    return items


def private_key(path):
    path = Path(path).resolve()
    require(not path.is_relative_to(ROOT), "REPORT_KEY_INSIDE_REPOSITORY")
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, "REPORT_KEY_PERMISSIONS")
    return serialization.load_der_private_key(path.read_bytes(), password=None)


def sign(payload, key, runner):
    signature = base64.urlsafe_b64encode(key.sign(canonical(payload))).rstrip(b"=").decode()
    return {"payload": payload, "keyId": runner, "algorithm": "Ed25519", "signature": signature}


def build(kind, request, items, protocol_versions):
    scope = request.get("scope", "peer_service")
    payload = {"passed": True, "kind": kind, "platform": "macos-pf", "scope": scope,
               "protocolVersions": protocol_versions, "evidence": items,
               "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if kind == "exemption":
        require(scope == "peer_inbound" and request.get("protectionSetSha256"), "REPORT_SCOPE_INVALID")
        payload["protectionSetSha256"] = request["protectionSetSha256"]
    else:
        require(request.get("level") in ("lab_auto", "authorized_auto", "alert_only"), "REPORT_LEVEL_INVALID")
        require(scope != "peer_inbound" or request.get("exemptionEvidenceSha256"), "REPORT_EXEMPTION_REQUIRED")
        payload["capability"] = {k: v for k, v in request.items() if k not in WITHOUT_EVIDENCE}
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("platform", "exemption"), required=True)
    parser.add_argument("--capability-request", type=Path, required=True)
    parser.add_argument("--lab-run", type=Path, action="append", default=[])
    parser.add_argument("--e3-summary", type=Path, action="append", default=[])
    parser.add_argument("--protocol-versions", type=Path, required=True)
    parser.add_argument("--runner-identity", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "REPORT_OUTPUT_EXISTS")
    request = load(args.capability_request)
    require(request.get("runnerIdentity") == args.runner_identity, "REPORT_IDENTITY_MISMATCH")
    items = collect(args.lab_run, args.e3_summary, request.get("scope", "peer_service"))
    envelope = sign(build(args.kind, request, items, load(args.protocol_versions)),
                    private_key(args.private_key), args.runner_identity)
    with args.output.open("xb") as stream:
        stream.write(canonical(envelope))
    os.chmod(args.output, 0o600)
    print(json.dumps({"kind": args.kind, "sha256": file_digest(args.output), "evidence": len(items)}))


if __name__ == "__main__":
    try:
        main()
    except Rejected as exc:
        raise SystemExit(str(exc))
