#!/usr/bin/env python3
"""K9-6 无授权全链路演练（隔离 schema、内存防火墙，全部标 synthetic）。

1. S1：克隆业务库，按 A18 顺序导入 r4 lab M2 组合（synthetic final），停在 candidate；
2. e3_bootstrap.py --mode rehearse 以 S1 为源：S2 克隆内引导批准/激活、E3 替身矩阵、K6 synthetic platform；
3. 回到 S1：开关关闭时引导与 synthetic 报告导入均被拒；开关开启后导入 K6 platform 与 synthetic canary，
   封存、guard-reviewer 独立批准；
4. lab_run.py --mode rehearse 以 S1 为源、复用该已批准组合，跑 1 段场景完成会话创建、准入与仅 lab 激活；
5. 删除 S1 及本次克隆，核对业务库前后逐表摘要。

不写业务库、不运行真实 PF；所有报告与结果都不得作为正式证据。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from executor.common import canonical, digest
from scripts.p5 import e3_bootstrap
from scripts.p7 import j1_run, lab_run
from scripts.p7.lab_run import R4_SUBJECT_SHA256, freeze_scenarios, require, stamp

HOME = Path.home() / "Workspace"


def write(path, value):
    e3_bootstrap.write(path, value)


def load(path):
    return json.loads(Path(path).read_bytes())


class Backend(lab_run.Runner):
    """复用 lab_run 的隔离后端启动与登录；每个阶段独立目录、独立申请人，不复用会话。"""
    def __init__(self, args, work, schema, trust, bootstrap_reports):
        ns = SimpleNamespace(directory=work, artifacts=args.artifacts, mode="rehearse", scenario=args.scenario, port=args.port,
                             java=args.java_home / "bin/java", reviewer_file=args.reviewer_file, operator_file=args.operator_file,
                             report_trust=args.report_trust, mysql_service=args.mysql_service, import_plan=args.import_plan,
                             go=args.go, selection=args.selection)
        super().__init__(ns)
        self.schema = schema
        self.bootstrap_reports = bootstrap_reports
        self.db = j1_run.Database(args.mysql_service)
        work.mkdir(parents=True, mode=0o700)
        (work / "private").mkdir(mode=0o700)
        (work / "bin").mkdir(mode=0o700)
        shutil.copy2(ROOT / "backend/target/cyber-security-backend-0.1.0-SNAPSHOT.jar", work / "bin/backend.jar")
        write(work / "private/trust.json", trust)
        original = load(args.operator_file)
        username = "k9-operator-" + uuid.uuid4().hex[:8]
        quoted = lambda value: "'" + value.replace("'", "''") + "'"
        self.db.query("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) SELECT " + quoted(str(uuid.uuid4())) + "," +
                      quoted(username) + ",'K9 isolated rehearsal',password_hash,'active' FROM sys_user WHERE username=" + quoted(original["username"]), schema)
        self.db.query("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT u.id,r.id,'global','*' FROM sys_user u CROSS JOIN sys_role r "
                      "WHERE u.username=" + quoted(username) + " AND r.role_key IN ('platform_admin','model_operator','security_analyst')", schema)
        write(work / "private/isolated-operator.json", {"username": username, "password": original["password"]})

    def stop(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def import_report(self, bundle, ref, expected=None):
        """expected 为错误码时断言被拒并返回码；否则返回评价记录 ID。"""
        body = {"reportRef": ref["ref"], "sha256": ref["sha256"], "runnerIdentity": ref["runnerIdentity"]}
        if expected is None:
            return self.op.v2("/release-bundles/" + bundle + "/imports", body)["id"]
        payload = self.op.call("POST", "/api/v2/release-bundles/" + bundle + "/imports", body, {"Idempotency-Key": str(uuid.uuid4())}, (400, 403, 409, 422))
        error = payload.get("error", {}) if isinstance(payload, dict) else {}
        code = error.get("code") if isinstance(error, dict) else None
        code = code.get("code") if isinstance(code, dict) else code
        require(code == expected, "K9_NEGATIVE_UNEXPECTED:" + str(code))
        return code


def signer(directory, name):
    key = Ed25519PrivateKey.generate()
    path = directory / (name + ".der")
    with path.open("xb") as stream:
        stream.write(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
    import base64
    return key, base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


def signed(artifacts, directory, name, payload, key, runner):
    from scripts.p5.platform_report import sign
    path = directory / (name + ".json")
    write(path, sign(payload, key, runner))
    return {"ref": str(path.relative_to(artifacts)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "runnerIdentity": runner}


def build_s1(args, attempt, s1, runner_name, key, trust, report_dir):
    """模拟 A18 后的业务库：冻结策略 + r4 candidate + 一份 synthetic final（与 lab_run 同一 provenance）。"""
    backend = Backend(args, attempt / "s1-build", s1, trust, True)
    try:
        backend.start_backend()
        plan = load(args.import_plan)
        policy = plan["decisionPolicy"]
        require(digest(policy) == digest(load(args.artifacts / "packages/host-guard-round2-20261011-r4/policy-m2-lab.json")), "K9_POLICY_MISMATCH")
        if int(backend.db.query("SELECT COUNT(*) FROM guard_decision_policy WHERE public_id='" + policy["policyId"] + "'", s1)) == 0:
            created = backend.op.v2("/decision-policies", policy)
            backend.rev.v2("/decision-policies/" + created["id"] + "/reviews", {"decision": "approve", "reason": "K9 S1：模拟 A18 导入冻结 r4 策略"}, 1)
        body = dict(plan["releaseBundle"], modelId=plan["existingModel"]["id"], policyId=policy["policyId"],
                    evaluationPlanId=plan["existingEvaluationPlan"]["id"], capabilityIds=sorted(x["id"] for x in plan["existingCapabilities"]))
        bundle = backend.op.v2("/release-bundles", body)
        require(bundle["subjectSha256"] == args.subject_sha256, "K9_S1_SUBJECT_MISMATCH")
        source = load(args.scenario)
        rows = freeze_scenarios(source, args.artifacts)
        provenance = lab_run.synthetic_provenance(source, policy, body["extractorSha256"], lab_run.executor_digest())
        payload = lab_run.synthetic_payload("final", rows, bundle["subjectSha256"], policy["evaluationPlanSha256"], body["protocolVersions"],
                                            lab_run.executor_digest(), provenance)
        final = signed(args.artifacts, report_dir, "s1-final", payload, key, runner_name)
        backend.import_report(bundle["id"], final)
        return {"bundleId": bundle["id"], "subjectSha256": bundle["subjectSha256"], "final": final, "rows": rows,
                "provenance": provenance, "policy": policy, "versions": body["protocolVersions"]}
    finally:
        backend.stop()


def run(args):
    db = j1_run.Database(args.mysql_service)
    attempt = e3_bootstrap.next_attempt(args.directory / "k9-6")
    report_dir = args.artifacts / "k9-e3" / (attempt.name + "-s1-" + uuid.uuid4().hex[:8])
    report_dir.mkdir(parents=True, mode=0o700)
    key_dir = HOME / "ai/keys/cyber-guard-rehearsals" / report_dir.name
    key_dir.mkdir(parents=True, mode=0o700)
    runner_name = "k9-s1-runner-" + uuid.uuid4().hex[:12]
    key, public = signer(key_dir, runner_name)
    trust = dict(load(args.report_trust), **{runner_name: public})
    business_before = e3_bootstrap.snapshot(db, "cyber_security")
    write(attempt / "business-before.json", business_before)
    s1 = "cyber_guard_k9s1_" + uuid.uuid4().hex
    gate = {"schema": "k9-6-rehearsal/1", "startedAt": stamp(), "s1Schema": s1, "synthetic": True, "realPF": False, "checks": {}}
    created, lab_schema = False, None
    try:
        db.clone("cyber_security", s1, attempt / "s1-business-backup.sql")
        created = True
        s1_facts = build_s1(args, attempt, s1, runner_name, key, trust, report_dir)
        gate["bundleId"] = s1_facts["bundleId"]
        gate["checks"]["s1CandidateWithFinal"] = True
        # 第 2 步：E3 引导克隆演练（S2 为 e3_bootstrap 自建、自删）
        command = ["/bin/sh", str(ROOT / "executor/python.sh"), "-B", str(ROOT / "scripts/p5/e3_bootstrap.py"), "--mode", "rehearse",
                   "--source-schema", s1, "--bundle-id", s1_facts["bundleId"], "--directory", str(attempt / "e3"),
                   "--attempts", str(args.directory / "attempts.json"), "--subject-sha256", args.subject_sha256]
        with (attempt / "e3-bootstrap.log").open("xb") as stream:
            code = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT).returncode
        require(code == 0, "K9_E3_BOOTSTRAP_REHEARSAL_FAILED")
        e3_attempt = attempt / "e3/attempt-01"
        e3_state, k6 = load(e3_attempt / "state.json"), load(e3_attempt / "k6.json")
        work = Path(e3_state["work"])
        gate["e3Attempt"] = str(e3_attempt)
        gate["checks"].update(cloneSubjectMatchesS1=e3_state["cloneBundle"] == e3_state["sourceBundle"],
                              s1UnchangedByE3=e3_state["sourceUnchanged"],
                              e3RoundsPassed=load(work / "e3/summary.json")["passed"])
        bootstrap = load(work / "bootstrap.json")
        boot_trust = load(work / "private/bootstrap-trust.json")
        synthetic_trust = load(Path(k6["trust"]))
        platform = {"ref": k6["reportRef"], "sha256": k6["sha256"], "runnerIdentity": k6["runnerIdentity"]}
        # 第 3 步：开关关闭——即使 trust 含引导与演练身份，也必须按 evidenceKind 拒绝。
        negative = Backend(args, attempt / "s1-negative", s1, dict(trust, **boot_trust, **synthetic_trust), False)
        try:
            negative.start_backend()
            boot_ref = next(r for r in bootstrap["reports"] if r["kind"] == "platform")
            gate["checks"]["bootstrapRejectedWhenSwitchOff"] = negative.import_report(
                s1_facts["bundleId"], {"ref": boot_ref["reportRef"], "sha256": boot_ref["sha256"], "runnerIdentity": boot_ref["runnerIdentity"]},
                "REPORT_EVIDENCE_KIND_NOT_ALLOWED") == "REPORT_EVIDENCE_KIND_NOT_ALLOWED"
            gate["checks"]["syntheticRejectedWhenSwitchOff"] = negative.import_report(
                s1_facts["bundleId"], platform, "REPORT_EVIDENCE_KIND_NOT_ALLOWED") == "REPORT_EVIDENCE_KIND_NOT_ALLOWED"
        finally:
            negative.stop()
        canary = signed(args.artifacts, report_dir, "s1-canary",
                        lab_run.synthetic_payload("canary", s1_facts["rows"], s1_facts["subjectSha256"], s1_facts["policy"]["evaluationPlanSha256"],
                                                  s1_facts["versions"], lab_run.executor_digest(), s1_facts["provenance"]), key, runner_name)
        seal = Backend(args, attempt / "s1-seal", s1, dict(trust, **synthetic_trust), True)
        try:
            seal.start_backend()
            bundle = s1_facts["bundleId"]
            finals = [r for r in e3_bootstrap.rows(db, "SELECT JSON_OBJECT('id',e.public_id) FROM guard_evaluation_run e JOIN guard_release_bundle b "
                                                       "ON b.id=e.bundle_id WHERE b.public_id='" + bundle + "' AND e.run_kind='final' AND e.status='passed'", s1)]
            ids = [f["id"] for f in finals] + [seal.import_report(bundle, platform), seal.import_report(bundle, canary)]
            sealed = seal.op.v2("/release-bundles/" + bundle + "/sealings", {"evaluationIds": ids}, 1)
            approved = seal.rev.v2("/release-bundles/" + bundle + "/decisions", {"decision": "approve", "reason": "K9-6 synthetic：K6 报告封存后独立批准"},
                                   sealed["revision"])
            gate["checks"]["s1SealedWithK6Platform"] = sealed["status"] == "evaluated"
            gate["checks"]["s1ApprovedByIndependentReviewer"] = approved["status"] == "approved"
        finally:
            seal.stop()
        # 第 4 步：lab_run 复用该已批准组合，在其自建克隆中仅 lab 激活并完成会话准入。
        reports = {"final": s1_facts["final"], "platform": platform, "canary": canary}
        write(attempt / "existing-reports.json", reports)
        write(attempt / "extra-trust.json", dict({runner_name: public}, **synthetic_trust))
        lab_dir = attempt / ("g3-" + report_dir.name)
        command = ["/bin/sh", str(ROOT / "executor/python.sh"), "-B", str(ROOT / "scripts/p7/lab_run.py"), "--mode", "rehearse",
                   "--directory", str(lab_dir), "--source-schema", s1, "--existing-bundle", bundle,
                   "--existing-reports", str(attempt / "existing-reports.json"), "--extra-trust", str(attempt / "extra-trust.json"),
                   "--scenarios", args.lab_scenarios, "--port", str(args.port + 1), "--subject-sha256", args.subject_sha256,
                   "--import-plan", str(args.import_plan)]
        with (attempt / "lab-run.log").open("xb") as stream:
            code = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT).returncode
        lab_state = load(lab_dir / "state.json") if (lab_dir / "state.json").exists() else {}
        lab_schema = lab_state.get("schemaName")
        gate["labRun"] = {"returnCode": code, "directory": str(lab_dir), "sessionId": lab_state.get("sessionId"),
                          "reportImported": lab_state.get("reportImported"), "captureComplete": lab_state.get("captureComplete")}
        if lab_schema:
            binding = e3_bootstrap.rows(db, "SELECT JSON_OBJECT('status',s.status,'bundle',b.public_id,'environment',a.environment) FROM guard_asset_binding s "
                                            "JOIN guard_release_bundle b ON b.id=s.bundle_id JOIN asset a ON a.id=s.asset_id", lab_schema)
            run_row = e3_bootstrap.rows(db, "SELECT JSON_OBJECT('status',status) FROM guard_lab_run", lab_schema)
            gate["checks"]["activatedOnlyOnLabAsset"] = bool(binding) and all(b["environment"] == "lab" and b["bundle"] == bundle for b in binding)
            gate["checks"]["labSessionCompleted"] = [r["status"] for r in run_row] == ["completed"]
        gate["checks"]["labRunExitZero"] = code == 0
    finally:
        for schema in (s1, lab_schema):
            if schema and (schema == s1 and created or schema == lab_schema):
                db.query("DROP DATABASE IF EXISTS `" + schema + "`")
        after = e3_bootstrap.snapshot(db, "cyber_security")
        write(attempt / "business-after.json", after)
        gate["checks"]["businessUnchanged"] = after == business_before
        gate["schemasDropped"] = [s for s in (s1, lab_schema) if s]
        gate["finishedAt"] = stamp()
        gate["passed"] = bool(gate["checks"]) and all(gate["checks"].values()) and len(gate["checks"]) >= 11
        write(attempt / "gate.json", gate)
    return gate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / ".cache/k9-20261012")
    parser.add_argument("--artifacts", type=Path, default=HOME / "ai/artifacts/cyber-guard")
    parser.add_argument("--scenario", type=Path, default=ROOT / ".cache/j2-20261011/g3-scenario.json")
    parser.add_argument("--selection", type=Path, default=ROOT / ".cache/j1-20261011-reg-preroll30/selection.json")
    parser.add_argument("--import-plan", type=Path, default=ROOT / ".cache/j2-20261011/import-rehearsal/lab-plan.json")
    parser.add_argument("--subject-sha256", type=lab_run.subject_sha256, default=R4_SUBJECT_SHA256, help="期望组合 subject；默认保留 r4")
    parser.add_argument("--operator-file", type=Path, default=ROOT / ".cache/j1-20261011-v9/private/operator.json")
    parser.add_argument("--reviewer-file", type=Path, default=HOME / "ai/keys/cyber-guard-reviewer/credentials.json")
    parser.add_argument("--report-trust", type=Path, default=HOME / "ai/keys/cyber-guard-trust/report-trust.json")
    parser.add_argument("--mysql-service", type=Path, default=HOME / "development/services/databases/mysql-server-8.0.42")
    parser.add_argument("--java-home", type=Path, default=HOME / "development/runtimes/java/temurin-25.0.2/Contents/Home")
    parser.add_argument("--go", type=Path, default=HOME / "development/runtimes/go/go-1.26.4/bin/go")
    parser.add_argument("--port", type=int, default=19543)
    parser.add_argument("--lab-scenarios", default="port_scan-1")
    args = parser.parse_args()
    args.artifacts = args.artifacts.resolve()
    os.umask(0o077)
    gate = run(args)
    print(json.dumps(gate, ensure_ascii=False, indent=1))
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
