#!/usr/bin/env python3
"""K9 E3 引导克隆编排器。

在业务库（pf）或已模拟 A18 的隔离 schema（rehearse）的克隆中，用 e3-bootstrap 专用身份
签发的引导报告把同一 r4 组合封存、独立批准，再由 E3 subject 入口在克隆内建 lab 回环资产、
激活并运行联合矩阵。克隆随后删除并核对源库前后逐表摘要，生成 K6 所需的 executionContext。

- 源库只读：仅 mysqldump 与 SELECT；任何写入都发生在 ``cyber_guard_k9_<hex>`` 克隆。
- 引导报告 ``evidenceKind=bootstrap``，信任文件只交给克隆后端；正式库按 K9-1 开关拒绝。
- rehearse 使用内存防火墙，K6 只能产出 synthetic platform；pf 在任何副作用前核对业务库
  r4 为 candidate 且已导入正式 final，并要求 A6 引用，每轮由 root 暂存副本执行（另行授权）。
- 每次运行新开 attempt 目录，失败目录保留，不覆盖、不续跑。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from executor.common import canonical, digest, require
from executor.subject_binding import validate as validate_binding
from scripts.p5 import platform_report
from scripts.p7 import j1_run
from scripts.p7.lab_run import R4_SUBJECT_SHA256, freeze_scenarios, original_mapping, stamp, subject_sha256

BUSINESS = "cyber_security"
SOURCE_SCHEMA = re.compile(r"cyber_guard_[a-z0-9_]{1,52}")
SEGMENTS = {"peer_service": ("brute_force-1", "brute_force"), "peer_inbound": ("port_scan-1", "port_scan")}
SCENARIOS = [(scope, scenario) for scope in ("peer_service", "peer_inbound") for scenario in ("revoke", "disconnect", "receipt_loss")]
HOME = Path.home() / "Workspace"


def write(path, value):
    with Path(path).open("xb") as stream:
        stream.write(canonical(value) + b"\n")
    Path(path).chmod(0o600)


def load(path):
    return json.loads(Path(path).read_bytes())


def rows(db, sql, schema):
    return [json.loads(line) for line in db.query(sql, schema).decode().splitlines() if line.strip()]


def snapshot(db, schema):
    """逐表行数与按行排序后的内容摘要；只写摘要，不写行内容。"""
    tables = db.query("SELECT table_name FROM information_schema.tables WHERE table_schema='" + schema +
                      "' AND table_type='BASE TABLE' ORDER BY table_name").decode().splitlines()
    return {t: {"rows": int(db.query("SELECT COUNT(*) FROM `" + t + "`", schema)),
                "sha256": hashlib.sha256(b"\n".join(sorted(db.query("SELECT * FROM `" + t + "`", schema).splitlines()))).hexdigest()}
            for t in tables}


def bundle_facts(db, schema, bundle_id):
    found = rows(db, "SELECT JSON_OBJECT('bundleId',public_id,'status',status,'environment',environment,"
                     "'subjectSha256',subject_sha256,'subject',CAST(subject_json AS JSON),'revision',revision) "
                     "FROM guard_release_bundle WHERE public_id='" + bundle_id + "'", schema)
    require(len(found) == 1, "K9_R4_NOT_FOUND")
    finals = rows(db, "SELECT JSON_OBJECT('id',e.public_id,'status',e.status,'runner',e.runner_identity,"
                      "'evidenceKind',JSON_UNQUOTE(JSON_EXTRACT(CAST(e.payload_json AS JSON),'$.evidenceKind'))) "
                      "FROM guard_evaluation_run e JOIN guard_release_bundle b ON b.id=e.bundle_id "
                      "WHERE b.public_id='" + bundle_id + "' AND e.run_kind='final'", schema)
    return dict(found[0], finals=finals)


def check_candidate(facts, expected, formal):
    """克隆前的指定组合必须是同一 subject 的 lab candidate，并已有通过的 final。"""
    require(facts["status"] == "candidate" and facts["environment"] == "lab", "K9_R4_NOT_CANDIDATE")
    require(digest(facts["subject"]) == facts["subjectSha256"] == expected, "K9_R4_SUBJECT_MISMATCH")
    passed = [f for f in facts["finals"] if f["status"] == "passed"]
    require(passed, "K9_R4_FINAL_MISSING")
    if formal:
        # 正式路径只接受 A18 后重新签发的正式 final；演练或引导报告不能冒充。
        require(all(f["evidenceKind"] not in ("synthetic", "bootstrap") for f in passed), "K9_R4_FINAL_NOT_FORMAL")
    return {"bundleId": facts["bundleId"], "subjectSha256": facts["subjectSha256"]}


def preflight(args, db):
    """所有拒绝都发生在建目录、克隆或启动进程之前。"""
    require(str(uuid.UUID(args.bundle_id)) == args.bundle_id, "K9_BUNDLE_ID_INVALID")
    if args.mode == "pf":
        require(args.source_schema == BUSINESS, "K9_PF_SOURCE_MUST_BE_BUSINESS_DB")
        require(bool(args.authorization_reference), "K9_PF_AUTHORIZATION_REQUIRED")
        # root 侧每轮先复制、核验暂存包再等管道；用户侧须等其就绪标记，否则后端的 45 秒握手会先超时（同 T3.8b）。
        require(getattr(args, "ready_dir", None) is not None and Path(args.ready_dir).is_absolute(), "K9_PF_READY_DIR_REQUIRED")
    else:
        require(args.source_schema != BUSINESS and SOURCE_SCHEMA.fullmatch(args.source_schema), "K9_REHEARSE_SOURCE_INVALID")
    facts = bundle_facts(db, args.source_schema, args.bundle_id)
    source = check_candidate(facts, args.subject_sha256, args.mode == "pf")
    return facts, source


def wait_ready(marker, timeout, clock=time.monotonic, pause=time.sleep):
    """等待 lab_root_launch.py --ready-marker 创建的就绪标记；超时则不启动本轮后端。"""
    deadline = clock() + timeout
    while not Path(marker).is_file():
        require(clock() < deadline, "K9_PF_ROOT_NOT_READY")
        pause(1)


def next_attempt(root):
    root.mkdir(parents=True, exist_ok=True)
    numbers = [int(p.name[8:]) for p in root.iterdir() if p.is_dir() and re.fullmatch(r"attempt-\d+", p.name)]
    path = root / f"attempt-{max(numbers, default=0) + 1:02d}"
    path.mkdir(mode=0o700)
    return path


def segments(args):
    """冻结片段逐文件核对；服务端口与来源从原始 PCAP 推出，不由调用方指定。"""
    source = load(args.scenario)
    frozen = {r["scenarioId"]: r for r in freeze_scenarios(source, args.artifacts)}
    selection = {v["segmentId"]: v for v in load(args.selection)}
    result = {}
    chosen = dict(SEGMENTS, peer_inbound=(args.inbound_segment, "port_scan"))
    for scope, (segment, family) in chosen.items():
        row = frozen[segment]
        require(row["family"] == family, "K9_SEGMENT_FAMILY_MISMATCH")
        mapping = original_mapping(row, selection[segment], args.artifacts)
        require(scope == "peer_inbound" or len(mapping["ports"]) == 1, "K9_SEGMENT_SERVICE_PORT_AMBIGUOUS")
        result[scope] = {"segmentId": segment, "family": family, "pcap": str((args.artifacts / row["pcapRef"]).resolve()),
                         "sha256": row["pcapSha256"], "host": mapping["host"], "servicePort": mapping["port"],
                         # 与 lab 回放同一采集起点：上下文覆盖从登记的预热起点起算，保留原预热和报文间隔。
                         "captureStart": row["captureStart"],
                         "peerCount": len(mapping["peers"])}
    return result


def new_key(directory, name):
    key = Ed25519PrivateKey.generate()
    path = directory / (name + ".der")
    with path.open("xb") as stream:
        stream.write(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
    public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                           serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    return key, path, public


def bootstrap_reports(work, artifacts, source, subject, clone):
    """引导报告只声明“克隆内引导”，不携带任何执行事实，不能充当 platform/canary 证据。"""
    key_id = "e3-bootstrap-" + uuid.uuid4().hex[:16]
    key, _, public = new_key(work / "private", key_id)
    write(work / "private/bootstrap-trust.json", {key_id: public})
    out = work / "bootstrap-reports"
    out.mkdir(mode=0o700)
    listed = []
    for kind in ("platform", "canary"):
        payload = {"reportVersion": "host-guard-e3-bootstrap/1", "runKind": kind, "evidenceKind": "bootstrap", "passed": True,
                   "subjectSha256": source["subjectSha256"], "evaluationPlanSha256": subject["evaluationPlanSha256"],
                   "protocolVersions": subject["protocolVersions"], "cloneSchema": clone, "issuedAt": stamp(),
                   "limitations": ["clone-only bootstrap to run E3 against this subject; carries no execution evidence"]}
        path = out / (kind + ".json")
        write(path, platform_report.sign(payload, key, key_id))
        listed.append({"kind": kind, "reportRef": str(path.relative_to(artifacts)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                       "runnerIdentity": key_id})
    value = {"bundleId": source["bundleId"], "subjectSha256": source["subjectSha256"], "reports": listed}
    write(work / "bootstrap.json", value)
    return value


def tool_env(args):
    from scripts.p7.j1_run import secret
    java = args.java_home
    env = dict(os.environ, JAVA_HOME=str(java), DB_TEST_BASE_URL="jdbc:mysql://127.0.0.1:3306", DB_TEST_USERNAME="root",
               DB_TEST_PASSWORD=secret("com.xyh.cyber-security.db-test"), RABBITMQ_IT_ENABLED="false")
    env["PATH"] = str(java / "bin") + os.pathsep + str(args.go.parent) + os.pathsep + env.get("PATH", "")
    for key in ("P5_EXTERNAL_EXECUTOR", "P5_SCOPE", "P5_SCENARIO", "HOSTGUARD_SUBJECT_BINDING", "HOSTGUARD_LAB_AUTHORIZATION"):
        env.pop(key, None)
    return env


def orchestrate(args, env, directory, extra, log):
    command = ["/bin/sh", str(ROOT / "executor/python.sh"), "-B", str(ROOT / "scripts/p5/orchestrate.py"),
               "--directory", str(directory), "--java-home", str(args.java_home), "--maven", str(args.maven),
               "--go", str(args.go), "--mysql", str(args.mysql_service / "bin/mysql")] + extra
    with log.open("xb") as stream:
        return subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT).returncode


def subject_rows(db, clone, bundle_id):
    found = rows(db, "SELECT JSON_OBJECT('bundleId',public_id,'subjectSha256',subject_sha256,'status',status) "
                     "FROM guard_release_bundle WHERE public_id='" + bundle_id + "'", clone)
    require(len(found) == 1, "K9_CLONE_BUNDLE_MISSING")
    return found[0]


def run(args):
    db = j1_run.Database(args.mysql_service)
    facts, source = preflight(args, db)
    attempt = next_attempt(args.directory)
    work = args.artifacts / "k9-e3" / (attempt.name + "-" + uuid.uuid4().hex[:8])
    work.mkdir(parents=True, mode=0o700)
    (work / "private").mkdir(mode=0o700)
    binding = validate_binding({"bundleId": source["bundleId"], "subject": facts["subject"], "subjectSha256": source["subjectSha256"]})
    write(work / "subject-binding.json", binding)
    write(work / "segments.json", segments(args))
    clone = "cyber_guard_k9_" + uuid.uuid4().hex
    state = {"schema": "k9-e3-bootstrap/1", "mode": args.mode, "sourceSchema": args.source_schema, "cloneSchema": clone,
             "work": str(work), "sourceBundle": source, "startedAt": stamp(), "realPF": False, "status": "running"}
    write(attempt / "pointer.json", {"work": str(work), "cloneSchema": clone})
    before = snapshot(db, args.source_schema)
    write(work / "source-before.json", before)
    created = False
    error = None
    try:
        db.clone(args.source_schema, clone, work / "private/source-dump.sql")
        created = True
        clone_bundle = subject_rows(db, clone, args.bundle_id)
        require(clone_bundle["status"] == "candidate", "K9_CLONE_R4_NOT_CANDIDATE")
        state["cloneBundle"] = {"bundleId": clone_bundle["bundleId"], "subjectSha256": clone_bundle["subjectSha256"]}
        require(state["cloneBundle"] == source, "K9_CLONE_SUBJECT_MISMATCH")
        boot = bootstrap_reports(work, args.artifacts, source, facts["subject"], clone)
        state["bootstrapReports"] = [{"sha256": r["sha256"], "keyId": r["runnerIdentity"]} for r in boot["reports"]]
        env = tool_env(args)
        if args.rounds:
            require(args.mode == "rehearse", "K9_ROUNDS_DIAGNOSTIC_ONLY")
            env["P5_SUBJECT_ROUNDS"] = args.rounds
            state["diagnosticRounds"] = args.rounds.split(",")
        common = ["--subject-binding", str(work / "subject-binding.json"), "--subject-schema", clone,
                  "--subject-artifact-root", str(args.artifacts), "--subject-report-trust", str(work / "private/bootstrap-trust.json")]
        code = orchestrate(args, env, work / "bootstrap", ["--mode", "rehearse", "--subject-step", "bootstrap",
                                                          "--subject-bootstrap", str(work / "bootstrap.json")] + common,
                           attempt / "bootstrap.log")
        require(code == 0, "K9_BOOTSTRAP_FAILED")
        state["bootstrap"] = load(work / "bootstrap/bootstrap-result.json")
        require(subject_rows(db, clone, args.bundle_id)["status"] == "approved", "K9_BOOTSTRAP_NOT_APPROVED")
        e3 = []
        if args.mode == "rehearse":
            code = orchestrate(args, env, work / "e3", ["--mode", "rehearse", "--subject-step", "e3",
                                                       "--subject-segments", str(work / "segments.json")] + common, attempt / "e3.log")
            e3.append(str(work / "e3/summary.json"))
            require(code == 0, "K9_E3_FAILED")
        else:
            # 每轮须在 A6 授权下由操作者另行以 root 启动 lab_root_launch.py e3-executor（同 T3.8b 流程）。
            for scope, scenario in SCENARIOS:
                directory = work / f"e3-{scope}-{scenario}"
                wait_ready(args.ready_dir / f"e3-{scope}-{scenario}.ready", args.ready_timeout)
                code = orchestrate(args, env, directory, ["--mode", "pf", "--scope", scope, "--scenario", scenario,
                                                          "--authorization-reference", args.authorization_reference,
                                                          "--subject-step", "e3", "--subject-segments", str(work / "segments.json")] + common,
                                   attempt / f"e3-{scope}-{scenario}.log")
                e3.append(str(directory / "summary.json"))
                require(code == 0, "K9_E3_FAILED")
        state["e3Summaries"] = e3
        state["cloneBundleAfter"] = subject_rows(db, clone, args.bundle_id)
    except Exception as exc:
        error = str(exc) if isinstance(exc, (ValueError,)) or exc.__class__.__name__ == "Rejected" else exc.__class__.__name__
        raise
    finally:
        if created:
            db.query("DROP DATABASE `" + clone + "`")
        after = snapshot(db, args.source_schema)
        write(work / "source-after.json", after)
        state.update(cloneDropped=created, sourceUnchanged=before == after, finishedAt=stamp(),
                     status="failed" if error else "passed", error=error)
        if not error:
            require(before == after, "K9_SOURCE_CHANGED")
            # K6 必须读取的执行上下文：源库逐表摘要、克隆中同一 bundle/subject 及引导报告摘要。
            context = {"cloneSchema": clone, "bootstrapReports": state["bootstrapReports"], "businessBefore": before,
                       "businessAfter": after, "sourceBundle": source, "cloneBundle": state["cloneBundle"],
                       "subjectMatchesSource": state["cloneBundle"] == source}
            write(work / "execution-context.json", context)
        write(attempt / "state.json", state)
        record(args.attempts, attempt, state)
    if args.mode == "rehearse" and not args.rounds:
        state["k6"] = rehearsal_report(args, work, attempt)
        write(attempt / "k6.json", state["k6"])
    return state


def rehearsal_report(args, work, attempt):
    """替身证据只走 K6 的 --rehearsal 路径：synthetic platform，由一次性演练身份签名。"""
    name = "k9-synthetic-runner-" + uuid.uuid4().hex[:12]
    key_dir = HOME / "ai/keys/cyber-guard-rehearsals" / work.name
    key_dir.mkdir(parents=True, mode=0o700)
    _, key_path, public = new_key(key_dir, name)
    write(work / "private/synthetic-trust.json", {name: public})
    reports = work / "reports"
    reports.mkdir(mode=0o700)
    base = ["/bin/sh", str(ROOT / "executor/python.sh"), "-B", str(ROOT / "scripts/p5/subject_report.py")]
    shared = ["--kind", "platform", "--subject", str(work / "subject-binding.json"), "--e3-summary", str(work / "e3/summary.json"),
              "--execution-context", str(work / "execution-context.json"), "--rehearsal"]
    steps = [base + ["generate"] + shared + ["--output", str(reports / "platform.payload.json")],
             base + ["sign", "--input", str(reports / "platform.payload.json"), "--output", str(reports / "platform.synthetic.json"),
                     "--private-key", str(key_path), "--runner-identity", name, "--rehearsal"],
             base + ["verify"] + shared + ["--input", str(reports / "platform.synthetic.json"), "--trust", str(work / "private/synthetic-trust.json")]]
    for index, command in enumerate(steps):
        with (attempt / f"k6-{index}.log").open("xb") as stream:
            code = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT).returncode
        require(code == 0, "K9_K6_REHEARSAL_FAILED")
    path = reports / "platform.synthetic.json"
    return {"reportRef": str(path.relative_to(args.artifacts)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "runnerIdentity": name, "trust": str(work / "private/synthetic-trust.json"), "keyFile": str(key_path)}


def record(index, attempt, state):
    current = load(index) if index.exists() else []
    current.append({"attempt": attempt.name, "directory": str(attempt), "work": state["work"], "mode": state["mode"],
                    "failure": state.get("error"), "classification": "passed_rehearsal" if state["status"] == "passed" else "engineering_incomplete",
                    "sourceUnchanged": state.get("sourceUnchanged"), "realPF": False})
    temporary = index.with_suffix(".next")
    temporary.write_bytes(canonical(current) + b"\n")
    temporary.replace(index)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("rehearse", "pf"), required=True)
    parser.add_argument("--source-schema", required=True)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--subject-sha256", type=subject_sha256, default=R4_SUBJECT_SHA256, help="期望组合 subject；默认保留 r4")
    parser.add_argument("--authorization-reference", help="pf：A6 单轮授权引用")
    parser.add_argument("--ready-dir", type=Path, help="pf：root 侧每轮 --ready-marker 所在目录，标记名 e3-<scope>-<scenario>.ready")
    parser.add_argument("--ready-timeout", type=float, default=1800, help="pf：每轮等待 root 就绪的秒数")
    parser.add_argument("--inbound-segment", default=SEGMENTS["peer_inbound"][0], help="peer_inbound 使用的已登记 port_scan 片段")
    parser.add_argument("--rounds", help="仅诊断：逗号分隔的 scope-scenario；不完整矩阵不生成 K6 报告")
    parser.add_argument("--directory", type=Path, default=ROOT / ".cache/k9-20261012")
    parser.add_argument("--attempts", type=Path, default=ROOT / ".cache/k9-20261012/attempts.json")
    parser.add_argument("--artifacts", type=Path, default=HOME / "ai/artifacts/cyber-guard")
    parser.add_argument("--scenario", type=Path, default=ROOT / ".cache/j2-20261011/g3-scenario.json")
    parser.add_argument("--selection", type=Path, default=ROOT / ".cache/j1-20261011-reg-preroll30/selection.json")
    parser.add_argument("--mysql-service", type=Path, default=HOME / "development/services/databases/mysql-server-8.0.42")
    parser.add_argument("--java-home", type=Path, default=HOME / "development/runtimes/java/temurin-25.0.2/Contents/Home")
    parser.add_argument("--maven", type=Path, default=HOME / "development/toolchains/build/apache-maven-3.9.13/bin/mvn")
    parser.add_argument("--go", type=Path, default=HOME / "development/runtimes/go/go-1.26.4/bin/go")
    args = parser.parse_args()
    args.artifacts = args.artifacts.resolve()
    os.umask(0o077)
    print(json.dumps(run(args), ensure_ascii=False, indent=1)[:4000])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(str(exc) if isinstance(exc, ValueError) or exc.__class__.__name__ == "Rejected" else "K9_RUNTIME_FAILED: " + exc.__class__.__name__,
              file=sys.stderr)
        raise SystemExit(2)
