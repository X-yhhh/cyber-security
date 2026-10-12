"""E3 前置检查与隔离 P4/Go 联合编排；dry-run 不请求 sudo、不修改 PF 或数据库。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from executor.common import canonical, digest, require, write_new
from executor.contract import protected_ports_sha256
from executor.pki import create


def probe(args, env=None):
    """只返回退出码和受控版本输出；失败时不透传可能包含凭据的诊断。"""
    try:
        r = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)
        return r.returncode, r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def preflight(args):
    protection = json.loads((ROOT / "scripts/p5/lab-protection.json").read_text())
    require(set(protection) == {"protectedBudgetTargetIds", "protectedServicePorts"} and
            protection["protectedBudgetTargetIds"] == [] and
            all(type(p) is int and 1 <= p <= 65535 for p in protection["protectedServicePorts"]) and
            len(set(protection["protectedServicePorts"]) | {22, 53, 3389}) <= 128,
            "P4_PROTECTION_INVALID")
    env = dict(os.environ, JAVA_HOME=str(args.java_home),
               PATH=str(args.java_home / "bin") + os.pathsep + os.environ.get("PATH", ""))
    code, version = probe([str(args.java_home / "bin/java"), "-version"], env)
    # java -version 写 stderr，使用 release 文件核对精确主版本。
    release = args.java_home / "release"
    java25 = code == 0 and release.is_file() and re.search(r'JAVA_VERSION="25[.\"]', release.read_text()) is not None
    mcode, mversion = probe([str(args.maven), "--version"], env)
    gcode, gversion = probe([str(args.go), "version"])
    pcode, _ = probe([sys.executable, "-c", "import cryptography,jsonschema,rfc8785"])
    base = os.environ.get("DB_TEST_BASE_URL", "")
    dburl = urllib.parse.urlsplit(base.removeprefix("jdbc:"))
    localdb = dburl.scheme == "mysql" and dburl.hostname in ("127.0.0.1", "localhost") and dburl.path in ("", "/") and not dburl.query and not dburl.username
    credentials = all(os.environ.get(k) for k in ("DB_TEST_USERNAME", "DB_TEST_PASSWORD"))
    dbcode, dbversion = (127, "")
    grants = ""
    if localdb and credentials:
        dbcode, dbversion = probe([str(args.mysql), "--protocol=TCP", "-h", "127.0.0.1", "-P", str(dburl.port or 3306),
                                  "-u", os.environ["DB_TEST_USERNAME"], "-N", "-B", "-e", "SELECT VERSION()"],
                                 dict(os.environ, MYSQL_PWD=os.environ["DB_TEST_PASSWORD"]))
        _, grants = probe([str(args.mysql), "--protocol=TCP", "-h", "127.0.0.1", "-P", str(dburl.port or 3306),
                           "-u", os.environ["DB_TEST_USERNAME"], "-N", "-B", "-e", "SHOW GRANTS FOR CURRENT_USER"],
                          dict(os.environ, MYSQL_PWD=os.environ["DB_TEST_PASSWORD"]))
    default = (ROOT / "backend/src/main/resources/application.yml").read_text()
    global_privileges = set()
    for grant in grants.splitlines():
        match = re.match(r"GRANT (.+?) ON \*\.\* TO ", grant)
        if match:
            global_privileges.update(match[1].split(", "))
    checks = {"jdk25": java25, "maven": mcode == 0 and "Java version: 25" in mversion,
              "go1264": gcode == 0 and "go1.26.4" in gversion, "pythonDependencies": pcode == 0,
              "mysql8": dbcode == 0 and dbversion.startswith("8."), "isolatedDatabaseURL": localdb,
              "databaseCredentialsPresent": credentials, "schemaCreateDropPrivileges":
              "ALL PRIVILEGES" in global_privileges or {"CREATE", "DROP"} <= global_privileges,
              "defaultHasNoGuard": "guard:" not in default and "cyber.guard." not in default,
              "labProfilePresent": (ROOT / "backend/src/main/resources/application-lab.yml").is_file(),
              "lo0": probe(["/sbin/ifconfig", "lo0"])[0] == 0,
              "pfToolsPresent": Path("/sbin/pfctl").is_file() and Path("/usr/bin/clang").is_file()}
    pfcode, _ = probe(["/sbin/pfctl", "-s", "info"])
    report = {"kind": "p5-e3-preflight/1", "dryRun": args.mode == "dry-run", "checks": checks,
              "prepared": all(checks.values()), "sudoRequested": False, "firewallModified": False,
              "businessDatabaseModified": False, "realPFAcceptance": False,
              "protectionSetSha256": digest(protection), "protectedPortsSha256": protected_ports_sha256(protection["protectedServicePorts"]),
              "configuration": {"profile": "lab", "interface": "lo0", "backend": "HTTPS TLS1.3 loopback",
                                "targets": "Go guardtargets mTLS with separate collector/executor certificates",
                                "schema": "cyber_guard_api_p4_<random UUID>; created and dropped by isolated fixture",
                                "signingKey": "ephemeral DER PKCS8 Ed25519 reference; 0600",
                                "runnerTrust": "ephemeral runner public key reference; 0600",
                                "executorTrust": "separate command public key trustFile from lab.executor.trust-file; 0600",
                                "artifactRoot": "dedicated run directory outside repository",
                                "ttlSeconds": 60, "continuousSeconds": 120, "activeRules": 10, "newPerMinute": 5},
              "matrix": [{"scope": scope, "scenarios": ["revoke", "disconnect", "receipt_loss"]}
                         for scope in ("peer_service", "peer_inbound")],
              "pending": ["A4 per-round explicit authorization for sudo/PF/lo0 alias",
                          "PF root/anchors/status/helper ABI checked again under A4", "A5 business V22 not executed",
                          "synthetic model/reports are fixture evidence, not G3 or release qualification"],
              "pfReadableWithoutSudo": pfcode == 0}
    args.directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    write_new(args.directory / "preflight.json", canonical(report))
    print(json.dumps(report, indent=2))
    return report, env


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("dry-run", "rehearse", "pf"), default="dry-run")
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--java-home", type=Path, default=Path(os.environ.get("JAVA25_HOME", os.environ.get("JAVA_HOME", "/nonexistent"))))
    for name in ("maven", "go", "mysql"):
        command = "mvn" if name == "maven" else name
        p.add_argument("--" + name, type=Path, default=Path(shutil.which(command) or "/nonexistent"))
    p.add_argument("--authorization-reference")
    p.add_argument("--subject-binding",type=Path,help="K6：必须与 root 暂存包及实际执行配置的 subject 一致")
    p.add_argument("--scope", choices=("peer_service", "peer_inbound"))
    p.add_argument("--scenario", choices=("revoke", "disconnect", "receipt_loss"))
    p.add_argument("--external-executor", action="store_true",
                   help="演练模式下也经中继连接外部执行端，用于无 root 验证拆分协议")
    args = p.parse_args()
    require(args.directory.is_absolute() and not args.directory.resolve().is_relative_to(ROOT.resolve()), "EXTERNAL_RUN_DIRECTORY_REQUIRED")
    require(args.mode != "pf" or args.authorization_reference, "A4_AUTHORIZATION_REFERENCE_REQUIRED")
    # 真实 PF 只由 root 暂存副本中的执行端操作（lab_root_launch.py e3-executor）；后端、Maven 与 JUnit 不以 root 运行。
    require(args.mode != "pf" or os.geteuid() != 0, "A4_BACKEND_MUST_NOT_RUN_AS_ROOT")
    require((args.scope is None) == (args.scenario is None), "LAB_SINGLE_ROUND_PAIR_REQUIRED")
    require(args.mode != "pf" or args.scope is not None, "A4_SINGLE_ROUND_REQUIRED")
    os.umask(0o077)
    report, env = preflight(args)
    binding=None
    if args.subject_binding:
        from executor.subject_binding import validate
        binding=validate(json.loads(args.subject_binding.read_bytes()))
        write_new(args.directory/'subject-binding.json',canonical(binding))
    if args.mode == "dry-run":
        return 0 if report["prepared"] else 1
    require(report["prepared"], "PREFLIGHT_FAILED")
    create(args.directory / "backend-pki")
    binary = args.directory / "guardtargets"
    build = subprocess.run([str(args.go), "build", "-o", str(binary), "./cmd/guardtargets"], cwd=ROOT / "sensor", capture_output=True)
    require(build.returncode == 0, "GUARDTARGETS_BUILD_FAILED")
    env.update(P5_JOINT_LAB="true", P5_RUN_DIR=str(args.directory), P5_PYTHON=sys.executable,
               P5_GUARDTARGETS=str(binary), P5_FIREWALL=args.mode, P5_A4_REFERENCE=args.authorization_reference or "")
    for key in ("P5_SCOPE", "P5_SCENARIO", "P5_EXTERNAL_EXECUTOR"):
        env.pop(key, None)
    if args.mode == "pf" or args.external_executor:
        env["P5_EXTERNAL_EXECUTOR"] = "true"
    if args.scope:
        env.update(P5_SCOPE=args.scope, P5_SCENARIO=args.scenario)
    with (args.directory / "backend.log").open("xb") as log:
        result = subprocess.run([str(args.maven), "-B", "-Dtest=GuardJointLabTest#jointMatrix", "test"],
                                cwd=ROOT / "backend", env=env, stdout=log, stderr=subprocess.STDOUT)
    summaries = [args.directory / f"{scope}-{scenario}/result.json"
                 for scope in ("peer_service", "peer_inbound") for scenario in ("revoke", "disconnect", "receipt_loss")
                 if (args.directory / f"{scope}-{scenario}/result.json").is_file()]
    rows = [json.loads(path.read_text()) for path in summaries]
    source_paths = sorted((ROOT / "scripts/p5").glob("*.py")) + sorted((ROOT / "executor").glob("*.py"))
    source_paths += [ROOT / "backend/src/main/resources/application-lab.yml", ROOT / "scripts/p5/lab-protection.json"]
    source_paths += sorted((ROOT / "backend/src/main/java/com/xyh/cybersecurity/guard").glob("*.java"))
    outcome = {"passed": result.returncode == 0 and len(rows) == (1 if args.scope else 6) and all(r["passed"] for r in rows),
               "realPF": args.mode == "pf" and bool(rows) and all(r.get("realPF") is True for r in rows), "scenarios": [{k: r[k] for k in ("scope", "scenario", "passed")} for r in rows],
               "guardtargetsSha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "sourceSha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in source_paths},
               "configurationSha256": {str(path.relative_to(args.directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                                       for path in sorted(args.directory.glob("*/executor-config.json"))},
               "businessDatabaseModified": False}
    if binding is not None:outcome['subjectBinding']=binding
    write_new(args.directory / "summary.json", canonical(outcome))
    print(json.dumps(outcome, indent=2))
    return 0 if outcome["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(str(exc) if exc.__class__.__name__ == "Rejected" else "JOINT_LAB_FAILED", file=sys.stderr)
        raise SystemExit(1)
