#!/usr/bin/env python3
"""J1 research 演练运行器：冻结清单、真实 mTLS/ONNX/MySQL 两轮回放。

仅使用已批准 research 组合和无执行范围的虚拟资产。原件留在 Mac，
不读取 test、不拟合、不改变模型/策略、不接执行器或目标、不签命令。
数据库在业务库完整快照的隔离副本运行；私钥和凭据只写 0600 文件。
运行结果与验收通过分开；每次运行只创建新目录，不覆盖历史证据。
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import uuid

import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


UTC = timezone.utc


def stamp():
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def uid():
    return str(uuid.uuid4())


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def jcs(value):
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def write(path, value, mode=0o600):
    path = Path(path)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    path.chmod(mode)


def event(kind, **values):
    print(json.dumps(dict(at=stamp(), event=kind, **values), ensure_ascii=False), flush=True)


def secret(service):
    return subprocess.run(["/usr/bin/security", "find-generic-password", "-a", os.environ["USER"],
                           "-s", service, "-w"], check=True, capture_output=True, text=True).stdout.strip()


class Database:
    def __init__(self, service):
        self.service = service
        self.env = dict(os.environ, MYSQL_PWD=secret("com.xyh.cyber-security.db-test"))
        self.client = [str(service / "bin/mysql"), "--protocol=TCP", "--host=127.0.0.1", "--port=3306",
                       "--user=root", "--batch", "--raw", "--skip-column-names", "--connect-timeout=5"]

    def query(self, sql, schema=None):
        p = subprocess.run(self.client + ([schema] if schema else []), input=sql.encode(),
                           env=self.env, capture_output=True, timeout=300)
        if p.returncode:
            raise RuntimeError("SQL operation failed; secret-bearing stderr suppressed")
        return p.stdout

    def snapshot(self, schema):
        tables = ["guard_observation_batch", "guard_observation", "guard_inference", "guard_rule_evaluation",
                  "guard_episode", "guard_decision", "guard_action", "guard_command", "guard_executor",
                  "guard_target_binding", "guard_asset_binding", "guard_replay_run"]
        counts = {t: int(self.query("SELECT COUNT(*) FROM " + t, schema)) for t in tables}
        return dict(schema=schema, at=stamp(), counts=counts,
                    accountsSha256=hashlib.sha256(self.query("SELECT * FROM sys_user ORDER BY id", schema)).hexdigest(),
                    historySha256=hashlib.sha256(self.query("SELECT * FROM flyway_schema_history ORDER BY installed_rank", schema)).hexdigest(),
                    bundleStatusSha256=hashlib.sha256(self.query("SELECT public_id,status,revision FROM guard_release_bundle ORDER BY id", schema)).hexdigest())

    def clone(self, source, target, backup):
        before = self.snapshot(source)
        dump = [str(self.service / "bin/mysqldump"), "--protocol=TCP", "--host=127.0.0.1", "--user=root",
                "--single-transaction", "--routines", "--triggers", "--events", "--hex-blob",
                "--set-gtid-purged=OFF", "--no-tablespaces", source]
        with backup.open("xb") as stream:
            p = subprocess.run(dump, env=self.env, stdout=stream, stderr=subprocess.PIPE, timeout=300)
        backup.chmod(0o600)
        if p.returncode:
            raise RuntimeError("database snapshot failed")
        self.query(f"CREATE DATABASE `{target}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin")
        with backup.open("rb") as stream:
            p = subprocess.run(self.client + [target], env=self.env, stdin=stream, capture_output=True, timeout=300)
        if p.returncode:
            raise RuntimeError("isolated database restore failed")
        restored = self.snapshot(target)
        for key in ("counts", "accountsSha256", "historySha256", "bundleStatusSha256"):
            if before[key] != restored[key]:
                raise RuntimeError("database snapshot parity failed: " + key)
        return dict(source=before, restored=restored, backupSha256=sha(backup), restoreVerified=True)


class Session:
    def __init__(self, base, context):
        self.base = base
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                                 urllib.request.HTTPCookieProcessor(self.cookies))
        self.csrf = None

    def call(self, method, path, body=None, headers=None, expected=(200,)):
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        h = {"Content-Type": "application/json", "Accept": "application/json", **(headers or {})}
        if self.csrf and method != "GET":
            h["X-CSRF-TOKEN"] = self.csrf
        req = urllib.request.Request(self.base + path, data=data, headers=h, method=method)
        try:
            with self.opener.open(req, timeout=60) as response:
                status, payload = response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            status, payload = error.code, json.loads(error.read())
        if status not in expected:
            code = payload.get("error", {}).get("code") if isinstance(payload, dict) else "invalid_response"
            raise RuntimeError(f"{method} {path}: HTTP {status} {code}")
        return payload

    def login(self, credentials):
        self.csrf = self.call("GET", "/api/v2/auth/csrf")["data"]["token"]
        self.call("POST", "/api/v2/auth/login", credentials, {"Idempotency-Key": uid()})
        self.csrf = self.call("GET", "/api/v2/auth/csrf")["data"]["token"]
        return self

    def v2(self, path, body=None, revision=None, method="POST"):
        headers = {"Idempotency-Key": uid()}
        if revision is not None:
            headers["If-Match"] = str(revision)
        return self.call(method, "/api/v2" + path, body, headers, (200, 201, 202))["data"]

    def machine(self, sensor, credential, operation, body):
        return self.call("POST", f"/api/v2/machine/sensors/{sensor}/{operation}", body,
                         {"Authorization": "Bearer " + credential, "Idempotency-Key": uid()}, (200, 202))["data"]


def tls_files(directory):
    directory.mkdir(mode=0o700)
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "J1 temporary CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
          .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
          .sign(ca_key, hashes.SHA256()))
    for name, key in [("ca", ca_key)]:
        (directory / (name + ".key")).write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    password = secrets.token_urlsafe(32)
    for name, purpose in [("server", ExtendedKeyUsageOID.SERVER_AUTH), ("client", ExtendedKeyUsageOID.CLIENT_AUTH)]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "J1 " + name)]))
                .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
                .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
                .add_extension(x509.ExtendedKeyUsage([purpose]), False))
        if name == "server":
            import ipaddress
            cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                         x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        cert = cert.sign(ca_key, hashes.SHA256())
        (directory / (name + ".key")).write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (directory / (name + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        if name == "server":
            (directory / "server.p12").write_bytes(pkcs12.serialize_key_and_certificates(b"server", key, cert, [ca],
                                                  serialization.BestAvailableEncryption(password.encode())))
    (directory / "trust.p12").write_bytes(pkcs12.serialize_java_truststore([pkcs12.PKCS12Certificate(ca,b"ca")],
                                             serialization.BestAvailableEncryption(password.encode())))
    for p in directory.iterdir():
        p.chmod(0o600)
    return password


def ssl_context(directory, client=True):
    ctx = ssl.create_default_context(cafile=str(directory / "ca.pem"))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if client:
        ctx.load_cert_chain(str(directory / "client.pem"), str(directory / "client.key"))
    return ctx


def process_privileges(pids):
    """记录本次进程的有效 uid，并枚举执行器/pfctl 进程；PF 规则只能由 root 修改，非 root 且无执行器即不可能写入。"""
    listing = subprocess.run(["/bin/ps", "-axo", "pid=,uid=,command="], capture_output=True, text=True, check=True).stdout.splitlines()
    rows = {int(line.split()[0]): line.split(None, 2) for line in listing if line.strip()}
    owned = [dict(pid=pid, uid=int(rows[pid][1]), command=rows[pid][2][:120]) for pid in pids if pid in rows]
    markers = ("-m executor", "pf_lab", "joint_executor", "lab_root_launch", "/sbin/pfctl")
    executors = [line.split(None, 2)[2][:120] for line in listing if line.strip() and any(m in line for m in markers)]
    return dict(at=stamp(), runnerUid=os.geteuid(), processes=owned, executorOrPfctlProcesses=executors)


def capture_start(segment):
    """片段登记的采集起点（原事件时间，RFC3339 微秒）；未登记则为空，回放与离线均从首包起算。"""
    us = segment.get("captureStartUs")
    return [] if us is None else ["-capture-start", datetime.fromtimestamp(us / 1e6, UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")]


def pf_snapshot(allowed=False):
    """只在已显式授权时读取 PF；默认留下未执行原因，绝不调用 sudo 或 pfctl。"""
    commands = [("info", ["/usr/bin/sudo", "-n", "/sbin/pfctl", "-s", "info"]),
                ("rules", ["/usr/bin/sudo", "-n", "/sbin/pfctl", "-sr"]),
                ("anchors", ["/usr/bin/sudo", "-n", "/sbin/pfctl", "-a", "*", "-sr"])]
    if not allowed:
        return [dict(operation=operation, attempted=False, exitCode=None, stdoutSha256=None,
                     reason="not_executed_authorization_boundary") for operation, _ in commands]
    results = []
    for operation, command in commands:
        p = subprocess.run(command, capture_output=True, timeout=10)
        results.append(dict(operation=operation, attempted=True, exitCode=p.returncode,
                            stdoutSha256=hashlib.sha256(p.stdout).hexdigest()))
    return results


class Run:
    def __init__(self, args):
        self.args = args
        self.root = Path.cwd()
        self.work = args.work.resolve()
        self.artifact = args.artifacts.resolve()
        self.package = self.artifact / args.package_ref
        self.replay_ref = "replays/" + self.work.name
        self.public = self.artifact / self.replay_ref
        self.java = args.java.resolve()
        self.jar = self.work / "bin/backend.jar"
        self.schema = "cyber_j1_" + datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        self.db = Database(args.mysql_service)
        self.process = None

    def backend(self, password):
        suffix = getattr(self, "resume_suffix", "")
        keystores = getattr(self, "resume_keystores", self.work / "private/tls")
        env = dict(os.environ, DB_URL="jdbc:mysql://127.0.0.1:3306/" + self.schema,
                   DB_USERNAME="root", DB_PASSWORD=self.db.env["MYSQL_PWD"], DB_POOL_SIZE=str(self.args.server_threads+4),
                   LOGIN_THROTTLE_HMAC_KEY=secret("com.xyh.cyber-security.login-throttle-hmac"),
                   SERVER_PORT=str(self.args.port), SERVER_ADDRESS="127.0.0.1", SESSION_COOKIE_SECURE="true",
                   OUTBOX_RELAY_ENABLED="false", INGEST_CONSUMER_ENABLED="false", CYBER_DRIFT_ENABLED="false",
                   SERVER_SSL_ENABLED="true", SERVER_SSL_CLIENT_AUTH="need", SERVER_SSL_ENABLED_PROTOCOLS="TLSv1.3",
                   SERVER_SSL_KEY_STORE=str(keystores / "server.p12"), SERVER_SSL_KEY_STORE_TYPE="PKCS12",
                   SERVER_SSL_KEY_STORE_PASSWORD=password, SERVER_SSL_TRUST_STORE=str(keystores / "trust.p12"),
                   SERVER_SSL_TRUST_STORE_TYPE="PKCS12", SERVER_SSL_TRUST_STORE_PASSWORD=password)
        command = [str(self.java), "--enable-native-access=ALL-UNNAMED", "-Xms256m", "-Xmx2g",
                   "-Dcyber.guard.automation-enabled=false", "-Dcyber.guard.artifact-root=" + str(self.artifact),
                   "-Dcyber.guard.report-trust-file=" + str(self.args.report_trust),
                   "-Dcyber.model-artifact.root=" + str(Path.home()/"Workspace/deliveries"),
                   f"-Dserver.tomcat.threads.max={self.args.server_threads}", f"-Dserver.tomcat.threads.min-spare={self.args.server_threads}", "-Dserver.tomcat.accept-count=64",
                   "-Dspring.session.timeout=4h", "-Dserver.servlet.session.timeout=4h", "-jar", str(self.jar)]
        log = (self.work / ("backend" + suffix + ".log")).open("xb")
        self.process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        self.base = f"https://127.0.0.1:{self.args.port}"
        self.context = ssl_context(self.work / "private/tls")
        for _ in range(90):
            if self.process.poll() is not None:
                raise RuntimeError("backend exited during startup")
            try:
                with urllib.request.urlopen(self.base + "/api/v2/auth/csrf", context=self.context, timeout=2):
                    break
            except (urllib.error.URLError, ConnectionError):
                time.sleep(1)
        else:
            raise RuntimeError("backend startup timeout")
        with socket.create_connection(("127.0.0.1", self.args.port), timeout=5) as connection:
            with self.context.wrap_socket(connection, server_hostname="127.0.0.1") as connection:
                tls_version = connection.version()
        denied = False
        try:
            urllib.request.urlopen(self.base + "/api/v2/auth/csrf", context=ssl_context(self.work / "private/tls", False), timeout=5)
        except (urllib.error.URLError, ssl.SSLError, ConnectionError):
            denied = True
        if tls_version != "TLSv1.3" or not denied:
            raise RuntimeError("mTLS negative probe failed")
        write(self.work / ("transport" + suffix + ".json"), dict(at=stamp(), tlsVersion=tls_version, clientCertificateRequired=denied,
                                                listener="loopback", backendPid=self.process.pid, backendSha256=sha(self.jar),
                                                serverThreads=self.args.server_threads, observationConsumer="research T2 after T1 commit", automationEnabled=False))
        self.operator = Session(self.base, self.context).login(json.loads(self.args.operator_file.read_text()))
        creds = json.loads(self.args.reviewer_file.read_text())
        self.reviewer = Session(self.base, self.context).login({"username": creds.get("username", "guard-reviewer"), "password": creds["password"]})

    def freeze(self):
        if self.args.scenario_ref:
            frozen=self.artifact/self.args.scenario_ref
            self.scenario=read_scenario=json.loads(frozen.read_text())
            self.scenario_sha=sha(frozen)
            self.public=frozen.parent
            self.replay_ref=str(self.public.relative_to(self.artifact))
            if sha(self.jar)!=read_scenario["backendSha256"] or sha(self.work/"bin/guardlive")!=read_scenario["sensorSha256"]:
                raise RuntimeError("frozen scenario binary mismatch")
            shutil.copyfile(frozen,self.work/"scenario.json")
            (self.work/"scenario.json").chmod(0o400)
            event("scenario_reused_without_changes",sha256=self.scenario_sha,segments=len(self.scenario["segments"]))
            return
        rebound = None
        if self.args.rebind_scenario_ref:
            # 沿用已冻结的片段清单（PCAP 引用与摘要逐项不变），只重新绑定修复后的二进制与源码清单。
            origin = self.artifact / self.args.rebind_scenario_ref
            draft = json.loads(origin.read_text())
            rebound = dict(scenarioRef=self.args.rebind_scenario_ref, scenarioSha256=sha(origin),
                           segmentsSha256=jcs([{k: v for k, v in s.items() if k != "captureStartUs"} for s in draft["segments"]]))
            if self.args.capture_warmup_seconds:
                # 传感器在首包前已运行：采集起点 = 原首包 − 预热，PCAP 字节与片段边界不变；登记于回放前。
                for segment in draft["segments"]:
                    segment["captureStartUs"] = segment["sourceFirstUs"] - self.args.capture_warmup_seconds * 1_000_000
                rebound["captureWarmupSeconds"] = self.args.capture_warmup_seconds
            for segment in draft["segments"]:
                self.artifact.joinpath(segment["pcapRef"]).resolve().relative_to(self.artifact)
                if sha(self.artifact / segment["pcapRef"]) != segment["pcapSha256"]:
                    raise RuntimeError("frozen pcap digest mismatch")
        else:
            draft = json.loads((self.args.registration / "draft-scenario.json").read_text())
        manifest = json.loads((self.package / "model-manifest.json").read_text())
        policy = json.loads((self.package / "policy-research.json").read_text())
        lab = json.loads((self.package / "policy-m1-lab.json").read_text())
        same = ["familyPolicies", "rulePolicies", "maxEvidenceAgeMs", "minEvidenceSpanMs", "contextWindowSeconds", "minPeerFlowStarts", "profile", "acceptedProfiles"]
        if any(policy.get(k) != lab.get(k) for k in same):
            raise RuntimeError("research numerical policy differs from M1")
        self.public.mkdir(parents=True, mode=0o700, exist_ok=False)
        (self.public / "clips").mkdir(mode=0o700)
        for segment in ([] if rebound else draft["segments"]):
            origin = self.args.registration / "clips" / (segment["segmentId"] + ".pcap")
            if sha(origin) != segment["pcapSha256"]:
                raise RuntimeError("pre-freeze pcap digest mismatch")
            target = self.public / "clips" / origin.name
            shutil.copyfile(origin, target)
            target.chmod(0o400)
            segment["pcapRef"] = self.replay_ref + "/clips/" + origin.name
        closeout = self.args.closeout
        if sha(closeout) != self.args.closeout_sha:
            raise RuntimeError("signed final closeout binding mismatch")
        shutil.copyfile(closeout, self.public / "closeout.json")
        (self.public / "closeout.json").chmod(0o400)
        inventory = []
        for p in sorted(self.package.rglob("*")):
            if p.is_file():
                inventory.append(dict(path=str(p.relative_to(self.package)), sha256=sha(p)))
        source_files = sorted(set(subprocess.run(["rg", "--files", "backend/src", "sensor/internal", "sensor/cmd",
                           "scripts/p7"], check=True, capture_output=True, text=True).stdout.splitlines()))
        sources = [dict(path=p, sha256=sha(p)) for p in source_files]
        write(self.work / "source-manifest.json", sources, 0o400)
        draft.update(frozenAt=stamp(), modelId=manifest["modelId"], policyId=policy["policyId"],
                     modelSha256=manifest["artifactSha256"], manifestSha256=sha(self.package / "model-manifest.json"),
                     policySha256=jcs(policy), policyRawSha256=sha(self.package / "policy-research.json"),
                     m1PolicyRawSha256=sha(self.package / "policy-m1-lab.json"), numericalPolicyEqualsM1=True,
                     backendSha256=sha(self.jar), sensorSha256=sha(self.work / "bin/guardlive"),
                     guardextractSha256=sha(self.work / "bin/guardextract"), guardreplaydiffSha256=sha(self.work / "bin/guardreplaydiff"),
                     extractorSha256=manifest["extractorSha256"], sourceManifestSha256=sha(self.work / "source-manifest.json"),
                     deliveryInventorySha256=jcs(inventory), baseCommit=subprocess.run(["git", "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip(),
                     closeoutSha256=self.args.closeout_sha,
                     replayConcurrency=sum(s["family"] == "normal" for s in draft["segments"]) + min(self.args.attack_concurrency, sum(s["family"] != "normal" for s in draft["segments"])),
                     registrationVerificationSha256=sha(self.work/"registration-verification.json"),
                     gatesExcludedFromHypothetical=["liveCaptureHealth", "targetBinding", "executionAuthorization", "protectionAndBudget"],
                     serverThreads=self.args.server_threads, packageRef=self.args.package_ref,
                     attackConcurrency=self.args.attack_concurrency, maxBatchSize=self.args.batch_size)
        if rebound:
            if jcs([{k: v for k, v in s.items() if k != "captureStartUs"} for s in draft["segments"]]) != rebound["segmentsSha256"]:
                raise RuntimeError("rebinding changed frozen segments")
            draft["reboundFrom"] = rebound
        write(self.public / "scenario.json", draft, 0o400)
        write(self.work / "scenario.json", draft, 0o400)
        write(self.work / "delivery-manifest.json", inventory, 0o400)
        self.scenario = draft
        self.scenario_sha = sha(self.public / "scenario.json")
        event("scenario_frozen", sha256=self.scenario_sha, segments=len(draft["segments"]), normalSeconds=draft["normalDurationSeconds"])

    def identities(self, round_number):
        path = self.work / f"round-{round_number}"
        path.mkdir(mode=0o700)
        records = []
        for segment in self.scenario["segments"]:
            sid = segment["segmentId"]
            segment_dir = path / sid
            segment_dir.mkdir(mode=0o700)
            asset = self.operator.v2("/assets", dict(assetKey=f"{self.work.name}-{round_number}-{sid}", platform="macos", environment="research", owner="J1 replay only"))["id"]
            auth = self.operator.v2(f"/assets/{asset}/authorizations", dict(interfaces=["replay0"], observationAllowed=True, executionScopes=[],
                    validFrom=(datetime.now(UTC)-timedelta(minutes=1)).isoformat().replace("+00:00","Z"), validUntil=(datetime.now(UTC)+timedelta(hours=4)).isoformat().replace("+00:00","Z"), evidenceRef=self.replay_ref+"/scenario.json"))["id"]
            self.reviewer.v2(f"/authorizations/{auth}/decisions", dict(decision="approve", reason="J1 research 仅观察、执行范围为空"), 1)
            scope, boot = uid(), uid()
            sensor = self.operator.v2("/sensors", dict(assetId=asset, platform="macos", captureScopeId=scope))
            token = segment_dir / "credential"
            token.write_text(sensor["credential"])
            token.chmod(0o600)
            config = dict(contractVersion="host-guard/5.0.0-rc.2", profileSha256=json.loads((self.package/"model-manifest.json").read_text())["featureProfileSha256"],
                          captureHealthVersion="host-guard-capture-health/1.0.0", interfaceIds=["replay0"], limits=dict(maxBatchSize=self.scenario.get("maxBatchSize",100)),
                          captureScopeId=scope, addressFamily="ipv4", buildSha256=self.scenario["sensorSha256"])
            config_id = self.operator.v2(f"/sensors/{sensor['id']}/configs", config)["id"]
            self.reviewer.v2(f"/sensor-configs/{config_id}/decisions", dict(decision="approve", reason="J1 冻结传感器摘要与捕获域"), 1)
            self.operator.machine(sensor["id"], sensor["credential"], "heartbeats", dict(bootId=boot, version="J1 research", configHash=jcs(config), lastSequence=0, clockSkewMs=None))
            secret_file = segment_dir / "peer-secret"
            if round_number == 1:
                secret_file.write_bytes(os.urandom(32))
            else:
                shutil.copyfile(self.work / "round-1" / sid / "peer-secret", secret_file)
            secret_file.chmod(0o600)
            selection = next(s for s in self.selection if s["segmentId"] == sid)
            common = dict(assetId=asset, sensorId=sensor["id"], bootId=boot, captureScopeId=scope,
                          localAddresses=[selection["host"]], secretFile=str(secret_file), keyEpoch=1)
            write(segment_dir / "extract-config.json", common)
            live = dict(common, environment="research", captureScope="all_inbound_tcp", interface="replay0", allowedInterfaces=["replay0"],
                        authorizedUntil=(datetime.now(UTC)+timedelta(hours=4)).isoformat().replace("+00:00","Z"),
                        upload=dict(baseUrl=self.base, caFile=str(self.work/"private/tls/ca.pem"), certificateFile=str(self.work/"private/tls/client.pem"),
                                    keyFile=str(self.work/"private/tls/client.key"), credentialFile=str(token), spoolDir=str(segment_dir/"spool"), healthWindowMs=1000))
            write(segment_dir / "live-config.json", live)
            records.append(dict(segmentId=sid, assetId=asset, sensorId=sensor["id"], bootId=boot, captureScopeId=scope, configId=config_id, authorizationId=auth))
        request = dict(scenarioId=self.scenario["scenarioId"], scenarioSha256=self.scenario_sha,
                       modelId=self.scenario["modelId"], policyId=self.scenario["policyId"], speed=1)
        run = self.operator.v2("/replay-runs", request)
        state = dict(round=round_number, replayRunId=run["id"], bundleId=run["bundleId"], scenarioSha256=self.scenario_sha, bindings=records)
        write(path / "state.json", state)
        return state

    def reference(self, state):
        path = self.work / f"round-{state['round']}"
        completed_segments = []
        for segment in self.scenario["segments"]:
            if self.args.diagnostic_segments and segment["segmentId"] not in self.args.diagnostic_segments:
                continue
            directory = path / segment["segmentId"]
            log = (directory / "reference.log").open("xb")
            command = [str(self.work / "bin/guardextract"), "-config", str(directory/"extract-config.json"), "-pcap", str(self.artifact/segment["pcapRef"]),
                       "-out", str(directory/"extracted.jsonl"), "-ledger", str(directory/"ledger.jsonl"), "-report", str(directory/"extract-report.json")] + capture_start(segment)
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
            with (directory/"extracted.jsonl").open() as source, (directory/"offline.jsonl").open("x") as target:
                for line in source:
                    observation = json.loads(line)
                    if observation["transport"] == "tcp" and observation["direction"] != "outbound":
                        target.write(line)
            (directory/"offline.jsonl").chmod(0o600)
            command = [str(self.java), "--enable-native-access=ALL-UNNAMED", "-Dloader.main=com.xyh.cybersecurity.guard.GuardReplayReference",
                       "-cp", str(self.jar), "org.springframework.boot.loader.launch.PropertiesLauncher", str(self.artifact),
                       self.args.package_ref+"/model-manifest.json", self.args.package_ref+"/policy-research.json", self.replay_ref+"/closeout.json",
                       str(directory/"offline.jsonl"), str(directory/"reference.jsonl")]
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
            log.close()
            (directory/"reference.jsonl").chmod(0o600)
            completed_segments.append(segment["segmentId"])
        event("offline_reference_completed", round=state["round"], segments=len(completed_segments),
              selectedSegments=completed_segments)

    def replay(self, state):
        path = self.work / f"round-{state['round']}"
        bindings = [{k: r[k] for k in ("segmentId", "sensorId", "bootId")} for r in state["bindings"]]
        self.operator.v2(f"/replay-runs/{state['replayRunId']}/starts", dict(scenarioRef=self.replay_ref+"/scenario.json", closeoutRef=self.replay_ref+"/closeout.json", bindings=bindings))
        if self.args.record_jfr:
            # JFR 仅保存到私有诊断目录，分析本轮实际 T1/T2 成本，不改变执行门禁或验收时限。
            subprocess.run([str(self.java.parent/"jcmd"), str(self.process.pid), "JFR.configure", "stackdepth=128"],
                           check=True, capture_output=True)
            subprocess.run([str(self.java.parent/"jcmd"), str(self.process.pid), "JFR.start", "name=j1",
                            "settings=profile", "cyber.guard.BatchPhase#enabled=true", "cyber.guard.BatchPhase#threshold=0ms",
                            "dumponexit=true", "filename="+str(self.work/"private/replay.jfr")],
                           check=True, capture_output=True)
        jobs, privileges = [], []
        def launch(segment):
            directory = path / segment["segmentId"]
            log = (directory / "live.log").open("xb")
            # 进程内排空时限放宽到 10 分钟，确认时间如实计入 J1-5，不再中途退出改由外部续传。
            command = [str(self.work/"bin/guardlive"), "-config", str(directory/"live-config.json"), "-pcap", str(self.artifact/segment["pcapRef"]),
                       "-out", str(directory/"live.jsonl"), "-report", str(directory/"live-report.json"), "-drain-timeout", "10m"] + capture_start(segment)
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            jobs.append((segment, directory, process, log))
            privileges.append(process_privileges([self.process.pid, process.pid]))
        # 每个捕获域独立以 1 倍速走文件；正常片段同时运行作为背景负载，攻击片段按 --attack-concurrency 分批，
        # 并发数如实登记，正常时长之和不当作单主机连续正常时间。
        normal = [s for s in self.scenario["segments"] if s["family"] == "normal"]
        attacks = [s for s in self.scenario["segments"] if s["family"] != "normal"]
        if self.args.diagnostic_segments:
            # 仅诊断：只跑指定片段，结果不得作为 J1 判定（审计会因片段缺失而失败）。
            normal = [s for s in normal if s["segmentId"] in self.args.diagnostic_segments]
            attacks = [s for s in attacks if s["segmentId"] in self.args.diagnostic_segments]
            for segment in normal:
                launch(segment)
            pending = list(attacks)
        if not self.args.diagnostic_segments:
            for segment in normal:
                launch(segment)
            pending = list(attacks)
        event("replay_started", round=state["round"], normalConcurrency=len(normal), attackConcurrency=self.args.attack_concurrency,
              selectedSegments=[s["segmentId"] for s in normal + attacks], diagnosticOnly=bool(self.args.diagnostic_segments), speedPerSegment=1)
        started = last = time.monotonic()
        while pending or any(p.poll() is None for _, _, p, _ in jobs):
            running = sum(p.poll() is None for s, _, p, _ in jobs if s["family"] != "normal")
            while pending and running < self.args.attack_concurrency:
                launch(pending.pop(0)); running += 1
            if self.process.poll() is not None:
                raise RuntimeError("backend stopped during replay")
            if time.monotonic()-started > 7200:
                raise RuntimeError("replay capture timeout")
            time.sleep(1)
            if time.monotonic()-last >= 20:
                last = time.monotonic()
                event("replay_progress", round=state["round"], completed=sum(p.poll() is not None for _,_,p,_ in jobs), total=len(normal)+len(attacks), elapsedSeconds=round(last-started))
        write(path/"privileges.json", privileges)
        for segment, directory, p, log in jobs:
            log.close()
            report = json.loads((directory/"live-report.json").read_text()) if (directory/"live-report.json").exists() else {}
            if report.get("upload", {}).get("pendingBatches", 0):
                self.drain(directory)
            write(directory/"process.json", dict(exitCode=p.returncode, originalUploadReportPresent=bool(report)))
            self.compare(directory)
        # 从真实数据库导出本轮不可变事实；不导出凭据、口令哈希或其他资产数据。
        self.export(state)
        if self.args.record_jfr:
            subprocess.run([str(self.java.parent/"jcmd"), str(self.process.pid), "JFR.stop", "name=j1"],
                           check=True, capture_output=True)
            (self.work/"private/replay.jfr").chmod(0o600)
        event("replay_completed", round=state["round"], elapsedSeconds=round(time.monotonic()-started))

    def diagnostic(self, state):
        """部分片段只形成诊断证据；不登记 completed，不生成 J1 汇总或允许 J2。"""
        from j1_audit import analyze_segment, qualifying_sources
        policy = json.loads((self.package/"policy-research.json").read_text())
        thresholds = {p["family"]: p["alertThreshold"] for p in policy["familyPolicies"]}
        minimum = {p["family"]: p["minDistinctFlows"] for p in policy["familyPolicies"]}
        closeout = json.loads((self.public/"closeout.json").read_text())
        path = self.work/f"round-{state['round']}"
        results = []
        for segment in self.scenario["segments"]:
            if segment["segmentId"] not in self.args.diagnostic_segments:
                continue
            qualifying = qualifying_sources(closeout,segment["family"])
            binding = next(b for b in state["bindings"] if b["segmentId"] == segment["segmentId"])
            results.append(analyze_segment(path/segment["segmentId"], segment, binding, thresholds,
                                           minimum.get(segment["family"], 1), path/"diagnostic"/segment["segmentId"], qualifying))
        write(self.work/"diagnostic.json", dict(stage="J1-diagnostic", diagnosticOnly=True, j1Passed=None, J2Allowed=False,
              replayRunId=state["replayRunId"], scenarioSha256=self.scenario_sha, segmentResults=results,
              limitation="只回放选定片段，隔离会话未登记 completed；不能代替两轮完整 J1 验收。"))
        event("diagnostic_completed", segments=len(results), J2Allowed=False)

    def compare(self, directory):
        """原报告不改；续传完成另登记比较摘要，原时延/失败状态仍用于 J1 判定。"""
        report=json.loads((directory/"live-report.json").read_text());report_path=directory/"live-report.json"
        if report["status"]!="completed":
            config=json.loads((directory/"live-config.json").read_text());spool=directory/"spool"/config["bootId"]
            segment=next(s for s in self.scenario["segments"] if s["segmentId"]==directory.name)
            if any(not (spool/p.name.replace("batch-","ack-")).exists() for p in spool.glob("batch-*.json")) or report["replay"]["packets"]!=segment["packets"]:
                raise RuntimeError("capture or upload incomplete; comparison completion refused")
            report_path=directory/"comparison-report.json"
            if not report_path.exists():
                original=report["status"];report.update(status="completed",originalStatus=original,comparisonOnly=True,
                                                        originalReportSha256=sha(directory/"live-report.json"),uploadRecovered=True)
                write(report_path,report,0o400)
        destination=directory/"observations-diff.json"
        if destination.exists():
            if destination.stat().st_size:return
            destination.rename(directory/("observations-diff-empty-"+str(time.time_ns())+".json"))
        with destination.open("xb") as output:
            diff=subprocess.run([str(self.work/"bin/guardreplaydiff"),"-offline",str(directory/"offline.jsonl"),"-replay",str(directory/"live.jsonl"),"-report",str(report_path)],stdout=output,stderr=subprocess.PIPE)
        if diff.returncode not in (0,1):raise RuntimeError("observation comparison failed; original report retained")

    def drain(self, directory):
        """只续传原 spool；409 仅在原 T1 摘要一致时重新开启一次消费，不改字节。"""
        config=json.loads((directory/"live-config.json").read_text())
        spool=directory/"spool"/config["bootId"]
        initial_pending=sum(not (spool/p.name.replace("batch-","ack-")).exists() for p in spool.glob("batch-*.json"))
        repeated_sequence=None;repeated_attempts=0
        for attempt in range(initial_pending+3):
            pending=[p for p in sorted(spool.glob("batch-*.json")) if not (spool/p.name.replace("batch-","ack-")).exists()]
            if not pending:return
            tag="-"+str(time.time_ns())
            with (directory/("drain"+tag+".log")).open("xb") as log:
                result=subprocess.run([str(self.work/"bin/guardlive"),"-config",str(directory/"live-config.json"),"-drain",
                                       "-report",str(directory/("drain-report"+tag+".json")),"-drain-timeout","10m"],
                                      stdout=log,stderr=subprocess.STDOUT,timeout=620)
            if result.returncode==0:return
            report=json.loads((directory/("drain-report"+tag+".json")).read_text())
            pending=[p for p in sorted(spool.glob("batch-*.json")) if not (spool/p.name.replace("batch-","ack-")).exists()]
            if not pending and not report.get("upload",{}).get("fatalCode"):
                event("drain_ended_after_last_durable_ack",segment=directory.name,exitCode=result.returncode)
                return
            if report.get("upload",{}).get("fatalCode")!="IDEMPOTENCY_CONFLICT" or not pending:
                raise RuntimeError("spool drain failed; original evidence retained")
            batch=json.loads(pending[0].read_text())
            existing=self.db.query("SELECT request_sha256 FROM guard_observation_batch WHERE public_id='"+batch["batchId"]+"'",self.schema).decode().strip()
            if existing!=jcs(batch):raise RuntimeError("actual T1 idempotency conflict; resume refused")
            repeated_attempts=repeated_attempts+1 if repeated_sequence==batch["sequence"] else 1
            repeated_sequence=batch["sequence"]
            if repeated_attempts>3:raise RuntimeError("same payload made no progress; resume refused")
            event("same_payload_t2_retry",segment=directory.name,sequence=batch["sequence"],attempt=attempt+1)
            time.sleep(2)
        raise RuntimeError("same-payload T2 retry exhausted; evidence retained")

    def resume(self):
        """中断后保留 schema、身份、原采集/确认时间及 TLS 证书，不重新采集已完成轮次。"""
        self.schema=json.loads((self.work/"database-clone.json").read_text())["restored"]["schema"]
        self.selection=json.loads((self.args.registration/"selection.json").read_text())
        frozen=self.artifact/self.args.scenario_ref
        self.scenario=json.loads(frozen.read_text());self.scenario_sha=sha(frozen)
        self.public=frozen.parent;self.replay_ref=str(self.public.relative_to(self.artifact))
        if self.scenario_sha!=sha(self.work/"scenario.json") or sha(self.jar)!=self.scenario["backendSha256"] or sha(self.work/"bin/guardlive")!=self.scenario["sensorSha256"]:
            raise RuntimeError("resume frozen identity mismatch")
        self.args.operator_file=self.work/"private/isolated-operator.json"
        self.resume_suffix="-resume-"+datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        # PEM 身份保持不变；新容器密码只驻留内存，旧 keystore 与证据不覆盖。
        self.resume_keystores=self.work/"private"/self.resume_suffix.lstrip("-")
        self.resume_keystores.mkdir(mode=0o700)
        tls=self.work/"private/tls";password=secrets.token_urlsafe(32)
        key=serialization.load_pem_private_key((tls/"server.key").read_bytes(),password=None)
        certificate=x509.load_pem_x509_certificate((tls/"server.pem").read_bytes())
        ca=x509.load_pem_x509_certificate((tls/"ca.pem").read_bytes())
        (self.resume_keystores/"server.p12").write_bytes(pkcs12.serialize_key_and_certificates(b"server",key,certificate,[ca],serialization.BestAvailableEncryption(password.encode())))
        (self.resume_keystores/"trust.p12").write_bytes(pkcs12.serialize_java_truststore([pkcs12.PKCS12Certificate(ca,b"ca")],serialization.BestAvailableEncryption(password.encode())))
        for p in self.resume_keystores.iterdir():p.chmod(0o600)
        try:
            self.backend(password)
            event("frozen_backend_resumed",schema=self.schema,backendSha256=sha(self.jar))
            for number in (1,2):
                path=self.work/f"round-{number}"
                if not path.exists():
                    state=self.identities(number);self.reference(state);self.replay(state)
                else:
                    state=json.loads((path/"state.json").read_text())
                    for binding in state["bindings"]:
                        directory=path/binding["segmentId"]
                        if not (directory/"live-report.json").exists():raise RuntimeError("capture incomplete; resume will not silently recollect")
                        self.drain(directory)
                        self.compare(directory)
                    self.export(state)
                from j1_audit import assess_round
                result_path=path/"result.json"
                if not result_path.exists():write(result_path,assess_round(path,self.scenario,self.scenario_sha),0o400)
                public=self.public/f"round-{number}-result.json"
                if not public.exists():shutil.copyfile(result_path,public);public.chmod(0o400)
                if not (path/"completion.json").exists():
                    completion=self.operator.v2(f"/replay-runs/{state['replayRunId']}/completions",dict(reportRef=self.replay_ref+f"/round-{number}-result.json",reportSha256=sha(public)))
                    write(path/"completion.json",completion)
                event("round_registered",round=number)
            write(self.work/"database-after.json",self.db.snapshot(self.schema))
            write(self.work/"source-database-after.json",self.db.snapshot(self.args.source_schema))
        finally:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:self.process.wait(30)
                except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
            write(self.work/("pf-after"+self.resume_suffix+".json"),pf_snapshot(self.args.allow_pf_snapshot))
            write(self.work/("stopped"+self.resume_suffix+".json"),dict(at=stamp(),backendExitCode=None if self.process is None else self.process.poll(),schema=self.schema,port=self.args.port))
        from j1_audit import assess_all
        assess_all(self.work)

    def export(self, state):
        path = self.work / f"round-{state['round']}"
        for binding in state["bindings"]:
            directory = path / binding["segmentId"]
            sensor = binding["sensorId"]
            selects = {
                "batches": f"SELECT JSON_OBJECT('batchId',b.public_id,'sequence',b.sequence_no,'createdAt',DATE_FORMAT(b.created_at,'%Y-%m-%dT%H:%i:%s.%fZ'),'result',CAST(b.result_json AS JSON)) FROM guard_observation_batch b JOIN sensor_agent s ON s.id=b.sensor_id WHERE s.public_id='{sensor}' ORDER BY b.sequence_no",
                "observations": f"SELECT payload_json FROM guard_observation o JOIN sensor_agent s ON s.id=o.sensor_id WHERE s.public_id='{sensor}' ORDER BY o.id",
                "inferences": f"SELECT JSON_OBJECT('observationId',o.public_id,'status',i.status,'score',i.score,'family',i.family,'familyScores',CAST(i.family_scores_json AS JSON),'applicability',i.applicability,'errorCode',i.error_code,'completedAt',DATE_FORMAT(i.completed_at,'%Y-%m-%dT%H:%i:%s.%fZ')) FROM guard_inference i JOIN guard_observation o ON o.id=i.observation_id JOIN sensor_agent s ON s.id=o.sensor_id WHERE s.public_id='{sensor}' ORDER BY i.id",
                "rules": f"SELECT JSON_OBJECT('observationId',o.public_id,'ruleId',r.rule_id,'family',r.family,'matched',r.matched,'applicable',r.applicable) FROM guard_rule_evaluation r JOIN guard_observation o ON o.id=r.observation_id JOIN sensor_agent s ON s.id=o.sensor_id WHERE s.public_id='{sensor}' ORDER BY r.id",
                # 证据 JSON 很大；按主键顺序流式读取，避免 filesort 耗尽 MySQL 排序内存。
                "decisions": f"SELECT JSON_OBJECT('decisionId',d.public_id,'episodeId',e.public_id,'decision',d.decision,'reasonCode',d.reason_code,'decidedAt',DATE_FORMAT(d.decided_at,'%Y-%m-%dT%H:%i:%s.%fZ'),'bucketStart',DATE_FORMAT(e.bucket_start,'%Y-%m-%dT%H:%i:%s.%fZ'),'family',e.family,'source',e.source,'ruleId',e.rule_id,'peerKey',e.peer_key,'servicePort',e.service_port,'evidence',CAST(d.evidence_json AS JSON)) FROM guard_decision d FORCE INDEX (PRIMARY) STRAIGHT_JOIN guard_episode e ON e.id=d.episode_id STRAIGHT_JOIN sensor_agent s ON s.id=e.sensor_id WHERE s.public_id='{sensor}' ORDER BY d.id",
            }
            for name, sql in selects.items():
                p = directory/("db-"+name+".jsonl")
                p.write_bytes(self.db.query(sql, self.schema))
                p.chmod(0o600)

    def run(self):
        self.selection = json.loads((self.args.registration/"selection.json").read_text())
        # 新诊断目录可以只预置二进制；凭据目录须在克隆和写入隔离身份前准备好。
        (self.work/"private").mkdir(mode=0o700, exist_ok=True)
        write(self.work/"pf-before.json", pf_snapshot(self.args.allow_pf_snapshot))
        backup_dir = self.args.mysql_service/"backups"
        backup_dir.mkdir(exist_ok=True)
        backup = backup_dir/(self.schema+"-source.sql")
        clone = self.db.clone(self.args.source_schema, self.schema, backup)
        write(self.work/"database-clone.json", clone)
        event("database_restore_verified", schema=self.schema, sourceSchema=self.args.source_schema)
        # 临时隔离身份复制已有口令校验值，不修改源库、admin 或原账号角色。
        original=json.loads(self.args.operator_file.read_text())
        username="j1-operator-"+secrets.token_hex(8)
        key=uid()
        def quoted(s):return "'"+s.replace("'","''")+"'"
        self.db.query("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) SELECT "+quoted(key)+","+quoted(username)+",'J1 隔离研究操作身份',password_hash,'active' FROM sys_user WHERE username="+quoted(original["username"]),self.schema)
        self.db.query("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT u.id,r.id,'global','*' FROM sys_user u CROSS JOIN sys_role r WHERE u.username="+quoted(username)+" AND r.role_key IN ('platform_admin','model_operator','security_analyst')",self.schema)
        write(self.work/"private/isolated-operator.json",dict(username=username,password=original["password"]))
        self.args.operator_file=self.work/"private/isolated-operator.json"
        password = tls_files(self.work/"private/tls")
        try:
            self.backend(password)
            from policy_text import restore
            # V24 只改存储类型；克隆前已改动末位的策略按原件摘要换回原文，判定读取的阈值与冻结策略逐位一致。
            write(self.work/"policy-text-restore.json", restore(self.db.query, self.schema,
                  [self.package/"policy-research.json", self.package/"policy-m1-lab.json"]))
            write(self.work/"database-before.json", self.db.snapshot(self.schema))
            self.freeze()
            for round_number in ((1,) if self.args.diagnostic_segments else (1, 2)):
                state = self.identities(round_number)
                self.reference(state)
                self.replay(state)
                if self.args.diagnostic_segments:
                    self.diagnostic(state)
                    break
                from j1_audit import assess_round
                report = assess_round(self.work/f"round-{round_number}", self.scenario, self.scenario_sha)
                write(self.work/f"round-{round_number}"/"result.json", report, 0o400)
                result_file = self.public/f"round-{round_number}-result.json"
                shutil.copyfile(self.work/f"round-{round_number}"/"result.json", result_file)
                result_file.chmod(0o400)
                result = self.operator.v2(f"/replay-runs/{state['replayRunId']}/completions", dict(reportRef=self.replay_ref+f"/round-{round_number}-result.json", reportSha256=sha(result_file)))
                write(self.work/f"round-{round_number}"/"completion.json", result)
            write(self.work/"database-after.json", self.db.snapshot(self.schema))
            write(self.work/"source-database-after.json", self.db.snapshot(self.args.source_schema))
        finally:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(30)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
            write(self.work/"pf-after.json", pf_snapshot(self.args.allow_pf_snapshot))
            write(self.work/"stopped.json", dict(at=stamp(), backendExitCode=None if self.process is None else self.process.poll(), schema=self.schema, port=self.args.port))
        if not self.args.diagnostic_segments:
            from j1_audit import assess_all
            assess_all(self.work)


def main():
    home = Path.home()/"Workspace"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--operator-file", type=Path, required=True)
    parser.add_argument("--reviewer-file", type=Path, default=home/"ai/keys/cyber-guard-reviewer/credentials.json")
    parser.add_argument("--report-trust", type=Path, default=home/"ai/keys/cyber-guard-trust/report-trust.json")
    parser.add_argument("--artifacts", type=Path, default=home/"ai/artifacts/cyber-guard")
    parser.add_argument("--package-ref", default="packages/host-guard-round2-20261010-r2")
    parser.add_argument("--java", type=Path, default=home/"development/runtimes/java/temurin-25.0.2/Contents/Home/bin/java")
    parser.add_argument("--mysql-service", type=Path, default=home/"development/services/databases/mysql-server-8.0.42")
    parser.add_argument("--source-schema", default="cyber_security")
    parser.add_argument("--closeout", type=Path, required=True)
    parser.add_argument("--closeout-sha", required=True)
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--scenario-ref", help="复用先前已冻结清单的制品引用；不重选片段、不改清单")
    parser.add_argument("--resume",action="store_true",help="只恢复已有 schema/spool；不重采集、不覆盖历史证据")
    parser.add_argument("--rebind-scenario-ref", help="沿用已冻结清单的片段（逐项不变），为修复后的二进制登记新的场景文件")
    parser.add_argument("--server-threads", type=int, default=6, help="后端 Tomcat 线程数；推理仍受 2 个推理槽约束")
    parser.add_argument("--capture-warmup-seconds", type=int, default=0, help="与 --rebind-scenario-ref 合用：登记首包前的采集预热秒数")
    parser.add_argument("--diagnostic-segments", nargs="*", default=None, help="仅诊断：只回放这些片段，不产生可判定结果")
    parser.add_argument("--record-jfr", action="store_true", help="仅部分片段诊断时记录私有 JFR 性能证据")
    parser.add_argument("--allow-pf-snapshot", action="store_true", help="仅在另有明确授权时读取 PF；默认不运行 sudo 或 pfctl")
    parser.add_argument("--attack-concurrency", type=int, default=18, help="同时回放的攻击片段数；正常片段始终同时运行")
    parser.add_argument("--batch-size", type=int, default=100, help="登记传输批次上限（1..512）；不改变 1 MiB 请求体和批末判定语义")
    args = parser.parse_args()
    if not args.java.is_file() or not (args.work/"bin/backend.jar").is_file():
        raise RuntimeError("frozen JDK25/backend binary is required")
    if args.resume and not args.scenario_ref:parser.error("resume requires frozen scenario-ref")
    if args.diagnostic_segments is not None and not args.diagnostic_segments:parser.error("diagnostic requires at least one segment")
    if args.resume and args.diagnostic_segments:parser.error("diagnostic cannot resume a formal run")
    if args.record_jfr and not args.diagnostic_segments:parser.error("JFR recording requires diagnostic segments")
    if args.attack_concurrency < 1 or args.attack_concurrency > 18:parser.error("attack-concurrency must be 1..18")
    if not 1 <= args.batch_size <= 512:parser.error("batch-size must be 1..512")
    run=Run(args)
    run.resume() if args.resume else run.run()


if __name__ == "__main__":
    main()
