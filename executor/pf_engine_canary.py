"""回环 lab 的签名命令/PF/独立恢复器 canary；与正式入口使用同一授权门禁，不设例外。"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

from cryptography.hazmat.primitives import serialization

from .__main__ import build, cycle, flush
from .common import Rejected, canonical, digest, ident, instant, parse, private_file, require, stamp, write_new
from .pf_canary import canary_scope
from .canary_targets import CanaryTargets
from .canary_control import CanaryControl


SCENARIOS = ("ttl", "revoke", "before_ledger", "after_ledger", "after_install", "parallel", "reject",
             "disconnect", "receipt_loss", "asset_limit", "rate_limit", "renewal_limit",
             "revoked_authorization", "expired_authorization")


class LoopbackResolver:
    """只为本机 canary 提供短期 127.0.0.2 到登记测试端口的解析。"""

    def __init__(self, port):
        self.port = port

    def resolve(self, _payload):
        now = time.time()
        return {"endpoints": {"Local": f"127.0.0.1:{self.port}",
                              "Peer": "127.0.0.2:55010", "Protocol": 6},
                "lastPacketAt": stamp(now), "expiresAt": stamp(now + 15)}


def run(config_path, signing_key, key_id, output, mode="peer_service", guardtargets=None, scenario="ttl"):
    require(not output.exists(), "CANARY_OUTPUT_EXISTS")
    require(scenario in SCENARIOS, "CANARY_SCENARIO_INVALID")
    require(mode == "peer_service" or guardtargets is not None, "CANARY_REAL_TARGET_REQUIRED")
    engine = build(config_path, resolver=False)
    config = engine.config()
    port, _ = canary_scope(config, mode)
    # 全入站验收走正式授权：命令使用的首个能力必须已在 inboundCapabilities 登记。
    require(mode == "peer_service" or any(item["capabilityId"] == config["capabilityIds"][0]
                                          for item in config.get("inboundCapabilities", [])),
            "CANARY_SCOPE_REQUIRED")
    require(port + 1 in set(config["protectedServicePorts"]), "CANARY_SCOPE_REQUIRED")
    require(port + 2 not in set(config["protectedServicePorts"]), "CANARY_SCOPE_REQUIRED")
    with socket.socket() as source:
        try:
            source.bind(("127.0.0.2", 0))
        except OSError as exc:
            raise Rejected("CANARY_LOOPBACK_ALIAS_REQUIRED") from exc
    engine.adapter.preflight()
    require(not engine.adapter.inventory() and engine.store.get("boot") is None and
            not engine.store.commands(), "CANARY_DEDICATED_STATE_REQUIRED")
    private = serialization.load_der_private_key(private_file(signing_key).read_bytes(), password=None)
    engine.resolver = LoopbackResolver(port)
    stop = threading.Event()
    servers = []
    threads = []
    recovery = None
    targets = None
    report = {"platform": "macos-pf", "scope": mode, "scenario": scenario,
              "fixtureResolver": guardtargets is None, "independentRecovery": True,
              "rebootTested": False, "passed": False, "configSha256": digest(config)}

    def echo(conn):
        with conn:
            conn.settimeout(.2)
            while not stop.is_set():
                try:
                    data = conn.recv(64)
                    if not data:
                        break
                    conn.sendall(data)
                except socket.timeout:
                    continue
                except OSError:
                    break

    def accept(server):
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                thread = threading.Thread(target=echo, args=(conn,), daemon=True)
                thread.start()
                threads.append(thread)
            except socket.timeout:
                continue
            except OSError:
                break

    def pulse():
        while not stop.is_set():
            engine.pulse("executor")
            stop.wait(.2)

    def probe(number, source="127.0.0.2"):
        with socket.socket() as conn:
            conn.settimeout(.3)
            conn.bind((source, 0))
            try:
                conn.connect(("127.0.0.1", number))
                conn.sendall(b"p5-canary")
                return conn.recv(9) == b"p5-canary"
            except OSError:
                return False

    def command(peer_port):
        now = time.time()
        payload = {k: config[k] for k in ("assetId", "executorId", "sensorId", "captureScopeId", "environment")}
        payload.update(contractVersion="host-guard/5.0.0-rc.3", executorBootId=engine.boot,
                       commandId=ident(), actionId=ident(), idempotencyKey=ident(),
                       bootId=ident(), targetRef=ident(), peerKey="a" * 64, keyEpoch=1,
                       actionType="temporary_block", scope=mode, addressFamily="ipv4",
                       direction="inbound", transport="tcp", servicePort=None if mode == "peer_inbound" else port,
                       capabilityId=config["capabilityIds"][0], bundleId=config["bundleIds"][0],
                       policySha256=config["policyHashes"][0], evidenceSha256="b" * 64,
                       authorizationId=config["authorization"]["id"],
                       authorizationRevision=config["authorization"]["revision"],
                       issuedAt=stamp(now), applyBy=stamp(now + 2), blockUntil=stamp(now + 5),
                       leaseExpiresAt=stamp(now + 10))
        if targets is not None:
            binding, registered = targets.lease(mode, port, peer_port)
            payload.update(bootId=binding["bootId"], targetRef=binding["targetRef"])
            report["targetBinding"] = registered
            # 服务冷启动的等待不消费命令 applyBy 窗口，引用本身仍使用原期限。
            now = time.time()
            payload.update(issuedAt=stamp(now), applyBy=stamp(now + 2), blockUntil=stamp(now + 5),
                           leaseExpiresAt=stamp(now + 10))
        return {"payload": payload, "keyId": key_id, "algorithm": "Ed25519",
                "signature": base64.urlsafe_b64encode(private.sign(canonical(payload))).rstrip(b"=").decode()}

    def sign(payload):
        return {"payload": payload, "keyId": key_id, "algorithm": "Ed25519",
                "signature": base64.urlsafe_b64encode(private.sign(canonical(payload))).rstrip(b"=").decode()}

    def submit(envelope):
        try:
            return engine.accept(envelope)
        except Rejected as exc:
            return str(exc)

    with ExitStack() as stack:
        stack.enter_context(engine.store.lock("run", blocking=False))
        stack.callback(engine.adapter.close)
        try:
            for number in (port, port + 1, port + 2):
                server = socket.socket()
                server.bind(("127.0.0.1", number))
                server.listen(8)
                server.settimeout(.2)
                servers.append(server)
                thread = threading.Thread(target=accept, args=(server,), daemon=True)
                thread.start()
                threads.append(thread)
            before = {"target": probe(port), "control": probe(port + 1), "otherTarget": probe(port + 2)}
            require(all(before.values()), "CANARY_BASELINE_FAILED")
            report["before"] = before
            engine.start()
            if guardtargets is not None:
                targets = CanaryTargets(engine, guardtargets)
                engine.resolver = targets.resolver
            thread = threading.Thread(target=pulse, daemon=True)
            thread.start()
            threads.append(thread)
            recovery = subprocess.Popen([sys.executable, "-m", "executor", "recover", "--config", str(config_path)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 3
            while not engine.healthy_recovery() and time.monotonic() < deadline:
                require(recovery.poll() is None, "RECOVERY_PENDING")
                time.sleep(.05)
            require(engine.healthy_recovery(), "RECOVERY_PENDING")
            with socket.socket() as established, socket.socket() as protected:
                established.settimeout(.3)
                established.bind(("127.0.0.2", 0))
                established.connect(("127.0.0.1", port))
                protected.settimeout(.3)
                protected.bind(("127.0.0.2", 0))
                protected.connect(("127.0.0.1", port + 1))
                for conn in (established, protected):
                    conn.sendall(b"p5-canary")
                    require(conn.recv(9) == b"p5-canary", "CANARY_BASELINE_FAILED")
                signed = command(established.getsockname()[1])
                report["commandSha256"] = digest(signed)
                if scenario in ("before_ledger", "after_ledger", "after_install"):
                    require(targets is not None, "CANARY_REAL_TARGET_REQUIRED")
                    envelope_file = engine.store.root / "fault-command.json"
                    resolver_file = engine.store.root / "fault-resolver.json"
                    marker = engine.store.root / "fault-marker.json"
                    write_new(envelope_file, canonical(signed))
                    write_new(resolver_file, canonical(targets.resolver_config))
                    child = subprocess.run([sys.executable, "-m", "executor.canary_fault", "--config", str(config_path),
                                            "--envelope", str(envelope_file), "--resolver-config", str(resolver_file),
                                            "--marker", str(marker), "--stage", scenario],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                    require(child.returncode == 71 and marker.exists(), "CANARY_FAULT_NOT_REACHED")
                    report["fault"] = parse(marker.read_bytes())
                    require(report["fault"]["actualRules"] == (1 if scenario == "after_install" else 0),
                            "CANARY_FAULT_STATE_FAILED")
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        row = engine.store.command(signed["payload"]["commandId"])
                        if not engine.adapter.inventory() and (row is None or row["clearedAt"] is not None):
                            break
                        time.sleep(.05)
                    report["after"] = {"rulesEmpty": not engine.adapter.inventory(), "target": probe(port),
                                       "control": probe(port + 1), "ledgerConsistent": row is None if scenario == "before_ledger"
                                       else row is not None and row["status"] == "uncertain" and row["clearedAt"] is not None}
                    report["passed"] = all(report["after"].values())
                    report["finalState"] = engine.snapshot()
                    require(report["passed"], "CANARY_FAULT_RECOVERY_FAILED")
                    return
                if scenario == "reject":
                    p = signed["payload"]
                    cases = {"wrongBoot": {"executorBootId": ident()}, "unknownTarget": {"targetRef": ident()},
                             "wrongAsset": {"assetId": ident()}, "wrongExecutor": {"executorId": ident()},
                             "expiredCommand": {"issuedAt": stamp(time.time() - 20), "applyBy": stamp(time.time() - 18),
                                                "blockUntil": stamp(time.time() - 15)},
                             "wrongAuthorization": {"authorizationRevision": p["authorizationRevision"] + 1},
                             "wrongScope": {"scope": "peer_service", "servicePort": port + 2},
                             "protectedPort": {"scope": "peer_service", "servicePort": port + 1}}
                    outcomes = {}
                    for name, changes in cases.items():
                        envelope = sign({**p, "commandId": ident(), "actionId": ident(), "idempotencyKey": ident(), **changes})
                        outcomes[name] = submit(envelope)
                    tampered = {**signed, "payload": {**p, "evidenceSha256": "c" * 64}}
                    outcomes["tamperedSignature"] = submit(tampered)
                    report["rejections"] = outcomes
                    expected = {"wrongBoot": "BOOT_ID_MISMATCH", "unknownTarget": "CONTROL_PLANE_UNAVAILABLE",
                                "wrongAsset": "SCOPE_DENIED", "wrongExecutor": "SCOPE_DENIED",
                                "expiredCommand": "COMMAND_EXPIRED", "wrongAuthorization": "AUTHORIZATION_INACTIVE",
                                "wrongScope": "SCOPE_DENIED", "protectedPort": "SCOPE_DENIED",
                                "tamperedSignature": "SIGNATURE_INVALID"}
                    report["passed"] = (outcomes == expected and
                                        not engine.adapter.inventory() and probe(port) and probe(port + 1))
                    report["finalState"] = engine.snapshot()
                    require(report["passed"], "CANARY_REJECTION_FAILED")
                    return
                require(engine.accept(signed) == "applied", "CANARY_APPLY_FAILED")
                report["appliedState"] = engine.snapshot()
                first_deadline = engine.store.command(signed["payload"]["commandId"])["deadline"]
                duplicate = engine.accept(signed) == "applied" and (
                    engine.store.command(signed["payload"]["commandId"])["deadline"] == first_deadline)
                if scenario == "parallel":
                    p = signed["payload"]
                    candidates = [sign({**p, "commandId": ident(), "actionId": ident(), "idempotencyKey": ident()})
                                  for _ in range(3)]
                    with ThreadPoolExecutor(max_workers=3) as pool:
                        outcomes = list(pool.map(submit, candidates))
                    report["concurrentResults"] = outcomes
                    require(outcomes == ["TARGET_BUDGET_BUSY"] * 3 and len(engine.adapter.inventory()) == 1,
                            "CANARY_BUDGET_FAILED")
                during = {"newTarget": probe(port), "control": probe(port + 1), "otherTarget": probe(port + 2),
                          "normalPeer": probe(port, "127.0.0.1")}
                try:
                    protected.sendall(b"p5-canary")
                    during["establishedControl"] = protected.recv(9) == b"p5-canary"
                except OSError:
                    during["establishedControl"] = False
                try:
                    established.sendall(b"p5-canary")
                    during["establishedTarget"] = established.recv(9) == b"p5-canary"
                except OSError:
                    during["establishedTarget"] = False
            report.update(before=before, during=during, idempotentNoExtension=duplicate)
            if scenario == "asset_limit":
                p = signed["payload"]
                binding, _ = targets.lease("peer_service", port, 55003)
                candidate = sign({**p, "commandId": ident(), "actionId": ident(), "idempotencyKey": ident(),
                                  "targetRef": binding["targetRef"], "scope": "peer_service", "servicePort": port})
                report["assetBudgetResult"] = submit(candidate)
                require(report["assetBudgetResult"] == "ASSET_CONCURRENT_LIMIT", "CANARY_BUDGET_FAILED")
            if scenario in ("revoked_authorization", "expired_authorization"):
                changed = parse(private_file(config_path).read_bytes())
                if scenario == "revoked_authorization":
                    changed["authorization"]["status"] = "revoked"
                else:
                    changed["authorization"]["validUntil"] = stamp(time.time())
                updated = engine.store.root / "updated-config.json"
                write_new(updated, canonical(changed))
                os.replace(updated, config_path)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and engine.adapter.inventory():
                    time.sleep(.05)
                row = engine.store.command(signed["payload"]["commandId"])
                report["authorizationCleanup"] = not engine.adapter.inventory() and row["status"] == "uncertain"
                require(report["authorizationCleanup"], "CANARY_AUTHORIZATION_RECOVERY_FAILED")
            if scenario == "revoke":
                p = signed["payload"]
                engine.revoke({"revocationId": ident(), "actionId": p["actionId"], "commandId": p["commandId"],
                               "executorId": p["executorId"], "assetId": p["assetId"], "environment": "lab",
                               "desiredRevision": 1, "issuedAt": stamp(time.time()), "reasonCode": "USER_REVOKED"})
            if scenario in ("disconnect", "receipt_loss"):
                require(targets is not None, "CANARY_REAL_TARGET_REQUIRED")
                control_fixture = CanaryControl(engine, targets.pki, signed)
                try:
                    if scenario == "disconnect":
                        control_fixture.close()
                    try:
                        cycle(engine, control_fixture.control)
                        require(False, "CANARY_CONNECTION_FAILURE_EXPECTED")
                    except Rejected as exc:
                        require(str(exc) == "CONTROL_PLANE_UNAVAILABLE", "CANARY_UNEXPECTED_CONNECTION_ERROR")
                    row = engine.store.command(signed["payload"]["commandId"])
                    report["disconnected"] = {"paused": engine.store.get("paused"),
                                              "uncertain": row["status"] == "uncertain",
                                              "rulesEmpty": not engine.adapter.inventory(),
                                              "sameDeadline": row["deadline"] == first_deadline,
                                              "sameCommand": len([r for r in engine.store.commands() if r["installed"]]) == 1}
                    require(all(report["disconnected"].values()), "CANARY_DISCONNECT_FAILED")
                    if scenario == "receipt_loss":
                        flush(engine, control_fixture.control)
                        receipts = control_fixture.receipts
                        report["receiptRetrySameIdAndContent"] = len(receipts) >= 2 and receipts[0] == receipts[1]
                        require(report["receiptRetrySameIdAndContent"], "CANARY_RECEIPT_RETRY_FAILED")
                finally:
                    control_fixture.close()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                require(recovery.poll() is None, "RECOVERY_PENDING")
                row = engine.store.command(signed["payload"]["commandId"])
                if not engine.adapter.inventory() and row["status"] in ("revoked", "expired"):
                    break
                time.sleep(.1)
            row = engine.store.command(signed["payload"]["commandId"])
            if scenario in ("rate_limit", "renewal_limit"):
                engine.pulse("executor")
                candidate = command(55003)
                report["nextActionResult"] = submit(candidate)
                expected = "ASSET_RATE_LIMIT" if scenario == "rate_limit" else "TARGET_CONTINUOUS_BUDGET"
                require(report["nextActionResult"] == expected, "CANARY_BUDGET_FAILED")
            expected_status = "revoked" if scenario == "revoke" else "expired"
            after = {"target": probe(port), "control": probe(port + 1), "otherTarget": probe(port + 2),
                     "rulesEmpty": not engine.adapter.inventory(), "terminalStatus": row["status"] == expected_status,
                     "clearedAtRecorded": row["clearedAt"] is not None,
                     "withinDeadline": row["clearedAt"] is not None and row["clearedAt"] <= instant(row["payload"]["blockUntil"]) + 1,
                     "duplicateRemainsTerminal": engine.accept(signed) == expected_status}
            passed = (duplicate and not during["newTarget"] and not during["establishedTarget"] and
                      during["otherTarget"] == (mode == "peer_service") and
                      during["control"] and during["establishedControl"] and during["normalPeer"] and all(after.values()))
            report.update(after=after, passed=passed, clearedAt=stamp(row["clearedAt"]) if row["clearedAt"] else None,
                          finalState=engine.snapshot())
            require(passed, "CANARY_EFFECT_OR_RECOVERY_FAILED")
        finally:
            stop.set()
            if recovery is not None:
                recovery.terminate()
                try:
                    recovery.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    recovery.kill()
                    recovery.wait(timeout=3)
            try:
                engine.stop()
                report["cleanupVerified"] = not engine.adapter.inventory()
            except Exception:
                report.update(cleanupVerified=False, passed=False)
                raise
            finally:
                if targets is not None:
                    targets.close()
                for server in servers:
                    server.close()
                for thread in threads:
                    thread.join(1)
                write_new(output, canonical(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--signing-key", required=True, type=Path)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--scope", choices=("peer_service", "peer_inbound"), default="peer_service")
    parser.add_argument("--guardtargets", type=Path)
    parser.add_argument("--scenario", choices=SCENARIOS, default="ttl")
    args = parser.parse_args()
    run(args.config, args.signing_key, args.key_id, args.output, args.scope, args.guardtargets, args.scenario)
