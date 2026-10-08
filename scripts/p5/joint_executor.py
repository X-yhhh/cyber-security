"""隔离 P4 HTTPS + Go/mTLS 执行端；标准输出仅为脱敏 JSON 行控制协议。"""
import argparse
from contextlib import ExitStack
import copy
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from executor.__main__ import cycle, flush
from executor.canary_targets import CanaryTargets
from executor.common import Rejected, canonical, digest, parse, read_private, require, stamp, write_new
from executor.config import RuntimeConfig
from executor.contract import capability_set_sha256, protected_ports_sha256
from executor.engine import Engine
from executor.platform import PF
from executor.storage import Store
from executor.transport import ControlPlane
from pf_session import session


class MemoryFirewall:
    """无权限演练的规则替身；不调用 PF，也不宣称流量被阻断。"""
    def __init__(self):
        self.rules = {}

    def handle(self, command):
        return "rehearsal:" + command

    def install(self, command, scope, apply_by=None):
        require(apply_by is None or time.time() < apply_by, "TARGET_REF_STALE")
        self.rules[command] = {"handle": self.handle(command), "scope": copy.deepcopy(scope)}

    def inventory(self):
        return copy.deepcopy(self.rules)

    def remove(self, command, scope):
        require(self.rules.get(command, {}).get("scope") == scope, "RULE_OWNERSHIP_UNVERIFIED")
        del self.rules[command]

    def close(self):
        pass


class FaultTransport:
    """断连在真实 HTTPS 发送前注入；回执丢失在服务端已接受后注入响应丢失。"""
    def __init__(self, control, scenario):
        self.control, self.scenario = control, scenario
        self.inject = False
        self.facts = {"injected": False, "receiptId": None, "receiptSha256": None, "sameReceiptRetried": False}

    def post(self, operation, body, request_id=None):
        if self.inject and self.scenario == "disconnect":
            self.inject = False
            self.facts["injected"] = True
            raise Rejected("CONTROL_PLANE_UNAVAILABLE")
        result = self.control.post(operation, body, request_id)
        if operation == "receipts":
            if self.facts["receiptId"] == request_id:
                require(self.facts["receiptSha256"] == digest(body), "RECEIPT_RETRY_CHANGED")
                self.facts["sameReceiptRetried"] = True
            if self.inject and self.scenario == "receipt_loss":
                self.inject = False
                self.facts.update(injected=True, receiptId=request_id, receiptSha256=digest(body))
                raise Rejected("CONTROL_PLANE_UNAVAILABLE")
        return result


def reply(value):
    print(canonical(value).decode(), flush=True)


def interrupted(*_):
    """JUnit 停止子进程时仍进入 ExitStack，先清理自身规则再归还 PF 会话。"""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise Rejected("LAB_INTERRUPTED")


def run(directory):
    os.umask(0o077)
    data = read_private(directory / "input.json")
    mode = os.environ.get("P5_FIREWALL", "rehearse")
    require(mode in ("pf", "rehearse"), "LAB_MODE_REQUIRED")
    c = {k: data[k] for k in ("assetId", "executorId", "sensorId", "captureScopeId", "authorization", "controlPlaneURL", "controlPlaneCA")}
    c.update(platform="pf", environment="lab", interface="lo0", localAddresses=["127.0.0.1"],
        peerAddresses=["127.0.0.2"], servicePorts=[443], protectedServicePorts=data["protection"]["protectedServicePorts"],
        protectedPeers=[], stateDir=str(directory / "state"), capabilityIds=[data["capabilityId"]],
        bundleIds=[data["bundleId"]], policyHashes=[data["policySha256"]],
        limits={"maxTtlSeconds": 60, "maxContinuousBlockSeconds": 120, "maxActiveRulesPerAsset": 10, "maxNewActionsPerMinute": 5},
        trustFile=data["commandTrustFile"], budgetKeyFile=str(directory / "budget.key"),
        credentialFile=str(directory / "credential"))
    if data["scope"] == "peer_inbound":
        c["inboundCapabilities"] = [{"capabilityId": data["capabilityId"], "protectionSetSha256": digest(data["protection"]),
            "protectedPortsSha256": protected_ports_sha256(c["protectedServicePorts"])}]
    c["capabilityHash"] = capability_set_sha256(c)
    require(c["capabilityHash"] == data["capabilityHash"], "LAB_CAPABILITY_MISMATCH")
    trust = read_private(Path(c["trustFile"]))
    write_new(Path(c["credentialFile"]), data["credential"].encode())
    key = os.urandom(32)
    write_new(Path(c["budgetKeyFile"]), key)
    result = {"passed": False, "scope": data["scope"], "scenario": data["scenario"], "realPF": mode == "pf",
              "realControlPlaneHTTPS": True, "realGoMTLS": True, "recovery": "separate_process" if mode == "pf" else "thread_fixture"}
    with ExitStack() as stack:
        if mode == "pf":
            helper, check, pf_facts = stack.enter_context(session(directory, c["executorId"], os.environ.get("P5_A4_REFERENCE")))
            c["pfHelper"] = str(helper)
            adapter = PF(c["executorId"], str(helper))
            stack.callback(adapter.close)
            adapter.preflight()
        else:
            adapter, check = MemoryFirewall(), lambda: None
        store = Store(c["stateDir"])
        engine = Engine(store, adapter, None, lambda: c, lambda: trust, key)
        stack.enter_context(store.lock("run", blocking=False))
        engine.start()
        targets = CanaryTargets(engine, os.environ["P5_GUARDTARGETS"])
        stack.callback(targets.close)
        c.update(targets.resolver_config)
        engine.resolver = targets.resolver
        config_path = directory / "executor-config.json"
        write_new(config_path, canonical(c))
        engine.config = RuntimeConfig(config_path)
        stop = threading.Event()
        def heartbeat():
            while not stop.wait(.15):
                engine.pulse("executor")
                if mode == "rehearse":
                    engine.pulse("recovery")
                    engine.recover()
        thread = threading.Thread(target=heartbeat, daemon=True)
        thread.start()
        def stop_heartbeat():
            stop.set()
            thread.join(3)
        stack.callback(stop_heartbeat)
        if mode == "pf":
            log = stack.enter_context((directory / "recovery.log").open("xb"))
            process = subprocess.Popen([sys.executable, "-m", "executor", "recover", "--config", str(config_path)],
                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            def stop_recovery():
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                require(process.returncode == 0, "LAB_RECOVERY_PROCESS_FAILED")
            stack.callback(stop_recovery)
        # 在恢复进程存活后进入机器协议；退出顺序先清规则再停恢复器。
        stack.callback(engine.stop)
        engine.pulse("executor")
        deadline = time.monotonic() + 3
        while not engine.healthy_recovery() and time.monotonic() < deadline:
            time.sleep(.05)
        require(engine.healthy_recovery(), "LAB_RECOVERY_START_FAILED")
        control = FaultTransport(ControlPlane(engine.config), data["scenario"])
        cycle(engine, control)
        reply({"executorBoot": engine.boot, "collectorBoot": targets.boot})
        for line in sys.stdin:
            operation = parse(line)["operation"]
            if operation == "lease":
                binding, registered = targets.lease(data["scope"], 443, 55123)
                registration = control.post("target-bindings", registered, registered["bindingId"])
                reply({"binding": {**binding, "stableTargetToken": registered["stableTargetToken"]}, "registration": registration})
            elif operation == "apply":
                control.inject = data["scenario"] == "receipt_loss"
                try:
                    cycle(engine, control)
                except Rejected as exc:
                    require(data["scenario"] == "receipt_loss" and control.facts["injected"] and
                            str(exc) == "CONTROL_PLANE_UNAVAILABLE", "LAB_FAULT_FAILED")
                rows = store.commands()
                require(len(rows) == 1 and rows[0]["installed"], "LAB_APPLY_FAILED")
                require(data["scenario"] == "receipt_loss" or
                        (rows[0]["status"] == "applied" and len(adapter.inventory()) == 1), "LAB_APPLY_FAILED")
                result.update(commandId=rows[0]["payload"]["commandId"], installedAt=stamp(time.time()),
                              installedStateDigest=engine.snapshot()["stateDigest"] if data["scenario"] != "receipt_loss" else None)
                check()
                if data["scenario"] == "disconnect":
                    control.inject = True
                    try:
                        flush(engine, control)
                    except Rejected as exc:
                        require(str(exc) == "CONTROL_PLANE_UNAVAILABLE", "LAB_FAULT_FAILED")
                        engine.control_lost()
                if data["scenario"] != "revoke":
                    require(control.facts["injected"] and not adapter.inventory() and store.get("paused"), "LAB_DISCONNECT_CLEANUP_FAILED")
                    result["faultCleaned"] = True
                reply({"installed": True})
            elif operation == "finish":
                cycle(engine, control)
                rows = store.commands()
                require(rows[0]["status"] == "revoked" and not adapter.inventory() and not store.pending(), "LAB_REVOKE_FAILED")
                check()
                require(data["scenario"] != "receipt_loss" or control.facts["sameReceiptRetried"], "LAB_RECEIPT_NOT_RETRIED")
                result.update(passed=True, cleanedAt=stamp(time.time()), ownedRuleCount=0,
                    finalStateDigest=engine.snapshot()["stateDigest"], revocationCount=len(store.revocations()), fault=control.facts,
                    ledger={"commandCount": len(rows), "status": rows[0]["status"], "clearedAt": rows[0]["clearedAt"],
                            "reservedUntil": rows[0]["payload"]["blockUntil"], "pendingReceiptCount": len(store.pending())})
                break
            else:
                require(False, "LAB_PROTOCOL_INVALID")
        require(result["passed"], "LAB_PROTOCOL_INCOMPLETE")
    if mode == "pf":
        result["passed"] = result["passed"] and pf_facts["passed"]
    write_new(directory / "result.json", canonical(result))
    reply({"cleaned": result["passed"]})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        run(args.directory)
    except Exception as exc:
        reply({"error": str(exc) if isinstance(exc, Rejected) else "LAB_LOCAL_FAILURE"})
        raise SystemExit(1)
