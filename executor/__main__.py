"""本地服务入口；run 与 recover 必须作为两个独立进程启动。"""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import signal
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import config
from .common import Rejected, canonical, digest, ident, instant, private_file, public_der, read_private, require, stamp, write_new
from .engine import Engine
from .platform import PF, WFP
from .storage import Store
from .transport import ControlPlane, TargetResolver


def keys(directory, key_id):
    """创建本地命令密钥与稳定预算密钥；绝不打印私钥或覆写已有目录。"""
    directory = Path(directory)
    require(directory.is_absolute(), "ABSOLUTE_DIRECTORY_REQUIRED")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    key = Ed25519PrivateKey.generate()
    write_new(directory / "signing.der", key.private_bytes(serialization.Encoding.DER,
              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write_new(directory / "trust.json", canonical({key_id: {"status": "active", "publicKeyDer": public_der(key.public_key()),
              "notBefore": stamp(time.time() - 1), "notAfter": stamp(time.time() + 365 * 86400)}}))
    write_new(directory / "budget.key", os.urandom(32))
    print("LOCAL_KEYS_CREATED")


def build(path, resolver=True):
    read = config.RuntimeConfig(path)
    c = read()
    store = Store(c["stateDir"])
    adapter = PF(c["executorId"], c["pfHelper"]) if c["platform"] == "pf" else WFP(c["executorId"], c["interface"])
    key = private_file(c["budgetKeyFile"]).read_bytes()
    require(len(key) >= 32, "BUDGET_KEY_INVALID")
    return Engine(store, adapter, TargetResolver(read) if resolver else None, read,
                  lambda: read_private(read()["trustFile"]), key)


def flush(engine, control):
    """回执 ID 与内容持久化重试；核对始终重新枚举，避免发送已过期实态。"""
    for key, operation, body in engine.store.pending():
        control.post(operation, body, key)
        engine.store.ack(key)
    control.post("reconciliations", engine.snapshot())
    for proof in engine.clearance_proofs():
        key = "clearance:" + proof["commandId"]
        if not engine.store.get(key, False):
            control.post("clearance-proofs", proof)
            engine.store.set(key, True)


def cycle(engine, control):
    """通信失败不能被当成命令未执行；暂停并保存实态与原 ID 供重连核对。"""
    try:
        _cycle(engine, control)
    except Rejected as exc:
        if str(exc) == "CONTROL_PLANE_UNAVAILABLE":
            engine.control_lost()
        raise


def _cycle(engine, control):
    engine.pulse("executor")
    engine.recover()
    snapshot = engine.snapshot()
    pending = bool(snapshot["recoveryErrors"]) or engine.store.get("paused", True) or not engine.healthy_recovery()
    c = engine.config()
    result = control.post("heartbeats", {"bootId": engine.boot, "adapterVersion": "hostguard-executor/1",
        "capabilityHash": c["capabilityHash"], "pendingRecovery": pending,
        "activeRuleCount": None if snapshot["recoveryErrors"] else len(snapshot["ownedRules"]),
        "clockSkewMs": 0 if engine.trusted_clock() else None})
    require(abs(instant(result["serverTime"]) - time.time()) <= 1, "CLOCK_UNTRUSTED")
    flush(engine, control)
    rows = engine.store.commands()
    for token in {r["token"] for r in rows if r["token"]}:
        related = [r for r in rows if r["token"] == token]
        if related and all(r["clearedAt"] is not None and time.time() >= r["clearedAt"] + 120 for r in related):
            proof = control.post("budget-proofs", {"stableTargetToken": token})
            if proof["chargedMs"] == 0 and proof["healthProofSha256"] and instant(proof["cycleStartedAt"]) > engine.store.get("cycle:" + token, 0):
                engine.reset_budget(token, proof)
    claims = control.post("command-claims", {"bootId": engine.boot, "capabilityHash": c["capabilityHash"],
                                             "maxItems": 10, "waitSeconds": 0})
    require(isinstance(claims.get("commands"), list) and isinstance(claims.get("revocations"), list) and
            len(claims["commands"]) + len(claims["revocations"]) <= 10, "CONTROL_RESPONSE_INVALID")
    for value in claims["revocations"]:
        engine.revoke(value)
    if not pending:
        for value in claims["commands"]:
            try:
                engine.accept(value)
            except Rejected as exc:
                engine.store.audit("command.rejected", errorCode=str(exc))
    flush(engine, control)


def serve(path, role):
    engine = build(path, resolver=role == "run")
    stop = False

    def stopping(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    with ExitStack() as stack:
        stack.callback(engine.adapter.close)
        stack.enter_context(engine.store.lock(role, blocking=False))
        try:
            if role == "run":
                engine.start()
                control = ControlPlane(engine.config)
                engine.pulse("executor")
                deadline = time.monotonic() + 2
                while not stop and not engine.healthy_recovery() and time.monotonic() < deadline:
                    time.sleep(.05)
            while not stop:
                started = time.monotonic()
                try:
                    if role == "run":
                        cycle(engine, control)
                    elif engine.store.get("boot"):
                        engine.boot = engine.store.get("boot")
                        engine.pulse("recovery")
                        owner = engine.store.get("executorHeartbeat", {})
                        lost = owner.get("boot") != engine.boot or not 0 <= time.monotonic() - owner.get("at", -100) <= 4
                        engine.recover(force=lost)
                except (Rejected, OSError) as exc:
                    code = str(exc) if isinstance(exc, Rejected) else "LOCAL_IO_FAILED"
                    engine.store.audit("service.error", errorCode=code)
                    if code == "CLOCK_UNTRUSTED":
                        engine.stop()
                time.sleep(max(0, (.25 if role == "recover" else 1) - (time.monotonic() - started)))
        finally:
            engine.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    init = subs.add_parser("keygen")
    init.add_argument("--directory", required=True)
    init.add_argument("--key-id", required=True)
    ipc = subs.add_parser("target-pki")
    ipc.add_argument("--directory", required=True)
    binding = subs.add_parser("bind-target")
    binding.add_argument("--config", required=True)
    binding.add_argument("--input", required=True)
    service = subs.add_parser("launchd-config")
    for name in ("directory", "python", "source", "config", "target-binary", "target-config"):
        service.add_argument("--" + name, required=True)
    for name in ("run", "recover", "check", "cleanup", "status"):
        sub = subs.add_parser(name)
        sub.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        if args.command == "keygen":
            keys(args.directory, args.key_id)
        elif args.command == "target-pki":
            from .pki import create
            create(args.directory)
            print("LOCAL_IPC_IDENTITIES_CREATED")
        elif args.command == "launchd-config":
            from .services import launchd
            launchd(args.directory, args.python, args.source, args.config, args.target_binary, args.target_config)
            print("LAUNCHD_CONFIG_CREATED_NOT_INSTALLED")
        elif args.command == "bind-target":
            engine = build(args.config)
            try:
                value = read_private(args.input)
                require(set(value) == {"binding", "expiresAt"} and engine.boot, "TARGET_BINDING_INVALID")
                p = value["binding"]
                binding = engine.target_binding(p, engine.resolver.resolve(p), value["expiresAt"])
                result = ControlPlane(engine.config).post("target-bindings", binding, binding["bindingId"])
                print(canonical({"bindingId": result["bindingId"], "budgetTargetId": result["budgetTargetId"]}).decode())
            finally:
                engine.adapter.close()
        elif args.command in ("run", "recover"):
            serve(args.config, args.command)
        else:
            engine = build(args.config, resolver=False)
            try:
                if args.command == "check":
                    engine.adapter.preflight()
                    print("PLATFORM_PREFLIGHT_OK")
                elif args.command == "cleanup":
                    engine.stop()
                    print("OWNED_RULES_CLEARED")
                else:
                    snapshot = engine.snapshot()
                    print(canonical({"activeRuleCount": len(snapshot["ownedRules"]),
                                     "executorBootId": engine.store.get("boot"),
                                     "recoveryErrors": snapshot["recoveryErrors"],
                                     "paused": engine.store.get("paused", True),
                                     "pendingReceipts": len(engine.store.pending())}).decode())
            finally:
                engine.adapter.close()
    except (Rejected, OSError, KeyError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Rejected) else "EXECUTOR_CONFIGURATION_OR_IO_FAILED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
