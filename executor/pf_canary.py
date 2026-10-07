"""P5 已配置 PF 的回环验收入口；不重启、不挂接根规则、不启用/停用 PF。

必须先由管理员挂接专用 anchor、安装 helper 并给 lo0 配置 127.0.0.2；
完整命令路径还需独立恢复进程。只使用已登记回环高端口，输出仅含连接布尔值和清理结果。
"""
import argparse
import base64
from contextlib import ExitStack
from pathlib import Path
import socket
import threading
import time
import uuid

from cryptography.hazmat.primitives import serialization

from .__main__ import build
from .common import Rejected, canonical, ident, private_file, read_private, require, stamp, write_new
from .contract import unprotected_ranges


def canary_scope(config, mode):
    """仅允许专用回环 lab 端口；全入站模式须明确保留相邻控制端口。"""
    require(mode in ("peer_service", "peer_inbound") and config["platform"] == "pf" and
            config["environment"] == "lab" and config["interface"] == "lo0" and
            config["localAddresses"] == ["127.0.0.1"] and config["peerAddresses"] == ["127.0.0.2"] and
            len(config["servicePorts"]) == 1 and 49152 <= config["servicePorts"][0] <= 65533,
            "CANARY_SCOPE_REQUIRED")
    port = config["servicePorts"][0]
    if mode == "peer_inbound":
        protected = set(config["protectedServicePorts"]) | {22, 53, 3389}
        require(port not in protected and port + 1 in protected, "CANARY_SCOPE_REQUIRED")
        return port, {"local": "127.0.0.1", "peer": "127.0.0.2", "interface": "lo0",
                      "port": None, "ranges": unprotected_ranges(protected)}
    return port, None


def run(config_path, signing_key, key_id, output, mode="peer_service"):
    engine = build(config_path, resolver=mode == "peer_service")
    c = engine.config()
    port, inbound = canary_scope(c, mode)
    with socket.socket() as source:
        try:
            source.bind(("127.0.0.2", 0))
        except OSError as exc:
            raise Rejected("CANARY_LOOPBACK_ALIAS_REQUIRED") from exc
    engine.adapter.preflight()
    require(not engine.adapter.inventory(), "RECOVERY_PENDING")
    if inbound is None:
        require(engine.boot and engine.healthy_recovery() and signing_key and key_id, "RECOVERY_PENDING")
        private = serialization.load_der_private_key(private_file(signing_key).read_bytes(), password=None)
    else:
        require(engine.store.get("boot") is None and not engine.store.commands(), "CANARY_DEDICATED_STATE_REQUIRED")
    locks = ExitStack()
    stop = threading.Event()
    servers, threads = [], []

    def echo(conn):
        with conn:
            conn.settimeout(.2)
            while not stop.is_set():
                try:
                    data = conn.recv(64)
                    if not data:
                        return
                    conn.sendall(data)
                except socket.timeout:
                    continue
                except OSError:
                    return

    def accept(server):
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                thread = threading.Thread(target=echo, args=(conn,), daemon=True)
                threads.append(thread)
                thread.start()
            except socket.timeout:
                continue
            except OSError:
                return

    def connection(number):
        conn = socket.socket()
        conn.settimeout(.3)
        conn.bind(("127.0.0.2", 0))
        try:
            conn.connect(("127.0.0.1", number))
        except BaseException:
            conn.close()
            raise
        return conn

    def probe(number):
        try:
            with connection(number) as conn:
                conn.sendall(b"p5-canary")
                return conn.recv(9) == b"p5-canary"
        except OSError:
            return False

    try:
        if inbound is not None:
            locks.enter_context(engine.store.lock("run", blocking=False))
            locks.enter_context(engine.store.lock("recover", blocking=False))
            require(engine.store.get("boot") is None and not engine.adapter.inventory(),
                    "CANARY_DEDICATED_STATE_REQUIRED")
        for number in (port, port + 1):
            server = socket.socket()
            server.bind(("127.0.0.1", number))
            server.listen(8)
            server.settimeout(.2)
            servers.append(server)
            thread = threading.Thread(target=accept, args=(server,), daemon=True)
            thread.start()
            threads.append(thread)
        before = {"target": probe(port), "control": probe(port + 1)}
        require(all(before.values()), "CANARY_BASELINE_FAILED")
        with connection(port) as established:
            if inbound is None:
                # 输入来自已登记 collector 的短期目标引用。
                binding = read_private(Path(c["stateDir"]) / "canary-binding.json")
                now = time.time()
                p = {**binding["binding"], "contractVersion": "host-guard/5.0.0-rc.3", "executorId": c["executorId"],
                     "executorBootId": engine.boot, "commandId": ident(), "actionId": ident(), "idempotencyKey": ident(),
                     "actionType": "temporary_block", "scope": "peer_service", "capabilityId": c["capabilityIds"][0],
                     "bundleId": c["bundleIds"][0], "policySha256": c["policyHashes"][0], "evidenceSha256": "0" * 64,
                     "authorizationId": c["authorization"]["id"], "authorizationRevision": c["authorization"]["revision"],
                     "issuedAt": stamp(now), "applyBy": stamp(now + 2), "blockUntil": stamp(now + 5), "leaseExpiresAt": stamp(now + 5)}
                command = {"payload": p, "keyId": key_id, "algorithm": "Ed25519",
                           "signature": base64.urlsafe_b64encode(private.sign(canonical(p))).rstrip(b"=").decode()}
                require(engine.accept(command) == "applied", "CANARY_APPLY_FAILED")
            else:
                # 直接测 PF 适配器，不签发命令。
                command_id = str(uuid.uuid4())
                engine.adapter.install(command_id, inbound, time.time() + 2)
                require(engine.adapter.inventory().get(command_id, {}).get("scope") == inbound,
                        "CANARY_APPLY_FAILED")
            during = {"newTarget": probe(port), "control": probe(port + 1)}
            try:
                established.sendall(b"p5-canary")
                during["establishedTarget"] = established.recv(9) == b"p5-canary"
            except OSError:
                during["establishedTarget"] = False
            if inbound is not None:
                engine.adapter.remove(command_id, inbound)
                command_id = None
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline and engine.adapter.inventory():
            time.sleep(.05)
        after = {"target": probe(port), "control": probe(port + 1), "rulesEmpty": not engine.adapter.inventory()}
        passed = not during["newTarget"] and not during["establishedTarget"] and during["control"] and all(after.values())
        write_new(output, canonical({"platform": "macos-pf", "scope": mode, "before": before,
                                    "during": during, "after": after, "passed": passed,
                                    "adapterOnly": inbound is not None,
                                    "ttlRecoveryTested": inbound is None, "rebootTested": False}))
        require(passed, "CANARY_EFFECT_OR_RECOVERY_FAILED")
    finally:
        try:
            if inbound is None:
                engine.store.set("paused", True)
                engine.recover(force=True)
            elif "command_id" in locals() and command_id is not None:
                engine.adapter.remove(command_id, inbound)
        finally:
            stop.set()
            for server in servers:
                server.close()
            for thread in threads:
                thread.join(1)
            locks.close()
            engine.adapter.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--signing-key")
    parser.add_argument("--key-id")
    parser.add_argument("--scope", choices=("peer_service", "peer_inbound"), default="peer_service")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    run(args.config, args.signing_key, args.key_id, args.output, args.scope)
