"""P5 已配置 PF 的回环验收入口；不重启、不挂接根规则、不启用/停用 PF。

必须先由管理员挂接专用 anchor、安装 helper 并配置独立恢复进程。只使用
127.0.0.1/127.0.0.2 和已登记高端口，输出仅含连接布尔值、摘要与清理结果。
"""
import argparse
import base64
from pathlib import Path
import socket
import threading
import time

from cryptography.hazmat.primitives import serialization

from .__main__ import build
from .common import canonical, ident, private_file, read_private, require, stamp, write_new


def run(config_path, signing_key, key_id, output):
    engine = build(config_path)
    c = engine.config()
    require(c["platform"] == "pf" and c["environment"] == "lab" and c["interface"] == "lo0" and
            c["localAddresses"] == ["127.0.0.1"] and c["peerAddresses"] == ["127.0.0.2"] and
            len(c["servicePorts"]) == 1 and 49152 <= c["servicePorts"][0] <= 65533,
            "CANARY_SCOPE_REQUIRED")
    port = c["servicePorts"][0]
    engine.adapter.preflight()
    require(not engine.adapter.inventory() and engine.boot and engine.healthy_recovery(), "RECOVERY_PENDING")
    private = serialization.load_der_private_key(private_file(signing_key).read_bytes(), password=None)
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
        for number in (port, port + 1):
            server = socket.socket()
            server.bind(("127.0.0.1", number))
            server.listen(8)
            server.settimeout(.2)
            servers.append(server)
            thread = threading.Thread(target=accept, args=(server,), daemon=True)
            thread.start()
            threads.append(thread)
        # 输入来自已登记 collector 的短期目标引用；不在此入口制造研究数据或任意地址命令。
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
        before = {"target": probe(port), "control": probe(port + 1)}
        require(all(before.values()), "CANARY_BASELINE_FAILED")
        with connection(port) as established:
            require(engine.accept(command) == "applied", "CANARY_APPLY_FAILED")
            during = {"newTarget": probe(port), "control": probe(port + 1)}
            try:
                established.sendall(b"p5-canary")
                during["establishedTarget"] = established.recv(9) == b"p5-canary"
            except OSError:
                during["establishedTarget"] = False
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline and engine.adapter.inventory():
            time.sleep(.05)
        after = {"target": probe(port), "control": probe(port + 1), "rulesEmpty": not engine.adapter.inventory()}
        passed = not during["newTarget"] and not during["establishedTarget"] and during["control"] and all(after.values())
        write_new(output, canonical({"platform": "macos-pf", "scope": "loopback-canary", "before": before,
                                    "during": during, "after": after, "passed": passed, "rebootTested": False}))
        require(passed, "CANARY_EFFECT_OR_RECOVERY_FAILED")
    finally:
        engine.store.set("paused", True)
        engine.recover(force=True)
        stop.set()
        for server in servers:
            server.close()
        for thread in threads:
            thread.join(1)
        engine.adapter.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    run(args.config, args.signing_key, args.key_id, args.output)
