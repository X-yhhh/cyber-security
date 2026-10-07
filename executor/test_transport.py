"""真实 TLS 与 Go IPC 对接；固定命令仅进入故障替身，不写系统防火墙。"""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from . import test_engine
from .__main__ import cycle, flush
from .common import Rejected, canonical, ident, parse, stamp, write_new
from .contract import BINDING_FIELDS, SCHEMAS
from .pki import create
from .transport import ControlPlane, HTTPS, TargetResolver


class TransportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pki = self.root / "pki"
        self.fingerprints = create(self.pki)

    def test_machine_tls_idempotent_receipt_retry_and_revocation(self):
        fixture = test_engine.EngineTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.clock = time
        fixture.engine.clock = time
        fixture.resolver.clock = time
        fixture.config["authorization"].update(validFrom=stamp(time.time() - 60), validUntil=stamp(time.time() + 600))
        fixture.trust["test"].update(notBefore=stamp(time.time() - 60), notAfter=stamp(time.time() + 600))
        fixture.engine.start()
        fixture.engine.pulse("recovery")
        command = fixture.signed(fixture.payload())
        requests, receipts = [], {}
        state = {"failReceiptOnce": True, "revocations": []}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass

            def do_POST(self):
                if self.headers.get("Authorization") != "Bearer synthetic-executor-only":
                    self.send_error(401)
                    return
                body = parse(self.rfile.read(int(self.headers["Content-Length"])))
                operation = self.path.rsplit("/", 1)[-1]
                requests.append((operation, self.headers.get("Idempotency-Key"), body))
                if operation == "heartbeats":
                    data = {"serverTime": stamp(time.time()), "status": "active"}
                elif operation == "command-claims":
                    data = {"commands": [] if state["revocations"] else [command], "revocations": state["revocations"], "serverTime": stamp(time.time())}
                elif operation == "receipts":
                    key = body["receiptId"]
                    if key in receipts:
                        assert receipts[key] == body
                    receipts[key] = body
                    if state["failReceiptOnce"]:
                        state["failReceiptOnce"] = False
                        self.send_error(503)
                        return
                    data = {"persisted": True, "projected": True}
                else:
                    data = {"status": "verified", "errorCount": 0}
                output = canonical({"data": data, "error": None, "requestId": ident()})
                self.send_response(200)
                self.send_header("Content-Length", str(len(output)))
                self.end_headers()
                self.wfile.write(output)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.pki / "server.pem", self.pki / "server.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(2)))
        credential = self.root / "credential"
        write_new(credential, b"synthetic-executor-only")
        fixture.config.update(controlPlaneURL=f"https://127.0.0.1:{server.server_port}",
                              controlPlaneCA=str(self.pki / "ca.pem"), credentialFile=str(credential), capabilityHash="c" * 64)
        control = ControlPlane(lambda: fixture.config)
        with self.assertRaisesRegex(Rejected, "CONTROL_PLANE_UNAVAILABLE"):
            cycle(fixture.engine, control)
        self.assertEqual(fixture.firewall.installs, 1)
        self.assertTrue(fixture.store.get("paused"))
        self.assertFalse(fixture.firewall.rules)
        row = fixture.store.command(command["payload"]["commandId"])
        self.assertEqual(row["status"], "uncertain")
        self.assertIsNotNone(row["clearedAt"])
        pending_id = fixture.store.pending()[0][0]
        flush(fixture.engine, control)
        retries = [r for r in requests if r[0] == "receipts" and r[1] == pending_id]
        self.assertEqual(len(retries), 2)
        self.assertEqual(retries[0][2], retries[1][2])
        state["revocations"] = [fixture.revocation(command["payload"])]
        fixture.engine.pulse("recovery")
        cycle(fixture.engine, control)
        self.assertFalse(fixture.firewall.rules)
        self.assertEqual(fixture.store.command(command["payload"]["commandId"])["status"], "revoked")

    def test_python_resolves_go_mtls_target_and_rejects_wrong_identity(self):
        executable = Path(os.environ.get("P5_GUARDTARGETS", str(Path(__file__).resolve().parents[1] / "sensor/bin/guardtargets")))
        self.assertTrue(executable.is_file(), "先构建 sensor/bin/guardtargets")
        observation = parse((SCHEMAS / "examples/observation.json").read_bytes())
        now = time.time()
        observation.update(environment="lab", direction="inbound", servicePort=55001,
                           firstSeenAt=stamp(now - 1), asOf=stamp(now), lastPacketAt=stamp(now), emittedAt=stamp(now))
        boot = ident()
        scope = {"AssetID": observation["assetId"], "SensorID": observation["sensorId"], "BootID": observation["bootId"],
                 "CaptureScopeID": observation["captureScopeId"], "Environment": "lab", "ExecutorBootID": boot,
                 "KeyEpoch": 1, "LocalAddresses": ["127.0.0.1"], "CollectorCertSHA256": self.fingerprints["collector"],
                 "ExecutorCertSHA256": self.fingerprints["executor"]}
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        c = {"listen": f"127.0.0.1:{port}", "certificateFile": str(self.pki / "server.pem"),
             "keyFile": str(self.pki / "server.key"), "caFile": str(self.pki / "ca.pem"),
             "authorizedUntil": stamp(now + 30), "scope": scope}
        path = self.root / "target.json"
        write_new(path, canonical(c))
        process = subprocess.Popen([str(executable), "-config", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        def cleanup():
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)
        self.addCleanup(cleanup)
        url = f"https://127.0.0.1:{port}"
        collector = HTTPS(url, self.pki / "ca.pem", self.pki / "collector.pem", self.pki / "collector.key", local=True)
        endpoints = {"Local": "127.0.0.1:55001", "Peer": "127.0.0.2:55002", "Protocol": 6}
        deadline = time.monotonic() + 3
        while True:
            try:
                lease = collector.post("/v1/targets/lease", {"observation": observation, "endpoints": endpoints})
                break
            except Rejected:
                if time.monotonic() >= deadline or process.poll() is not None:
                    raise
                time.sleep(.03)
        config = {"targetURL": url, "targetCA": str(self.pki / "ca.pem"),
                  "targetCertificate": str(self.pki / "executor.pem"), "targetKey": str(self.pki / "executor.key")}
        resolver = TargetResolver(lambda: config)
        p = {**observation, "executorBootId": boot, "targetRef": lease["targetRef"], "scope": "peer_service"}
        resolved = resolver.resolve(p)
        self.assertEqual(resolved["endpoints"], endpoints)
        self.assertEqual(resolved["expiresAt"], lease["expiresAt"])
        with self.assertRaises(Rejected):
            resolver.resolve({**p, "bootId": ident()})
        inbound_lease = collector.post("/v1/targets/lease", {"observation": observation,
                                                        "endpoints": endpoints, "scope": "peer_inbound"})
        inbound = {**p, "targetRef": inbound_lease["targetRef"], "scope": "peer_inbound", "servicePort": None}
        self.assertEqual(resolver.resolve(inbound)["endpoints"], endpoints)
        with self.assertRaises(Rejected):
            resolver.resolve({**inbound, "scope": "peer_service", "servicePort": 55001})
        with self.assertRaises(Rejected):
            collector.post("/v1/targets/resolve", {"targetRef": p["targetRef"], "binding": {k: p[k] for k in BINDING_FIELDS}})
        with self.assertRaisesRegex(Rejected, "HTTPS_REQUIRED"):
            HTTPS("http://127.0.0.1:80")


if __name__ == "__main__":
    unittest.main()
