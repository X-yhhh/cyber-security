"""独立回环验收的真实 Go/mTLS 目标服务，不采集或连接外部网络。"""
from pathlib import Path
import socket
import subprocess
import time

from .common import Rejected, canonical, ident, parse, require, stamp, write_new
from .contract import SCHEMAS
from .pki import create
from .transport import HTTPS, TargetResolver


class CanaryTargets:
    """分离 collector/executor 身份；每条命令只使用一次新鲜登记的引用。"""

    def __init__(self, engine, executable):
        self.engine = engine
        self.directory = engine.store.root / "canary-targets"
        self.directory.mkdir(mode=0o700)
        self.pki = self.directory / "pki"
        fingerprints = create(self.pki)
        self.boot = ident()
        c = engine.config()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        scope = {"AssetID": c["assetId"], "SensorID": c["sensorId"], "BootID": self.boot,
                 "CaptureScopeID": c["captureScopeId"], "Environment": "lab",
                 "ExecutorBootID": engine.boot, "KeyEpoch": 1, "LocalAddresses": ["127.0.0.1"],
                 "CollectorCertSHA256": fingerprints["collector"], "ExecutorCertSHA256": fingerprints["executor"]}
        config = {"listen": f"127.0.0.1:{port}", "certificateFile": str(self.pki / "server.pem"),
                  "keyFile": str(self.pki / "server.key"), "caFile": str(self.pki / "ca.pem"),
                  "authorizedUntil": c["authorization"]["validUntil"], "scope": scope}
        path = self.directory / "target.json"
        write_new(path, canonical(config))
        self.process = subprocess.Popen([str(Path(executable).resolve()), "-config", str(path)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        url = f"https://127.0.0.1:{port}"
        self.collector = HTTPS(url, self.pki / "ca.pem", self.pki / "collector.pem",
                               self.pki / "collector.key", local=True)
        self.resolver_config = {
            "targetURL": url, "targetCA": str(self.pki / "ca.pem"),
            "targetCertificate": str(self.pki / "executor.pem"), "targetKey": str(self.pki / "executor.key")}
        self.resolver = TargetResolver(lambda: self.resolver_config)

    def lease(self, mode, port, peer_port):
        c, now = self.engine.config(), time.time()
        observation = parse((SCHEMAS / "examples/observation.json").read_bytes())
        observation.update({k: c[k] for k in ("assetId", "sensorId", "captureScopeId", "environment")})
        observation.update(bootId=self.boot, direction="inbound", servicePort=port, peerKey="a" * 64,
                           keyEpoch=1, firstSeenAt=stamp(now - 1), asOf=stamp(now),
                           lastPacketAt=stamp(now), emittedAt=stamp(now))
        request = {"observation": observation, "scope": mode,
                   "endpoints": {"Local": f"127.0.0.1:{port}", "Peer": f"127.0.0.2:{peer_port}", "Protocol": 6}}
        deadline = time.monotonic() + 3
        while True:
            try:
                lease = self.collector.post("/v1/targets/lease", request)
                break
            except Rejected:
                require(self.process.poll() is None and time.monotonic() < deadline, "CANARY_TARGET_START_FAILED")
                time.sleep(.03)
        binding = {**observation, "executorBootId": self.engine.boot, "targetRef": lease["targetRef"],
                   "scope": mode, "servicePort": None if mode == "peer_inbound" else port}
        resolved = self.resolver.resolve(binding)
        require(resolved["expiresAt"] == lease["expiresAt"], "TARGET_REFERENCE_REJECTED")
        return binding, self.engine.target_binding(binding, resolved, lease["expiresAt"])

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
