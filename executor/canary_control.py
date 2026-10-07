"""仅绑定回环的 TLS 控制面故障夹具；不替代 P4 服务或数据库验收。"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import threading
import time

from .common import canonical, digest, ident, parse, stamp, write_new
from .transport import ControlPlane


class CanaryControl:
    """模拟已持久化回执但响应丢失，记录 ID 与内容重试的一致性。"""

    def __init__(self, engine, pki, signed):
        self.receipts = []
        self.fail_receipt = True
        self.closed = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                if self.headers.get("Authorization") != "Bearer loopback-canary-only":
                    self.send_error(401)
                    return
                body = parse(self.rfile.read(int(self.headers["Content-Length"])))
                operation = self.path.rsplit("/", 1)[-1]
                if operation == "heartbeats":
                    value = {"serverTime": stamp(time.time()), "status": "active"}
                elif operation == "receipts":
                    fixture.receipts.append((body["receiptId"], digest(body)))
                    if fixture.fail_receipt:
                        fixture.fail_receipt = False
                        self.send_error(503)
                        return
                    value = {"persisted": True, "projected": True}
                elif operation == "command-claims":
                    value = {"commands": [signed], "revocations": [], "serverTime": stamp(time.time())}
                else:
                    value = {"status": "verified", "errorCount": 0}
                data = canonical({"data": value, "error": None, "requestId": ident()})
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(pki / "server.pem", pki / "server.key")
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        credential = engine.store.root / "canary-credential"
        write_new(credential, b"loopback-canary-only")
        self.control = ControlPlane(lambda: {**engine.config(), "controlPlaneCA": str(pki / "ca.pem"),
                                             "controlPlaneURL": f"https://127.0.0.1:{self.server.server_port}",
                                             "credentialFile": str(credential)})

    def close(self):
        if not self.closed:
            self.closed = True
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(2)
