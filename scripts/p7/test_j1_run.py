"""J1 runner 的权限边界回归：默认不得调用 sudo 或 pfctl。"""
import unittest
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import j1_run


class SessionV2Test(unittest.TestCase):
    """用严格的本地 HTTP 契约验证登录幂等头与会话轮换后的 CSRF，不接业务服务。"""

    def test_login_uses_v2_and_refreshes_csrf_before_business_write(self):
        records = []

        class Handler(BaseHTTPRequestHandler):
            logged_in = False

            def log_message(self, *args):
                pass

            def reply(self, status, data=None, code=None):
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(dict(requestId='test-session', data=data,
                    error=None if code is None else dict(code=code))).encode())

            def do_GET(self):
                records.append(('GET', self.path))
                if self.path != '/api/v2/auth/csrf':
                    return self.reply(404, code='RESOURCE_NOT_FOUND')
                self.reply(200, dict(token='after' if Handler.logged_in else 'before'))

            def do_POST(self):
                records.append(('POST', self.path))
                self.rfile.read(int(self.headers.get('Content-Length', '0')))
                if self.path == '/api/v2/auth/login':
                    try:
                        uuid.UUID(self.headers.get('Idempotency-Key', ''))
                    except ValueError:
                        return self.reply(400, code='INVALID_UUID')
                    if self.headers.get('X-CSRF-TOKEN') != 'before':
                        return self.reply(403, code='CSRF_INVALID')
                    Handler.logged_in = True
                    return self.reply(200, dict(id=1))
                if self.path == '/api/v2/assets' and self.headers.get('X-CSRF-TOKEN') == 'after':
                    return self.reply(200, dict(accepted=True))
                self.reply(403, code='CSRF_INVALID')

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            session = j1_run.Session(f'http://127.0.0.1:{server.server_port}', None)
            session.login(dict(username='fixture', password=str(uuid.uuid4())))
            self.assertEqual(session.call('POST', '/api/v2/assets', {})['data'], dict(accepted=True))
            self.assertEqual(records, [('GET', '/api/v2/auth/csrf'), ('POST', '/api/v2/auth/login'),
                                      ('GET', '/api/v2/auth/csrf'), ('POST', '/api/v2/assets')])
        finally:
            server.shutdown()
            worker.join(timeout=2)
            server.server_close()


class PfSnapshotTest(unittest.TestCase):
    def test_default_snapshot_records_authorization_boundary_without_subprocess(self):
        with patch.object(j1_run.subprocess, "run") as run:
            snapshot = j1_run.pf_snapshot()
        run.assert_not_called()
        self.assertEqual([entry["operation"] for entry in snapshot], ["info", "rules", "anchors"])
        self.assertTrue(all(entry["attempted"] is False for entry in snapshot))
        self.assertTrue(all(entry["exitCode"] is None for entry in snapshot))
        self.assertTrue(all(entry["reason"] == "not_executed_authorization_boundary" for entry in snapshot))

    def test_explicit_option_is_the_only_path_that_invokes_pf_commands(self):
        completed = type("Completed", (), {"returncode": 0, "stdout": b"fixture"})()
        with patch.object(j1_run.subprocess, "run", return_value=completed) as run:
            snapshot = j1_run.pf_snapshot(True)
        self.assertEqual(run.call_count, 3)
        self.assertTrue(all(entry["attempted"] is True and entry["exitCode"] == 0 for entry in snapshot))


if __name__ == "__main__":
    unittest.main()
