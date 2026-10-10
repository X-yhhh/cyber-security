"""B3 导入器只允许登记、独立审查后封存的协议测试。"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("import_bundle", Path(__file__).with_name("import_bundle.py"))
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class FakeApi(BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    fail_path: str | None = None
    policy_status = "reviewed"
    plan_hash = ""
    resources: dict = {}
    tamper_path: str | None = None
    expected_csrf = "synthetic-csrf"

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def respond(self, status: int, data: dict) -> None:
        payload = json.dumps({"requestId": "test", "data": data, "error": None}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        type(self).requests.append(("GET", self.path))
        data = dict(type(self).resources.get(self.path, {}))
        if self.path.startswith("/decision-policies/") and type(self).policy_status != "draft":
            data["status"] = type(self).policy_status
        if self.path == type(self).tamper_path:
            data["definitionSha256"] = "0" * 64
            data["reportSha256"] = "0" * 64
        self.respond(200 if data else 404, data)

    def do_POST(self) -> None:
        type(self).requests.append(("POST", self.path))
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if self.headers.get("X-CSRF-TOKEN") != self.expected_csrf:
            self.respond(403, {})
            return
        if self.path == type(self).fail_path:
            self.respond(422, {"code": "REJECTED"})
            return
        responses = {
            "/models": {"id": "model-id", "candidateOnly": True, "validationStatus": "pending"},
            "/models/model-id/validations": {"status": "validated", "artifactSha256": "f" * 64},
            "/evaluation-plans": {"id": "plan-id", "planSha256": type(self).plan_hash},
            "/capabilities": {"id": "capability-id", "level": "research", "scope": "peer_service"},
            "/decision-policies": {"id": "policy-id", "status": "draft", "revision": 1},
            "/release-bundles": {"id": "bundle-id", "status": "candidate", "revision": 1, "subjectSha256": ""},
            "/release-bundles/bundle-id/imports": {"id": "evaluation-id", "status": "passed"},
            "/release-bundles/bundle-id/sealings": {"id": "bundle-id", "status": "evaluated", "revision": 2, "sealedManifestSha256": "e" * 64},
        }
        cls = type(self)
        if self.path == "/models":
            cls.resources["/models/model-id"] = {"id": "model-id", "manifestSha256": body["manifestSha256"], "validationStatus": "pending", "artifactSha256": "f" * 64,
                "manifest": {"modelId": "model-id", "artifactSha256": "f" * 64, "evaluationPlanSha256": cls.plan_hash, "contractVersion": "host-guard/5.0.0-rc.3"}}
        if self.path == "/capabilities":
            cls.resources["/capabilities/capability-id"] = {"id": "capability-id", "payload": body, "level": body["level"], "scope": body.get("scope", "peer_service")}
        if self.path == "/decision-policies":
            cls.resources["/decision-policies/policy-id"] = {"id": "policy-id", "status": "draft", "modelId": "model-id", "definitionSha256": MODULE.sha256(body)}
        if self.path == "/release-bundles":
            subject = {"contractVersion": "host-guard/5.0.0-rc.3", "protocolVersions": body["protocolVersions"], "modelId": "model-id", "manifestSha256": "a" * 64,
                "policyId": "policy-id", "policySha256": cls.resources["/decision-policies/policy-id"]["definitionSha256"], "featureProfileSha256": body["featureProfileSha256"],
                "extractorSha256": body["extractorSha256"], "evaluationPlanSha256": cls.plan_hash, "capabilityIds": sorted(body["capabilityIds"]), "environment": "research"}
            responses[self.path]["subjectSha256"] = MODULE.sha256(subject)
            cls.resources["bundle"] = responses[self.path]
        if self.path.endswith("/imports"):
            cls.resources["/evaluations/evaluation-id"] = {"id": "evaluation-id", "status": "passed", "bundleId": "bundle-id", "reportSha256": body["sha256"]}
        if self.path.endswith("/sealings"):
            responses[self.path]["sealedManifestSha256"] = MODULE.sha256({"subjectSha256": cls.resources["bundle"]["subjectSha256"], "reports": [{"evaluationId": "evaluation-id", "reportSha256": "d" * 64}]})
        if self.path == cls.tamper_path:
            for field in ("subjectSha256", "sealedManifestSha256"):
                if field in responses[self.path]:
                    responses[self.path][field] = "0" * 64
        self.respond(201 if self.path in responses else 404, responses.get(self.path, {"code": "NOT_FOUND"}))


class ImportBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.plan = json.loads((Path(__file__).parent / "testdata" / "import-bundle-plan.json").read_text())
        FakeApi.requests = []
        FakeApi.fail_path = None
        FakeApi.policy_status = "draft"
        FakeApi.resources = {}
        FakeApi.tamper_path = None
        FakeApi.plan_hash = MODULE.sha256(self.plan["evaluationPlan"])
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeApi)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.api = MODULE.Api(f"http://127.0.0.1:{self.server.server_port}", None, FakeApi.expected_csrf)
        self.state = self.root / "state.json"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.temp.cleanup()

    def test_import_order_and_manual_approval_barriers(self) -> None:
        MODULE.prepare(self.api, self.plan, self.state)
        self.assertEqual([path for method, path in FakeApi.requests if method == "POST"], ["/models", "/models/model-id/validations", "/evaluation-plans", "/capabilities", "/decision-policies"])
        self.assertFalse(any("reviews" in path or "decisions" in path or "activations" in path for _, path in FakeApi.requests))
        FakeApi.policy_status = "reviewed"
        MODULE.resume(self.api, self.state)
        self.assertEqual([path for method, path in FakeApi.requests if method == "POST"][-3:], ["/release-bundles", "/release-bundles/bundle-id/imports", "/release-bundles/bundle-id/sealings"])
        self.assertFalse(any("reviews" in path or path.endswith("/decisions") or "activations" in path for _, path in FakeApi.requests))
        self.assertEqual(MODULE.load(self.state)["phase"], "awaiting-bundle-decision")

    def test_hash_mismatch_stops_before_capability(self) -> None:
        FakeApi.plan_hash = "0" * 64
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.prepare(self.api, self.plan, self.state)
        self.assertEqual([path for method, path in FakeApi.requests if method == "POST"], ["/models", "/models/model-id/validations", "/evaluation-plans"])

    def test_failure_stops_without_downstream_calls(self) -> None:
        FakeApi.fail_path = "/capabilities"
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.prepare(self.api, self.plan, self.state)
        self.assertEqual([path for method, path in FakeApi.requests if method == "POST"], ["/models", "/models/model-id/validations", "/evaluation-plans", "/capabilities"])

    def test_resume_requires_independent_review(self) -> None:
        MODULE.prepare(self.api, self.plan, self.state)
        FakeApi.policy_status = "draft"
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.resume(self.api, self.state)
        self.assertEqual(FakeApi.requests[-1], ("GET", "/decision-policies/policy-id"))

    def test_reviewed_policy_hash_mismatch_stops_before_bundle(self) -> None:
        MODULE.prepare(self.api, self.plan, self.state)
        FakeApi.policy_status = "reviewed"
        FakeApi.tamper_path = "/decision-policies/policy-id"
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.resume(self.api, self.state)
        self.assertNotIn(("POST", "/release-bundles"), FakeApi.requests)

    def test_report_hash_mismatch_stops_before_sealing(self) -> None:
        MODULE.prepare(self.api, self.plan, self.state)
        FakeApi.policy_status = "reviewed"
        FakeApi.tamper_path = "/evaluations/evaluation-id"
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.resume(self.api, self.state)
        self.assertFalse(any(path.endswith("/sealings") for _, path in FakeApi.requests))

    def test_existing_state_is_not_overwritten(self) -> None:
        self.state.write_text("{}")
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.prepare(self.api, self.plan, self.state)
        self.assertEqual(FakeApi.requests, [])

    def test_bundle_hash_mismatch_stops_before_report_import(self) -> None:
        MODULE.prepare(self.api, self.plan, self.state)
        FakeApi.policy_status = "reviewed"
        FakeApi.tamper_path = "/release-bundles"
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.resume(self.api, self.state)
        self.assertEqual(FakeApi.requests[-1], ("POST", "/release-bundles"))
        self.assertEqual(MODULE.load(self.state)["phase"], "importing-reports")

    def test_sealing_hash_mismatch_does_not_claim_completion(self) -> None:
        MODULE.prepare(self.api, self.plan, self.state)
        FakeApi.policy_status = "reviewed"
        FakeApi.tamper_path = "/release-bundles/bundle-id/sealings"
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.resume(self.api, self.state)
        self.assertNotEqual(MODULE.load(self.state)["phase"], "awaiting-bundle-decision")

    def test_canonical_digest_uses_jcs_numeric_encoding(self) -> None:
        self.assertEqual(MODULE.sha256({"number": 1.0}), MODULE.sha256({"number": 1}))

    def existing_capabilities(self) -> list[dict]:
        payload = self.plan.pop("capability")
        refs = []
        for index, family in enumerate(("port_scan", "bruteforce", "dos_flood", "dos_slow"), 1):
            identifier = f"b1000000-0000-4000-8000-{index:012d}"
            cap = dict(payload, capabilityKey=family, family=family, level="lab_auto")
            if family == "port_scan":
                cap.update(scope="peer_inbound", protectionSetSha256="b" * 64,
                           exemptionEvidenceRef="fixture:exemption", exemptionEvidenceSha256="c" * 64)
            ref = {"id": identifier, "payload": cap, "payloadSha256": MODULE.sha256(cap)}
            refs.append(ref)
            FakeApi.resources[f"/capabilities/{identifier}"] = dict(id=identifier, payload=cap,
                level=cap["level"], scope=cap.get("scope", "peer_service"))
        self.plan["existingCapabilities"] = refs
        self.plan["decisionPolicy"]["supportedCapabilityIds"] = "${capabilityIds}"
        self.plan["releaseBundle"]["capabilityIds"] = "${capabilityIds}"
        return refs

    def test_reuses_four_lab_auto_capabilities_without_registration(self) -> None:
        refs = self.existing_capabilities()
        MODULE.prepare(self.api, self.plan, self.state)
        self.assertEqual(MODULE.load(self.state)["capabilityIds"], sorted(ref["id"] for ref in refs))
        FakeApi.policy_status = "reviewed"
        MODULE.resume(self.api, self.state)
        self.assertNotIn(("POST", "/capabilities"), FakeApi.requests)
        self.assertEqual(MODULE.load(self.state)["phase"], "awaiting-bundle-decision")

    def test_existing_payload_drift_stops_before_any_write(self) -> None:
        refs = self.existing_capabilities()
        FakeApi.resources[f"/capabilities/{refs[0]['id']}"]["payload"] = dict(refs[0]["payload"], level="research")
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.prepare(self.api, self.plan, self.state)
        self.assertFalse(any(method == "POST" for method, _ in FakeApi.requests))

    def test_missing_existing_capability_stops_before_any_write(self) -> None:
        refs = self.existing_capabilities()
        del FakeApi.resources[f"/capabilities/{refs[0]['id']}"]
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.prepare(self.api, self.plan, self.state)
        self.assertFalse(any(method == "POST" for method, _ in FakeApi.requests))

    def test_ambiguous_duplicate_and_bad_digest_plans_are_rejected(self) -> None:
        refs = self.existing_capabilities()
        for change in (lambda p: p.update(capability=refs[0]["payload"]),
                       lambda p: p["existingCapabilities"].append(refs[0]),
                       lambda p: p["existingCapabilities"][0].update(payloadSha256="0" * 64)):
            plan = json.loads(json.dumps(self.plan))
            change(plan)
            with self.assertRaises(MODULE.ImportFailure):
                MODULE.prepare(self.api, plan, self.state)
        self.assertEqual(FakeApi.requests, [])

    def test_existing_capabilities_are_revalidated_on_resume(self) -> None:
        refs = self.existing_capabilities()
        MODULE.prepare(self.api, self.plan, self.state)
        FakeApi.policy_status = "reviewed"
        FakeApi.resources[f"/capabilities/{refs[0]['id']}"]["level"] = "research"
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.resume(self.api, self.state)
        self.assertNotIn(("POST", "/release-bundles"), FakeApi.requests)

    def test_partial_bundle_capability_set_is_rejected_before_policy(self) -> None:
        refs = self.existing_capabilities()
        self.plan["releaseBundle"]["capabilityIds"] = [refs[0]["id"]]
        with self.assertRaises(MODULE.ImportFailure):
            MODULE.prepare(self.api, self.plan, self.state)
        self.assertNotIn(("POST", "/decision-policies"), FakeApi.requests)


if __name__ == "__main__":
    unittest.main()
