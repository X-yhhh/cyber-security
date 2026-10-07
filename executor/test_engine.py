"""P5 必需行为回归：故障注入使用规则替身，不宣称 OS 生效或恢复验收。"""
import base64
import copy
import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .common import Rejected, canonical, digest, ident, parse, public_der, stamp
from .contract import scope_hash, verify
from .engine import Engine
from .storage import Store


class Clock:
    wall = 1791200000.0
    mono = 1000.0

    def time(self): return self.wall
    def monotonic(self): return self.mono
    def advance(self, value):
        self.wall += value
        self.mono += value


class Crash(BaseException):
    pass


class Firewall:
    def __init__(self):
        self.rules = {}
        self.installs = 0
        self.crash = False
        self.fail_remove = False

    def handle(self, command): return "fixture:" + command

    def install(self, command, scope, apply_by=None):
        self.rules[command] = {"handle": self.handle(command), "scope": copy.deepcopy(scope)}
        self.installs += 1
        if self.crash:
            raise Crash()

    def inventory(self): return copy.deepcopy(self.rules)

    def remove(self, command, scope):
        if self.fail_remove:
            raise OSError("synthetic removal failure")
        self.rules.pop(command, None)


class Resolver:
    def __init__(self, clock):
        self.clock = clock
        self.result = {"Local": "192.0.2.1:55001", "Peer": "192.0.2.2:55002", "Protocol": 6}

    def resolve(self, payload):
        at = self.clock.time()
        return {"endpoints": self.result, "lastPacketAt": stamp(at), "expiresAt": stamp(at + 15)}


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock, self.firewall = Clock(), Firewall()
        self.resolver = Resolver(self.clock)
        self.clock.wall, self.clock.mono = 1791200000.0, 1000.0
        self.key = Ed25519PrivateKey.generate()
        self.trust = {"test": {"status": "active", "notBefore": stamp(self.clock.time() - 100),
                              "notAfter": stamp(self.clock.time() + 10000), "publicKeyDer": public_der(self.key.public_key())}}
        self.config = {k: ident() for k in ("assetId", "executorId", "sensorId", "captureScopeId")}
        self.config.update(environment="lab", interface="lo0", localAddresses=["192.0.2.1"],
                           peerAddresses=["192.0.2.2", "192.0.2.3"], servicePorts=[55001],
                           protectedServicePorts=[22, 53, 3389], protectedPeers=[], capabilityIds=[ident()],
                           bundleIds=[ident()], policyHashes=["a" * 64],
                           authorization={"id": ident(), "revision": 1, "status": "active",
                                          "validFrom": stamp(self.clock.time() - 60), "validUntil": stamp(self.clock.time() + 10000)},
                           limits={"maxTtlSeconds": 60, "maxContinuousBlockSeconds": 120,
                                   "maxActiveRulesPerAsset": 10, "maxNewActionsPerMinute": 5})
        self.store = Store(Path(self.temp.name) / "state")
        self.engine = Engine(self.store, self.firewall, self.resolver, lambda: self.config,
                             lambda: self.trust, b"test-only-stable-budget-key-32bytes", self.clock)
        self.engine.start()
        self.engine.pulse("recovery")

    def payload(self, **changes):
        c, now = self.config, self.clock.time()
        p = {k: c[k] for k in ("assetId", "executorId", "sensorId", "captureScopeId", "environment")}
        p.update(contractVersion="host-guard/5.0.0-rc.3", commandId=ident(), actionId=ident(),
                 executorBootId=self.engine.boot, bootId=ident(), targetRef=ident(), peerKey="b" * 64,
                 keyEpoch=1, actionType="temporary_block", scope="peer_service", addressFamily="ipv4",
                 direction="inbound", transport="tcp", servicePort=55001, capabilityId=c["capabilityIds"][0],
                 bundleId=c["bundleIds"][0], policySha256=c["policyHashes"][0], evidenceSha256="c" * 64,
                 authorizationId=c["authorization"]["id"], authorizationRevision=1,
                 issuedAt=stamp(now), applyBy=stamp(now + 5), leaseExpiresAt=stamp(now + 30),
                 blockUntil=stamp(now + 30), idempotencyKey=ident())
        p.update(changes)
        return p

    def signed(self, p):
        return {"payload": p, "keyId": "test", "algorithm": "Ed25519",
                "signature": base64.urlsafe_b64encode(self.key.sign(canonical(p))).rstrip(b"=").decode()}

    def accept(self, **changes):
        p = self.payload(**changes)
        return p, self.engine.accept(self.signed(p))

    def revocation(self, p, revision=1):
        return {"revocationId": ident(), "actionId": p["actionId"], "commandId": p["commandId"],
                "executorId": p["executorId"], "assetId": p["assetId"], "environment": "lab",
                "desiredRevision": revision, "issuedAt": stamp(self.clock.time()), "reasonCode": "USER_REVOKED"}

    def test_tamper_key_revocation_rotation_and_duplicate_json(self):
        p = self.payload()
        envelope = self.signed(p)
        envelope["payload"]["servicePort"] = 80
        with self.assertRaisesRegex(Rejected, "SIGNATURE_INVALID"):
            self.engine.accept(envelope)
        self.trust["test"]["status"] = "revoked"
        with self.assertRaisesRegex(Rejected, "SIGNING_KEY_UNTRUSTED"):
            self.engine.accept(self.signed(self.payload()))
        self.trust["test"]["status"] = "active"
        self.assertEqual(verify(self.signed(self.payload()), self.trust, self.clock.time())["servicePort"], 55001)
        with self.assertRaisesRegex(Rejected, "DUPLICATE_JSON_FIELD"):
            parse('{"keyId":"a","keyId":"b"}')
        self.assertEqual(self.firewall.installs, 0)

    def test_identity_expiry_scope_and_protection_rejections(self):
        cases = [{"executorBootId": ident()}, {"assetId": ident()}, {"authorizationRevision": 2},
                 {"applyBy": stamp(self.clock.time() - 1)}, {"direction": "outbound"},
                 {"blockUntil": stamp(self.clock.time() + 90), "leaseExpiresAt": stamp(self.clock.time() + 90)}]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.accept(**change)
        self.config["protectedPeers"] = ["192.0.2.2/32"]
        with self.assertRaisesRegex(Rejected, "PROTECTED_TARGET"):
            self.accept()
        self.assertEqual(self.firewall.installs, 0)

    def test_peer_inbound_is_rejected_before_install_with_rc2_receipt(self):
        p = self.payload(scope="peer_inbound", servicePort=None)
        with self.assertRaisesRegex(Rejected, "PROTECTED_TARGET"):
            self.engine.accept(self.signed(p))
        self.assertEqual(self.firewall.installs, 0)
        self.assertEqual(self.store.command(p["commandId"])["status"], "rejected")
        receipt = self.store.pending()[0][2]
        self.assertEqual(receipt["contractVersion"], "host-guard/5.0.0-rc.2")
        self.assertEqual(receipt["errorCode"], "PROTECTED_TARGET")

    def test_peer_inbound_binding_has_distinct_stable_budget_identity(self):
        service = self.payload()
        inbound = self.payload(scope="peer_inbound", servicePort=None)
        resolved = self.resolver.resolve(inbound)
        bound = self.engine.target_binding(inbound, resolved, resolved["expiresAt"])
        self.assertEqual(bound["scope"], "peer_inbound")
        self.assertIsNone(bound["servicePort"])
        service_scope = self.engine._resolve(service, resolved)[0]
        old_identity = {"assetId": service["assetId"], "environment": service["environment"],
                        "peer": service_scope["peer"], "direction": service["direction"],
                        "transport": "tcp", "servicePort": service_scope["port"], "addressFamily": "ipv4"}
        old_token = hmac.new(self.engine.budget_key, canonical(old_identity), hashlib.sha256).hexdigest()
        self.assertEqual(self.engine.stable_target(service, service_scope), old_token)
        self.assertNotEqual(bound["stableTargetToken"], old_token)

    def test_same_command_retries_do_not_extend_ttl_and_conflict_rejected(self):
        p, status = self.accept()
        self.assertEqual(status, "applied")
        before = self.store.command(p["commandId"])["deadline"]
        self.clock.advance(3)
        self.assertEqual(self.engine.accept(self.signed(p)), "applied")
        self.assertEqual(self.store.command(p["commandId"])["deadline"], before)
        altered = {**p, "evidenceSha256": "d" * 64}
        with self.assertRaisesRegex(Rejected, "IDEMPOTENCY_CONFLICT"):
            self.engine.accept(self.signed(altered))
        self.clock.advance(27)
        self.engine.recover()
        self.assertEqual(self.store.command(p["commandId"])["status"], "expired")
        self.assertFalse(self.firewall.rules)
        self.assertEqual(self.engine.accept(self.signed(p)), "expired")
        self.assertEqual(self.firewall.installs, 1)

    def test_revocation_tombstone_prevents_reapply_and_rejects_old_revision(self):
        p, _ = self.accept()
        rev = self.revocation(p, 3)
        self.engine.revoke(rev)
        self.assertFalse(self.firewall.rules)
        self.assertEqual(self.engine.accept(self.signed(p)), "revoked")
        with self.assertRaisesRegex(Rejected, "STALE_REVOCATION"):
            self.engine.revoke(self.revocation(p, 2))
        delayed = self.payload()
        early = self.revocation(delayed)
        self.engine.revoke(early)
        self.assertIn(early, Store(self.store.root).revocations())
        self.assertEqual(self.engine.snapshot()["pendingRevocations"][0]["revocationId"], early["revocationId"])
        with self.assertRaisesRegex(Rejected, "COMMAND_REVOKED"):
            self.engine.accept(self.signed(delayed))
        self.assertEqual(self.firewall.installs, 1)

    def test_crash_after_rule_before_receipt_is_recovered_from_intent(self):
        self.firewall.crash = True
        p = self.payload()
        with self.assertRaises(Crash):
            self.engine.accept(self.signed(p))
        self.assertTrue(self.firewall.rules)
        self.assertEqual(self.store.command(p["commandId"])["status"], "prepared")
        self.engine.recover()
        self.assertFalse(self.firewall.rules)
        self.assertEqual(self.store.command(p["commandId"])["status"], "uncertain")
        self.clock.advance(31)
        self.engine.recover()
        self.assertEqual(self.store.command(p["commandId"])["status"], "expired")

    def test_restart_and_backward_clock_clear_without_extending(self):
        p, _ = self.accept()
        self.clock.wall -= 10
        self.engine.recover()
        self.assertFalse(self.firewall.rules)
        self.assertTrue(self.store.get("paused"))
        before = self.store.command(p["commandId"])["deadline"]
        self.engine.start()
        self.assertEqual(self.store.command(p["commandId"])["deadline"], before)
        self.assertNotEqual(self.engine.boot, p["executorBootId"])
        self.assertEqual(self.firewall.installs, 1)

    def test_cleanup_failure_keeps_uncertain_budget_and_pauses(self):
        p, _ = self.accept()
        self.firewall.fail_remove = True
        self.clock.advance(30)
        self.engine.recover()
        self.assertEqual(self.store.command(p["commandId"])["status"], "recovery_failed")
        self.assertTrue(self.firewall.rules)
        self.assertTrue(self.engine.snapshot()["recoveryErrors"])
        with self.assertRaisesRegex(Rejected, "RECOVERY_PENDING"):
            self.engine.stop()
        self.engine.pulse("recovery")
        with self.assertRaisesRegex(Rejected, "RECOVERY_PENDING"):
            self.accept()
        self.firewall.fail_remove = False
        self.engine.stop()
        self.assertEqual(self.store.command(p["commandId"])["status"], "expired")

    def test_receipt_loss_persists_same_id_and_state_digest_matches_contract(self):
        p, _ = self.accept()
        pending = self.store.pending()
        self.assertEqual(len(pending), 1)
        receipt = pending[0][2]
        self.assertEqual(receipt["contractVersion"], "host-guard/5.0.0-rc.2")
        snapshot = self.engine.snapshot()
        state = {"digestVersion": "guard-state/1", "assetId": p["assetId"], "executorId": p["executorId"],
                 "executorBootId": self.engine.boot, "rules": snapshot["ownedRules"], "pendingRevocations": []}
        self.assertEqual(digest(state), receipt["stateDigest"])
        self.assertEqual(snapshot["ownedRules"][0]["normalizedScopeSha256"], scope_hash(p))
        reopened = Store(self.store.root)
        self.assertEqual(reopened.pending(), pending)
        self.engine.recover()
        self.assertEqual(self.store.pending(), pending)

    def test_parallel_commands_share_target_and_asset_budget(self):
        commands = [self.signed(self.payload()) for _ in range(5)]
        def submit(value):
            try:
                return self.engine.accept(value)
            except Rejected as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=5) as pool:
            outcomes = list(pool.map(submit, commands))
        self.assertEqual(outcomes.count("applied"), 1)
        self.assertEqual(outcomes.count("TARGET_BUDGET_BUSY"), 4)

    def test_budget_continuity_across_key_epoch_and_boot(self):
        for index in range(4):
            self.engine.pulse("recovery")
            self.accept(keyEpoch=index + 1, peerKey=f"{index + 1:064x}")
            self.clock.advance(30)
            self.engine.recover()
        self.engine.start()
        self.engine.pulse("recovery")
        with self.assertRaisesRegex(Rejected, "TARGET_CONTINUOUS_BUDGET"):
            self.accept(keyEpoch=10)
        self.assertEqual(len({r["token"] for r in self.store.commands() if r["token"]}), 1)

    def test_unknown_rule_not_deleted_and_no_new_command(self):
        unknown = ident()
        self.firewall.rules[unknown] = {"handle": "alien", "scope": {}}
        self.engine.recover()
        self.assertIn(unknown, self.firewall.rules)
        self.assertTrue(self.engine.snapshot()["recoveryErrors"])
        with self.assertRaisesRegex(Rejected, "RECOVERY_PENDING"):
            self.accept()

    def test_recovery_heartbeat_is_required(self):
        self.clock.advance(2)
        with self.assertRaisesRegex(Rejected, "RECOVERY_PENDING"):
            self.accept()

    def test_empty_rules_do_not_reset_budget_without_health_proof(self):
        p, _ = self.accept()
        self.clock.advance(31)
        self.engine.recover()
        row = self.store.command(p["commandId"])
        proof = {"stableTargetToken": row["token"], "chargedMs": 0, "healthProofSha256": None,
                 "cycleStartedAt": stamp(self.clock.time()), "budgetTargetId": ident()}
        with self.assertRaisesRegex(Rejected, "BUDGET_RECOVERY_UNVERIFIED"):
            self.engine.reset_budget(row["token"], proof)
        self.clock.advance(121)
        proof.update(healthProofSha256="e" * 64, cycleStartedAt=stamp(self.clock.time()))
        self.engine.reset_budget(row["token"], proof)
        self.assertEqual(self.store.get("cycle:" + row["token"]), self.clock.time())

    def test_budget_key_change_cannot_create_new_allowance(self):
        self.accept()
        self.engine.budget_key = b"different-test-only-key-of-32bytes"
        with self.assertRaisesRegex(Rejected, "LEDGER_IDENTITY_CHANGED"):
            self.engine.start()


if __name__ == "__main__":
    unittest.main()
