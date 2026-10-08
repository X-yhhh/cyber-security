"""P5 必需行为回归：故障注入使用规则替身，不宣称 OS 生效或恢复验收。"""
import base64
import copy
import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .common import Rejected, canonical, digest, ident, instant, parse, public_der, stamp
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
        self.max_rules = 0

    def handle(self, command): return "fixture:" + command

    def install(self, command, scope, apply_by=None):
        self.rules[command] = {"handle": self.handle(command), "scope": copy.deepcopy(scope)}
        self.installs += 1
        self.max_rules = max(self.max_rules, len(self.rules))
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

    def keep_recovery_alive(self):
        """真实 TLS 测试持续提供恢复器存活旁证；不放宽正式的一秒心跳门禁。"""
        stop = threading.Event()
        self.engine.pulse("recovery")
        def heartbeat():
            while not stop.wait(.1):
                self.engine.pulse("recovery")
        thread = threading.Thread(target=heartbeat, daemon=True)
        thread.start()
        self.addCleanup(lambda: (stop.set(), thread.join(2)))

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

    def test_e4_signing_key_and_policy_rotation_keep_budget_and_tombstone(self):
        """真实换签名密钥/策略哈希仍绑定同一稳定目标，不产生新的 120 秒额度。"""
        tokens = set()
        for index in range(4):
            key = Ed25519PrivateKey.generate()
            key_id = "rotated-" + str(index)
            self.trust[key_id] = {"status": "active", "notBefore": stamp(self.clock.time() - 1),
                "notAfter": stamp(self.clock.time() + 1000), "publicKeyDer": public_der(key.public_key())}
            policy = digest({"policyVersion": index})
            self.config["policyHashes"].append(policy)
            p = self.payload(keyEpoch=index + 1, policySha256=policy)
            signed = {"payload": p, "keyId": key_id, "algorithm": "Ed25519",
                "signature": base64.urlsafe_b64encode(key.sign(canonical(p))).rstrip(b"=").decode()}
            self.engine.pulse("recovery")
            self.assertEqual(self.engine.accept(signed), "applied")
            tokens.add(self.store.command(p["commandId"])["token"])
            self.clock.advance(30)
            self.engine.recover()
        self.assertEqual(len(tokens), 1)
        self.engine.pulse("recovery")
        fresh = copy.deepcopy(p)
        fresh.update(commandId=ident(), actionId=ident(), targetRef=ident(), idempotencyKey=ident(),
                     issuedAt=stamp(self.clock.time()), applyBy=stamp(self.clock.time() + 5),
                     blockUntil=stamp(self.clock.time() + 30), leaseExpiresAt=stamp(self.clock.time() + 30))
        signed["payload"] = fresh
        signed["signature"] = base64.urlsafe_b64encode(key.sign(canonical(fresh))).rstrip(b"=").decode()
        with self.assertRaisesRegex(Rejected, "TARGET_CONTINUOUS_BUDGET"):
            self.engine.accept(signed)
        self.engine.revoke(self.revocation(p))
        fresh.update(commandId=ident(), actionId=ident(), idempotencyKey=ident())
        signed["signature"] = base64.urlsafe_b64encode(key.sign(canonical(fresh))).rstrip(b"=").decode()
        with self.assertRaisesRegex(Rejected, "TARGET_REVOKED"):
            self.engine.accept(signed)
        self.assertEqual(self.firewall.installs, 4)

    def test_unknown_rule_not_deleted_and_no_new_command(self):
        unknown = ident()
        self.firewall.rules[unknown] = {"handle": "alien", "scope": {}}
        self.engine.recover()
        self.assertIn(unknown, self.firewall.rules)
        self.assertIn("STATE_RECONCILIATION_FAILED", self.engine.snapshot()["recoveryErrors"])
        self.assertTrue(self.store.get("paused"))
        with self.assertRaisesRegex(Rejected, "RECOVERY_PENDING"):
            self.accept()

    def test_unknown_rule_on_accept_or_snapshot_pauses_without_deletion(self):
        for entry in ("accept", "snapshot"):
            with self.subTest(entry=entry):
                self.store.set("paused", False)
                unknown = ident()
                self.firewall.rules[unknown] = {"handle": "alien", "scope": {}}
                before = self.firewall.inventory()
                if entry == "accept":
                    p = self.payload()
                    with self.assertRaisesRegex(Rejected, "STATE_RECONCILIATION_FAILED"):
                        self.engine.accept(self.signed(p))
                    self.assertEqual(self.store.command(p["commandId"])["error"], "STATE_RECONCILIATION_FAILED")
                else:
                    self.assertIn("STATE_RECONCILIATION_FAILED", self.engine.snapshot()["recoveryErrors"])
                self.assertTrue(self.store.get("paused"))
                self.assertEqual(before, self.firewall.inventory())
                self.assertEqual(self.firewall.installs, 0)

    def test_inventory_failure_on_accept_keeps_rejection_and_pause(self):
        p = self.payload()
        with patch.object(self.firewall, "inventory", side_effect=Rejected("UNKNOWN_OWNED_RULE")):
            with self.assertRaisesRegex(Rejected, "STATE_RECONCILIATION_FAILED"):
                self.engine.accept(self.signed(p))
            self.assertIn("STATE_RECONCILIATION_FAILED", self.engine.snapshot()["recoveryErrors"])
        self.assertEqual(self.store.command(p["commandId"])["status"], "rejected")
        self.assertTrue(self.store.get("paused"))
        self.assertEqual(self.firewall.installs, 0)

    def test_recovery_heartbeat_is_required(self):
        self.clock.advance(2)
        with self.assertRaisesRegex(Rejected, "RECOVERY_PENDING"):
            self.accept()

    def test_control_loss_preserves_budget_and_blocks_reissue_until_reconciled(self):
        p, _ = self.accept()
        before = self.store.command(p["commandId"])
        self.engine.control_lost()
        row = self.store.command(p["commandId"])
        self.assertEqual(row["status"], "uncertain")
        self.assertEqual(row["deadline"], before["deadline"])
        self.assertEqual(row["token"], before["token"])
        self.assertIsNotNone(row["clearedAt"])
        self.assertFalse(self.firewall.rules)
        self.assertEqual(self.engine.accept(self.signed(p)), "uncertain")
        with self.assertRaisesRegex(Rejected, "RECOVERY_PENDING"):
            self.accept()
        self.assertEqual(self.firewall.installs, 1)
        self.clock.advance(31)
        self.engine.recover()
        self.assertEqual(self.store.command(p["commandId"])["status"], "expired")
        self.assertTrue(self.store.get("paused"))

    def test_control_loss_cleanup_failure_remains_visible(self):
        p, _ = self.accept()
        self.firewall.fail_remove = True
        self.engine.control_lost()
        self.assertEqual(self.store.command(p["commandId"])["status"], "recovery_failed")
        self.assertTrue(self.engine.snapshot()["recoveryErrors"])
        self.assertTrue(self.store.get("paused"))
        self.firewall.fail_remove = False
        self.engine.recover()
        self.assertFalse(self.firewall.rules)

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

    def test_revoked_target_requires_budget_recovery_proof_before_new_cycle(self):
        p, _ = self.accept()
        self.engine.revoke(self.revocation(p))
        row = self.store.command(p["commandId"])
        self.clock.advance(121)
        self.engine.pulse("recovery")
        with self.assertRaisesRegex(Rejected, "TARGET_REVOKED"):
            self.accept(keyEpoch=2)
        proof = {"stableTargetToken": row["token"], "chargedMs": 0, "healthProofSha256": None,
                 "cycleStartedAt": stamp(self.clock.time()), "budgetTargetId": ident()}
        with self.assertRaisesRegex(Rejected, "BUDGET_RECOVERY_UNVERIFIED"):
            self.engine.reset_budget(row["token"], proof)
        proof["healthProofSha256"] = "e" * 64
        self.engine.reset_budget(row["token"], proof)
        new, status = self.accept(keyEpoch=2)
        self.assertEqual(status, "applied")
        self.assertEqual(self.store.command(new["commandId"])["token"], row["token"])
        self.assertEqual(self.store.command(p["commandId"]), row)
        self.assertEqual(self.engine.accept(self.signed(p)), "revoked")
        self.assertEqual(len(self.firewall.rules), 1)


class RenewalCases:
    """E2 五组组合复用于普通执行器和全入站 canary；时钟、规则均为替身。

    检查点核对物理规则数、不可变租约/单调截止、已预留动作数及累计秒数。
    撤销只释放活动槽，不冲销累计预算；续封必须是新动作。
    """

    def renewal_payload(self, **changes):
        return self.fixture.payload(**changes)

    def assert_budget(self, rules, actions, seconds):
        f = self.fixture
        rows = [r for r in f.store.commands() if r["token"] is not None]
        self.assertEqual(len(f.firewall.inventory()), rules)
        self.assertEqual(len(rows), actions)
        self.assertEqual(sum(instant(r["payload"]["blockUntil"]) - r["created"] for r in rows), seconds)
        self.assertEqual(len([r for r in rows if r["status"] not in ("revoked", "expired", "rejected")]), rules)
        with f.store.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE event='command.prepared'").fetchone()[0], actions)
        previous = getattr(self, "budget_checkpoint", (0, 0, {}))
        self.assertGreaterEqual(actions, previous[0])
        self.assertGreaterEqual(seconds, previous[1])
        deadlines = {}
        for row in rows:
            p = row["payload"]
            self.assertLessEqual(instant(p["blockUntil"]), instant(p["leaseExpiresAt"]))
            self.assertLessEqual(row["deadline"], f.clock.monotonic() + instant(p["leaseExpiresAt"]) - f.clock.time())
            value = (row["deadline"], p["blockUntil"], p["leaseExpiresAt"])
            if p["commandId"] in previous[2]:
                self.assertEqual(value, previous[2][p["commandId"]])
            deadlines[p["commandId"]] = value
        self.budget_checkpoint = actions, seconds, deadlines

    def submit(self, p):
        try:
            return self.engine.accept(self.fixture.signed(p))
        except Rejected as exc:
            return str(exc)

    def parallel(self, *operations):
        gate = threading.Barrier(len(operations))
        def invoke(operation):
            gate.wait(timeout=5)
            return operation()
        with ThreadPoolExecutor(max_workers=len(operations)) as pool:
            return list(pool.map(invoke, operations))

    def test_e2_simultaneous_revoke_and_renewal(self):
        f = self.fixture
        p = self.renewal_payload()
        self.assertEqual(self.submit(p), "applied")
        self.assert_budget(1, 1, 30)
        renewal = self.renewal_payload()
        outcomes = self.parallel(lambda: self.engine.revoke(f.revocation(p)), lambda: self.submit(renewal))
        self.assertIsNone(outcomes[0])
        self.assertIn(outcomes[1], ("TARGET_BUDGET_BUSY", "TARGET_REVOKED"))
        self.assertEqual(f.store.command(p["commandId"])["status"], "revoked")
        self.assertEqual(self.submit(self.renewal_payload()), "TARGET_REVOKED")
        self.assert_budget(0, 1, 30)
        self.assertEqual(f.firewall.max_rules, 1)
        self.assertEqual(f.firewall.installs, 1)

    def test_e2_revoke_before_renewal_survives_restart(self):
        f = self.fixture
        p = self.renewal_payload()
        self.assertEqual(self.submit(p), "applied")
        self.assert_budget(1, 1, 30)
        self.engine.revoke(f.revocation(p))
        self.assert_budget(0, 1, 30)
        for restart in (False, True):
            if restart:
                self.engine.start()
                f.engine.boot = self.engine.boot
                self.engine.pulse("recovery")
            self.assertEqual(self.submit(self.renewal_payload(keyEpoch=2, peerKey="d" * 64)), "TARGET_REVOKED")
            self.assert_budget(0, 1, 30)
        self.assertEqual(f.firewall.installs, 1)

    def test_e2_duplicate_renewal_charged_once_without_extension(self):
        f = self.fixture
        first = self.renewal_payload()
        self.assertEqual(self.submit(first), "applied")
        self.assert_budget(1, 1, 30)
        f.clock.advance(30)
        self.engine.recover()
        self.assert_budget(0, 1, 30)
        self.engine.pulse("recovery")
        renewal = self.renewal_payload()
        self.assertEqual(self.parallel(lambda: self.submit(renewal), lambda: self.submit(renewal)), ["applied"] * 2)
        self.assert_budget(1, 2, 60)
        f.clock.advance(3)
        self.assertEqual(self.submit(renewal), "applied")
        self.assertEqual(self.submit({**renewal, "blockUntil": stamp(f.clock.time() + 30)}), "IDEMPOTENCY_CONFLICT")
        self.assert_budget(1, 2, 60)
        f.clock.advance(27)
        self.engine.recover()
        self.assert_budget(0, 2, 60)
        self.assertEqual(f.firewall.installs, 2)
        self.assertEqual(f.firewall.max_rules, 1)

    def test_e2_over_budget_renewal_keeps_original_deadline(self):
        f = self.fixture
        f.config["limits"]["maxContinuousBlockSeconds"] = 45
        p = self.renewal_payload()
        self.assertEqual(self.submit(p), "applied")
        self.assert_budget(1, 1, 30)
        f.clock.advance(2)
        self.engine.pulse("recovery")
        self.assertEqual(self.submit(self.renewal_payload()), "TARGET_BUDGET_BUSY")
        self.assert_budget(1, 1, 30)
        f.clock.advance(28)
        self.engine.recover()
        self.assertEqual(f.store.command(p["commandId"])["clearedAt"], instant(p["blockUntil"]))
        self.assert_budget(0, 1, 30)
        self.engine.pulse("recovery")
        self.assertEqual(self.submit(self.renewal_payload()), "TARGET_CONTINUOUS_BUDGET")
        self.assert_budget(0, 1, 30)
        self.assertEqual(f.firewall.installs, 1)

    def other_target(self):
        self.fixture.resolver.result["Peer"] = "192.0.2.3:55002"
        return self.renewal_payload()

    def test_e2_different_targets_concurrent_revocation(self):
        f = self.fixture
        f.config["limits"]["maxActiveRulesPerAsset"] = 2
        first = self.renewal_payload()
        self.assertEqual(self.submit(first), "applied")
        self.assert_budget(1, 1, 30)
        second = self.other_target()
        self.assertEqual(self.submit(second), "applied")
        self.assertNotEqual(f.store.command(first["commandId"])["token"], f.store.command(second["commandId"])["token"])
        self.assert_budget(2, 2, 60)
        self.parallel(lambda: self.engine.revoke(f.revocation(first)), lambda: self.engine.revoke(f.revocation(second)))
        self.assert_budget(0, 2, 60)
        for p in (first, second):
            self.assertEqual(f.store.command(p["commandId"])["status"], "revoked")
            self.assertEqual(self.submit(p), "revoked")
        self.assert_budget(0, 2, 60)
        self.assertEqual(f.firewall.max_rules, 2)


class RenewalEngineTest(RenewalCases, unittest.TestCase):
    def setUp(self):
        self.fixture = EngineTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.engine = self.fixture.engine


if __name__ == "__main__":
    unittest.main()
