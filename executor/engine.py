"""先记意图再写规则；恢复进程与控制面失联时仍独立清理本机规则。"""
import hashlib
import hmac
import time
import uuid

from .common import Rejected, canonical, digest, ident, instant, require, stamp
from .contract import BINDING_FIELDS, TERMINAL, authorize, endpoints, scope_hash, validate, verify


class Engine:
    def __init__(self, store, adapter, resolver, config, trust, budget_key, clock=time):
        self.store, self.adapter, self.resolver = store, adapter, resolver
        self.config, self.trust, self.budget_key, self.clock = config, trust, budget_key, clock
        self.identity = {k: config()[k] for k in ("assetId", "executorId", "environment")}
        self.boot = store.get("boot")

    def start(self):
        """进程重启先清理旧规则；旧命令永远不被重新安装或延长。"""
        with self.store.lock():
            identity = dict(self.identity)
            identity["budgetKeySha256"] = hashlib.sha256(self.budget_key).hexdigest()
            old = self.store.get("identity")
            require(old is None or old == identity, "LEDGER_IDENTITY_CHANGED")
            self.store.set("identity", identity)
            self.boot = ident()
            self.store.set("boot", self.boot)
            self.store.set("clock", self.clock.time() - self.clock.monotonic())
            self.store.set("paused", False)
            self._recover(force=True)
            self.store.audit("executor.started", self.boot)
        return self.boot

    def trusted_clock(self):
        anchor = self.store.get("clock")
        return anchor is not None and abs(self.clock.time() - self.clock.monotonic() - anchor) <= 1

    def pulse(self, role):
        self.store.set(role + "Heartbeat", {"at": self.clock.monotonic(), "boot": self.store.get("boot")})

    def healthy_recovery(self):
        heartbeat = self.store.get("recoveryHeartbeat", {})
        return heartbeat.get("boot") == self.boot and 0 <= self.clock.monotonic() - heartbeat.get("at", -100) < 1

    def stable_target(self, payload, scope):
        value = {"assetId": payload["assetId"], "environment": payload["environment"],
                 "peer": scope["peer"], "direction": payload["direction"], "transport": "tcp",
                 "servicePort": scope["port"], "addressFamily": "ipv4"}
        if payload["scope"] == "peer_inbound":
            value["scope"] = "peer_inbound"
        return hmac.new(self.budget_key, canonical(value), hashlib.sha256).hexdigest()

    def target_binding(self, payload, resolved, expires):
        scope, deadline = self._resolve(payload, resolved)
        require(instant(expires) == instant(resolved["expiresAt"]), "TARGET_REFERENCE_REJECTED")
        token = self.stable_target(payload, scope)
        return {"bindingId": ident(), "executorBootId": self.boot, "sensorId": payload["sensorId"],
                "collectorBootId": payload["bootId"], "captureScopeId": payload["captureScopeId"],
                "targetRef": payload["targetRef"], "peerKey": payload["peerKey"],
                "keyEpoch": payload["keyEpoch"], "direction": payload["direction"], "transport": "tcp",
                "scope": payload["scope"], "servicePort": payload["servicePort"], "addressFamily": "ipv4",
                "stableTargetToken": token, "scopeDigest": digest({"stableTargetToken": token}),
                "expiresAt": expires}

    def _resolve(self, payload, resolved):
        require(isinstance(resolved, dict) and set(resolved) == {"endpoints", "expiresAt", "lastPacketAt"},
                "TARGET_REFERENCE_REJECTED")
        now = self.clock.time()
        last, expires = instant(resolved["lastPacketAt"]), instant(resolved["expiresAt"])
        require(last <= now < last + 10 and now < expires <= last + 15, "TARGET_REF_STALE")
        return endpoints(payload, resolved["endpoints"], self.config()), min(expires, last + 10)

    def accept(self, envelope):
        """同键重领只返回账本状态；验签失败不信任命令身份、不生成伪回执。"""
        now = self.clock.time()
        p = verify(envelope, self.trust(), now)
        config = self.config()
        require(p["executorId"] == config["executorId"] and p["assetId"] == config["assetId"], "SCOPE_DENIED")
        try:
            return self._accept(p, {k: envelope[k] for k in ("keyId", "algorithm", "signature")})
        except Rejected as exc:
            # 已认证、归本机且从未落盘的命令可证明未执行；保存拒绝墓碑和可重试回执。
            with self.store.lock():
                if not any(any(r["payload"][k] == p[k] for k in ("commandId", "actionId", "idempotencyKey"))
                           for r in self.store.commands()):
                    row = {"payload": p, "hash": digest(p), "status": "rejected", "scope": None,
                           "token": None, "handle": self.adapter.handle(p["commandId"]), "created": now,
                           "deadline": 0, "installed": False, "clearedAt": now, "error": str(exc)}
                    self.store.save(row)
                    try:
                        actual = self.adapter.inventory()
                    except Exception:
                        # 此命令尚未写入规则；枚举失败仍须保存拒绝回执和暂停证据。
                        self._reconciliation_failed()
                        actual = {}
                    self._receipt(row, actual)
            raise

    def authorize_command(self, payload, config, now):
        """正式入口与回环验收共用同一门禁；全入站只认本机 inboundCapabilities 登记。"""
        authorize(payload, config, self.boot, now)

    def _accept(self, p, signing):
        now, config = self.clock.time(), self.config()
        content_hash = digest(p)
        with self.store.lock():
            for previous in self.store.commands():
                old = previous["payload"]
                if any(old[k] == p[k] for k in ("commandId", "actionId", "idempotencyKey")):
                    require(previous["hash"] == content_hash, "IDEMPOTENCY_CONFLICT")
                    return previous["status"]
            require(not any(r["commandId"] == p["commandId"] or r["actionId"] == p["actionId"]
                            for r in self.store.revocations()), "COMMAND_REVOKED")
            require(self.store.get("boot") == self.boot, "BOOT_ID_MISMATCH")
            require(all(config[k] == v for k, v in self.identity.items()), "LEDGER_IDENTITY_CHANGED")
            require(not self.store.get("paused", True), "RECOVERY_PENDING")
            require(self.trusted_clock(), "CLOCK_UNTRUSTED")
            require(self.healthy_recovery(), "RECOVERY_PENDING")
            self.authorize_command(p, config, now)
            resolved = self.resolver.resolve(p)
            scope, target_deadline = self._resolve(p, resolved)
            token = self.stable_target(p, scope)
            self._budget(p, token, config, now)
            try:
                actual = self.adapter.inventory()
                require(not self._unknown(actual), "STATE_RECONCILIATION_FAILED")
            except Exception as exc:
                self._reconciliation_failed()
                raise Rejected("STATE_RECONCILIATION_FAILED") from exc
            # IPC、枚举可能耗时：在持久化前再次核验租约、配置和恢复器。
            self.authorize_command(p, self.config(), self.clock.time())
            require(self.trusted_clock() and self.healthy_recovery(), "RECOVERY_PENDING")
            row = {"payload": p, "signing": signing, "hash": content_hash, "status": "prepared", "scope": scope,
                   "token": token, "handle": self.adapter.handle(p["commandId"]),
                   "created": now, "deadline": self.clock.monotonic() + instant(p["blockUntil"]) - self.clock.time(),
                   "installed": False, "clearedAt": None, "error": None}
            self.store.save(row)
            self.store.audit("command.prepared", p["commandId"], payloadSha256=content_hash)
            try:
                self.adapter.install(p["commandId"], scope, min(instant(p["applyBy"]), target_deadline))
                actual = self.adapter.inventory()
                require(self._matches(row, actual), "RULE_NOT_VERIFIED")
                row["installed"] = True
                row["status"] = "applied"
                self.store.save(row)
                self._receipt(row, actual)
                if not self.trusted_clock() or self.clock.time() >= instant(p["blockUntil"]) or self.clock.monotonic() >= row["deadline"]:
                    self._recover(force=True)
            except Exception:
                row["status"], row["error"] = "uncertain", "ADAPTER_APPLY_UNCERTAIN"
                self.store.save(row)
                self.store.set("paused", True)
                self.store.audit("command.uncertain", p["commandId"])
                self._recover(force=True)
            return self.store.command(p["commandId"])["status"]

    def _budget(self, p, token, config, now):
        rows = [r for r in self.store.commands() if r["status"] != "rejected"]
        cycle = self.store.get("cycle:" + token, 0)
        revoked = {r["commandId"] for r in self.store.revocations()}
        # 同一预算周期的撤销不能靠更换动作、引用或幂等键绕过；重启也不清除墓碑。
        require(not any(r["token"] == token and r["created"] >= cycle and
                        r["payload"]["commandId"] in revoked for r in rows), "TARGET_REVOKED")
        live = [r for r in rows if r["status"] not in TERMINAL]
        require(not any(r["token"] == token for r in live), "TARGET_BUDGET_BUSY")
        limits = config["limits"]
        require(len(live) < min(10, limits["maxActiveRulesPerAsset"]), "ASSET_CONCURRENT_LIMIT")
        require(sum(r["created"] > now - 60 for r in rows) < min(5, limits["maxNewActionsPerMinute"]),
                "ASSET_RATE_LIMIT")
        intervals = [(r["created"], max(instant(r["payload"]["blockUntil"]), r.get("clearedAt") or 0)) for r in rows
                     if r["token"] == token and r["created"] >= cycle]
        intervals.append((now, instant(p["blockUntil"])))
        merged = []
        for left, right in sorted(intervals):
            if merged and left <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], right)
            else:
                merged.append([left, right])
        require(sum(b - a for a, b in merged) <= min(120, limits["maxContinuousBlockSeconds"]),
                "TARGET_CONTINUOUS_BUDGET")

    def reset_budget(self, token, proof):
        """仅消费认证控制面的零额度证明；本地零规则或等待时间本身不能清零。"""
        with self.store.lock():
            rows = [r for r in self.store.commands() if r["token"] == token]
            require(proof["stableTargetToken"] == token and proof["chargedMs"] == 0 and
                    proof["healthProofSha256"] is not None and rows and
                    all(r["status"] in TERMINAL and r["clearedAt"] is not None for r in rows),
                    "BUDGET_RECOVERY_UNVERIFIED")
            cycle = instant(proof["cycleStartedAt"])
            require(cycle >= max(r["clearedAt"] for r in rows) + 120 and cycle <= self.clock.time(),
                    "BUDGET_RECOVERY_UNVERIFIED")
            actual = self.adapter.inventory()
            require(not self._unknown(actual) and not any(r["payload"]["commandId"] in actual for r in rows),
                    "BUDGET_RECOVERY_UNVERIFIED")
            self.store.set("cycle:" + token, cycle)
            self.store.audit("budget.recovered", proof["budgetTargetId"], proofSha256=digest(proof))

    def revoke(self, value):
        """仅由 HTTPS 领取通道调用；先持久化墓碑，清理不依赖旧授权仍有效。"""
        fields = set("revocationId actionId commandId executorId assetId environment desiredRevision issuedAt reasonCode".split())
        require(isinstance(value, dict) and set(value) == fields, "REVOCATION_INVALID")
        for field in ("revocationId", "actionId", "commandId", "executorId", "assetId"):
            try:
                require(isinstance(value[field], str) and str(uuid.UUID(value[field])) == value[field],
                        "REVOCATION_INVALID")
            except ValueError as exc:
                raise Rejected("REVOCATION_INVALID") from exc
        c = self.config()
        require(all(value[k] == c[k] for k in ("executorId", "assetId", "environment")) and
                type(value["desiredRevision"]) is int and value["desiredRevision"] > 0,
                "SCOPE_DENIED")
        require(instant(value["issuedAt"]) <= self.clock.time(), "INVALID_TIMESTAMP")
        with self.store.lock():
            row = self.store.command(value["commandId"])
            require(row is None or row["payload"]["actionId"] == value["actionId"],
                    "REVOCATION_BINDING_UNKNOWN")
            require(not any(r["payload"]["actionId"] == value["actionId"] and
                            r["payload"]["commandId"] != value["commandId"] for r in self.store.commands()),
                    "REVOCATION_BINDING_UNKNOWN")
            for old in self.store.revocations():
                if old["revocationId"] == value["revocationId"]:
                    require(old == value, "IDEMPOTENCY_CONFLICT")
                if old["actionId"] == value["actionId"]:
                    require(old["commandId"] == value["commandId"], "REVOCATION_BINDING_UNKNOWN")
                    require(value["desiredRevision"] >= old["desiredRevision"], "STALE_REVOCATION")
                if old["commandId"] == value["commandId"]:
                    require(old["actionId"] == value["actionId"], "REVOCATION_BINDING_UNKNOWN")
            # 领取响应可能丢失，撤销因此先于原命令到达；仍须落盘以阻止迟到应用。
            self.store.revoke(value)
            self.store.audit("revocation.persisted", value["revocationId"])
            self._recover()

    def recover(self, force=False):
        with self.store.lock():
            self.boot = self.store.get("boot")
            self._recover(force)

    def control_lost(self):
        """控制面或回执响应丢失时保留原命令身份，暂停新动作并核对清理。

        提前清理仍为 uncertain，预算不得因断连清零；追加回执重试同一 receiptId。
        """
        with self.store.lock():
            self.store.set("paused", True)
            for row in self.store.commands():
                if row["status"] in ("prepared", "applied"):
                    row["status"], row["error"] = "uncertain", "CONTROL_PLANE_UNAVAILABLE"
                    self.store.save(row)
            self.store.audit("control.disconnected", self.boot)
            self._recover(force=True)

    def stop(self):
        """先暂停新动作，再核验清理实态；残留或枚举失败必须让调用者报告失败。"""
        with self.store.lock():
            self.store.set("paused", True)
            self.boot = self.store.get("boot")
            self._recover(force=True)
            snapshot = self._snapshot()
            require(not snapshot["ownedRules"] and not snapshot["recoveryErrors"], "RECOVERY_PENDING")

    def _recover(self, force=False):
        now = self.clock.time()
        if not self.trusted_clock():
            force = True
            self.store.set("paused", True)
        revocations = {r["commandId"]: r for r in self.store.revocations()}
        try:
            actual = self.adapter.inventory()
        except Exception:
            self._reconciliation_failed()
            return
        unknown = self._unknown(actual)
        if unknown:
            self._reconciliation_failed()
        else:
            self.store.set("inventoryError", None)
        for row in self.store.commands():
            p = row["payload"]
            command = p["commandId"]
            if row["status"] in TERMINAL and command not in actual:
                continue
            expired = now >= instant(p["blockUntil"]) or self.clock.monotonic() >= row["deadline"]
            revoked = command in revocations
            invalid = p["executorBootId"] != self.boot or row["status"] != "applied"
            try:
                grant = self.config()["authorization"]
                invalid = invalid or grant["status"] != "active" or grant["id"] != p["authorizationId"] or grant["revision"] != p["authorizationRevision"] or now >= instant(grant["validUntil"])
                verify({"payload": p, **row["signing"]}, self.trust(), now)
            except Exception:
                invalid = True
            if not (force or expired or revoked or invalid):
                if not self._matches(row, actual):
                    row["status"], row["error"] = "uncertain", "RULE_STATE_CHANGED"
                    self.store.save(row)
                    self.store.set("paused", True)
                else:
                    self._receipt(row, actual)
                continue
            try:
                # 句柄由 commandId 确定，范围须与本地落盘意图一致；未知规则绝不代删。
                if command in actual:
                    require(self._matches(row, actual), "RULE_OWNERSHIP_UNVERIFIED")
                    # 已清理规则重现时，旧清零时刻不能继续作为预算恢复证据。
                    row["clearedAt"] = None
                    row.pop("clearedDigest", None)
                    self.store.set("clearance:" + command, False)
                    self.adapter.remove(command, row["scope"])
                actual = self.adapter.inventory()
                require(command not in actual, "RULE_CLEANUP_UNVERIFIED")
                if row["clearedAt"] is None:
                    row["clearedAt"] = self.clock.time()
                    row["clearedDigest"] = self.snapshot(actual)["stateDigest"]
                row["status"] = "revoked" if revoked else "expired" if expired else "uncertain"
                row["error"] = None if row["status"] in TERMINAL else "EARLY_RECOVERY_REQUIRES_RECONCILIATION"
                if row["status"] == "uncertain":
                    self.store.set("paused", True)
            except Exception:
                row["status"], row["error"] = "recovery_failed", "RULE_CLEANUP_UNVERIFIED"
                self.store.set("paused", True)
            self.store.save(row)
            self._receipt(row, actual, revocations.get(command))

    def _matches(self, row, actual):
        rule = actual.get(row["payload"]["commandId"])
        return rule is not None and rule["scope"] == row["scope"] and rule["handle"] == row["handle"]

    def _unknown(self, actual):
        known = {r["payload"]["commandId"]: r for r in self.store.commands()}
        return any(key not in known or not self._matches(known[key], actual) for key in actual)

    def _reconciliation_failed(self):
        """归属或枚举无法证明时持久暂停并追加脱敏证据，绝不删除未知规则。"""
        self.store.set("paused", True)
        if self.store.get("inventoryError") != "STATE_RECONCILIATION_FAILED":
            self.store.audit("state.reconciliation_failed", self.boot,
                             errorCode="STATE_RECONCILIATION_FAILED")
        self.store.set("inventoryError", "STATE_RECONCILIATION_FAILED")

    def snapshot(self, actual=None):
        """跨进程锁内枚举和读取账本，避免恢复与上报交错形成虚假的空规则摘要。"""
        if actual is not None:
            return self._snapshot(actual)
        with self.store.lock():
            return self._snapshot()

    def _snapshot(self, actual=None):
        errors = []
        if actual is None:
            try:
                actual = self.adapter.inventory()
            except Exception:
                actual = {}
                errors.append("RULE_ENUMERATION_FAILED")
                self._reconciliation_failed()
        if self._unknown(actual):
            errors.append("UNKNOWN_OWNED_RULE")
            self._reconciliation_failed()
        if self.store.get("inventoryError"):
            errors.append(self.store.get("inventoryError"))
        rules = []
        for row in self.store.commands():
            if self._matches(row, actual):
                p = row["payload"]
                rules.append({"actionId": p["actionId"], "commandId": p["commandId"],
                              "ruleHandle": row["handle"], "effectiveBlockUntil": p["blockUntil"],
                              "normalizedScopeSha256": scope_hash(p)})
            if row["status"] == "recovery_failed":
                errors.append("RULE_CLEANUP_UNVERIFIED")
        pending = []
        for r in self.store.revocations():
            row = self.store.command(r["commandId"])
            if row is None or row["status"] not in TERMINAL:
                pending.append({k: r[k] for k in ("revocationId", "actionId", "desiredRevision")})
        rules.sort(key=lambda r: r["ruleHandle"])
        pending.sort(key=lambda r: r["revocationId"])
        c = self.identity
        state = {"digestVersion": "guard-state/1", "assetId": c["assetId"], "executorId": c["executorId"],
                 "executorBootId": self.store.get("boot"), "rules": rules, "pendingRevocations": pending}
        return {"executorBootId": state["executorBootId"], "observedAt": stamp(self.clock.time()),
                "digestVersion": "guard-state/1", "stateDigest": digest(state), "ownedRules": rules,
                "pendingRevocations": pending, "recoveryErrors": sorted(set(errors))}

    def clearance_proofs(self):
        """清零证明保持原始时间与空规则摘要；断连补报不把重连时间伪装成清理时刻。"""
        return [{"commandId": r["payload"]["commandId"], "clearedAt": stamp(r["clearedAt"]),
                 "stateDigest": r["clearedDigest"]} for r in self.store.commands()
                if r["token"] and r["clearedAt"] is not None and r.get("clearedDigest")]

    def _receipt(self, row, actual, revocation=None):
        snap = self.snapshot(actual)
        p = row["payload"]
        receipt = {"contractVersion": "host-guard/5.0.0-rc.2", "receiptId": ident(), "commandId": p["commandId"],
                   "executorId": p["executorId"], "status": row["status"], "observedAt": snap["observedAt"],
                   "ruleHandle": row["handle"] if p["commandId"] in actual else None,
                   "effectiveBlockUntil": p["blockUntil"] if row["status"] == "applied" else None,
                   "errorCode": row["error"], "stateDigest": snap["stateDigest"],
                   "revocationId": revocation["revocationId"] if revocation else None}
        validate("action-receipt", receipt)
        fingerprint = digest({k: v for k, v in receipt.items() if k not in ("receiptId", "observedAt")})
        if row.get("receiptFingerprint") != fingerprint:
            self.store.queue("receipts", receipt["receiptId"], receipt)
            row["receiptFingerprint"] = fingerprint
            self.store.save(row)
            self.store.audit("command." + row["status"], p["commandId"], stateDigest=snap["stateDigest"])
