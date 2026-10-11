"""策略原文修复：只接受摘要一致且仅有 1 ULP 末位差的行；全部为合成数据，不连接数据库。"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import rfc8785

import policy_text


class PolicyTextTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original = {"alertThreshold": 0.9997792434692383, "rules": [{"threshold": 21}], "profile": "flow-prefix-v1"}
        self.raw = rfc8785.dumps(self.original)
        self.path = Path(self.temp.name) / "policy.json"
        self.path.write_bytes(self.raw)
        self.digest = hashlib.sha256(self.raw).hexdigest()

    def database(self, stored):
        state = {"text": stored, "updates": 0}

        def query(sql, schema):
            if sql.startswith("SELECT id,definition_sha256"):
                return f"1\t{self.digest}\t{state['text'].hex().upper()}\n".encode()
            if sql.startswith("UPDATE"):
                state["text"] = bytes.fromhex(sql.split("X'")[1].split("'")[0])
                state["updates"] += 1
                return b""
            return state["text"].hex().upper().encode() + b"\n"
        return state, query

    def test_restores_one_ulp_drift_and_keeps_exact_rows(self):
        drifted = json.dumps({**self.original, "alertThreshold": 0.9997792434692384}, separators=(",", ":")).encode()
        state, query = self.database(drifted)
        self.assertEqual(policy_text.restore(query, "s", [self.path])[0]["status"], "restored")
        self.assertEqual(state["text"], self.raw)
        self.assertEqual(policy_text.restore(query, "s", [self.path])[0]["status"], "exact")
        self.assertEqual(state["updates"], 1)

    def test_rejects_semantic_difference(self):
        changed = json.dumps({**self.original, "alertThreshold": 0.99}, separators=(",", ":")).encode()
        state, query = self.database(changed)
        self.assertEqual(policy_text.restore(query, "s", [self.path])[0]["status"], "rejected_semantic_difference")
        self.assertEqual(state["updates"], 0)


if __name__ == "__main__":
    unittest.main()
