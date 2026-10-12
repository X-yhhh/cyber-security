"""K9 E3 引导克隆编排器的前置门禁与报告上下文；不连接数据库、不启动进程。"""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from executor.common import digest
from scripts.p5 import e3_bootstrap as k9

BUNDLE = "c313b44e-e835-441a-9e50-ada7e92fdf0a"


class Db:
    """只回答 bundle_facts 的两条查询；任何写语句都会失败。"""
    def __init__(self, status="candidate", finals=None, subject=None):
        self.subject = subject or {"environment": "lab", "x": 1}
        self.bundle = {"bundleId": BUNDLE, "status": status, "environment": "lab", "subjectSha256": digest(self.subject),
                       "subject": self.subject, "revision": 3}
        self.finals = [{"id": "f", "status": "passed", "runner": "r", "evidenceKind": None}] if finals is None else finals
        self.queries = []

    def query(self, sql, schema=None):
        self.queries.append((sql, schema))
        assert sql.lstrip().upper().startswith("SELECT"), sql
        if "guard_evaluation_run" in sql:
            return "\n".join(json.dumps(f) for f in self.finals).encode()
        return json.dumps(self.bundle).encode()


def args(**kw):
    value = dict(mode="rehearse", source_schema="cyber_guard_k9s1_abc", bundle_id=BUNDLE, authorization_reference=None)
    value.update(kw)
    return SimpleNamespace(**value)


class E3BootstrapTest(unittest.TestCase):
    def test_rehearse_requires_isolated_source_and_candidate(self):
        db = Db()
        a = args(subject_sha256=db.bundle["subjectSha256"])
        facts, source = k9.preflight(a, db)
        self.assertEqual(source, {"bundleId": BUNDLE, "subjectSha256": db.bundle["subjectSha256"]})
        with self.assertRaisesRegex(Exception, "K9_REHEARSE_SOURCE_INVALID"):
            k9.preflight(args(source_schema="cyber_security", subject_sha256=db.bundle["subjectSha256"]), db)
        with self.assertRaisesRegex(Exception, "K9_R4_NOT_CANDIDATE"):
            k9.preflight(a, Db(status="approved"))
        with self.assertRaisesRegex(Exception, "K9_R4_SUBJECT_MISMATCH"):
            k9.preflight(args(subject_sha256="0" * 64), db)
        with self.assertRaisesRegex(Exception, "K9_R4_FINAL_MISSING"):
            k9.preflight(a, Db(finals=[]))

    def test_pf_requires_business_source_authorization_and_formal_final(self):
        db = Db()
        sha = db.bundle["subjectSha256"]
        with self.assertRaisesRegex(Exception, "K9_PF_SOURCE_MUST_BE_BUSINESS_DB"):
            k9.preflight(args(mode="pf", authorization_reference="A6-1", subject_sha256=sha), db)
        with self.assertRaisesRegex(Exception, "K9_PF_AUTHORIZATION_REQUIRED"):
            k9.preflight(args(mode="pf", source_schema="cyber_security", subject_sha256=sha), db)
        synthetic = Db(finals=[{"id": "f", "status": "passed", "runner": "r", "evidenceKind": "synthetic"}])
        with self.assertRaisesRegex(Exception, "K9_R4_FINAL_NOT_FORMAL"):
            k9.preflight(args(mode="pf", source_schema="cyber_security", authorization_reference="A6-1", subject_sha256=sha), synthetic)
        _, source = k9.preflight(args(mode="pf", source_schema="cyber_security", authorization_reference="A6-1", subject_sha256=sha), db)
        self.assertEqual(source["bundleId"], BUNDLE)

    def test_refusal_happens_before_any_directory_or_clone(self):
        with tempfile.TemporaryDirectory() as root:
            a = SimpleNamespace(mode="pf", source_schema="cyber_security", bundle_id=BUNDLE, authorization_reference=None,
                                subject_sha256="0" * 64, directory=Path(root) / "attempts", artifacts=Path(root) / "artifacts",
                                mysql_service=Path(root))
            db = Db()
            with patch.object(k9.j1_run, "Database", return_value=db), \
                 patch.object(k9.subprocess, "run", side_effect=AssertionError("unexpected process")):
                with self.assertRaisesRegex(Exception, "K9_PF_AUTHORIZATION_REQUIRED"):
                    k9.run(a)
            self.assertFalse((Path(root) / "attempts").exists())
            self.assertFalse((Path(root) / "artifacts").exists())
            self.assertEqual(db.queries, [])

    def test_attempt_numbers_never_reuse_failed_directories(self):
        with tempfile.TemporaryDirectory() as root:
            first = k9.next_attempt(Path(root))
            (Path(root) / "attempt-07").mkdir()
            self.assertEqual(first.name, "attempt-01")
            self.assertEqual(k9.next_attempt(Path(root)).name, "attempt-08")


if __name__ == "__main__":
    unittest.main()
