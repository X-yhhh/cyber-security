"""PF 会话安全清理的故障测试；所有系统操作均替身，不请求权限、不操作 PF。"""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from executor.common import Rejected, parse, write_new
from executor.pf_lab import DEFAULT_ROOT, USER_ANCHOR
import pf_session


class SessionCleanupTest(unittest.TestCase):
    def setUp(self):
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.directory = Path(self.resources.enter_context(tempfile.TemporaryDirectory()))
        self.root, self.alias, self.enabled = DEFAULT_ROOT, False, False
        self.calls = []
        self.fail_release = False
        self.executor_id = "00000000-0000-4000-8000-000000000001"
        self.resources.enter_context(patch.object(pf_session.sys, "platform", "darwin"))
        self.resources.enter_context(patch.object(pf_session.os, "geteuid", return_value=0))
        self.resources.enter_context(patch.object(pf_session, "read_rules", side_effect=self.rules))
        self.resources.enter_context(patch.object(pf_session, "command", side_effect=self.command))

    def rules(self, anchor=None):
        if anchor is None:
            return self.root
        if anchor == "com.apple/*":
            return b"apple-original\n"
        if anchor == USER_ANCHOR:
            return b""
        return b""

    def command(self, args, data=None, *, binary=False):
        self.calls.append(args)
        if args[0] == "/usr/bin/clang":
            write_new(Path(args[-1]), b"mock-helper")
        elif args[-1] == "--abi":
            return '{"kernelMatches":true}', ""
        elif args[0] == "/sbin/ifconfig":
            if "-alias" in args:
                self.alias = False
            elif "alias" in args:
                self.alias = True
            else:
                return "inet 127.0.0.2 " if self.alias else "inet 127.0.0.1 ", ""
        elif args[1:] == ["-s", "info"]:
            return "Status: Enabled" if self.enabled else "Status: Disabled", ""
        elif args[1] == "-R":
            self.root = data
        elif args[1] == "-E":
            self.enabled = True
            return "", "Token : 123"
        elif args[1] == "-X":
            if self.fail_release:
                raise Rejected("LAB_SYSTEM_COMMAND_FAILED")
            self.enabled = False
        return (b"", b"") if binary else ("", "")

    def facts(self):
        return parse((self.directory / "pf-session.json").read_bytes())

    def test_success_releases_only_own_token_and_alias(self):
        with pf_session.session(self.directory, self.executor_id, "A4-test") as (_, check, facts):
            check()
        self.assertTrue(facts["passed"])
        self.assertEqual(self.root, DEFAULT_ROOT)
        self.assertFalse(self.alias or self.enabled)
        self.assertIn(["/sbin/pfctl", "-X", "123"], self.calls)
        self.assertFalse(any("-d" in call or "-F" in call for call in self.calls))

    def test_utun_session_never_adds_loopback_alias(self):
        with pf_session.session(self.directory, self.executor_id, "demo-test", loopback_alias=False) as (_, check, facts):
            check()
        self.assertTrue(facts["passed"])
        self.assertFalse(any("alias" in call or "-alias" in call for call in self.calls))
        self.assertFalse(self.alias or self.enabled)

    def test_body_failure_still_restores_all_owned_changes(self):
        with self.assertRaises(Rejected):
            with pf_session.session(self.directory, self.executor_id, "A4-test"):
                raise Rejected("INJECTED_FAILURE")
        self.assertFalse(self.facts()["passed"])
        self.assertTrue(all(self.facts()["cleanup"].values()))
        self.assertEqual(self.root, DEFAULT_ROOT)
        self.assertFalse(self.alias or self.enabled)

    def test_external_root_change_is_preserved_and_other_cleanup_continues(self):
        external = b"externally-modified-rule\n"
        with self.assertRaises(Rejected):
            with pf_session.session(self.directory, self.executor_id, "A4-test"):
                self.root = external
        self.assertEqual(self.root, external)
        cleanup = self.facts()["cleanup"]
        self.assertFalse(cleanup["rootRestored"])
        self.assertTrue(cleanup["tokenReleased"] and cleanup["aliasRemoved"])

    def test_token_release_failure_does_not_skip_alias_cleanup(self):
        with self.assertRaises(Rejected):
            with pf_session.session(self.directory, self.executor_id, "A4-test"):
                self.fail_release = True
        self.assertEqual(self.root, DEFAULT_ROOT)
        self.assertFalse(self.alias)
        self.assertTrue(self.enabled)
        cleanup = self.facts()["cleanup"]
        self.assertFalse(cleanup["tokenReleased"])
        self.assertTrue(cleanup["aliasRemoved"])

    def test_unknown_initial_root_rejects_before_any_mutation(self):
        self.root = b"unknown-root\n"
        with self.assertRaisesRegex(Rejected, "LAB_UNEXPECTED_ROOT_RULES"):
            with pf_session.session(self.directory, self.executor_id, "A4-test"):
                self.fail("must not enter")
        self.assertEqual(self.calls, [["/sbin/pfctl", "-s", "info"]])

    def test_missing_authorization_rejects_without_system_calls(self):
        with self.assertRaisesRegex(Rejected, "A4_ROOT_AND_AUTHORIZATION_REQUIRED"):
            with pf_session.session(self.directory, self.executor_id, None):
                self.fail("must not enter")
        self.assertEqual(self.calls, [])


class OwnedRulesTest(unittest.TestCase):
    def test_empty_retained_child_anchors_are_not_rules(self):
        empty = b'anchor "64f3f61b-73ff-48d5-aead-3ec10be523ee" all {\n}\n'
        self.assertFalse(pf_session.owned_rules_remain(b""))
        self.assertFalse(pf_session.owned_rules_remain(empty * 2))
        rule = b'anchor "64f3f61b-73ff-48d5-aead-3ec10be523ee" all {\n  block drop quick on lo0 inet proto tcp from 127.0.0.2 to 127.0.0.1\n}\n'
        self.assertTrue(pf_session.owned_rules_remain(rule))
        self.assertTrue(pf_session.owned_rules_remain(b'anchor "other" all {\n}\n'))
        self.assertTrue(pf_session.owned_rules_remain(b'block drop all\n'))


if __name__ == "__main__":
    unittest.main()
