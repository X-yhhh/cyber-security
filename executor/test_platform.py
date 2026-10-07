"""PF 全入站区间与枚举的离线回归；不操作系统防火墙。"""
import uuid
import unittest
from pathlib import Path
import subprocess
import sys
import time

from .common import Rejected
from .contract import unprotected_ranges
from .pf_canary import canary_scope
from .platform import PF, inbound_ranges


class PlatformTest(unittest.TestCase):
    def test_protected_ports_are_excluded_and_ranges_cover_every_other_port(self):
        ranges = unprotected_ranges([443, 53, 443, 65535])
        scope = {"port": None, "ranges": ranges}
        self.assertEqual(inbound_ranges(scope), ranges)
        covered = {port for first, last in ranges for port in range(first, last + 1)}
        self.assertEqual(covered, set(range(1, 65536)) - {22, 53, 443, 3389, 65535})
        for altered in ([[1, 30], [31, 65535]], [[1, 21], [21, 65535]], [[1, 21]],
                        [[1, 21], [23, 53], [54, 65535]],
                        [[1, 21], [23, 52], [54, 3388], [3390, 9999], [10130, 65535]]):
            with self.subTest(altered=altered), self.assertRaises(Rejected):
                inbound_ranges({"port": None, "ranges": altered})
        self.assertEqual(inbound_ranges({"port": None, "ranges": unprotected_ranges([1, 23, 65535])}),
                         unprotected_ranges([1, 23, 65535]))

    def test_inbound_canary_requires_protected_control_port(self):
        config = {"platform": "pf", "environment": "lab", "interface": "lo0",
                  "localAddresses": ["127.0.0.1"], "peerAddresses": ["127.0.0.2"],
                  "servicePorts": [55001], "protectedServicePorts": [22, 53, 3389, 55002]}
        port, scope = canary_scope(config, "peer_inbound")
        self.assertEqual(port, 55001)
        self.assertFalse(any(first <= 55002 <= last for first, last in scope["ranges"]))
        self.assertTrue(any(first <= 55001 <= last for first, last in scope["ranges"]))
        for change in ({"protectedServicePorts": [22, 53, 3389]},
                       {"servicePorts": [55002]}, {"interface": "en0"},
                       {"peerAddresses": ["192.0.2.2"]}):
            with self.subTest(change=change), self.assertRaisesRegex(Rejected, "CANARY_SCOPE_REQUIRED"):
                canary_scope({**config, **change}, "peer_inbound")

    def test_inventory_reconstructs_inbound_scope_and_rejects_foreign_rule(self):
        command = str(uuid.uuid4())
        ranges = unprotected_ranges([443])
        lines = [f'block drop quick on lo0 inet proto tcp from 127.0.0.2 to 127.0.0.1 '
                 f'port {first}:{last} label "hg5-{command}"' for first, last in ranges]
        pf = object.__new__(PF)
        pf.root = PF.anchor_root(str(uuid.uuid4()))
        pf.run = lambda args: command if args[-1] == "Anchors" else "\n".join(lines)
        scope = pf.inventory()[command]["scope"]
        self.assertEqual(scope, {"local": "127.0.0.1", "peer": "127.0.0.2", "interface": "lo0",
                                 "port": None, "ranges": ranges})
        original = lines[0]
        lines[0] = lines[0].replace("127.0.0.2", "127.0.0.3")
        with self.assertRaisesRegex(Rejected, "UNKNOWN_OWNED_RULE"):
            pf.inventory()
        for invalid in ("65536:65537", "40:30", "unknown-service"):
            with self.subTest(invalid=invalid):
                lines[0] = original.replace("1:21", invalid)
                with self.assertRaisesRegex(Rejected, "UNKNOWN_OWNED_RULE"):
                    pf.inventory()

    def test_pf_install_uses_identical_ranges_for_rules_and_state_cleanup(self):
        command = str(uuid.uuid4())
        ranges = unprotected_ranges([443])
        scope = {"local": "127.0.0.1", "peer": "127.0.0.2", "port": None,
                 "interface": "lo0", "ranges": ranges}
        pf = object.__new__(PF)
        pf.root, pf.helper = PF.anchor_root(str(uuid.uuid4())), Path("/private/tmp/helper")
        self.assertEqual(len(pf.handle(command)), 62)
        pf.preflight, pf.inventory = lambda: None, lambda: {}
        calls = []
        pf.run = lambda args, data=None: calls.append((args, data))
        pf.install(command, scope, time.time() + 5)
        self.assertEqual(len(calls), 2)
        rules = calls[0][1].splitlines()
        self.assertEqual(len(rules), len(ranges))
        self.assertTrue(all("port 22 " not in rule and "port 53 " not in rule and
                            "port 443 " not in rule and "port 3389 " not in rule for rule in rules))
        self.assertEqual(calls[1][0][1:], ["kill-ranges", "127.0.0.1", "127.0.0.2",
                                             ",".join(f"{a}:{b}" for a, b in ranges), "lo0"])
        if sys.platform == "darwin":
            for executor_id in (str(uuid.uuid4()), "ffffffff-ffff-ffff-ffff-ffffffffffff"):
                with self.subTest(executor_id=executor_id):
                    pf.root = PF.anchor_root(executor_id)
                    result = subprocess.run(["/sbin/pfctl", "-n", "-a", pf.handle(command), "-f", "-"],
                                            input=calls[0][1], text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
