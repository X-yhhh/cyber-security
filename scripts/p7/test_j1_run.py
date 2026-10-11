"""J1 runner 的权限边界回归：默认不得调用 sudo 或 pfctl。"""
import unittest
from unittest.mock import patch

import j1_run


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
