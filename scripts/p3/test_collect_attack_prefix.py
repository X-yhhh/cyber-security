#!/usr/bin/env python3
"""collect_attack_prefix 的单元测试；不执行真实网络操作或 Npcap 采集。

测试覆盖：授权校验拒绝边界、活动登记结构、场景列表完整性、
输出路径独占创建、trainingAllowed 不变性。
"""
import json
import sys
import time
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))
import collect_attack_prefix as cap


def future_iso(seconds=600):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def base_scope(authorized_until=None):
    return dict(
        local='127.0.0.1',
        peer='127.0.0.2',
        port=80,
        captureInterface=r'\Device\NPF_Loopback',
        authorizedUntil=authorized_until or future_iso(),
        authorizationId='test-auth-001',
        maximumTotalSeconds=4000,
    )


class TestValidateScope(unittest.TestCase):

    def test_valid_scope_accepted(self):
        expiry = cap.validate_scope(base_scope())
        self.assertGreater(expiry, time.time())

    def test_wrong_local_rejected(self):
        s = base_scope(); s['local'] = '10.0.0.1'
        with self.assertRaises(ValueError):
            cap.validate_scope(s)

    def test_wrong_peer_rejected(self):
        s = base_scope(); s['peer'] = '10.0.0.2'
        with self.assertRaises(ValueError):
            cap.validate_scope(s)

    def test_wrong_port_rejected(self):
        s = base_scope(); s['port'] = 8080
        with self.assertRaises(ValueError):
            cap.validate_scope(s)

    def test_wrong_interface_rejected(self):
        s = base_scope(); s['captureInterface'] = r'\Device\NPF_eth0'
        with self.assertRaises(ValueError):
            cap.validate_scope(s)

    def test_expired_authorization_rejected(self):
        past = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        s = base_scope(authorized_until=past)
        with self.assertRaises(ValueError):
            cap.validate_scope(s)

    def test_missing_authorization_id_rejected(self):
        s = base_scope(); del s['authorizationId']
        with self.assertRaises(ValueError):
            cap.validate_scope(s)


class TestScenarios(unittest.TestCase):

    def test_eight_scenarios_defined(self):
        self.assertEqual(len(cap.SCENARIOS), 8)

    def test_four_slowloris(self):
        sl = [s for s in cap.SCENARIOS if s['mode'] == 'slowloris']
        self.assertEqual(len(sl), 4)

    def test_four_slowhttptest(self):
        sh = [s for s in cap.SCENARIOS if s['mode'] == 'slowhttptest']
        self.assertEqual(len(sh), 4)

    def test_group_ordinals_per_mode(self):
        for mode in ('slowloris', 'slowhttptest'):
            ordinals = sorted(s['groupOrdinal'] for s in cap.SCENARIOS if s['mode'] == mode)
            self.assertEqual(ordinals, [1, 2, 3, 4])

    def test_all_ids_unique(self):
        ids = [s['id'] for s in cap.SCENARIOS]
        self.assertEqual(len(ids), len(set(ids)))


class TestRunGroupStructure(unittest.TestCase):
    """run_group 的结构测试：mock NativeCapture 和网络操作，不访问真实接口。"""

    def _make_capture_mock(self):
        m = MagicMock()
        m.thread = MagicMock()
        m.close.return_value = dict(
            frames=100, nativeLink=12, error=None,
            stats=dict(recv=100, drop=0, ifdrop=0),
            passed=True,
        )
        return m

    def test_activity_json_written(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'group-01'
            scenario = cap.SCENARIOS[0]

            with (patch('collect_attack_prefix.NativeCapture',
                        return_value=self._make_capture_mock()),
                  patch('collect_attack_prefix._target_server', return_value=True),
                  patch('collect_attack_prefix._slowloris_worker'),
                  patch('time.sleep')):
                # 把活动时长压到 0
                orig = cap.ACTIVITY_SECONDS
                cap.ACTIVITY_SECONDS = 0
                try:
                    result = cap.run_group(root, scenario, time.time() + 3600)
                finally:
                    cap.ACTIVITY_SECONDS = orig

            self.assertTrue((root / 'activity.json').exists())
            data = json.loads((root / 'activity.json').read_text())
            self.assertEqual(data['scenarioId'], scenario['id'])
            self.assertEqual(data['mode'], scenario['mode'])
            self.assertFalse(data['trainingAllowed'])
            self.assertEqual(data['modelFits'], 0)

    def test_output_dir_must_not_exist(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'group-01'
            root.mkdir()  # 已存在
            with self.assertRaises(FileExistsError):
                cap.run_group(root, cap.SCENARIOS[0], time.time() + 3600)

    def test_training_always_false_in_output(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'group-01'
            scenario = cap.SCENARIOS[0]
            with (patch('collect_attack_prefix.NativeCapture',
                        return_value=self._make_capture_mock()),
                  patch('collect_attack_prefix._target_server', return_value=True),
                  patch('collect_attack_prefix._slowloris_worker'),
                  patch('time.sleep')):
                orig = cap.ACTIVITY_SECONDS
                cap.ACTIVITY_SECONDS = 0
                try:
                    result = cap.run_group(root, scenario, time.time() + 3600)
                finally:
                    cap.ACTIVITY_SECONDS = orig
            self.assertFalse(result['trainingAllowed'])


class TestHealthContinuity(unittest.TestCase):
    def _run(self, live):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'group-01'
            capture = TestRunGroupStructure._make_capture_mock(None)
            with (patch('collect_attack_prefix.NativeCapture', return_value=capture),
                  patch('collect_attack_prefix._target_server', return_value=True),
                  patch('collect_attack_prefix._slowloris_worker'),
                  patch('collect_attack_prefix.require_live', side_effect=live),
                  patch('collect_attack_prefix.ledger_check'), patch('collect_attack_prefix.ledger_append'),
                  patch('time.sleep')):
                orig = cap.ACTIVITY_SECONDS; cap.ACTIVITY_SECONDS = 0
                try:
                    return cap.run_group(root, cap.SCENARIOS[0], time.time() + 3600, ('observer', 'a', 's'))
                finally:
                    cap.ACTIVITY_SECONDS = orig

    def test_observer_must_be_live_before_activity(self):
        with self.assertRaises(ValueError):
            self._run([ValueError('健康观察器记录不实时')])

    def test_health_break_during_activity_fails_group(self):
        before = dict(observerSessionId='o', healthySinceMs=1.0)
        after = dict(observerSessionId='o', healthySinceMs=2.0)
        with self.assertRaisesRegex(RuntimeError, '失败'):
            self._run([before, after])

    def test_continuous_health_is_recorded(self):
        state = dict(observerSessionId='o', healthySinceMs=1.0)
        result = self._run([state, dict(state)])
        self.assertTrue(result['captureHealth']['continuous'])

    def test_scenarios_are_in_role_time_order(self):
        order = [cap.ROLE_ORDER.index(s['plannedRole']) for s in cap.SCENARIOS]
        self.assertEqual(order, sorted(order))

    def test_inter_activity_gap_covers_cooldown_and_ttl(self):
        self.assertGreaterEqual(cap.INTER_ACTIVITY_SECONDS, 120 + 60)
        self.assertGreaterEqual(cap.INTER_ACTIVITY_SECONDS, cap.ISOLATION_SECONDS)


class TestConstants(unittest.TestCase):

    def test_isolation_seconds(self):
        # 文档要求 ≥155 秒
        self.assertGreaterEqual(cap.ISOLATION_SECONDS, 155)

    def test_activity_seconds(self):
        # 活动时长不超过 120 秒
        self.assertLessEqual(cap.ACTIVITY_SECONDS, 120)

    def test_max_connections(self):
        self.assertEqual(cap.MAX_CONNECTIONS, 4)

    def test_addresses(self):
        self.assertEqual(cap.LOCAL, '127.0.0.1')
        self.assertEqual(cap.PEER, '127.0.0.2')
        self.assertEqual(cap.PORT, 80)


if __name__ == '__main__':
    unittest.main()
