"""健康观察器确定性回归：注入时钟与计数，不打开 Npcap、不产生网络流量。"""
import json
import tempfile
import threading
import unittest
from pathlib import Path

import capture_health_observer as obs
from capture_health import HealthChain

ASSET = '00000000-0000-4000-8000-000000000001'
SENSOR = '00000000-0000-4000-8000-000000000002'


class Clock:
    def __init__(self): self.t = 1_800_000_000.0
    def monotonic(self): return self.t
    def wall(self): return self.t


class ObserverTest(unittest.TestCase):
    def session(self, stats):
        root = Path(tempfile.mkdtemp(prefix='p3-health-')) / 'observer'
        clock = Clock()
        observer = obs.open_session(root, asset_id=ASSET, sensor_id=SENSOR, authorization_id='auth-test',
                                    authorized_until='2027-01-01T00:00:00+00:00', stats=stats,
                                    config=dict(windowMs=obs.WINDOW_MS), build_sha256='b' * 64,
                                    monotonic=clock.monotonic, wall=clock.wall)
        return root, clock, observer

    def records(self, root):
        return [json.loads(line) for line in (root / obs.RECORDS).read_text(encoding='utf-8').splitlines()]

    def verify(self, root, observer):
        chain = HealthChain([observer.binding]); state = None
        for record in self.records(root): state = chain.accept(record)
        return chain, state

    def test_continuous_records_prove_health_across_activity_gaps(self):
        counter = dict(packetsSeen=0, kernelDrops=0, capacityDrops=0)
        def stats():
            counter['packetsSeen'] += 7; return dict(counter)
        root, clock, observer = self.session(stats)
        for _ in range(60):
            clock.t += 4.9; observer.tick()
        chain, state = self.verify(root, observer)
        self.assertIsNone(state['reason'])
        start = clock.t - 60 * 4.9
        self.assertIsNotNone(chain.proof(observer.identity, start * 1000, clock.t * 1000))
        live = obs.require_live(root, ASSET, SENSOR, now_ms=clock.t * 1000 + 1000)
        self.assertAlmostEqual(live['healthySinceMs'], start * 1000, delta=1)

    def test_late_scheduler_is_sliced_and_marked_gap(self):
        root, clock, observer = self.session(lambda: dict(packetsSeen=1, kernelDrops=0, capacityDrops=0))
        clock.t += 4.9; observer.tick()
        clock.t += 12.0; emitted = observer.tick()
        self.assertEqual(len(emitted), 3)
        self.assertTrue(all(r['captureGap'] for r in emitted))
        clock.t += 4.9; observer.tick()
        _, state = self.verify(root, observer)
        self.assertIsNone(state['reason'])
        self.assertAlmostEqual(state['since'], (clock.t - 4.9) * 1000, delta=1)

    def test_unreadable_stats_and_drops_are_never_health(self):
        values = iter([dict(packetsSeen=1, kernelDrops=0, capacityDrops=0), RuntimeError('npcap')])
        def stats():
            value = next(values)
            if isinstance(value, Exception): raise value
            return value
        root, clock, observer = self.session(stats)
        clock.t += 4.9; observer.tick()
        _, state = self.verify(root, observer)
        self.assertEqual(state['reason'], 'UNKNOWN_COUNTER')
        root, clock, observer = self.session(iter([dict(packetsSeen=1, kernelDrops=0, capacityDrops=0),
                                                  dict(packetsSeen=5, kernelDrops=1, capacityDrops=0)]).__next__)
        clock.t += 4.9; observer.tick()
        _, state = self.verify(root, observer)
        self.assertEqual(state['reason'], 'CAPTURE_DROPS')
        with self.assertRaisesRegex(ValueError, '不健康'):
            obs.require_live(root, ASSET, SENSOR, now_ms=clock.t * 1000)

    def test_drain_fault_and_stale_or_foreign_observer_are_rejected(self):
        root, clock, observer = self.session(lambda: dict(packetsSeen=1, kernelDrops=0, capacityDrops=0))
        clock.t += 4.9; observer.tick()
        with self.assertRaisesRegex(ValueError, '不实时'):
            obs.require_live(root, ASSET, SENSOR, now_ms=clock.t * 1000 + 11000)
        with self.assertRaisesRegex(ValueError, '身份'):
            obs.require_live(root, ASSET, '00000000-0000-4000-8000-000000000009', now_ms=clock.t * 1000)
        clock.t += 4.9; observer.tick(fault=True)
        _, state = self.verify(root, observer)
        self.assertEqual(state['reason'], 'CAPTURE_GAP')

    def test_registry_binds_records_and_authorization(self):
        root, clock, observer = self.session(lambda: dict(packetsSeen=1, kernelDrops=0, capacityDrops=0))
        for _ in range(3):
            clock.t += 4.9; observer.tick()
        obs.finalize(root, 'stop_file')
        registry = json.loads((root / obs.REGISTRY).read_text(encoding='utf-8'))
        self.assertEqual(registry['recordsSha256'], obs.file_sha(root / obs.RECORDS))
        self.assertEqual(registry['observerBindings'], [observer.binding])
        self.assertTrue(registry['authenticatedCollectionRef'].startswith('auth-test:'))
        self.assertEqual(registry['targetBindings'], {})
        with self.assertRaises(FileExistsError):
            obs.open_session(root, asset_id=ASSET, sensor_id=SENSOR, authorization_id='x', authorized_until='x',
                             stats=lambda: None, config={}, build_sha256='b' * 64)

    def test_run_stops_on_stop_file(self):
        root, clock, observer = self.session(lambda: dict(packetsSeen=1, kernelDrops=0, capacityDrops=0))
        (root / obs.STOP).write_text('')
        observer.run(clock.t + 3600, threading.Event())
        self.assertFalse((root / obs.RECORDS).exists())


class LedgerTest(unittest.TestCase):
    def test_roles_advance_in_time_order_with_gap(self):
        root = Path(tempfile.mkdtemp(prefix='p3-ledger-'))
        obs.ledger_check(root, 'train', 190, now=0)
        obs.ledger_append(root, dict(kind='attack', plannedRole='validation_selection', endedAt=1000.0))
        with self.assertRaisesRegex(ValueError, '角色顺序'):
            obs.ledger_check(root, 'train', 190, now=5000)
        with self.assertRaisesRegex(ValueError, '不足 190'):
            obs.ledger_check(root, 'validation_calibration', 190, now=1100)
        obs.ledger_check(root, 'validation_selection', 190, now=1190)
        self.assertEqual(obs.ledger_ready_at(root, 190), 1190.0)
        with self.assertRaisesRegex(ValueError, '未知角色'):
            obs.ledger_check(root, 'final_test', 190, now=9999)


if __name__ == '__main__':
    unittest.main()
