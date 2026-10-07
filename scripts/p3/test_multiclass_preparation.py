"""P3-A 六档标签、时区、关联冲突和时间隔离的合成回归。"""
import json
import sqlite3
import unittest
import tempfile
from pathlib import Path

from multiclass_common import (CLASSES, MAPPING, assign_splits, decide, micros, runs, scenario_split,
                              model_input, normal_split, tuple_key, FEATURES, CONTEXT, unique_connections)
from prepare_multiclass import associate
from access_multiclass_test import evaluation_lock
from prepare_multiclass_l3 import verified_task, health_coverage


class LabelRules(unittest.TestCase):
    def test_each_included_attack(self):
        for raw, expected in MAPPING.items():
            with self.subTest(raw=raw):
                self.assertEqual(decide([{'rawLabel': raw}], '192.168.10.50', '172.16.0.1')[0], expected)

    def test_attempted_and_excluded_types(self):
        for raw in ('FTP-Patator - Attempted', 'Web Attack - XSS', 'Botnet', 'Heartbleed', 'Infiltration'):
            self.assertIsNone(decide([{'rawLabel': raw}], '192.168.10.50', '192.168.10.8')[0])

    def test_unmatched_nat_not_benign(self):
        for matches in ([], [{'rawLabel': 'BENIGN'}]):
            self.assertEqual(decide(matches, '192.168.10.50', '172.16.0.1')[1], 'unmatched_nat_source')

    def test_internal_normal(self):
        self.assertEqual(decide([], '192.168.10.3', '192.168.10.5')[0], 'normal')

    def test_host_window_excludes_normal(self):
        self.assertEqual(decide([{'rawLabel': 'BENIGN'}], '192.168.10.3', '192.168.10.8', True)[1], 'excluded_host_time_window')

    def test_reviewed_website_requires_benign_match(self):
        self.assertEqual(decide([{'rawLabel': 'BENIGN'}], '8.8.8.8', '192.168.10.5', reviewed_web=True), ('normal', None, 'analyst_reviewed'))
        self.assertIsNone(decide([], '8.8.8.8', '192.168.10.5', reviewed_web=True)[0])
        self.assertIsNone(decide([{'rawLabel': 'BENIGN'}], '8.8.8.8', '192.168.10.5')[0])

    def test_other_external_and_conflicts(self):
        self.assertIsNone(decide([{'rawLabel': 'BENIGN'}], '192.168.10.50', '8.8.8.8')[0])
        conflict = [{'rawLabel': 'FTP-Patator'}, {'rawLabel': 'BENIGN'}]
        self.assertEqual(decide(conflict, '192.168.10.50', '172.16.0.1')[1], 'association_conflict')

    def test_duplicate_same_label_not_conflict(self):
        self.assertEqual(decide([{'rawLabel': 'FTP-Patator'}] * 2, '192.168.10.50', '172.16.0.1')[0], 'brute_force')


class Association(unittest.TestCase):
    def test_reverse_tuple_and_utc(self):
        a, b = ('192.168.10.50', 80), ('172.16.0.1', 1000)
        self.assertEqual(tuple_key(6, a, b), tuple_key(6, b, a))
        self.assertEqual(micros('2017-07-04 11:53:44.398274'), micros('2017-07-04T08:53:44.398274-03:00'))
        self.assertEqual(micros('1970-01-01T00:00:00.000001Z'), 1)

    def test_exact_tolerance_boundary(self):
        connection = sqlite3.connect(':memory:')
        connection.execute('CREATE TABLE labels(day,tupleKey,startUs,rawLabel,csvRow,src,sport,dst,dport)')
        connection.execute('INSERT INTO labels VALUES(?,?,?,?,?,?,?,?,?)', ('tuesday', 'tuple', 1000000, 'FTP-Patator', 2, 'a', 1, 'b', 2))
        self.assertEqual(len(associate(connection, 'tuesday', 'tuple', 1001000, 1000)), 1)
        self.assertEqual(associate(connection, 'tuesday', 'tuple', 1001001, 1000), [])
        self.assertEqual(associate(connection, 'wednesday', 'tuple', 1000000, 1000), [])


class SplitAndFeatures(unittest.TestCase):
    def test_daily_normal_cycle_and_full_span_guard(self):
        base = micros('2017-07-04T00:00:00Z')
        self.assertEqual(normal_split(base + 86390000000, base + 86410000000), 'train')
        self.assertIsNone(normal_split(base + 86390000000, base + 90000000000))
        self.assertIsNone(normal_split(base + 3500000000, base + 3570000000))

    def test_l3_coverage_uses_verified_later_window_and_rejects_gap(self):
        binding = {'observerSessionId': 'session', 'captureScopeId': 'scope'}
        states = {0: {'sha256': 'a', 'since': 0, 'end': 1000},
                  1: {'sha256': 'b', 'since': 0, 'end': 2000},
                  2: {'sha256': 'c', 'since': 0, 'end': 3000}}
        health = {name: {**binding, 'sequence': seq, 'sha256': states[seq]['sha256'],
                        'healthySinceMs': 0, 'throughMs': states[seq]['end']}
                  for name, seq in (('before', 0), ('after', 1))}
        self.assertEqual(health_coverage(health, binding, states, 1100000, 2500000)['sequence'], 2)
        states[2]['since'] = 2200
        with self.assertRaises(ValueError):
            health_coverage(health, binding, states, 1100000, 2500000)
        health['after']['sha256'] = 'tampered'
        with self.assertRaises(ValueError):
            health_coverage(health, binding, states, 1100000, 1500000)

    def test_same_physical_identity_rejects_all_parents(self):
        records = [{'physicalConnectionId': 'same', 'parentConnectionId': key} for key in ('a', 'b')]
        unique, rejected = unique_connections(records + [{'physicalConnectionId': 'unique'}])
        self.assertEqual(set(unique), {'unique'})
        self.assertEqual(len(rejected), 2)

    def test_normal_cycle_and_30_second_guards(self):
        roles = [normal_split((block * 600 + 300) * 1000000) for block in range(10)]
        self.assertEqual(roles.count('train'), 6)
        self.assertEqual(roles.count('validation'), 2)
        self.assertEqual(roles.count('test'), 2)
        for second in (3570, 3600, 3630, 4770, 4800, 4830):
            self.assertIsNone(normal_split(second * 1000000))
        self.assertEqual(normal_split(3631 * 1000000), 'validation')
        self.assertEqual(normal_split(600 * 1000000), 'train')
        self.assertIsNone(normal_split(3500 * 1000000, 3700 * 1000000))
        self.assertEqual(normal_split(600 * 1000000, 700 * 1000000), 'train')

    @staticmethod
    def attack(index, start_s, length_s=1, scenario='DoS Hulk'):
        return {'physicalConnectionId': f'{scenario}-{index}', 'label': 'dos_flood', 'day': 'wednesday',
                'originalScenario': scenario, 'startUs': int(start_s * 1e6), 'endUs': int((start_s + length_s) * 1e6)}

    def test_runs_split_on_idle_gap_after_last_end(self):
        records = [self.attack(0, 0, 100), self.attack(1, 150), self.attack(2, 300)]
        # 第二条起点距第一条结束仅 50 秒，同一段；第三条距此前结束 149 秒，新段。
        self.assertEqual([len(segment) for segment in runs(records)], [2, 1])

    def test_burst_runs_assigned_whole_without_guard_loss(self):
        records = [self.attack(f'{run}-{i}', run * 1000 + i * .01)
                   for run, size in enumerate((600, 200, 200)) for i in range(size)]
        mapping, info = scenario_split(records)
        self.assertEqual(info['method'], 'whole_runs')
        self.assertEqual([row['split'] for row in info['runs']], ['train', 'validation', 'test'])
        self.assertNotIn(None, mapping.values())

    def test_continuous_run_uses_time_bounds_and_full_span_guard(self):
        records = [self.attack(i, i, 2) for i in range(1000)]
        mapping, info = scenario_split(records)
        self.assertEqual(info['method'], 'active_time')
        first, second = info['boundsUs']
        for row in records:
            role = mapping[row['physicalConnectionId']]
            crosses = any(row['startUs'] <= bound + 30e6 and row['endUs'] >= bound - 30e6 for bound in (first, second))
            self.assertEqual(role is None, crosses)
        self.assertEqual({role for role in mapping.values() if role}, {'train', 'validation', 'test'})

    def test_long_connections_search_bounds_keeps_every_split(self):
        # 四次突发、每条连接持续 200 秒：固定比例点会切进突发，搜索后每个集合仍有样本。
        records = [self.attack(f'{burst}-{i}', burst * 360 + i * .1, 200, 'DoS Slowhttptest')
                   for burst in range(4) for i in range(100)]
        assignments, report = assign_splits(records)
        counts = report['wednesday:DoS Slowhttptest']['connections']
        self.assertTrue(all(counts[split] >= 50 for split in ('train', 'validation', 'test')), counts)

    def test_scenario_missing_validation_fails_closed(self):
        records = [self.attack(i, i * .01) for i in range(60)]
        with self.assertRaises(ValueError):
            assign_splits(records)

    def test_equal_start_never_crosses_roles(self):
        records = [self.attack(i, (i // 20) * 60) for i in range(2000)]
        mapping, _ = scenario_split(records)
        for start in {record['startUs'] for record in records}:
            self.assertEqual(len({mapping[r['physicalConnectionId']] for r in records if r['startUs'] == start}), 1)

    def test_identity_not_exported_as_input(self):
        observation = {'contractVersion': 'host-guard/5.0.0-rc.2',
            'features': {key: 0 for key in FEATURES},
            'contexts': [{**{key: 0 for key in CONTEXT}, 'windowSeconds': window} for window in (1, 5, 30)],
            'transport': 'tcp', 'direction': 'inbound', 'serviceClass': 'web',
            'parentConnectionId': 'private', 'servicePort': 80, 'firstSeenAt': 'private', 'label': 'normal'}
        self.assertEqual(set(model_input(observation)), {'features', 'contexts', 'transport', 'direction', 'serviceClass'})
        self.assertNotIn('private', json.dumps(model_input(observation)))
        observation['features']['privateAddress'] = observation['features'].pop('elapsedMs')
        with self.assertRaises(ValueError):
            model_input(observation)

    def test_concurrent_test_access_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with evaluation_lock(root):
                with self.assertRaises(ValueError):
                    with evaluation_lock(root):
                        self.fail('不允许并发读取')
            self.assertFalse((root / '.test-access-lock').exists())
            self.assertIn('access_denied_busy', (root / 'test-access.jsonl').read_text())

    def test_l3_rejects_capture_loss_or_endpoint_count_mismatch(self):
        task = {'success': True, 'error': None, 'listenerClosed': True,
            'capture': {'passed': True, 'error': None,
                'stats': {'dropped': 0, 'interfaceDropped': 0, 'networkDropped': 0}},
            'captureHealth': {'continuous': True}, 'mode': 'slowloris',
            'profile': {'connections': 1}, 'attackResult': {'connected': 1, 'closedConnections': 1},
            'serverRecords': [{'peer': '127.0.0.2'}]}
        event = {'success': True, 'kind': 'attack'}
        self.assertEqual(verified_task(task, event), ('dos_slow', 1, None))
        task['capture']['stats']['dropped'] = 1
        with self.assertRaises(ValueError):
            verified_task(task, event)
        task['capture']['stats']['dropped'] = 0
        task['serverRecords'][0]['peer'] = '127.0.0.3'
        with self.assertRaises(ValueError):
            verified_task(task, event)


if __name__ == '__main__':
    unittest.main()
