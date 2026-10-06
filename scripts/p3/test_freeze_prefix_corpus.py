#!/usr/bin/env python3
"""来源重命名的端到端回归：保持近重复与上下文约束，允许真正隔离的不同序列。"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_prefix_corpus import read, sha, verify
from build_qualified_prefix import target_key
from freeze_prefix_corpus import health_binding, health_sessions
import capture_health_observer as health_observer


class SourceGroupingTest(unittest.TestCase):
    def test_source_names_cannot_split_duplicate_or_shared_context(self):
        # 200 秒且序列不同才可独立；来源名不同本身不豁免任何归并规则。
        for offset, different, reason, count in [
            (200, False, 'whole_parent_quantized_sequence', 1),
            (100, True, 'shared_source_context_150s', 1),
            (200, True, None, 2),
        ]:
            with self.subTest(offset=offset, different=different), tempfile.TemporaryDirectory() as td:
                root = Path(td); source = root / 'qualified'; source.mkdir()
                rows, observations, timeline = [], [], []
                for group in range(2):
                    first = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=offset * group)
                    stamp = lambda seconds: (first + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')
                    for ordinal, seconds in enumerate((1, 5)):
                        ident, parent, activity = f'obs-{group}-{ordinal}', f'parent-{group}', f'activity-{group}'
                        features = dict(elapsedMs=seconds * 1000, bytesInbound=64 + 256 * int(different) * group,
                                        bytesOutbound=64, packetsInbound=2, packetsOutbound=2,
                                        lengthMin=40, lengthMax=64, lengthMean=48, synCount=1,
                                        synAckCount=1, rstCount=0, finCount=0, handshakeSeen=True)
                        observations.append(dict(observationId=ident, parentConnectionId=parent,
                            contractVersion='host-guard/5.0.0-rc.2', profile='flow-prefix-v1',
                            direction='inbound', transport='tcp', addressFamily='ipv4', servicePort=80,
                            firstSeenAt=stamp(0), lastPacketAt=stamp(seconds), asOf=stamp(seconds), emittedAt=stamp(seconds),
                            features=features, quality={key: False for key in
                                ('captureGap', 'latePacket', 'truncated', 'offloadSuspected', 'capacityDrop')}))
                        rows.append(dict(observationId=ident, parentConnectionId=parent, activityId=activity,
                            sourceId=f'controlled_slowloris_g{group+1}', contextSourceId='controlled_windows_http_cde',
                            scenario='controlled_slowloris', plannedRole='independent_development', split='independent_development', label=1,
                            firstSeenAt=stamp(0), asOf=stamp(seconds), budgetTargetId='controlled-target'))
                    timeline.append(dict(episodeId=activity, activityId=activity, scenario='controlled_slowloris',
                                         label=1, plannedRole='independent_development', sourceId=f'controlled_slowloris_g{group+1}', targetId='controlled-target', startMs=first.timestamp()*1000,
                                         endMs=(first.timestamp()+6)*1000))
                for name, values in [('index.jsonl', rows), ('observations.jsonl', observations), ('label-timeline.jsonl', timeline)]:
                    (source/name).write_text(''.join(json.dumps(row)+'\n' for row in values), encoding='utf-8')
                (source/'readiness.json').write_text(json.dumps(dict(finalRead=False, modelFits=0,
                    outputHashes={name: sha(source/name) for name in ('index.jsonl', 'observations.jsonl', 'label-timeline.jsonl')})))
                reservation = root/'reservation.json'
                reservation.write_text(json.dumps(dict(modelScoresRead=False, finalFeaturesRead=False)))
                qualification = root/'qualification.json'
                qualification.write_text(json.dumps(dict(reservationSha256=sha(reservation), captures=[])))
                output = root/'corpus'
                result = subprocess.run([sys.executable, str(Path(__file__).with_name('freeze_prefix_corpus.py')),
                    '--qualified', str(source), '--qualification', str(qualification),
                    '--reservation', str(reservation), '--output', str(output)], capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                partition = read(output/'partitions.json')
                self.assertEqual(len(partition['groups']), count)
                self.assertEqual([edge['reason'] for edge in partition['edges']], [] if reason is None else [reason])
                verified = verify(output)
                self.assertFalse(verified['trainingAllowed'])
                self.assertEqual(verified['groupingSummary']['byScenario']['controlled_slowloris']['sourceGroups'], 2)
                self.assertEqual(verified['roleClassGroups']['independent_development']['1'], count)


class HealthBindingTest(unittest.TestCase):
    def test_controlled_target_requires_matching_authorization_and_health_chain(self):
        class Clock:
            now = 1_791_230_000.0

            def read(self):
                return self.now

        with tempfile.TemporaryDirectory() as td:
            root = Path(td); health = root / 'health'; clock = Clock()
            asset = '00000000-0000-4000-8000-000000000001'
            sensor = '00000000-0000-4000-8000-000000000002'
            started = clock.now
            authorized_until = health_observer.iso((started + 500) * 1000)
            config = dict(interface=health_observer.INTERFACE, filter=health_observer.FILTER)
            observer = health_observer.open_session(
                health, asset_id=asset, sensor_id=sensor, authorization_id='test-auth',
                authorized_until=authorized_until,
                stats=lambda: dict(packetsSeen=1, kernelDrops=0, capacityDrops=0),
                config=config, build_sha256=sha(Path(__file__).with_name('capture_health_observer.py')),
                monotonic=clock.read, wall=clock.read)
            for _ in range(46):
                clock.now += 4.9
                observer.tick()
            health_observer.finalize(health, 'stop_file')
            registry_path = health / 'health-registry.json'
            registry = read(registry_path)
            registry['stoppedAt'] = health_observer.iso(clock.now * 1000)
            registry_path.write_text(json.dumps(registry), encoding='utf-8')
            auth_path = root / 'authorization.json'
            authorization = dict(status='authorized_active', executionAuthorized=True,
                authorizationId='test-auth', validFrom=health_observer.iso((started - 10) * 1000),
                validUntil=authorized_until,
                scope=dict(host='win-dev', environment='isolated_loopback_research',
                    interface=health_observer.INTERFACE, local='127.0.0.1', peer='127.0.0.2',
                    servicePort=80, maxConcurrentConnections=4, firewallChanges=False,
                    externalTrafficAllowed=False))
            auth_path.write_text(json.dumps(authorization), encoding='utf-8')
            target = target_key(asset, '127.0.0.1:80', '127.0.0.2:0')
            rows = [dict(activityId=activity, sourceDomainId='controlled_windows_http_cde',
                         budgetTargetId=target, split='train', label=label,
                         firstSeenAt=health_observer.iso((started + begin) * 1000),
                         asOf=health_observer.iso((started + end) * 1000))
                    for activity, label, begin, end in [('attack', 1, 10, 15), ('benign', 0, 25, 30)]]
            rows.append(dict(sourceDomainId='public', budgetTargetId='public-target'))
            timelines = [dict(activityId=activity, targetId=target, label=int(activity == 'attack'),
                              startMs=(started + begin) * 1000, endMs=(started + end) * 1000)
                         for activity, begin, end in [('attack', 10, 15), ('benign', 25, 30)]]
            (health / 'activity-ledger.jsonl').write_text(''.join(json.dumps(entry) + '\n' for entry in [
                dict(activityId='attack', kind='attack', plannedRole='train', success=True, endedAt=started + 20),
                dict(activityId='benign', kind='benign', plannedRole='train', success=True, endedAt=started + 40),
            ]), encoding='utf-8')
            derived, records, binding, ledger = health_binding(registry_path, auth_path, rows, timelines)
            self.assertEqual(set(derived['targetBindings']), {target})
            self.assertEqual(derived['sourceRegistrySha256'], sha(registry_path))
            self.assertEqual([p.name for p in (records, binding, ledger)],
                             ['health-records.jsonl', 'observer-binding.json', 'activity-ledger.jsonl'])
            # 良性尾段不延长攻击规则的冷却；攻击尾段仍须保留完整旁证。
            timelines[1]['endMs'] = (started + 220) * 1000
            entries = [dict(activityId='attack', kind='attack', plannedRole='train', success=True,
                            endedAt=started + 20),
                       dict(activityId='benign', kind='benign', plannedRole='train', success=True,
                            endedAt=started + 225)]
            (health / 'activity-ledger.jsonl').write_text(
                ''.join(json.dumps(entry) + '\n' for entry in entries), encoding='utf-8')
            health_binding(registry_path, auth_path, rows, timelines)
            timelines[0]['endMs'] = (started + 60) * 1000
            entries[0]['endedAt'] = started + 60
            (health / 'activity-ledger.jsonl').write_text(
                ''.join(json.dumps(entry) + '\n' for entry in entries), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '冷却旁证'):
                health_binding(registry_path, auth_path, rows, timelines)
            timelines[0]['endMs'] = (started + 15) * 1000
            entries[0]['endedAt'] = started + 20
            (health / 'activity-ledger.jsonl').write_text(
                ''.join(json.dumps(entry) + '\n' for entry in entries), encoding='utf-8')
            authorization['validUntil'] = health_observer.iso((started + 501) * 1000)
            auth_path.write_text(json.dumps(authorization), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '授权'):
                health_binding(registry_path, auth_path, rows, timelines)
            auth_path.write_text(json.dumps(dict(authorization, validUntil=authorized_until)), encoding='utf-8')
            registry['recordsSha256'] = '0' * 64
            registry_path.write_text(json.dumps(registry), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '哈希'):
                health_binding(registry_path, auth_path, rows, timelines)

    def test_separate_health_sessions_keep_distinct_chains(self):
        class Clock:
            now = 1_791_230_000.0

            def read(self):
                return self.now

        with tempfile.TemporaryDirectory() as td:
            root = Path(td); clock = Clock()
            asset = '00000000-0000-4000-8000-000000000001'
            sensor = '00000000-0000-4000-8000-000000000002'
            start = clock.now
            until = health_observer.iso((start + 700) * 1000)
            auth = root / 'authorization.json'
            auth.write_text(json.dumps(dict(status='authorized_active', executionAuthorized=True,
                authorizationId='test-auth', validFrom=health_observer.iso((start - 10) * 1000),
                validUntil=until, scope=dict(host='win-dev', environment='isolated_loopback_research',
                    interface=health_observer.INTERFACE, local='127.0.0.1', peer='127.0.0.2',
                    servicePort=80, maxConcurrentConnections=4, firewallChanges=False,
                    externalTrafficAllowed=False))), encoding='utf-8')
            target = target_key(asset, '127.0.0.1:80', '127.0.0.2:0')
            rows = []; timelines = []; registries = []
            for ordinal in range(2):
                health = root / f'health-{ordinal}'
                began = clock.now
                observer = health_observer.open_session(
                    health, asset_id=asset, sensor_id=sensor, authorization_id='test-auth',
                    authorized_until=until, stats=lambda: dict(packetsSeen=1, kernelDrops=0, capacityDrops=0),
                    config=dict(interface=health_observer.INTERFACE, filter=health_observer.FILTER),
                    build_sha256=sha(Path(__file__).with_name('capture_health_observer.py')),
                    monotonic=clock.read, wall=clock.read)
                for _ in range(50):
                    clock.now += 4.9
                    observer.tick()
                health_observer.finalize(health, 'stop_file')
                registry = health / 'health-registry.json'
                registry_value = read(registry)
                registry_value['stoppedAt'] = health_observer.iso(clock.now * 1000)
                registry.write_text(json.dumps(registry_value), encoding='utf-8')
                activity = f'benign-{ordinal}'
                (health / 'activity-ledger.jsonl').write_text(json.dumps(dict(
                    activityId=activity, kind='benign', plannedRole='independent_development',
                    success=True, endedAt=began + 35)) + '\n', encoding='utf-8')
                rows.append(dict(activityId=activity, sourceDomainId='controlled_windows_http_cde',
                    budgetTargetId=target, split='independent_development', label=0,
                    firstSeenAt=health_observer.iso((began + 10) * 1000),
                    asOf=health_observer.iso((began + 25) * 1000)))
                timelines.append(dict(activityId=activity, targetId=target, label=0,
                    startMs=(began + 10) * 1000, endMs=(began + 25) * 1000))
                registries.append(registry)
                clock.now += 60
            output = root / 'output'; output.mkdir()
            derived, files = health_sessions(registries, [auth, auth], rows, timelines, output)
            self.assertEqual(derived['version'], 'p3-capture-health-registry-v2')
            self.assertFalse(derived['crossSessionContinuity'])
            self.assertEqual(len(derived['observerBindings']), 2)
            self.assertNotEqual(derived['observerBindings'][0]['observerSessionId'],
                                derived['observerBindings'][1]['observerSessionId'])
            self.assertEqual(len(files), 10)
            for session in derived['sessions']:
                self.assertEqual(sha(output / session['directory'] / 'authorization.json'),
                                 session['authorizationSha256'])
            with self.assertRaisesRegex(ValueError, '重复'):
                health_sessions([registries[0], registries[0]], [auth, auth], rows, timelines, root / 'unused')


if __name__ == '__main__':
    unittest.main()
