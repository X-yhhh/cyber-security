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


if __name__ == '__main__':
    unittest.main()
