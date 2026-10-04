"""数据补齐的泄漏、来源缺损及标签否决回归；不运行真实网络任务。"""
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import tarfile
import unittest
from unittest.mock import Mock, patch

from adjudicate_prefix import adjudicate, START
from build_dataset import deduplicate, eligible
from capture_prefix import derive
from remote_zip import RemoteZip
from delivery import install
from verify_dataset import verify


def sample(ident, parent, role, activity, signature):
    return ({'observationId': ident, 'parentConnectionId': parent, 'split': role,
             'activityId': activity, 'duplicateGroup': signature}, {})


class LeakageTests(unittest.TestCase):
    def test_cross_role_duplicate_excludes_all_parent_snapshots(self):
        data = [sample('1', 'a', 'train', 'a1', 'duplicate'),
                sample('2', 'a', 'train', 'a1', 'unique-sibling'),
                sample('3', 'b', 'validation_selection', 'a2', 'duplicate'),
                sample('4', 'c', 'train', 'a1', 'other-1'),
                sample('5', 'c', 'train', 'a1', 'other-2')]
        kept, report = deduplicate(data)
        self.assertEqual([r['observationId'] for r, _ in kept], ['4', '5'])
        self.assertEqual(report['wholeParentsExcluded'], 2)
        self.assertEqual(sum(r['sampleWeight'] for r, _ in kept), 1)

    def test_shared_parent_across_roles_rejected(self):
        with self.assertRaisesRegex(ValueError, '父连接'):
            deduplicate([sample('1', 'a', 'train', 'x', 's1'),
                         sample('2', 'a', 'validation_calibration', 'y', 's2')])

    def test_shared_activity_across_hosts_rejected(self):
        with self.assertRaisesRegex(ValueError, '活动'):
            deduplicate([sample('1', 'host-a-parent', 'train', 'same-client-task', 's1'),
                         sample('2', 'host-b-parent', 'validation_selection', 'same-client-task', 's2')])

    def test_duplicate_observation_rejected(self):
        with self.assertRaisesRegex(ValueError, '观察重复'):
            deduplicate([sample('1', 'a', 'train', 'x', 's1'), sample('1', 'a', 'train', 'x', 's1')])

    def test_eof_and_wrong_service_are_not_final_evidence(self):
        o = dict(addressFamily='ipv4', transport='tcp', direction='inbound', servicePort=80,
                 quality={'clockSkewMs': 0}, profile='flow-final-v1', closeReason='eof')
        self.assertEqual(eligible(o), 'incomplete_connection')
        o.update(closeReason='fin', servicePort=55161)
        self.assertEqual(eligible(o), 'scope')


class PrefixTests(unittest.TestCase):
    def fixture(self):
        label = dict(id='label', label='DoS Slowloris', overlaps=False,
                     origin='192.0.2.1:40000', responder='192.0.2.2:80', fwdPayload=100,
                     start=START, end=START + 10000000)
        join = dict(join='matched', expected=[1, 1, 100, 0], observed=[1, 1, 100, 0],
                    synStart=True, distinctSynSequences=1, reviewError='', timestampRegressions=0,
                    badHeaders=0, offloadPackets=0, headerCompleteUs=None,
                    independentContinuations=1, onsetCandidateUs=START + 1000)
        return label, join

    def test_publisher_artifact_overrides_structural_success(self):
        label, join = self.fixture()
        label['origin'] = '192.0.2.1:54114'
        self.assertEqual(adjudicate(label, join)['decision'], 'rejected')

    def test_attempted_and_completed_request_rejected(self):
        label, join = self.fixture()
        label['label'] += ' - Attempted'
        self.assertEqual(adjudicate(label, join)['decision'], 'rejected')
        label, join = self.fixture()
        join['headerCompleteUs'] = START + 5000
        self.assertEqual(adjudicate(label, join)['decision'], 'rejected')

    def test_out_of_window_onset_rejected(self):
        label, join = self.fixture()
        join['onsetCandidateUs'] = START - 1
        self.assertEqual(adjudicate(label, join)['decision'], 'rejected')


class SourceTests(unittest.TestCase):
    def test_receiver_rejects_changed_data_before_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'readiness.json').write_text(json.dumps({'indexSha256': '0' * 64}))
            (root / 'index.jsonl').write_text('changed input')
            with self.assertRaisesRegex(ValueError, '哈希不符'):
                verify(root)

    def test_delivery_rejects_path_escape_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / 'bad.tar.gz'
            payload = b'outside'
            manifest = {'public/../../outside': hashlib.sha256(payload).hexdigest()}
            with tarfile.open(archive, 'w:gz') as tar:
                for name, body in [('transfer-manifest.json', json.dumps(manifest).encode()),
                                   ('public/../../outside', payload)]:
                    info = tarfile.TarInfo(name)
                    info.size = len(body)
                    tar.addfile(info, io.BytesIO(body))
            with self.assertRaisesRegex(ValueError, '不安全'):
                install(root, archive, hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertFalse((root / 'contracts').exists())

    def test_source_tail_preserved_and_derivative_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, out = root / 'source.pcap', root / 'derived.pcap'
            header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            good = struct.pack('<IIII', 100, 0, 54, 54) + bytes(54)
            bad = struct.pack('<IIII', 101, 0, 54, 54) + bytes(49)
            source.write_bytes(header + good + bad)
            report = derive(source, out)
            self.assertEqual(source.read_bytes(), header + good + bad)
            self.assertEqual(out.read_bytes(), header + good)
            self.assertEqual(report['discardedTailBytes'], 65)
            self.assertFalse(report['sourceContainerComplete'])
            with self.assertRaises(FileExistsError):
                derive(source, out)

    @patch('remote_zip.requests.Session')
    def test_full_response_or_changed_etag_rejected(self, session):
        head = Mock(headers={'Content-Length': '20', 'ETag': '"fixed"'})
        session.return_value.head.return_value = head
        for status, etag in ((200, '"fixed"'), (206, '"changed"')):
            session.return_value.get.return_value = Mock(status_code=status,
                headers={'ETag': etag, 'Content-Range': 'bytes 0-19/20'}, content=bytes(20))
            with RemoteZip('https://example.invalid/public.zip') as remote:
                with self.assertRaises(ValueError):
                    remote.read(10)


if __name__ == '__main__':
    unittest.main()
