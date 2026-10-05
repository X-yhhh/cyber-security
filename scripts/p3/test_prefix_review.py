"""起点旁路必须因果、来源限定；此处仅用合成报文验证拒绝条件。"""
import unittest
from review_prefix_onsets import Review, prefix_label
from http_prefix_state import CausalHTTP
from build_qualified_prefix import source_connection,qualified_connection,source_identity


class PrefixReviewTests(unittest.TestCase):
    def packet(self, seq, flags=16, ts=1):
        return dict(seq=seq, flags=flags, ts=ts, payloadFullyCaptured=True)

    def test_numeric_source_requires_independent_continuation(self):
        review = Review('numeric_x_a')
        review.add(self.packet(10, 2), b'')
        first = b'GET / HTTP/1.1\r\nX-a: 123\r\n'
        review.add(self.packet(11, ts=10), first)
        self.assertIsNone(review.onset)
        continuation = b'X-a: 200\r\n'
        review.add(self.packet(11+len(first), ts=20), continuation)
        self.assertEqual(review.onset, 20)
        review.add(self.packet(11+len(first), ts=30), continuation)
        self.assertEqual(review.continuations, 1)
        self.assertIsNone(prefix_label(19, 20, 40, True))
        self.assertIsNone(prefix_label(20, 20, 40, True))
        self.assertEqual(prefix_label(21, 20, 40, True), 1)
        self.assertIsNone(prefix_label(41, 20, 40, True))

    def test_literal_b_is_not_numeric_publisher_rule(self):
        review = Review('numeric_x_a')
        review.add(self.packet(10, 2), b'')
        first = b'GET / HTTP/1.1\r\n'
        review.add(self.packet(11), first)
        review.add(self.packet(11+len(first), ts=20), b'X-a: b\r\n')
        self.assertIsNone(review.onset)
        self.assertEqual(review.payload_shapes['literal_b_x_a'], 1)

    def test_unknown_mode_never_promotes_final_label(self):
        self.assertIsNone(prefix_label(30, 20, 40, False))
        review = Review(None)
        review.add(self.packet(10, 2), b'')
        first = b'GET / HTTP/1.1\r\n'
        review.add(self.packet(11), first)
        review.add(self.packet(11+len(first)), b'X-a: 2\r\n')
        self.assertIsNone(review.onset)

    def test_gap_and_completed_request_are_not_onset(self):
        for complete in (False, True):
            review = Review('numeric_x_a')
            review.add(self.packet(10, 2), b'')
            first = b'GET / HTTP/1.1\r\n'+(b'\r\n' if complete else b'')
            review.add(self.packet(11), first)
            review.add(self.packet(11+len(first)+(0 if complete else 1)), b'X-a: 2\r\n')
            self.assertIsNone(review.onset)
            if not complete:self.assertEqual(review.invalid, 'sequence_gap')

    def test_reassembly_variants_and_future_conflict(self):
        review=CausalHTTP('slow_header');review.add(self.packet(10,2),b'')
        first=b'GET / HTTP/1.1\r\nHost: fixture\r\n';review.add(self.packet(11,ts=10),first)
        seq=11+len(first)
        review.add(self.packet(seq+4,ts=20),b' b\r\nX-test: 2\r\n')
        self.assertIsNone(review.onset)
        review.add(self.packet(seq,ts=21),b'X-a:')
        self.assertEqual(review.onset,21)
        old=review.snapshot()
        review.add(self.packet(seq,ts=30),b'X-a: b\r\n')
        self.assertEqual(review.continuations,1)
        review.add(self.packet(seq,ts=40),b'Y-a: b\r\n')
        self.assertEqual(review.invalid,'conflicting_overlap')
        self.assertIsNone(old['invalid']);self.assertEqual(old['evidence'],review.evidence)

    def test_body_and_legitimate_completion_are_distinct(self):
        review=CausalHTTP();review.add(self.packet(10,2),b'')
        head=b'POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n'
        review.add(self.packet(11,ts=10),head+b'12')
        self.assertIsNone(review.onset)
        review.add(self.packet(11+len(head)+2,ts=20),b'34')
        self.assertEqual(review.detected_mode,'slow_body')
        review.add(self.packet(11+len(head)+4,ts=30),b'567890')
        self.assertEqual(review.complete,30)
        completed=CausalHTTP();completed.add(self.packet(10,2),b'')
        completed.add(self.packet(11,ts=10),b'GET / HTTP/1.1\r\nX-a: b\r\n\r\n')
        completed.add(self.packet(41,ts=20),b'X-a: b\r\n')
        self.assertIsNone(completed.onset)

    def test_extension_method_body_progress_is_causal(self):
        # 实际来源曾被常见方法白名单误排除；仅有扩展方法仍不产生攻击起点。
        review=CausalHTTP();review.add(self.packet(10,2),b'')
        head=b'FAKEVERB /fixture HTTP/1.1\r\nContent-Length: 1000\r\n\r\n'
        review.add(self.packet(11,ts=10),head+b'a')
        self.assertIsNone(review.onset)
        review.add(self.packet(11,ts=20),head+b'a')
        self.assertIsNone(review.onset)
        review.add(self.packet(12+len(head),ts=30),b'b')
        self.assertEqual(review.detected_mode,'slow_body')
        self.assertEqual(review.onset,30)

    def test_exporter_boundary_and_idle_slice_keep_syn_identity(self):
        # 导出段末尾不等于 TCP 结束；晚来的陌生 parent 不得借时间区间取得标签。
        from datetime import datetime,timezone
        iso=lambda n:datetime.fromtimestamp(n/1e6,timezone.utc).isoformat()
        label=dict(id='source',origin='192.0.2.1:1234',responder='192.0.2.2:80',start=1000000,end=2100000)
        review=dict(firstUs=1000000,lastUs=9000000,headerCompleteUs=None,invalidReason=None,checks={'fullLabelJoin':True})
        registration=dict(scenario='cic2017_slowhttptest',rule={'end':8000000})
        qualified=qualified_connection(label,review,registration)
        self.assertEqual((qualified['exporterEnd'],qualified['end']),(2100000,8000000))
        self.assertEqual(source_identity(registration)['sourceId'],'cic2017_corrected')
        ledger={'Endpoints':{'Local':label['responder'],'Peer':label['origin']}}
        lookup={tuple(sorted((label['origin'],label['responder']))):[qualified]};parents={}
        initial=dict(parentConnectionId='one',firstSeenAt=iso(1000000),lastPacketAt=iso(2000000))
        self.assertEqual(source_connection(initial,ledger,lookup,parents),qualified)
        later=dict(parentConnectionId='one',firstSeenAt=iso(5000000),lastPacketAt=iso(6000000))
        self.assertEqual(source_connection(later,ledger,lookup,parents),qualified)
        self.assertIsNone(source_connection(dict(later,parentConnectionId='new'),ledger,lookup,parents))
        self.assertIsNone(source_connection(dict(later,lastPacketAt=iso(8100000)),ledger,lookup,parents))


if __name__ == '__main__':
    unittest.main()
