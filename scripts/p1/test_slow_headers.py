import unittest
from review_slow_headers import SlowHeaderReview


class OnsetTests(unittest.TestCase):
    def packet(self, seq, ts, flags=16):
        return {'seq':seq,'ts':ts,'flags':flags,'payloadFullyCaptured':True}

    def test_get_alone_is_not_onset_and_retransmission_is_not_new_evidence(self):
        r=SlowHeaderReview();r.add(self.packet(100,0,2),b'')
        initial=b'GET / HTTP/1.1\r\n'
        r.add(self.packet(101,10),initial)
        self.assertIsNone(r.onset)
        fragment=b'X-a: b\r\n';seq=101+len(initial)
        r.add(self.packet(seq,1000),fragment)
        r.add(self.packet(seq,2000),fragment)
        self.assertEqual(r.onset,1000)
        self.assertEqual(r.continuations,1)

    def test_other_dataset_header_value_is_not_silently_accepted(self):
        r=SlowHeaderReview();r.add(self.packet(100,0,2),b'')
        initial=b'GET / HTTP/1.1\r\n';r.add(self.packet(101,10),initial)
        r.add(self.packet(101+len(initial),1000),b'X-a: 123\r\n')
        self.assertIsNone(r.onset)

    def test_missing_bytes_cannot_produce_approved_onset(self):
        r=SlowHeaderReview();r.add(self.packet(100,0,2),b'')
        r.add(self.packet(110,10),b'X-a: 1\r\n')
        self.assertEqual(r.invalid,'sequence_gap')
        self.assertIsNone(r.onset)

    def test_complete_ordinary_request_cannot_be_relabelled_by_later_fragment(self):
        r=SlowHeaderReview();r.add(self.packet(100,0,2),b'')
        initial=b'GET / HTTP/1.1\r\n\r\n';r.add(self.packet(101,10),initial)
        r.add(self.packet(101+len(initial),1000),b'X-a: 1\r\n')
        self.assertIsNone(r.onset)


if __name__=='__main__':
    unittest.main()
