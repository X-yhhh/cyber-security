"""验证微秒边界、截断容器及相邻五元组不会被诊断工具静默合并。"""
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('diag',Path(__file__).with_name('diagnose_labels.py'))
diag=importlib.util.module_from_spec(spec);spec.loader.exec_module(diag)


class DiagnosticsTest(unittest.TestCase):
    def test_exact_microsecond_timestamp(self):
        self.assertEqual(diag.micros('1545410400.123456'),1545410400123456)
        self.assertEqual(diag.micros('0.000001'),1)

    def test_incomplete_record_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'cut.pcap'
            p.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+b'bad')
            with self.assertRaisesRegex(ValueError,'记录头截断'):list(diag.packets(p))

    def test_adjacent_packets_preserve_time_and_sequence(self):
        ethernet=bytes(12)+b'\x08\x00'
        ip=struct.pack('!BBHHHBBHII',0x45,0,40,0,0,64,6,0,0xc0000201,0xc6336401)
        def frame(seq):return ethernet+ip+struct.pack('!HHIIBBHHH',51000,55000,seq,0,0x50,2,1024,0,0)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'two.pcap'
            b=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
            for us,seq in [(1,42),(2,43)]:
                packet=frame(seq);b+=struct.pack('<IIII',10,us,len(packet),len(packet))+packet
            p.write_bytes(b);rows=list(diag.packets(p))
            self.assertEqual(rows[0][0],rows[1][0])
            self.assertEqual([v[1][0] for v in rows],[10000001,10000002])
            self.assertEqual([v[1][3] for v in rows],[42,43])


if __name__=='__main__':unittest.main()
