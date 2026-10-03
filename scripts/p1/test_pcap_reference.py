import collections
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from pcap_reference import frames,Metrics,tcp


class ReferenceTests(unittest.TestCase):
    def test_handshake_counts_initiation_and_response_separately(self):
        m=Metrics(1,1000)
        base={'ts':100,'src':(2,50000),'flags':2,'seq':42,'ack':0,'payloadBytes':0,'ipBytes':40}
        m.add(base)
        m.add({**base,'ts':200,'src':(1,80),'flags':18,'seq':77,'ack':43})
        m.add({**base,'ts':300,'flags':16,'seq':43,'ack':78})
        r=m.report()
        self.assertEqual((r['synCount'],r['synAckCount']),(1,1))
        self.assertTrue(r['handshakeSeen'])

    def test_partial_container_cannot_produce_complete_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'partial.pcap';p.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,256,12)+b'123')
            audit={}
            with self.assertRaises(ValueError):list(frames(p,audit))
            self.assertNotIn('completeContainer',audit)

    def test_future_packet_cannot_change_prefix(self):
        m=Metrics(1,1000);p={'ts':900,'src':(2,50000),'flags':2,'seq':1,'ack':0,'payloadBytes':0,'ipBytes':40}
        m.add(p);before=m.report();m.add({**p,'ts':1001,'ipBytes':1500,'payloadBytes':1460})
        self.assertEqual(before,m.report())

    def test_snaplen_truncation_preserves_wire_header_lengths(self):
        ip=bytearray(20);ip[0]=0x45;ip[9]=6;struct.pack_into('!H',ip,2,1500);struct.pack_into('!II',ip,12,1,2)
        header=bytearray(20);header[12]=0x50;header[13]=0x18;struct.pack_into('!HH',header,0,80,55000)
        packet=tcp(1,ip+header+b'x'*216,1500,12,collections.Counter())
        self.assertEqual(packet['payloadBytes'],1460);self.assertFalse(packet['payloadFullyCaptured'])


class PcapngTests(unittest.TestCase):
    def block(self,kind,body,endian='<'):
        length=12+len(body)
        return struct.pack(endian+'II',kind,length)+body+struct.pack(endian+'I',length)

    def capture(self,endian='<',options=b'',ticks=1234567,ident=0):
        section=self.block(0x0a0d0d0a,struct.pack(endian+'IHHq',0x1a2b3c4d,1,0,-1),endian)
        interface=self.block(1,struct.pack(endian+'HHI',1,0,256)+options,endian)
        packet=self.block(6,struct.pack(endian+'IIIII',ident,ticks>>32,ticks&0xffffffff,3,5)+b'abc\0',endian)
        return section+interface+packet

    def parse(self,data):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'misnamed.pcap';p.write_bytes(data)
            audit={};rows=list(frames(p,audit));return rows,audit

    def test_pcapng_preserves_container_hash_and_captured_vs_wire_lengths(self):
        data=self.capture();rows,audit=self.parse(data)
        self.assertEqual(rows,[(1234567,b'abc',5,1)])
        self.assertTrue(audit['completeContainer'])
        self.assertEqual(audit['sha256'],hashlib.sha256(data).hexdigest())
        self.assertEqual(audit['snapTruncatedFrames'],1)

    def test_big_endian_binary_resolution_and_signed_offset(self):
        opts=struct.pack('>HH',9,1)+b'\x8a\0\0\0'+struct.pack('>HHq',14,8,-1)
        rows,audit=self.parse(self.capture('>',opts,ticks=1536))
        self.assertEqual(rows[0][0],500000)
        self.assertEqual(audit['timestampUnitsPerSecond'],1024)

    def test_submicrosecond_precision_loss_is_reported(self):
        opts=struct.pack('<HH',9,1)+b'\x09\0\0\0'
        rows,audit=self.parse(self.capture(options=opts,ticks=1000000001))
        self.assertEqual(rows[0][0],1000000)
        self.assertEqual(audit['subMicrosecondTimestamps'],1)

    def test_truncation_bad_trailer_and_unknown_interface_fail_closed(self):
        data=self.capture()
        for broken in [data[:-1],data[:-4]+struct.pack('<I',999),self.capture(ident=1)]:
            with self.subTest(bytes=len(broken)),self.assertRaises(ValueError):self.parse(broken)

    def test_multiple_capture_domains_cannot_be_silently_merged(self):
        for extra in [self.capture(),self.block(1,struct.pack('<HHI',1,0,256))]:
            with self.assertRaisesRegex(ValueError,'捕获域'):self.parse(self.capture()+extra)

    def test_untimed_packet_cannot_be_silently_skipped(self):
        with self.assertRaisesRegex(ValueError,'无时间包'):
            self.parse(self.capture()+self.block(3,struct.pack('<I',0)))
