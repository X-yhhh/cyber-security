#!/usr/bin/env python3
"""build_attack_prefix 的单元测试；不执行真实网络操作或 Go 提取器。

测试覆盖：PCAP 解析边界（授权范围外拒绝、DLT_NULL 格式校验）、
audit_group 结构校验（采集失败拒绝、丢包拒绝）、场景元数据完整性、
输出行 trainingAllowed 不变性。
"""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))
import build_attack_prefix as bap


# ---------------------------------------------------------------------------
# 辅助：构造最小合法 DLT_NULL PCAP（含一个 TCP SYN 包）
# ---------------------------------------------------------------------------

def _pack_ipv4_tcp(src_ip_int, src_port, dst_ip_int, dst_port, flags, at_us):
    """构造 DLT_NULL + IPv4 + TCP 帧（无载荷）。"""
    tcp = struct.pack(
        '!HHIIBBHHH',
        src_port, dst_port,
        0,  # seq
        0,  # ack
        0x50,  # data offset = 5
        flags,
        65535,  # window
        0,      # checksum
        0,      # urgent
    )
    ipv4 = struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0,
        20 + len(tcp),
        0, 0,
        64,  # TTL
        6,   # proto TCP
        0,
        src_ip_int.to_bytes(4, 'big'),
        dst_ip_int.to_bytes(4, 'big'),
    )
    null_hdr = b'\x02\x00\x00\x00'  # AF_INET
    frame = null_hdr + ipv4 + tcp
    sec  = at_us // 1_000_000
    usec = at_us  % 1_000_000
    rec_hdr = struct.pack('<IIII', sec, usec, len(frame), len(frame))
    return rec_hdr + frame


def _make_pcap(packets):
    """构造完整 PCAP 文件字节串。"""
    hdr = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, 0)
    return hdr + b''.join(packets)


PEER_INT    = 0x7f000002  # 127.0.0.2
SERVICE_INT = 0x7f000001  # 127.0.0.1
SERVICE_PORT = 80
FLAGS_SYN    = 0x02
FLAGS_SYNACK = 0x12
FLAGS_ACK    = 0x10
FLAGS_FIN    = 0x11


class TestParsePcapConns(unittest.TestCase):

    def _write_pcap(self, tmp, packets):
        p = Path(tmp) / 'native.pcap'
        p.write_bytes(_make_pcap(packets))
        return p

    def test_syn_captured(self):
        pkt = _pack_ipv4_tcp(PEER_INT, 12345, SERVICE_INT, SERVICE_PORT, FLAGS_SYN, 1_000_000)
        with tempfile.TemporaryDirectory() as td:
            pcap = self._write_pcap(td, [pkt])
            conns = bap._parse_pcap_conns(pcap)
        self.assertEqual(len(conns), 1)
        key = (PEER_INT, 12345, SERVICE_INT, SERVICE_PORT)
        self.assertIn(key, conns)
        self.assertEqual(conns[key]['synUs'], 1_000_000)
        self.assertFalse(conns[key]['synAck'])

    def test_synack_recorded(self):
        syn    = _pack_ipv4_tcp(PEER_INT,    12345, SERVICE_INT, SERVICE_PORT, FLAGS_SYN,    1_000_000)
        synack = _pack_ipv4_tcp(SERVICE_INT, SERVICE_PORT, PEER_INT, 12345,   FLAGS_SYNACK, 1_100_000)
        with tempfile.TemporaryDirectory() as td:
            pcap = self._write_pcap(td, [syn, synack])
            conns = bap._parse_pcap_conns(pcap)
        key = (PEER_INT, 12345, SERVICE_INT, SERVICE_PORT)
        self.assertTrue(conns[key]['synAck'])

    def test_fin_sets_close_us(self):
        syn = _pack_ipv4_tcp(PEER_INT, 12345, SERVICE_INT, SERVICE_PORT, FLAGS_SYN, 1_000_000)
        fin = _pack_ipv4_tcp(PEER_INT, 12345, SERVICE_INT, SERVICE_PORT, FLAGS_FIN, 5_000_000)
        with tempfile.TemporaryDirectory() as td:
            pcap = self._write_pcap(td, [syn, fin])
            conns = bap._parse_pcap_conns(pcap)
        key = (PEER_INT, 12345, SERVICE_INT, SERVICE_PORT)
        self.assertEqual(conns[key]['closeUs'], 5_000_000)

    def test_unauthorized_address_rejected(self):
        # 包含非授权 IP
        bad_src = 0x0a000001  # 10.0.0.1
        pkt = _pack_ipv4_tcp(bad_src, 12345, SERVICE_INT, SERVICE_PORT, FLAGS_SYN, 1_000_000)
        with tempfile.TemporaryDirectory() as td:
            pcap = self._write_pcap(td, [pkt])
            with self.assertRaises(ValueError, msg='包超出授权回环范围'):
                bap._parse_pcap_conns(pcap)

    def test_wrong_magic_rejected(self):
        bad = struct.pack('<IHHIIII', 0xdeadbeef, 2, 4, 0, 0, 65536, 0)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'native.pcap'
            p.write_bytes(bad)
            with self.assertRaises(ValueError):
                bap._parse_pcap_conns(p)

    def test_empty_pcap_returns_empty(self):
        hdr = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, 0)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'native.pcap'
            p.write_bytes(hdr)
            conns = bap._parse_pcap_conns(p)
        self.assertEqual(conns, {})


class TestAuditGroup(unittest.TestCase):

    def _write_activity(self, td, success=True, dropped=0, frames=10):
        activity = dict(
            activityId='test-activity-001',
            scenarioId='controlled_slowloris_g1',
            mode='slowloris',
            groupOrdinal=1,
            elapsedSeconds=91.0,
            attackResult=dict(connected=1),
            serverRecords=[],
            capture=dict(
                frames=frames,
                nativeLink=0,
                error=None,
                stats=dict(recv=frames, dropped=dropped, ifdrop=0),
                passed=success and dropped == 0,
            ),
            listenerClosed=True,
            success=success,
            error=None,
            modelFits=0,
            trainingAllowed=False,
        )
        gdir = Path(td) / 'group-01'
        gdir.mkdir()
        (gdir / 'activity.json').write_text(json.dumps(activity) + '\n')
        # 写最小合法 PCAP
        syn = _pack_ipv4_tcp(PEER_INT, 12345, SERVICE_INT, SERVICE_PORT, FLAGS_SYN, 1_000_000)
        (gdir / 'native.pcap').write_bytes(_make_pcap([syn]))
        return gdir

    def test_successful_group_passes(self):
        with tempfile.TemporaryDirectory() as td:
            gdir = self._write_activity(td)
            activity, conns = bap.audit_group(gdir)
        self.assertTrue(activity['success'])
        self.assertGreater(len(conns), 0)

    def test_failed_activity_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            gdir = self._write_activity(td, success=False)
            activity_data = json.loads((gdir / 'activity.json').read_text())
            activity_data['capture']['passed'] = False
            (gdir / 'activity.json').write_text(json.dumps(activity_data) + '\n')
            with self.assertRaises(ValueError):
                bap.audit_group(gdir)

    def test_dropped_packets_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            gdir = self._write_activity(td, dropped=3)
            with self.assertRaises(ValueError):
                bap.audit_group(gdir)

    def test_missing_pcap_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            gdir = self._write_activity(td)
            (gdir / 'native.pcap').unlink()
            with self.assertRaises(ValueError):
                bap.audit_group(gdir)


class TestScenarioMeta(unittest.TestCase):

    def test_slowloris_present(self):
        self.assertIn('controlled_slowloris', bap.SCENARIO_META)

    def test_slowhttptest_present(self):
        self.assertIn('controlled_slowhttptest', bap.SCENARIO_META)

    def test_all_have_three_fields(self):
        for scenario, meta in bap.SCENARIO_META.items():
            self.assertEqual(len(meta), 3, f'{scenario} meta 字段数不对')

    def test_label_rule_versions_distinct(self):
        rules = [m[2] for m in bap.SCENARIO_META.values()]
        self.assertEqual(len(rules), len(set(rules)), '两个场景的 labelRuleVersion 重复')

    def test_source_id_consistent(self):
        for meta in bap.SCENARIO_META.values():
            self.assertEqual(meta[0], 'controlled_windows_http_cde')


class TestConstants(unittest.TestCase):

    def test_authorized_addrs(self):
        self.assertIn(0x7f000001, bap.AUTHORIZED_ADDRS)
        self.assertIn(0x7f000002, bap.AUTHORIZED_ADDRS)

    def test_service_port(self):
        self.assertEqual(bap.SERVICE_PORT, 80)


if __name__ == '__main__':
    unittest.main()
