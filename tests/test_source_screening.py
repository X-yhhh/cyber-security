"""验证阶段 1 的字节/许可/完整性门禁以及 Unknown 边界，不接公网或训练数据。"""
import json
import struct
import time
from pathlib import Path

import pytest

from cyber_training import source_screening as s


def plan(mode="pilot", size=1024, name="test.pcap"):
    return {"version": "source-screening-fetch-v1", "sourceId": "IoT-23/1.0.0", "files": [
        {"kind": mode, "name": name, "url": s.IOT23_PREFIX + "test/" + name,
         "maxBytes": size, "expectedBytes": size}]}


def packet(src="192.0.2.1", dst="192.0.2.2", sport=12345, dport=443):
    import ipaddress
    ethernet = bytes(12) + b"\x08\x00"
    ip = b"\x45\x00" + struct.pack(">H", 40) + bytes(5) + b"\x06" + bytes(2)
    ip += ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
    tcp = struct.pack(">HH", sport, dport) + bytes(16)
    return ethernet + ip + tcp


def fixture(tmp_path, labels, duplicate=False):
    pcap = tmp_path / "test.pcap"
    data = packet()
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
                     + struct.pack("<IIII", 1700000000, 123456, len(data), len(data)) + data)
    log = tmp_path / "conn.log.labeled"
    header = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tlabel\tdetailed-label\n"
    body = "1700000000.123456\tuid1\t192.0.2.1\t12345\t192.0.2.2\t443\ttcp\t" + labels + "\n"
    log.write_text(header + body * (2 if duplicate else 1), encoding="utf-8")
    return pcap, log


def test_download_budget_rejected_before_network():
    p = plan(size=s.GIB)
    p["files"].append({**p["files"][0], "name": "second.pcap"})
    with pytest.raises(ValueError, match="总预算"):
        s.validate_fetch_plan(p, "pilot")


@pytest.mark.parametrize("name", ["../trace.pcap", "a\\trace.pcap", "data.zip", "payload.exe", "source.py", ".hidden.pcap"])
def test_no_archive_executable_or_path_escape(name):
    with pytest.raises(ValueError):
        s.validate_fetch_plan(plan(name=name), "pilot")


@pytest.mark.parametrize("url", ["http://www.stratosphereips.org/", "https://login.microsoftonline.com/",
                                  "https://secret@zenodo.org/", "https://zenodo.org/?token=secret"])
def test_no_credentials_or_external_redirect(url):
    with pytest.raises(ValueError):
        s.validate_url(url)
    with pytest.raises(ValueError):
        s.PublicRedirect().redirect_request(None, None, 302, "", {}, url)


def test_reject_unpinned_size_and_other_source():
    p = plan()
    del p["files"][0]["expectedBytes"]
    with pytest.raises(ValueError, match="精确"):
        s.validate_fetch_plan(p, "pilot")
    p = plan()
    p["files"][0]["url"] = "https://zenodo.org/other.pcap"
    with pytest.raises(ValueError, match="子集"):
        s.validate_fetch_plan(p, "pilot")


def test_pilot_cannot_start_without_license(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan()), encoding="utf-8")
    with pytest.raises(ValueError, match="许可证据"):
        s.fetch(path, tmp_path / "output", "pilot")
    assert not (tmp_path / "output").exists()


def test_license_binding_rejects_modified_evidence(tmp_path):
    file = tmp_path / "faq.html"
    file.write_text("original", encoding="utf-8")
    review = {"decision": "ACCEPTED_ACADEMIC_ATTRIBUTED_SUBSET", "evidence": [
        {"file": "faq.html", "sha256": s.digest(file), "role": "publisher_faq"}]}
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(review), encoding="utf-8")
    file.write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="哈希"):
        s.verify_license(review_path, tmp_path)


def test_duplicate_or_conflict_stays_unknown(tmp_path):
    pcap, log = fixture(tmp_path, "Benign\t-", duplicate=True)
    report = s.audit_scenario(pcap, log, "dedicated_benign_device")
    assert report["decisions"] == {"Unknown|duplicate_or_conflicting_flow_key": 2}
    assert report["trainingEligibleRows"] == 0


@pytest.mark.parametrize("label", ["Benign\t-", "benign\t-"])
def test_benign_in_malicious_capture_never_becomes_normal(tmp_path, label):
    pcap, log = fixture(tmp_path, label)
    report = s.audit_scenario(pcap, log, "documented_malware_capture")
    assert report["decisions"] == {"Unknown|background_or_unconfirmed_label": 1}


@pytest.mark.parametrize("label,role,expected", [
    ("Benign\t-", "dedicated_benign_device", "Normal_candidate"),
    ("benign\t-", "dedicated_benign_device", "Normal_candidate"),
    ("Malicious\tC&C", "documented_malware_capture", "Attack_candidate")])
def test_exact_tuple_time_evidence_is_candidate_only(tmp_path, label, role, expected):
    pcap, log = fixture(tmp_path, label)
    report = s.audit_scenario(pcap, log, role)
    assert report["exactTupleStartPacketMatches"] == 1
    assert next(iter(report["decisions"])).startswith(expected)
    assert report["trainingEligibleRows"] == 0
    assert report["v4CompatibilityVerified"] is False
    assert "192.0.2." not in json.dumps(report["auditSamples"])
    log.write_text(log.read_text().replace("123456", "123457"), encoding="utf-8")
    report = s.audit_scenario(pcap, log, role)
    assert report["decisions"] == {"Unknown|no_exact_tuple_start_packet": 1}


def test_truncated_pcap_fails_audit(tmp_path):
    pcap, log = fixture(tmp_path, "Benign\t-")
    pcap.write_bytes(pcap.read_bytes()[:-1])
    with pytest.raises(ValueError, match="长度"):
        s.audit_scenario(pcap, log, "dedicated_benign_device")


def test_packet_and_time_caps_fail_closed(tmp_path, monkeypatch):
    pcap, log = fixture(tmp_path, "Benign\t-")
    with pytest.raises(ValueError, match="时间上限"):
        s.pcap_start_matches(pcap, set(), time.monotonic() - 1)
    monkeypatch.setattr(s, "MAX_PACKETS", 0)
    with pytest.raises(ValueError, match="包数"):
        s.pcap_start_matches(pcap, set(), time.monotonic() + 60)


def test_output_evidence_is_never_overwritten(tmp_path):
    path = tmp_path / "report.json"
    s.save_json(path, {"first": True})
    with pytest.raises(FileExistsError):
        s.save_json(path, {"second": True})
    assert json.loads(path.read_text()) == {"first": True}


def test_stream_budget_rejects_lying_content_length(tmp_path, monkeypatch):
    import io
    class Response(io.BytesIO):
        url = s.IOT23_PREFIX + "test/test.txt"
        headers = {"Content-Length": "2"}
    class Opener:
        def open(self, *args, **kwargs):
            return Response(b"123")
    monkeypatch.setattr(s.urllib.request, "build_opener", lambda *handlers: Opener())
    p = plan(mode="metadata", size=2, name="test.txt")
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(p), encoding="utf-8")
    report = s.fetch(path, tmp_path / "output", "metadata")
    assert report["complete"] is False
    assert report["files"][0]["error"] == "MEMBER_BYTE_LIMIT"
    assert report["files"][0]["sha256"] is None
    assert report["bytesWritten"] == 0
