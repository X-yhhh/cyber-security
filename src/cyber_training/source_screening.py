"""阶段 1 的有界公开来源审计；只读源文件，不训练、不评分、不读取既有 holdout。

网络入口只下载清单明确列出的公开成员，拒绝归档与可执行内容；报告只保存计数、
哈希和公开来源说明。PCAP—标签关联是起始包证据，完整分流与 v4 对拍留给阶段 2。
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

GIB = 1 << 30
MIB = 1 << 20
MAX_PILOT_BYTES = GIB
MAX_METADATA_BYTES = 16 * MIB
MAX_FILES = 32
MAX_SECONDS = 900
MAX_ROWS = 200_000
MAX_PACKETS = 5_000_000
PUBLIC_HOSTS = frozenset({"www.stratosphereips.org", "mcfp.felk.cvut.cz", "zenodo.org",
                         "research.unsw.edu.au", "www.unb.ca"})
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
              b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
IOT23_PREFIX = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
BENIGN_CAPTURES = {"CTU-Honeypot-Capture-4-1", "CTU-Honeypot-Capture-5-1", "CTU-Honeypot-Capture-7-1"}


def digest(path: Path) -> str:
    """流式读取内容计算 SHA-256；不加载或反序列化模型。"""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(MIB):
            h.update(chunk)
    return h.hexdigest()


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def save_json(path: Path, value) -> None:
    """独占创建报告；已有审计证据不得被重复运行覆盖。"""
    with path.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, ensure_ascii=False, indent=2, allow_nan=False)
        f.write("\n")


def validate_url(url: str) -> None:
    p = urllib.parse.urlsplit(url)
    if (p.scheme != "https" or p.hostname not in PUBLIC_HOSTS or p.port not in (None, 443)
            or p.username or p.password or p.query or p.fragment):
        raise ValueError("URL 必须是白名单内无凭据、无查询参数的公开 HTTPS 地址")


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    """重定向仍须留在已登记的公开域名内，不追随登录或签名下载地址。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_fetch_plan(plan: dict, mode: str) -> list[dict]:
    """下载前检查成员数、原始字节预算、扩展名及许可；不遍历或解压远端归档。"""
    if plan.get("version") != "source-screening-fetch-v1" or mode not in ("metadata", "pilot"):
        raise ValueError("不支持的清单或模式")
    files = [f for f in plan["files"] if f["kind"] == mode]
    if not files or len(files) > MAX_FILES:
        raise ValueError("成员数越界")
    names = set()
    total = 0
    for item in files:
        validate_url(item["url"])
        name = item["name"]
        if not name or Path(name).name != name or name in names or "\\" in name or name.startswith("."):
            raise ValueError("成员名重复或不安全")
        names.add(name)
        if type(item["maxBytes"]) is not int or not 0 < item["maxBytes"] <= MAX_PILOT_BYTES:
            raise ValueError("成员字节上限非法")
        if mode == "metadata" and item["maxBytes"] > 2 * MIB:
            raise ValueError("元数据成员过大")
        if mode == "pilot":
            if plan.get("sourceId") != "IoT-23/1.0.0" or not item["url"].startswith(IOT23_PREFIX):
                raise ValueError("pilot 超出本轮许可核对的官方 IoT-23 子集")
            if not name.endswith((".pcap", ".pcapng", ".log", ".labeled", ".csv", ".txt")):
                raise ValueError("pilot 禁止归档、可执行文件和脚本")
            expected = item.get("expectedBytes")
            if type(expected) is not int or not 0 < expected <= item["maxBytes"]:
                raise ValueError("pilot 必须预先登记精确成员字节数")
        total += item["maxBytes"]
    if total > (MAX_METADATA_BYTES if mode == "metadata" else MAX_PILOT_BYTES):
        raise ValueError("原始成员总预算越界")
    return files


def verify_license(review_path: Path, metadata_root: Path) -> dict:
    """复核许可决定绑定的发布方 FAQ、官方 DOI 和历史冲突原文；不凭布尔值放行。"""
    review = json.loads(review_path.read_text(encoding="utf-8"))
    if review.get("decision") != "ACCEPTED_ACADEMIC_ATTRIBUTED_SUBSET":
        raise ValueError("许可未解决")
    bodies = {}
    for item in review["evidence"]:
        path = metadata_root / item["file"]
        if Path(item["file"]).name != item["file"] or digest(path) != item["sha256"]:
            raise ValueError("许可证据哈希不符")
        bodies[item["role"]] = path.read_text(encoding="utf-8")
    if "You do not need to ask permission from us" not in bodies["publisher_faq"]:
        raise ValueError("缺少发布方明确许可")
    record = json.loads(bodies["official_doi"])
    if (record.get("id") != 4743746 or record["metadata"]["license"]["id"] != "cc-by-4.0"
            or record["metadata"]["version"] != "1.0.0"):
        raise ValueError("官方版本或许可不符")
    if "You need authorization from the Stratosphere Lab" not in bodies["historical_conflict"]:
        raise ValueError("没有保留历史冲突证据")
    if not review.get("citation") or review.get("scope") != "offline_public_iot23_subset_only":
        raise ValueError("缺少引用或限定用途")
    return review


def fetch(plan_path: Path, output: Path, mode: str, review_path: Path | None = None,
          metadata_root: Path | None = None, ca_file: Path | None = None) -> dict:
    """有界读取公开清单，成功与失败均留 manifest；失败成员不得充当完整证据。"""
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    files = validate_fetch_plan(plan, mode)
    if mode == "pilot":
        if review_path is None or metadata_root is None:
            raise ValueError("pilot 必须先复核许可证据")
        verify_license(review_path, metadata_root)
    output.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + MAX_SECONDS
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    opener = urllib.request.build_opener(PublicRedirect(), urllib.request.HTTPSHandler(context=context))
    results = []
    for item in files:
        entry = {"name": item["name"], "url": item["url"], "kind": mode, "status": "FAILED",
                 "bytes": 0, "sha256": None}
        results.append(entry)
        if time.monotonic() >= deadline:
            entry["error"] = "TOTAL_TIME_LIMIT"
            continue
        try:
            req = urllib.request.Request(item["url"], headers={"Accept-Encoding": "identity"})
            with opener.open(req, timeout=min(25, deadline - time.monotonic())) as response:
                validate_url(response.url)
                length = response.headers.get("Content-Length")
                if length and int(length) > item["maxBytes"]:
                    raise ValueError("MEMBER_BYTE_LIMIT")
                entry["contentLength"] = int(length) if length else None
                entry["lastModified"] = response.headers.get("Last-Modified")
                entry["etag"] = response.headers.get("ETag")
                with (output / item["name"]).open("xb") as dest:
                    while True:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("TOTAL_TIME_LIMIT")
                        chunk = response.read(min(MIB, item["maxBytes"] - entry["bytes"] + 1))
                        if not chunk:
                            break
                        if entry["bytes"] + len(chunk) > item["maxBytes"]:
                            raise ValueError("MEMBER_BYTE_LIMIT")
                        if entry["bytes"] == 0 and mode == "pilot" and chunk.startswith((b"PK", b"MZ", b"\x7fELF", b"\x1f\x8b")):
                            raise ValueError("ARCHIVE_OR_EXECUTABLE_CONTENT")
                        dest.write(chunk)
                        entry["bytes"] += len(chunk)
            if ((length and entry["bytes"] != int(length))
                    or (mode == "pilot" and entry["bytes"] != item["expectedBytes"])):
                raise ValueError("MEMBER_LENGTH_MISMATCH")
            entry.update(status="COMPLETE", sha256=digest(output / item["name"]))
        except urllib.error.HTTPError as e:
            entry["error"] = "HTTP_" + str(e.code)
        except (ValueError, TimeoutError, socket.timeout) as e:
            entry["error"] = str(e) if str(e).isupper() else type(e).__name__
        except (urllib.error.URLError, OSError) as e:
            entry["error"] = type(e).__name__
    report = {"version": "source-screening-fetch-report-v1", "mode": mode,
              "planSha256": digest(plan_path), "files": results,
              "licenseReviewSha256": digest(review_path) if mode == "pilot" else None,
              "caBundleSha256": digest(ca_file) if ca_file else None,
              "bytesWritten": sum(e["bytes"] for e in results),
              "complete": all(e["status"] == "COMPLETE" for e in results),
              "trainingExecuted": False, "predictionsExecuted": 0, "holdoutRead": False}
    save_json(output / "fetch-report.json", report)
    return report


def read_zeek(path: Path, deadline: float):
    """只解析发布方 TSV 数据，不执行脚本；字段或行数非法时拒绝整个审计。"""
    fields = None
    rows = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            if len(line) > 65536 or time.monotonic() >= deadline:
                raise ValueError("标签行或时间上限越界")
            if line.startswith("#fields"):
                fields = line.split()[1:]
                if len(set(fields)) != len(fields):
                    raise ValueError("字段重复")
            elif line.strip() and not line.startswith("#"):
                values = line.split()
                if fields is None or len(values) != len(fields):
                    raise ValueError("Zeek 字段数量不符")
                rows += 1
                if rows > MAX_ROWS:
                    raise ValueError("标签行数上限越界")
                yield dict(zip(fields, values))


def flow_key(row: dict):
    """以微秒起点及双向端点/协议关联；UID 不能代替时间与端点一致性检查。"""
    try:
        tick = Decimal(row["ts"]) * 1_000_000
        if not tick.is_finite() or tick < 0 or tick != tick.to_integral_value():
            raise ValueError("时间精度非法")
        endpoints = sorted([(str(ipaddress.ip_address(row["id.orig_h"])), int(row["id.orig_p"])),
                            (str(ipaddress.ip_address(row["id.resp_h"])), int(row["id.resp_p"]))])
        if any(not 0 <= p <= 65535 for _, p in endpoints):
            raise ValueError("端口非法")
        if row["proto"] not in ("tcp", "udp", "icmp"):
            raise ValueError("不支持的协议")
        return int(tick), row["proto"], tuple(endpoints)
    except (KeyError, InvalidOperation) as e:
        raise ValueError("缺少可关联的流字段") from e


def packet_key(data: bytes, tick: int):
    """仅查看 Ethernet/IP/TCP/UDP 头，不保存或分析载荷；不支持的包不猜造端点。"""
    if len(data) < 14:
        return None
    eth = int.from_bytes(data[12:14], "big")
    offset = 14
    for _ in range(2):
        if eth not in (0x8100, 0x88A8):
            break
        if len(data) < offset + 4:
            return None
        eth = int.from_bytes(data[offset + 2:offset + 4], "big")
        offset += 4
    if eth != 0x0800 or len(data) < offset + 20 or data[offset] >> 4 != 4:
        return None
    ihl = (data[offset] & 15) * 4
    if ihl < 20 or len(data) < offset + ihl or int.from_bytes(data[offset + 6:offset + 8], "big") & 0x1FFF:
        return None
    proto = {6: "tcp", 17: "udp"}.get(data[offset + 9])
    if not proto or len(data) < offset + ihl + 4:
        return None
    src = str(ipaddress.ip_address(data[offset + 12:offset + 16]))
    dst = str(ipaddress.ip_address(data[offset + 16:offset + 20]))
    sport, dport = struct.unpack(">HH", data[offset + ihl:offset + ihl + 4])
    return tick, proto, tuple(sorted(((src, sport), (dst, dport))))


def pcap_start_matches(path: Path, keys: set, deadline: float) -> tuple[set, dict]:
    """遍历有界经典 PCAP 验证流起始包；不是完整分流、标签传播或 v4 特征提取。"""
    found = set()
    packets = 0
    low = high = None
    with path.open("rb") as f:
        header = f.read(24)
        if len(header) != 24 or header[:4] not in PCAP_MAGIC:
            raise ValueError("不支持的 PCAP 容器")
        endian, scale = PCAP_MAGIC[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or linktype != 1 or snaplen > 16 * MIB:
            raise ValueError("不支持的 PCAP 版本、链路或 snaplen")
        size = path.stat().st_size
        while raw := f.read(16):
            packets += 1
            if len(raw) != 16 or packets > MAX_PACKETS or time.monotonic() >= deadline:
                raise ValueError("PCAP 截断、包数或时间上限越界")
            sec, frac, captured, wire = struct.unpack(endian + "IIII", raw)
            if frac * scale >= 1_000_000_000 or captured > snaplen or captured > wire or f.tell() + captured > size:
                raise ValueError("PCAP 记录长度或时间非法")
            data = f.read(min(128, captured))
            f.seek(captured - len(data), 1)
            tick = sec * 1_000_000 + frac * scale // 1000
            low = tick if low is None else min(low, tick)
            high = tick if high is None else max(high, tick)
            key = packet_key(data, tick)
            if key in keys:
                found.add(key)
    if not packets:
        raise ValueError("空 PCAP")
    def utc(tick):
        return datetime.fromtimestamp(tick / 1_000_000, timezone.utc).isoformat()
    return found, {"packets": packets, "firstUtc": utc(low), "lastUtc": utc(high),
                   "linkType": "Ethernet", "headerBytesInspectedPerPacketMax": 128}


def audit_scenario(pcap: Path, labels: Path, role: str) -> dict:
    """独立良性场景才可产生 Normal 候选；恶意场景中的 Benign/未匹配流保留 Unknown。"""
    if role not in ("dedicated_benign_device", "documented_malware_capture"):
        raise ValueError("场景角色必须有发布方证据")
    if pcap.stat().st_size + labels.stat().st_size > MAX_PILOT_BYTES:
        raise ValueError("场景原始字节超限")
    deadline = time.monotonic() + MAX_SECONDS
    grouped = defaultdict(list)
    labels_count = Counter()
    first = last = None
    required = {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "label", "detailed-label"}
    fields = None
    for row in read_zeek(labels, deadline):
        fields = sorted(row)
        if not required <= row.keys():
            raise ValueError("缺少逐流标签、时间或端点字段")
        key = flow_key(row)
        grouped[key].append((row["label"], row["detailed-label"]))
        labels_count[row["label"] + "|" + row["detailed-label"]] += 1
        first = key[0] if first is None else min(first, key[0])
        last = key[0] if last is None else max(last, key[0])
    if not grouped:
        raise ValueError("空标签文件")
    matches, capture = pcap_start_matches(pcap, set(grouped), deadline)
    decisions = Counter()
    protocols = Counter()
    sample = []
    for key, values in grouped.items():
        if len(values) != 1:
            target, reason = "Unknown", "duplicate_or_conflicting_flow_key"
        elif key not in matches:
            target, reason = "Unknown", "no_exact_tuple_start_packet"
        elif role == "dedicated_benign_device" and values[0][0].casefold() == "benign" and values[0][1] == "-":
            target, reason = "Normal_candidate", "publisher_benign_device_and_exact_packet"
        elif role == "documented_malware_capture" and values[0][0].casefold() == "malicious" and values[0][1] != "-":
            target, reason = "Attack_candidate", "publisher_detailed_flow_label_and_exact_packet"
        else:
            target, reason = "Unknown", "background_or_unconfirmed_label"
        decisions[target + "|" + reason] += len(values)
        protocols[target + "|" + key[1]] += len(values)
        if target != "Unknown" and len(sample) < 8:
            sample.append({"flowKeySha256": fingerprint(key), "label": target,
                           "publisherLabel": values[0][0], "publisherDetailedLabel": values[0][1], "basis": reason})
    return {"version": "source-screening-scenario-v1", "role": role,
            "pcapSha256": digest(pcap), "labelsSha256": digest(labels),
            "pcapBytes": pcap.stat().st_size, "labelBytes": labels.stat().st_size,
            "labelSchema": fields, "labelRows": sum(labels_count.values()), "publisherLabels": dict(labels_count),
            "uniqueKeys": len(grouped), "exactTupleStartPacketMatches": len(matches),
            "exactTupleStartPacketMatchRate": len(matches) / len(grouped),
            "labelFirstUtc": datetime.fromtimestamp(first / 1_000_000, timezone.utc).isoformat(),
            "labelLastUtc": datetime.fromtimestamp(last / 1_000_000, timezone.utc).isoformat(),
            "capture": capture, "decisions": dict(decisions), "auditSamples": sample,
            "candidateProtocolCounts": dict(protocols), "labelCaseNormalization": "casefold_only_on_explicit_publisher_coarse_label",
            "trainingEligibleRows": 0, "trustedLabelsHumanReviewed": False,
            "fullConnectionJoinVerified": False, "v4CompatibilityVerified": False,
            "trainingExecuted": False, "predictionsExecuted": 0, "holdoutRead": False}


def audit(fetch_root: Path, spec_path: Path, output: Path) -> dict:
    """先复核所有下载成员的长度和哈希，再审查选定场景；拒绝失败下载与修改后文件。"""
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    if spec.get("version") != "source-screening-scenarios-v1" or spec.get("sourceId") != "IoT-23/1.0.0":
        raise ValueError("不支持的场景审查范围")
    report = json.loads((fetch_root / "fetch-report.json").read_text(encoding="utf-8"))
    if not report["complete"] or report["mode"] != "pilot":
        raise ValueError("pilot 下载未完整通过")
    files = {}
    urls = {}
    for item in report["files"]:
        path = fetch_root / item["name"]
        if Path(item["name"]).name != item["name"] or path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            raise ValueError("源成员长度或哈希发生变化")
        files[item["name"]] = path
        urls[item["name"]] = item["url"]
    scenarios = []
    for item in spec["scenarios"]:
        capture_id = item["scenarioId"].split("/")[0]
        if (item["role"] == "dedicated_benign_device") != (capture_id in BENIGN_CAPTURES):
            raise ValueError("场景角色与发布方的独立良性场景清单不符")
        prefix = IOT23_PREFIX + item["scenarioId"] + "/"
        if not all(urls[item[key]].startswith(prefix) for key in ("pcap", "labels")):
            raise ValueError("PCAP 与标签不属于同一官方场景")
        scenario = audit_scenario(files[item["pcap"]], files[item["labels"]], item["role"])
        scenario["scenarioId"] = item["scenarioId"]
        scenarios.append(scenario)
    normal = sum(n for s in scenarios for k, n in s["decisions"].items() if k.startswith("Normal_candidate|"))
    attack = sum(n for s in scenarios for k, n in s["decisions"].items() if k.startswith("Attack_candidate|"))
    result = {"version": "source-screening-pilot-v2", "sourceId": spec["sourceId"],
              "auditorSha256": digest(Path(__file__)),
              "licenseReviewSha256": report["licenseReviewSha256"],
              "fetchReportSha256": digest(fetch_root / "fetch-report.json"), "scenarioSpecSha256": digest(spec_path),
              "scenarios": scenarios, "normalPilotCandidates": normal, "attackPilotCandidates": attack,
              "stage2Candidate": normal > 0 and attack > 0,
              "trainingEligibleRows": 0, "readinessStatus": "BLOCKED", "trainingAuthorized": False,
              "trainingExecuted": False, "predictionsExecuted": 0, "holdoutRead": False,
              "limitations": ["仅验证发布标签对应的双向端点、协议和微秒起始包，完整连接/分段 join 留待阶段 2。",
                              "良性证据来自独立设备场景与发布方说明，未将恶意场景的 Benign/背景改为 Normal。",
                              "尚未进行第二人标签复核、v4 兼容性、样本量门禁或独立活动分区，不能训练。"]}
    save_json(output, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("fetch")
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--mode", choices=("metadata", "pilot"), required=True)
    p.add_argument("--license-review", type=Path)
    p.add_argument("--metadata-root", type=Path)
    p.add_argument("--ca-file", type=Path, help="本次 HTTPS 校验使用的公开 CA bundle；不改系统信任库")
    p = sub.add_parser("audit")
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--spec", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "fetch":
        result = fetch(args.plan, args.out, args.mode, args.license_review, args.metadata_root, args.ca_file)
        print(json.dumps({"complete": result["complete"], "bytesWritten": result["bytesWritten"],
                          "files": [{"name": e["name"], "status": e["status"], "error": e.get("error")} for e in result["files"]]}))
        if not result["complete"]:
            raise SystemExit(2)
    else:
        result = audit(args.data, args.spec, args.out)
        print(json.dumps({k: result[k] for k in ("stage2Candidate", "normalPilotCandidates", "attackPilotCandidates", "trainingAuthorized")}))


if __name__ == "__main__":
    main()
