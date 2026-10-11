#!/usr/bin/env python3
"""V24 后修复策略原文：按不可变摘要把 MySQL JSON 时期改动末位的 definition_json 换回原件字节。

V24 把 guard_decision_policy.definition_json 改为 LONGTEXT 原文存储，但既有行按当时的 JSON 文本转换，
MySQL 解析时已改动的双精度末位不会自动恢复。本工具只接受这样的修复：
- 原件的 RFC 8785 摘要等于该行登记的 definition_sha256；
- 库内文本与原件结构完全相同，数值只允许相等或相差 1 个 ULP（即 JSON 解析造成的末位变化）。
任何其他差异都拒绝，不改动该行。不改变策略语义、状态、审核记录或摘要列。
"""
import argparse
import binascii
import hashlib
import json
import math
from pathlib import Path
import sys

import rfc8785


def canonical(value):
    return rfc8785.dumps(value)


def ulp_equivalent(stored, original):
    """结构与非数值字段逐项相等；浮点数相等或互为相邻双精度数。"""
    if isinstance(original, bool) or original is None or isinstance(original, str):
        return stored == original and type(stored) is type(original)
    if isinstance(original, (int, float)):
        if isinstance(stored, bool) or not isinstance(stored, (int, float)):
            return False
        a, b = float(stored), float(original)
        return a == b or math.nextafter(b, math.inf) == a or math.nextafter(b, -math.inf) == a
    if isinstance(original, list):
        return isinstance(stored, list) and len(stored) == len(original) and all(map(ulp_equivalent, stored, original))
    if isinstance(original, dict):
        return isinstance(stored, dict) and stored.keys() == original.keys() and all(ulp_equivalent(stored[k], original[k]) for k in original)
    return False


def originals(paths):
    result = {}
    for path in paths:
        raw = canonical(json.loads(Path(path).read_bytes()))
        result[hashlib.sha256(raw).hexdigest()] = raw
    return result


def restore(query, schema, original_files):
    """query(sql, schema) 返回 mysql --batch --raw 输出字节。返回逐行结果；只修复摘要与 ULP 校验都通过的行。"""
    known = originals(original_files)
    rows = query("SELECT id,definition_sha256,HEX(definition_json) FROM guard_decision_policy ORDER BY id", schema)
    results = []
    for line in rows.decode().splitlines():
        row_id, digest, hex_text = line.split("\t")
        stored = binascii.unhexlify(hex_text)
        item = dict(id=int(row_id), definitionSha256=digest)
        if digest not in known:
            results.append(dict(item, status="no_original"))
            continue
        original = known[digest]
        if stored == original:
            results.append(dict(item, status="exact"))
            continue
        if not ulp_equivalent(json.loads(stored), json.loads(original)):
            results.append(dict(item, status="rejected_semantic_difference"))
            continue
        query(f"UPDATE guard_decision_policy SET definition_json=CONVERT(X'{original.hex()}' USING utf8mb4) "
              f"WHERE id={int(row_id)} AND definition_sha256='{digest}'", schema)
        after = binascii.unhexlify(query(f"SELECT HEX(definition_json) FROM guard_decision_policy WHERE id={int(row_id)}", schema).strip())
        if after != original:
            raise RuntimeError(f"policy {row_id} restore verification failed")
        results.append(dict(item, status="restored", storedSha256=hashlib.sha256(stored).hexdigest()))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mysql", type=Path, required=True, help="mysql 客户端；口令由 MYSQL_PWD 环境变量提供")
    parser.add_argument("--schema", required=True)
    parser.add_argument("--policy", type=Path, action="append", required=True, help="原件策略文件，可多次给出")
    args = parser.parse_args()
    import subprocess

    def query(sql, schema):
        p = subprocess.run([str(args.mysql), "--protocol=TCP", "--host=127.0.0.1", "--port=3306", "--user=root",
                            "--batch", "--raw", "--skip-column-names", schema], input=sql.encode(), capture_output=True, timeout=120)
        if p.returncode:
            raise RuntimeError("SQL operation failed; secret-bearing stderr suppressed")
        return p.stdout
    results = restore(query, args.schema, args.policy)
    print(json.dumps(results, ensure_ascii=False, indent=2))
    if any(r["status"] == "rejected_semantic_difference" for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
