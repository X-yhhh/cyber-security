"""路线 B 阶段 1 §7.1 第 1～3 项的训练端审计：公式对拍、单主机视角 ``ct_*`` 重算、``service`` 端口口径重算。

输入：经登记 manifest 校验的 ``d1_raw.parquet`` 与 ``split-d1-raw.npz``（行位置索引）。
约束：
- 不读取、不解锁 holdout；所有统计只在 train + validation 行上报告。
- ``ct_*`` 重算只使用流元数据（地址、端口、协议、时间），不使用标签，在去重前的完整时间轴上计算（路线 B D2）。
- 本步骤不训练模型、不修改切分，只输出审计报告与按行对齐的重算列缓存（位于 runs/，不入库）。
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from scipy import stats

from . import GLOBAL_SEED
from .datasets import load_cached, load_manifest
from .guard import SplitIndex
from .runtime import RUNS_ROOT, RunContext, keep_awake, sha256_file, write_json

WINDOW = 100
# D4 固定端口映射（按响应方端口，即 UNSW 的 dsport），与传感器探测脚本 window.go 完全一致。
PORT_MAP = {
    ("udp", 67): "dhcp", ("udp", 68): "dhcp", ("tcp", 53): "dns", ("udp", 53): "dns",
    ("tcp", 21): "ftp", ("tcp", 20): "ftp-data", ("tcp", 80): "http", ("tcp", 8080): "http",
    ("tcp", 6667): "irc", ("tcp", 110): "pop3", ("udp", 1812): "radius", ("udp", 1813): "radius",
    ("tcp", 25): "smtp", ("udp", 161): "snmp", ("udp", 162): "snmp", ("tcp", 22): "ssh", ("tcp", 443): "ssl",
}
CT_FIELDS = ("ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
             "ct_dst_src_ltm")
RAW_COLUMNS = ["srcip", "sport", "dstip", "dsport", "proto", "service", "dur", "sbytes", "dbytes", "Sload", "Dload",
               "Spkts", "Dpkts", "smeansz", "dmeansz", "Stime", "Ltime", "tcprtt", "synack", "ackdat", *CT_FIELDS]
# 与探测报告相同的退化判定：标准差 < 1，或众数占比 ≥ 95%。
DEGENERATE_STD, DEGENERATE_MODE = 1.0, 0.95


def service_v4(proto: pd.Series, port: pd.Series) -> pd.Series:
    """D4：只按 (协议, 响应方端口) 查固定映射表，未命中或非 TCP/UDP 取 ``-``；不读取原 Bro 识别值。"""
    proto = proto.astype("string").str.lower().fillna("")
    port = pd.to_numeric(port, errors="coerce")
    out = pd.Series("-", index=proto.index, dtype="object")
    for (p, n), name in PORT_MAP.items():
        out[(proto == p).to_numpy() & (port == n).to_numpy()] = name
    return out


def _classify(address: Any) -> tuple[bool, bool]:
    """返回 (是否合法 IPv4, 作为目的地址时是否按 D12 排除)。

    广播只能按地址判断：UNSW 各子网为 /24，因此末字节 255 视为子网广播（假设写入报告）。
    """
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        return False, True
    if ip.version != 4:
        return False, True
    bad = ip.is_multicast or ip.is_loopback or ip.is_unspecified or str(ip).endswith(".255")
    return True, bad


def _pair(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """把两列整数码合成一个紧凑整数码（先相乘再重新 factorize，避免溢出与稀疏）。"""
    return pd.factorize(a.astype(np.int64) * (int(b.max()) + 1) + b.astype(np.int64))[0]


def recompute_ct(raw: pd.DataFrame, window: int = WINDOW) -> pd.DataFrame:
    """按 D2 单主机视角重算 7 个 ``ct_*``，返回与 ``raw`` 按行对齐的结果。

    - 窗口：每个主机 h 的最近 ``window`` 条已完成流，成员为 h 作为源或目的的全部流（自环只计一次），
      按 (Ltime, Stime, 原始行号) 排序（UNSW 时间戳为秒级，行号作确定性 tie-break）。
    - 视角：每条流以响应方（dstip）为传感器主机，计数包含当前流自身；语义沿用 UNSW 原定义（src=发起方）。
    - 窗口未满、源地址非法或目的地址按 D12 排除时取 NaN（不造值）。
    """
    n = len(raw)
    codes, uniques = pd.factorize(pd.concat([raw["srcip"], raw["dstip"]], ignore_index=True).astype("string"))
    src, dst = codes[:n], codes[n:]
    cls = np.array([_classify(u) for u in uniques], dtype=bool).reshape(-1, 2)
    valid, bad_dst = cls[:, 0], cls[:, 1]
    included = valid[src] & ~bad_dst[dst]
    flows = np.flatnonzero(included)
    order = flows[np.lexsort((flows, raw["Stime"].to_numpy()[flows], raw["Ltime"].to_numpy()[flows]))]
    rank = np.empty(n, dtype=np.int64)
    rank[order] = np.arange(order.size)
    self_loop = src[order] == dst[order]
    m_flow = np.concatenate([order, order[~self_loop]])
    m_host = np.concatenate([src[order], dst[order][~self_loop]])
    idx = np.lexsort((rank[m_flow], m_host))
    m_flow, m_host = m_flow[idx], m_host[idx]
    start = np.r_[True, m_host[1:] != m_host[:-1]]
    group_first = np.maximum.accumulate(np.where(start, np.arange(m_host.size), 0))
    pos = np.arange(m_host.size) - group_first
    target = (m_host == dst[m_flow]) & (pos >= window - 1)

    svc = service_v4(raw["proto"], raw["dsport"])
    svc_code = pd.factorize(svc)[0]
    sport = pd.factorize(raw["sport"])[0]
    dsport = pd.factorize(raw["dsport"])[0]
    keys = {
        "ct_srv_src": _pair(svc_code, src), "ct_srv_dst": _pair(svc_code, dst),
        "ct_dst_ltm": dst, "ct_src_ltm": src, "ct_src_dport_ltm": _pair(src, dsport),
        "ct_dst_sport_ltm": _pair(dst, sport), "ct_dst_src_ltm": _pair(src, dst),
    }
    out = pd.DataFrame(index=raw.index)
    span = int(pos.max()) + 1 if pos.size else 1
    for name, key in keys.items():
        g = _pair(m_host, key[m_flow]).astype(np.int64)
        enc = g * span + pos
        ordered = np.sort(enc)
        hi = np.searchsorted(ordered, enc[target], side="right")
        lo = np.searchsorted(ordered, g[target] * span + (pos[target] - window + 1), side="left")
        values = np.full(n, np.nan)
        values[m_flow[target]] = hi - lo
        out[f"{name}_v4"] = values
    out["service_v4"] = svc.to_numpy()
    out["window_ready"] = ~np.isnan(out["ct_dst_ltm_v4"].to_numpy())
    out["excluded"] = ~included
    return out


def _share(mask: np.ndarray) -> float:
    return float(np.mean(mask)) if mask.size else float("nan")


def _rel_err(actual: np.ndarray, expected: np.ndarray) -> np.ndarray:
    return np.abs(actual - expected) / np.maximum(np.abs(expected), 1e-9)


def formula_checks(raw: pd.DataFrame) -> dict[str, Any]:
    """§4.3 D6/D7 与握手字段的公式假设在 CSV 上是否成立。只读，不改数据。"""
    f = {c: raw[c].to_numpy(dtype="float64") for c in ("dur", "sbytes", "dbytes", "Sload", "Dload", "Spkts",
                                                         "Dpkts", "smeansz", "dmeansz", "tcprtt", "synack",
                                                         "ackdat", "Stime", "Ltime")}
    proto = raw["proto"].astype("string").str.lower().to_numpy()
    pos = f["dur"] > 0
    out: dict[str, Any] = {"rows": int(len(raw))}
    for side, b, load in (("s", "sbytes", "Sload"), ("d", "dbytes", "Dload")):
        exp = f[b][pos] * 8 / f["dur"][pos]
        err = _rel_err(f[load][pos], exp)
        ratio = f[load][pos] / np.maximum(exp, 1e-9)
        out[f"{side}load_vs_bytes_x8_over_dur"] = {
            "rows_dur_gt_0": int(pos.sum()), "within_1pct": _share(err <= 0.01), "within_10pct": _share(err <= 0.10),
            "ratio_p5_p50_p95": [float(np.quantile(ratio, q)) for q in (0.05, 0.5, 0.95)] if ratio.size else None,
            "load_zero_when_dur_0": _share(f[load][~pos] == 0),
        }
    for side, b, p, m in (("s", "sbytes", "Spkts", "smeansz"), ("d", "dbytes", "Dpkts", "dmeansz")):
        has = f[p] > 0
        exp = f[b][has] / f[p][has]
        out[f"{side}mean_vs_bytes_over_pkts"] = {
            "rows_pkts_gt_0": int(has.sum()),
            "within_1_byte": _share(np.abs(f[m][has] - exp) <= 1.0),
            "equals_floor": _share(f[m][has] == np.floor(exp)), "equals_round": _share(f[m][has] == np.round(exp)),
            "mean_zero_when_pkts_0": _share(f[m][~has] == 0),
        }
    tcp = proto == "tcp"
    hs = tcp & (f["synack"] > 0) & (f["ackdat"] > 0)
    out["tcprtt_vs_synack_plus_ackdat"] = {
        "tcp_rows": int(tcp.sum()), "tcp_handshake_nonzero": _share(hs[tcp]),
        "within_1e-6": _share(np.abs(f["tcprtt"][hs] - f["synack"][hs] - f["ackdat"][hs]) <= 1e-6),
        "non_tcp_all_zero": _share((f["tcprtt"][~tcp] == 0) & (f["synack"][~tcp] == 0) & (f["ackdat"][~tcp] == 0)),
    }
    span = f["Ltime"] - f["Stime"]
    out["dur_vs_ltime_minus_stime"] = {"within_1s": _share(np.abs(f["dur"] - span) <= 1.0)}
    by_proto = {}
    for p in ("tcp", "udp"):
        d = f["dur"][proto == p]
        by_proto[p] = {"rows": int(d.size), "p99": float(np.quantile(d, 0.99)) if d.size else None,
                       "max": float(d.max()) if d.size else None, "share_gt_300s": _share(d > 300),
                       "share_gt_60s": _share(d > 60), "share_dur_0": _share(d == 0)}
    out["dur_by_proto"] = by_proto
    return out


def _dist(v: np.ndarray) -> dict[str, Any]:
    if not v.size:
        return {"n": 0}
    vals, counts = np.unique(v, return_counts=True)
    top = int(np.argmax(counts))
    std = float(v.std())
    mode_share = float(counts[top] / v.size)
    return {"n": int(v.size), "mean": float(v.mean()), "std": std,
            "p1_p50_p99": [float(np.quantile(v, q)) for q in (0.01, 0.5, 0.99)], "max": float(v.max()),
            "mode": float(vals[top]), "mode_share": mode_share,
            "degenerate": bool(std < DEGENERATE_STD or mode_share >= DEGENERATE_MODE)}


def compare_ct(raw: pd.DataFrame, re: pd.DataFrame, rows: np.ndarray) -> dict[str, Any]:
    """在给定行（train + validation）上对比 CSV 原列与单主机重算列；只统计窗口已满的行。"""
    ready = re["window_ready"].to_numpy()[rows]
    sel = rows[ready]
    out: dict[str, Any] = {"rows": int(rows.size), "window_ready_share": _share(ready),
                           "excluded_share": _share(re["excluded"].to_numpy()[rows])}
    for name in CT_FIELDS:
        a = raw[name].to_numpy(dtype="float64")[sel]
        b = re[f"{name}_v4"].to_numpy(dtype="float64")[sel]
        ks = stats.ks_2samp(a, b) if a.size else None
        rho = stats.spearmanr(a, b).statistic if a.size > 2 else float("nan")
        out[name] = {"csv": _dist(a), "v4": _dist(b), "ks": float(ks.statistic) if ks else None,
                     "exact_match": _share(a == b), "spearman": float(rho)}
    return out


def compare_service(raw: pd.DataFrame, re: pd.DataFrame, rows: np.ndarray) -> dict[str, Any]:
    """D4 端口口径与原 Bro 识别值的一致率，只作记录（路线 B §7.1 第 3 项）。"""
    orig = raw["service"].astype("string").fillna("-").to_numpy()[rows]
    v4 = re["service_v4"].to_numpy()[rows]
    pairs = pd.Series(list(zip(orig[orig != v4], v4[orig != v4]))).value_counts().head(15)
    dist = lambda x: {k: float(v) for k, v in pd.Series(x).value_counts(normalize=True).head(14).items()}  # noqa: E731
    return {"rows": int(rows.size), "agreement": _share(orig == v4), "csv_distribution": dist(orig),
            "v4_distribution": dist(v4), "top_disagreements": [[a, b, int(c)] for (a, b), c in pairs.items()]}


def _pct(v: Any) -> str:
    return "—" if v is None or (isinstance(v, float) and np.isnan(v)) else f"{100 * v:.2f}%"


def _num(v: Any) -> str:
    return "—" if v is None else f"{v:.4g}"


def render_report(fc: dict[str, Any], ct: dict[str, Any], svc: dict[str, Any], split_dir: str) -> str:
    """生成审计报告 Markdown。不含地址与单条流，只有字段级统计。"""
    L = ["# 路线 B §7.1 训练端特征审计（第 1～3 项）", "",
         f"数据：`d1_raw.parquet`（登记 manifest 校验通过）；切分：`{split_dir}`。统计只在 train + validation "
         f"共 {ct['rows']:,} 行上计算，holdout 未读取。", "", "## 1. 公式对拍（§4.3 D6、D7、握手字段）", "",
         "| 检查项 | 结果 |", "|---|---|"]
    for side in ("s", "d"):
        x = fc[f"{side}load_vs_bytes_x8_over_dur"]
        L.append(f"| `{side}load ≈ {side}bytes×8/dur`（dur>0，{x['rows_dur_gt_0']:,} 行） | 误差≤1%：{_pct(x['within_1pct'])}；"
                 f"≤10%：{_pct(x['within_10pct'])}；比值 p5/p50/p95 = "
                 f"{'/'.join(_num(r) for r in x['ratio_p5_p50_p95'] or [])}；dur=0 时 load=0：{_pct(x['load_zero_when_dur_0'])} |")
        m = fc[f"{side}mean_vs_bytes_over_pkts"]
        L.append(f"| `{side}mean ≈ {side}bytes/{side}pkts` | 误差≤1 字节：{_pct(m['within_1_byte'])}；等于向下取整："
                 f"{_pct(m['equals_floor'])}；等于四舍五入：{_pct(m['equals_round'])}；pkts=0 时 mean=0：{_pct(m['mean_zero_when_pkts_0'])} |")
    t = fc["tcprtt_vs_synack_plus_ackdat"]
    L.append(f"| `tcprtt = synack + ackdat`（TCP {t['tcp_rows']:,} 行） | 握手非零：{_pct(t['tcp_handshake_nonzero'])}；"
             f"等式误差≤1e-6：{_pct(t['within_1e-6'])}；非 TCP 三项全为 0：{_pct(t['non_tcp_all_zero'])} |")
    L.append(f"| `dur ≈ Ltime − Stime` | 误差≤1 s：{_pct(fc['dur_vs_ltime_minus_stime']['within_1s'])} |")
    for p, d in fc["dur_by_proto"].items():
        L.append(f"| `dur`（{p}，{d['rows']:,} 行） | p99 {_num(d['p99'])} s；最大 {_num(d['max'])} s；>60 s "
                 f"{_pct(d['share_gt_60s'])}；>300 s {_pct(d['share_gt_300s'])}；dur=0 {_pct(d['share_dur_0'])} |")
    L += ["", "## 2. 单主机视角 `ct_*` 重算（D2，响应方视角，窗口 100）", "",
          f"窗口已满：{_pct(ct['window_ready_share'])}；按 D12 排除：{_pct(ct['excluded_share'])}。以下只统计窗口已满的行。", "",
          "| 字段 | CSV 均值 | CSV 标准差 | 重算均值 | 重算标准差 | 重算众数占比 | KS | 逐行相等 | Spearman | 重算退化 |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|"]
    for name in CT_FIELDS:
        x = ct[name]
        L.append(f"| `{name}` | {_num(x['csv'].get('mean'))} | {_num(x['csv'].get('std'))} | {_num(x['v4'].get('mean'))} | "
                 f"{_num(x['v4'].get('std'))} | {_pct(x['v4'].get('mode_share'))} | {_num(x['ks'])} | {_pct(x['exact_match'])} | "
                 f"{_num(x['spearman'])} | {'是' if x['v4'].get('degenerate') else ''} |")
    L += ["", "退化判定与探测报告一致：标准差 < 1 或众数占比 ≥ 95%。", "",
          "## 3. `service` 端口口径重算（D4）", "", f"与原 Bro 识别值一致率：{_pct(svc['agreement'])}（只作记录）。", "",
          f"- 原值分布：{'，'.join(f'{k} {_pct(v)}' for k, v in svc['csv_distribution'].items())}",
          f"- 重算分布：{'，'.join(f'{k} {_pct(v)}' for k, v in svc['v4_distribution'].items())}",
          f"- 主要不一致（原值 → 重算）：{'；'.join(f'{a}→{b} {c:,}' for a, b, c in svc['top_disagreements'])}", ""]
    return "\n".join(L)


def latest_split_dir(runs_root: Path = RUNS_ROOT) -> Path:
    candidates = sorted(Path(runs_root).glob("split-*/split-d1-raw.npz"))
    if not candidates:
        raise FileNotFoundError("no split run found; run `python -m cyber_training.v2 split` first")
    return candidates[-1].parent


def run(seed: int = GLOBAL_SEED, split_dir: Path | None = None, manifest_path: Path | None = None) -> Path:
    """执行 §7.1 第 1～3 项审计。输出 ``feature-audit-*/``：报告、JSON 明细、按行对齐的重算列缓存。"""
    manifest_file, manifest = load_manifest(manifest_path)
    split_dir = Path(split_dir) if split_dir else latest_split_dir()
    ctx = RunContext("feature-audit", seed, {"register_manifest": str(manifest_file), "split_dir": str(split_dir),
                                             "window": WINDOW, "port_map": {f"{p}/{n}": s for (p, n), s in PORT_MAP.items()},
                                             "degenerate_std": DEGENERATE_STD, "degenerate_mode": DEGENERATE_MODE})
    log = ctx.path("training.log")

    def say(message: str) -> None:
        with log.open("a", encoding="utf-8") as stream:
            stream.write(message + "\n")
        print(message, flush=True)

    split = SplitIndex.load(split_dir / "split-d1-raw.npz")  # 不传审计日志：holdout 无法解锁
    rows = np.sort(np.concatenate([split.train, split.validation]))
    with keep_awake():
        say(f"loading d1_raw.parquet ({len(RAW_COLUMNS)} columns)")
        raw = load_cached("d1_raw.parquet", manifest, columns=RAW_COLUMNS)
        say(f"recomputing ct_* on {len(raw):,} rows (full timeline, metadata only)")
        re = recompute_ct(raw)
        cache = ctx.path("d1_raw-v4-recomputed.parquet")
        re.to_parquet(cache, index=False)
        say(f"formula checks and comparisons on {rows.size:,} train+validation rows")
        fc = formula_checks(raw.iloc[rows])
        ct = compare_ct(raw, re, rows)
        svc = compare_service(raw, re, rows)
    write_json(ctx.path("formula-checks.json"), fc)
    write_json(ctx.path("ct-comparison.json"), ct)
    write_json(ctx.path("service-agreement.json"), svc)
    write_json(ctx.path("recomputed-cache.json"), {"file": cache.name, "rows": int(len(re)),
                                                   "sha256": sha256_file(cache), "columns": list(re.columns)})
    ctx.path("feature-audit.md").write_text(render_report(fc, ct, svc, split_dir.name), encoding="utf-8")
    ctx.finish()
    say(f"done: {ctx.run_dir}")
    return ctx.run_dir
