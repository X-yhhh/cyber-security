import numpy as np
import pandas as pd
import pytest

from cyber_training.v2 import feature_audit as fa

KEYS = {
    "ct_srv_src": lambda r: (r["svc"], r["srcip"]), "ct_srv_dst": lambda r: (r["svc"], r["dstip"]),
    "ct_dst_ltm": lambda r: r["dstip"], "ct_src_ltm": lambda r: r["srcip"],
    "ct_src_dport_ltm": lambda r: (r["srcip"], r["dsport"]), "ct_dst_sport_ltm": lambda r: (r["dstip"], r["sport"]),
    "ct_dst_src_ltm": lambda r: (r["srcip"], r["dstip"]),
}


def synthetic(n=400, seed=0):
    rng = np.random.default_rng(seed)
    hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    stime = rng.integers(0, 60, n)
    frame = pd.DataFrame({
        "srcip": rng.choice(hosts + ["0"], n, p=[0.24, 0.24, 0.24, 0.24, 0.04]),
        "dstip": rng.choice(hosts + ["224.0.0.5", "10.0.0.255"], n, p=[0.23, 0.23, 0.23, 0.23, 0.04, 0.04]),
        "sport": rng.choice([1000, 2000, 3000], n), "dsport": rng.choice([22, 53, 80, 443, 9999], n),
        "proto": rng.choice(["tcp", "udp", "icmp"], n), "Stime": stime, "Ltime": stime + rng.integers(0, 5, n),
    })
    return frame


def brute_force(raw, window):
    svc = fa.service_v4(raw["proto"], raw["dsport"])
    rows = raw.assign(svc=svc.to_numpy())
    ok = []
    for i, r in rows.iterrows():
        valid, _ = fa._classify(r["srcip"])
        _, bad = fa._classify(r["dstip"])
        if valid and not bad:
            ok.append(i)
    ok.sort(key=lambda i: (rows.at[i, "Ltime"], rows.at[i, "Stime"], i))
    members: dict[str, list[int]] = {}
    out = {name: np.full(len(raw), np.nan) for name in KEYS}
    for i in ok:
        r = rows.loc[i]
        for h in {r["srcip"], r["dstip"]}:
            members.setdefault(h, []).append(i)
        win = members[r["dstip"]][-window:]
        if len(win) < window:
            continue
        for name, key in KEYS.items():
            out[name][i] = sum(key(rows.loc[j]) == key(r) for j in win)
    return out


def test_recompute_matches_brute_force():
    raw = synthetic()
    got = fa.recompute_ct(raw, window=5)
    want = brute_force(raw, 5)
    for name in KEYS:
        np.testing.assert_array_equal(got[f"{name}_v4"].to_numpy(), want[name], err_msg=name)
    assert got["window_ready"].any() and (~got["window_ready"]).any()


def test_exclusion_rules():
    raw = synthetic()
    got = fa.recompute_ct(raw, window=5)
    bad = raw["dstip"].isin(["224.0.0.5", "10.0.0.255"]) | (raw["srcip"] == "0")
    assert got["excluded"].to_numpy().tolist() == bad.to_numpy().tolist()
    assert got.loc[bad.to_numpy(), "ct_dst_ltm_v4"].isna().all()


def test_service_v4_port_map():
    proto = pd.Series(["tcp", "udp", "udp", "tcp", "icmp", "tcp", "udp"])
    port = pd.Series([443, 443, 53, 8080, 53, 12345, 67])
    assert fa.service_v4(proto, port).tolist() == ["ssl", "-", "dns", "http", "-", "-", "dhcp"]


def test_formula_checks_on_consistent_rows():
    raw = pd.DataFrame({
        "dur": [1.0, 0.0, 2.0], "sbytes": [100, 60, 400], "dbytes": [50, 0, 200], "Spkts": [2, 1, 4], "Dpkts": [1, 0, 2],
        "proto": ["tcp", "udp", "tcp"], "synack": [0.1, 0.0, 0.2], "ackdat": [0.05, 0.0, 0.1], "Stime": [0, 5, 10],
        "Ltime": [1, 5, 12],
    })
    raw["Sload"] = np.where(raw["dur"] > 0, raw["sbytes"] * 8 / raw["dur"].replace(0, 1), 0.0)
    raw["Dload"] = np.where(raw["dur"] > 0, raw["dbytes"] * 8 / raw["dur"].replace(0, 1), 0.0)
    raw["smeansz"] = raw["sbytes"] // raw["Spkts"]
    raw["dmeansz"] = np.where(raw["Dpkts"] > 0, raw["dbytes"] // raw["Dpkts"].replace(0, 1), 0)
    raw["tcprtt"] = raw["synack"] + raw["ackdat"]
    out = fa.formula_checks(raw)
    assert out["sload_vs_bytes_x8_over_dur"]["within_1pct"] == pytest.approx(1.0)
    assert out["sload_vs_bytes_x8_over_dur"]["load_zero_when_dur_0"] == pytest.approx(1.0)
    assert out["smean_vs_bytes_over_pkts"]["equals_floor"] == pytest.approx(1.0)
    assert out["tcprtt_vs_synack_plus_ackdat"]["within_1e-6"] == pytest.approx(1.0)
    assert out["dur_vs_ltime_minus_stime"]["within_1s"] == pytest.approx(1.0)
