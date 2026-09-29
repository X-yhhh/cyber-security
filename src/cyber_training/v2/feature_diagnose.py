"""路线 B §7.1.2 异常核查：F2→F3（`ct_*` 换成单主机重算值）的 Macro-F1 +0.021 是否来自主机身份捷径。

只读 train + validation，holdout 不读取。XGBoost 冻结参数、P1、单种子（消融中种子标准差 ≤ 0.0005，远小于待解释的 0.021）。
阈值统一在完整验证集上按 §7.3 选定，再在各子集上评估，避免子集各自选阈值造成的偏差。
变体：
- F2+单项：F2 中只把一个 `ct_*` 换成重算值，定位提升来源；
- F2+dst_host：F2 直接加目的主机编码（训练中未出现的主机记 -1），作主机身份上限对照；
- F3-组内置换：重算 `ct_*` 在（目的主机, 分区）内随机置换，保留每台主机的取值分布，破坏流级对应；
- F3-主机均值：重算 `ct_*` 换成该目的主机在训练行上的均值，只剩主机身份信息。
子集：验证集全部；目的主机 / 源主机未在训练分区出现的行。
"""

from __future__ import annotations

import json
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from . import GLOBAL_SEED
from .datasets import load_cached, load_manifest
from .feature_ablation import CT, PARAMS_RUN, VIEW_RUN, define_groups, load_frame
from .feature_audit import latest_split_dir
from .guard import SplitIndex
from .preprocess import SCHEME_BY_KEY, binary_metrics, build_preprocessor
from .runtime import RUNS_ROOT, RunContext, keep_awake, write_json
from .train import build_model, evaluate, release

SEED = GLOBAL_SEED


def shuffle_within(values: np.ndarray, groups: np.ndarray, seed: int) -> np.ndarray:
    """按组对行做同一随机置换（多列一起换）：保留组内联合分布，破坏行与取值的对应。"""
    rng = np.random.default_rng(seed)
    out = values.copy()
    order = np.argsort(groups, kind="stable")
    g = groups[order]
    bounds = np.flatnonzero(np.r_[True, g[1:] != g[:-1], True])
    for a, b in zip(bounds[:-1], bounds[1:]):
        idx = order[a:b]
        out[idx] = values[rng.permutation(idx)]
    return out


def host_mean(values: np.ndarray, groups: np.ndarray, train: np.ndarray) -> np.ndarray:
    """每行取所在组在训练行上的列均值；训练中未出现的组取训练总体均值。"""
    df = pd.DataFrame(values[train])
    df["g"] = groups[train]
    out = df.groupby("g").mean().reindex(groups).to_numpy()
    return np.where(np.isnan(out), np.nanmean(values[train], axis=0), out)


def subset_metrics(y: np.ndarray, prob: np.ndarray, threshold: float, mask: np.ndarray) -> dict[str, Any]:
    ys, ps = y[mask], prob[mask]
    out: dict[str, Any] = {"rows": int(mask.sum()), "attacks": int(ys.sum())}
    if not mask.any():
        return {**out, "macro_f1": np.nan, "fpr": np.nan, "fnr": np.nan, "pr_auc": np.nan}
    m = binary_metrics(ys, ps, threshold)
    both = len(np.unique(ys)) == 2
    return {**out, "macro_f1": m["macro_f1"] if both else np.nan, "fpr": m["fpr"],
            "fnr": m["fnr"] if ys.sum() else np.nan, "pr_auc": float(average_precision_score(ys, ps)) if both else np.nan}


def run() -> str:
    _, manifest = load_manifest()
    split_dir = latest_split_dir()
    audit_dir = sorted(RUNS_ROOT.glob("feature-audit-*/recomputed-cache.json"))[-1].parent
    v3 = json.loads((RUNS_ROOT / VIEW_RUN / "feature-views.json").read_text(encoding="utf-8"))["views"]["V3"]
    xgb = dict(json.loads((RUNS_ROOT / PARAMS_RUN / "model-selection.json").read_text(encoding="utf-8"))["params"]["XGBoost"])
    ctx = RunContext("feature-diagnose", SEED, {"split_dir": str(split_dir), "audit_dir": str(audit_dir), "xgboost": xgb})
    say = lambda m: (open(ctx.path("training.log"), "a", encoding="utf-8").write(m + "\n"), print(m, flush=True))  # noqa: E731
    split = SplitIndex.load(split_dir / "split-d1-raw.npz")  # 不传审计日志：holdout 无法解锁
    with keep_awake():
        frame, labels, _, ready = load_frame(manifest, audit_dir)
        ips = load_cached("d1_raw.parquet", manifest, columns=["srcip", "dstip"])
        codes, _ = pd.factorize(pd.concat([ips["srcip"], ips["dstip"]], ignore_index=True).astype("string"))
        n = len(frame)
        src, dst = codes[:n], codes[n:]
        del ips
        train = np.sort(split.train[ready[split.train]])
        val = np.sort(split.validation[ready[split.validation]])
        seen = np.zeros(codes.max() + 1, dtype=bool)
        seen[src[split.train]] = seen[dst[split.train]] = True
        seen_dst = np.zeros_like(seen)
        seen_dst[dst[split.train]] = True
        part = np.full(n, 2)
        part[split.train], part[split.validation] = 0, 1
        v4 = frame[[f"{c}_v4" for c in CT]].to_numpy(dtype=np.float64)
        shuf = shuffle_within(v4, dst * 3 + part, SEED)
        mean = host_mean(v4, dst, train)
        for i, c in enumerate(CT):
            frame[f"{c}_shuf"], frame[f"{c}_hmean"] = shuf[:, i].astype(np.float32), mean[:, i].astype(np.float32)
        frame["dst_host"] = np.where(seen_dst[dst], dst, -1).astype(np.float32)
        groups = define_groups(v3)
        f2 = [(c, c) for c, _ in groups["F2"]]
        f3 = [(c, f"{c}_v4" if s == "v4" else c) for c, s in groups["F3"]]
        variants = {"F2": f2, "F2-无ct": [(c, s) for c, s in f2 if c not in CT], "F3": f3}
        variants.update({f"F2+{c}": [(m, f"{m}_v4" if m == c else s) for m, s in f2] for c in CT})
        variants["F2+dst_host"] = f2 + [("dst_host", "dst_host")]
        variants["F3-组内置换"] = [(m, f"{m}_shuf" if m in CT else s) for m, s in f3]
        variants["F3-主机均值"] = [(m, f"{m}_hmean" if m in CT else s) for m, s in f3]
        y = labels[val]
        subsets = {"全部": np.ones(val.size, bool), "目的主机未见": ~seen[dst[val]], "源主机未见": ~seen[src[val]]}
        rows = []
        for name, spec in variants.items():
            cols, source = [c for c, _ in spec], [s for _, s in spec]
            pre = build_preprocessor(SCHEME_BY_KEY["P1"], SEED, cols)
            view = lambda r: frame.iloc[r][source].set_axis(cols, axis=1)  # noqa: E731
            xt = np.ascontiguousarray(pre.fit_transform(view(train)).astype(np.float32))
            xv = np.ascontiguousarray(pre.transform(view(val)).astype(np.float32))
            model = build_model("XGBoost", xgb, SEED)
            model.fit(xt, labels[train], xv, y)
            prob = model.predict(xv)
            thr = evaluate(y, prob)["threshold"]
            for sub, mask in subsets.items():
                rows.append({"variant": name, "subset": sub, "threshold": thr, **subset_metrics(y, prob, thr, mask)})
            release(model)
            say(f"{name}: macro_f1={rows[-3]['macro_f1']:.4f} fpr={rows[-3]['fpr']:.4%}")
    table = pd.DataFrame(rows)
    table.to_csv(ctx.path("diagnose.csv"), index=False)
    write_json(ctx.path("diagnose.json"), rows)
    ctx.finish()
    say(f"done: {ctx.run_dir}")
    return str(ctx.run_dir)
