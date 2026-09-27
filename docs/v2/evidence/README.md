# v2 第 3～7 步证据摘录

本目录从 Git 忽略的 `runs/` 中复制小体积、已审查（不含 IP、主机绝对路径、权重或原始数据）的证据文件，
文件名前缀为来源运行目录。原运行目录的完整产物与 `checksums.json` 保留在训练主机。

注意：以下运行的 `run-config.json` 记录的是运行时的上一个提交且 `dirty=true`（代码先运行、后提交）：
register → 061486a（代码提交于 bfc358f），split → bfc358f（代码提交于 7a825a7），
eda / preprocess → 7a825a7（代码提交于 7a825a7 / f9f11ac）。从第 7 步起改为先提交、再运行：feature-20260927-1249 记录提交 0a5f1c5（dirty=true 仅因当时未跟踪的 CLAUDE.md，代码与提交一致）。

| 文件 | SHA-256 |
|---|---|
| `eda-20260926-2231-d1-high-correlation-pairs.csv` | `5d4cb2a50c99fe6b72e39db4881940ef67627f957a25c6b5f822ca28878a1206` |
| `eda-20260926-2231-d1-mutual-information.csv` | `44807ce1cd4e2b6b329e3e98a74b8645dbc9fdabea26e20e864786aad72e76d6` |
| `eda-20260926-2231-eda-summary.json` | `c9d09880020e0f266fa54ce8c2152b5ee5495383409852644b81abc548d346de` |
| `preprocess-20260926-2250-preprocessing-comparison.md` | `d484a46a1b66d3403ded3372b71480e8730f615a22b6faccdde1ab956eb723e1` |
| `preprocess-20260926-2250-preprocessing-selection.json` | `70de753cfff23e017448fdb1334be7c222f1dce1090129b695bcae07161f9d6d` |
| `preprocess-20260926-2250-preprocessing-summary.csv` | `ef4884fff5ae962bef534d0aa4879dee00ec95b457a8ae2058b09b6acb619eb9` |
| `register-20260926-2019-dataset-manifest.json` | `a9cb06f9e16f8bca319d6bb93d4f4e5669d454a9f4b6ad6dab5420185ed5ca32` |
| `split-20260926-2119-split-audit.json` | `5eb1025abbfc5bc0aec0f78567f35017619811a2326e2576b7549385d3acbe7b` |
| `feature-20260927-1249-feature-comparison.md` | `fb53eb791a8053a04c96140fe9560c416fc4c99e564601cfb60e9455e8113c1a` |
| `feature-20260927-1249-feature-runs.csv` | `6c788f08cd6212cdbd396da1fa9dfbe897e5621fc52ab70b2cccd0eab13a6945` |
| `feature-20260927-1249-feature-selection.json` | `043fe8912ab3f46952483c2b37f5e6c032faac1cf06f074d9d3293b142559ed7` |
| `feature-20260927-1249-feature-summary.csv` | `5b5893868204a33bc0a4562aea4cc7c5ce64fbd15192a4dd37ec2a467e5dac4d` |
| `feature-20260927-1249-feature-views.json` | `56f90b087827a399c423e0831b4a133ba3e8a869443bdc22015ad7eee8f8e0f8` |
| `feature-20260927-1249-v2-importance.csv` | `e5f5d50c28a2081a1e597846fce11cbe90691a5102d8dbab896757a031318b08` |
