# v2 第 3～8 步证据摘录

本目录从 Git 忽略的 `runs/` 中复制小体积、已审查（不含 IP、主机绝对路径、权重或原始数据）的证据文件，
文件名前缀为来源运行目录。原运行目录的完整产物与 `checksums.json` 保留在训练主机。

注意：以下运行的 `run-config.json` 记录的是运行时的上一个提交且 `dirty=true`（代码先运行、后提交）：
register → 061486a（代码提交于 bfc358f），split → bfc358f（代码提交于 7a825a7），
eda / preprocess → 7a825a7（代码提交于 7a825a7 / f9f11ac）。从第 7 步起改为先提交、再运行：feature-20260927-1249 记录提交 0a5f1c5（dirty=true 仅因当时未跟踪的 CLAUDE.md，代码与提交一致）。
第 8 步三个运行（train-screen-20260927-1354、train-tune-20260927-1425、train-seeds-20260927-1458）记录提交 bc0df4e 且 dirty=true：代码先运行、后提交，训练代码提交于本次归档提交。三个运行都用 `--resume` 补跑或重生成过报告（初筛补跑 DT/RF/ET；调优与复现只重写选择 JSON 以去掉主机路径），逐次结果 CSV 保留全部原始行。`train-seeds-20260927-1458-candidate.json` 只含候选模型的参数、阈值、特征列与文件哈希，模型权重与预处理器不提交。

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
| `train-screen-20260927-1354-model-screening.md` | `e8bab35355cd05d8b0f41d414dac7789ef48158b6011094a16bdb0754252cf49` |
| `train-screen-20260927-1354-screen-runs.csv` | `8c3c3f976acd4e122f329ea21c54605f674d4336727f87bf16384c5f0a111808` |
| `train-screen-20260927-1354-screen-selection.json` | `fdab78a2244c75faee74521a37a6dbfa3d202067d3c9fef623f2c4534434239a` |
| `train-screen-20260927-1354-screen-summary.csv` | `78892aa664996b1fa99a8641612c93d1d3f914cd31e253f494bed8967af3be6f` |
| `train-seeds-20260927-1458-candidate.json` | `5730e98bb9707697ee7b97cceb1df6f0024dc1a8ceabfa409e9a3952ffaf012a` |
| `train-seeds-20260927-1458-model-comparison.md` | `74a26f17d98598db13d4743806e460bdd1b1f612b677ffc0022fa2493b0864a9` |
| `train-seeds-20260927-1458-model-comparison.png` | `f6b2fe3599a3e4c7556e6849de887124a26c49175301f3e7807788bd3a4a29b2` |
| `train-seeds-20260927-1458-model-selection.json` | `f97664d596231189a64ca5cdfc239795f1de2c0348e3689bd9bb6350ee4a5d77` |
| `train-seeds-20260927-1458-seed-runs.csv` | `1769a43303441e5998cebb545db7da380c68361105a77ffb0daf37187be3a3a4` |
| `train-seeds-20260927-1458-seed-summary.csv` | `8e1ae2fc4bdb4da5f18dbc57a1268c39cc5f8fb9ff75a9928923488d8384b77f` |
| `train-tune-20260927-1425-model-tuning.md` | `3b78eb7c00477fbb8e52d0544f1f43f541dff7fec5aa29e741bfc2d86e2a98ae` |
| `train-tune-20260927-1425-tune-best.csv` | `759aca822226705854cd727bb002a7c92f6f5f9ef13df8a64e538b63ab3f1564` |
| `train-tune-20260927-1425-tune-selection.json` | `887124d77792945110743898c06ecf09a5c5b6d9361eaa24c97e7e44ba746400` |
| `train-tune-20260927-1425-tune-trials.csv` | `added103a5f74e9b2d6afc882283d9f328ab7ede4dd731f6c1b8bfbd469fc2d4` |
