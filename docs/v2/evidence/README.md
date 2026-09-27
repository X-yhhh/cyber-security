# v2 第 3～10 步证据摘录

本目录从 Git 忽略的 `runs/` 中复制小体积、已审查（不含 IP、主机绝对路径、权重或原始数据）的证据文件，
文件名前缀为来源运行目录。原运行目录的完整产物与 `checksums.json` 保留在训练主机。

注意：以下运行的 `run-config.json` 记录的是运行时的上一个提交且 `dirty=true`（代码先运行、后提交）：
register → 061486a（代码提交于 bfc358f），split → bfc358f（代码提交于 7a825a7），
eda / preprocess → 7a825a7（代码提交于 7a825a7 / f9f11ac）。从第 7 步起改为先提交、再运行：feature-20260927-1249 记录提交 0a5f1c5（dirty=true 仅因当时未跟踪的 CLAUDE.md，代码与提交一致）。
第 8 步三个运行（train-screen-20260927-1354、train-tune-20260927-1425、train-seeds-20260927-1458）记录提交 bc0df4e 且 dirty=true：代码先运行、后提交，训练代码提交于本次归档提交。三个运行都用 `--resume` 补跑或重生成过报告（初筛补跑 DT/RF/ET；调优与复现只重写选择 JSON 以去掉主机路径），逐次结果 CSV 保留全部原始行。`train-seeds-20260927-1458-candidate.json` 只含候选模型的参数、阈值、特征列与文件哈希，模型权重与预处理器不提交。
第 8b 步运行 train-multiclass-20260927-1632 记录提交 22f7a0a 且 dirty=true：代码先运行、后提交，多分类代码提交于本次归档提交。`train-multiclass-20260927-1632-candidate.json` 只含 T2 候选模型的参数、类别映射、特征列与文件哈希，模型与预处理器不提交；官方测试文件未读取。
第 9 步运行 final-eval-20260927-1800 记录提交 bb25a99（dirty=false）：代码与冻结文件 `docs/v2/pre-final-freeze.json` 在解锁前已提交。`final-eval-20260927-1800-holdout-audit.jsonl` 是训练主机 `runs/holdout-audit.jsonl` 的副本，记录全部 holdout 解锁事件。
第 10 步运行 export-20260927-1912 记录提交 c067169（dirty=false）：代码先提交、后运行。只摘录报告、manifest、预处理契约与校验结果；`model.onnx` 与 `replay-sample.csv`（1 万条验证分区原始字段）不提交，SHA-256 记录在 manifest 中。

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
| `train-multiclass-20260927-1632-candidate.json` | `d63459266f58311bb710aa73980f0ba85f1786dd7884a0b34c3b660c0bb1840d` |
| `train-multiclass-20260927-1632-confusion-LightGBM-cw.csv` | `396410e3e3ad85b963624e400a8fc504008bdec8f147cc6cb3661c30b90ef8b7` |
| `train-multiclass-20260927-1632-confusion-selected.png` | `2e9ecb7685a28b2258f89f1b0f6eb227caf28cad0c3fc31e017d172ad08ca6e2` |
| `train-multiclass-20260927-1632-multiclass-report.md` | `0a94a2a0cf94d7c60853796e2d83e2ae1d25bdc0395bb9125c6008d97500cd30` |
| `train-multiclass-20260927-1632-multiclass-runs.csv` | `9bbf65627540701044f524dcc6e10578dc95f6c1cc06bb57bfaf089ba129ea77` |
| `train-multiclass-20260927-1632-multiclass-selection.json` | `3e1b2fff0417dfd1ccba21c2c505b0bd35a92af67233dc02eaea03f4d3db7c32` |
| `train-multiclass-20260927-1632-per-class-LightGBM-cw.csv` | `44d145fb2a493bc2cc4ff7aedb5eab9f896dae23311450dfc9d3a3230873dea8` |
| `final-eval-20260927-1800-final-evaluation.md` | `5a59d659ae36880f34edcb4785e5db0dcd42884eb97d378c712fec183ef65272` |
| `final-eval-20260927-1800-final-verdict.json` | `eaa37954cce2fb7df129bab03f1e3b525e253b06b9a60855fecb59c8debae5a3` |
| `final-eval-20260927-1800-generalization.csv` | `f982d3f331304dda77f61cb3dcd899a2bc2ee9bae24169f55155d560c8454ea2` |
| `final-eval-20260927-1800-holdout-audit.jsonl` | `342d0ba7547e06a0887f3d4f108f7dd5d679b738489be87669cb9d02eb87c314` |
| `final-eval-20260927-1800-t1-holdout-category-recall.csv` | `d850c8385d204a68bf59d6cc6b36b70a851faa86b0c6479c1d9a1b386cb34503` |
| `final-eval-20260927-1800-t1-holdout-metrics.json` | `be14e29baaacbc13a4fecda0bdb4b7758206315332e56fc9481afc83afc31721` |
| `final-eval-20260927-1800-t1-roc-pr.png` | `5cf63e646cbf561df8213b9634d89ceeabdc6e24c9062641814458a61b6ade76` |
| `final-eval-20260927-1800-t1-threshold-sensitivity.csv` | `b41f3a31fc055c0e4672a676947ea10269a0d500057bd955aca351d44059973d` |
| `final-eval-20260927-1800-t1-threshold-sensitivity.png` | `bbeb97cd53eb231d907c5b885686c3f6fd6bb44f3797ceb96003b4245c3b8d99` |
| `final-eval-20260927-1800-t2-test-confusion.csv` | `54d171dea6f56634a774fdde4b001d15d1e0b1a6c6125eb45787c81c56ad6870` |
| `final-eval-20260927-1800-t2-test-confusion.png` | `5fccfb48aca9bd857dddeb9355cb2e7a4aed8465b1032a606274bdfb8d16a27c` |
| `final-eval-20260927-1800-t2-test-metrics.json` | `99271124fef55aba49cc85c9a53f48ca8025a64de30a06789bea8e2245a80636` |
| `final-eval-20260927-1800-t2-test-per-class.csv` | `05d0c57ab667cbc1b73c26b844ab9faad0d68dbcb22afca9d5425514c8bb1541` |
| `export-20260927-1912-evaluation-report.md` | `18e8afbf2c7cfbd85e66e439cd8723e22bb80c261c1542b0b4071ba32322b98b` |
| `export-20260927-1912-export-parity.json` | `456a3cff601bf5370abf088b765596bdd7f58febf9a5d253563fd93bb0ec9c64` |
| `export-20260927-1912-export-performance.json` | `0d423b0462d241085c3a4df15e83ef73f490bbe41e7a442aa77bce30793a05b8` |
| `export-20260927-1912-export-verdict.json` | `2134b7c718e139ecacd4e93ebe203386c69e31bc73d6ec2d746dfe1a1cc7f37b` |
| `export-20260927-1912-model_manifest.json` | `bdd307f7d8c29d92b620661a456f05c58bcaa0e85ccec9787567bfd6d0a6d87f` |
| `export-20260927-1912-preprocessing.json` | `9f626a23caa8645e9384c4f1be76f015254fe97ff839afeaab2238c9ced264f1` |
