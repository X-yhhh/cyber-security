# 路线 B 阶段 1 训练端证据

来源运行：`runs/feature-audit-20260929-1327`（公式对拍、`ct_*` 与 `service` 重算）、`runs/feature-ablation-20260929-1359`（F0～F5 消融与泛化对照）、`runs/feature-diagnose-20260929-1420`（F2→F3 异常核查，原文件名 `diagnose.csv`）。
只含字段级与模型级统计，不含地址、绝对路径、权重或数据行；重算列缓存本体（parquet）不入库，`recomputed-cache.json` 记录其 SHA-256。
所有统计只用 train + validation，holdout 未读取。结论见 main 仓库 `docs/路线B-可移植特征契约v4实施路线.md` §7.1.1～§7.2 与 `docs/特征规格-unsw-nb15-flow-v4.md`。

| 文件 | SHA-256 |
|---|---|
| `ablation-info.json` | `1a07e1f06a7f5248ec7606e2714d6e632d6ddedd6d7b5e0e9790e95f3c15ed28` |
| `ablation-runs.csv` | `0fd7c23680e55fcde26f4636169a60d52d9cc3f3e2e83d9e59ff8754f58e2bec` |
| `ablation-summary.csv` | `69e2c7c52999fc3412dc15ff97f00a951668e71337c6399625afa4ebdc75806c` |
| `ct-comparison.json` | `996a4854188ba66feb77f541538e3b1898226ca3db0bf951e4ab59325a7cf330` |
| `feature-ablation.md` | `413b70b212737213689e7c468231e8d9bc62aee9a82c1ab65e521addab7b2a74` |
| `feature-audit.md` | `35ffcafeced5ada918a5c364ac1e3b0b720b85e5660eb3d7c6b25f9d5b214ac2` |
| `feature-diagnose.csv` | `858d2f11f2a8918381cd0dfda42ecb1f78f0c24c3fceadcac89ad95352d66beb` |
| `formula-checks.json` | `a0ae9427cab01092153045c4be3c6c7d9e8e38054bd3190451dcfe1a0a3bd869` |
| `g1-gate-check.json` | `1ba4a6548e31ac3136679425d33ea5f42bd3f38ff7b4e8242d626a34d38586c1` |
| `generalization-validation.csv` | `4d241809ee4333b87af42a85000fdf3382f91185a8eb25375e7ad06faeb5b351` |
| `recomputed-cache.json` | `ec34bd6289e1bc09d70ee7fb2e2bbf40cfa3df292af4a2687db0d4a813fa27e6` |
| `service-agreement.json` | `6020ba9f35a771240c3b133a0a17adc9783df77403352ccfca02390aeab7812f` |
