# P3-B 收口辅助脚本

本目录保存 P3-B 收口时实际运行过的两个辅助脚本，内容与运行时逐字节一致，仅用于追溯，不是新的训练入口。当前训练入口见 `src/cyber_training/host_guard/`。

收口证据 `.cache/p3b-20261007/closeout-v1|v2/checksums.json` 按运行时路径登记了它们的 SHA-256；入库后路径变化，哈希不变：

| 证据中的路径 | 入库路径 | SHA-256 |
|---|---|---|
| `scratch/p3b_payload/closeout_report.py` | `scripts/p3/closeout_report.py` | `65d8c449bf83da6f6ebe4cdeab177b24e03989aecb42ae302bc97f55ce308461` |
| `scratch/p3b_payload/prepare_sidecars.py` | `scripts/p3/prepare_sidecars.py` | `5f5ef33c98b8aacdc7e9fd5c59e66684b2ac65dfc148f1f9e0d7637f1d68b1c9` |

运行时它们与 `multiclass_train.py` 等模块平铺在同一目录（`from multiclass_train import ...`），对应模块现位于 `src/cyber_training/host_guard/`，内容与当时的副本一致。
