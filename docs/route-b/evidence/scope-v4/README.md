# 开发路线阶段 1 A1：收窄评估范围的 unsw-binary-2026.10.2

命令：`PYTHONPATH=src python -m cyber_training.v2 scope-v4 --scope-stage package`（源交付 `unsw-binary-2026.10.1`）。
2026-10-01 在本机开发 Mac 上由训练分支同一代码生成（win-dev 离线）；win-dev 恢复后以 `--scope-stage verify` 复核。

- 变更：`feature_contract.supported_protocols = ["tcp"]`、`feature_contract.requires_handshake_seen = true`；
  评估范围为 responder + IPv4 + TCP + handshake_seen=true。`limitations` 追加范围说明，`provenance.derived_from`
  记录源版本、源 manifest SHA-256 与上一级派生链。
- 不变：model.onnx（`c87b883d…9358`）、preprocessing.json、阈值 0.3535（不可调）、fixtures、`feature_baseline_stats`。
  基线仍为 2026.10.1 的训练分区口径（responder + IPv4，全部协议）：UNSW CSV 没有逐包信息，无法按 handshake_seen 重算同口径基线。
- 自校验 14 项全部通过（`delivery-check.json`）：新 manifest SHA-256 `f2f3464b7af3218b75246454483eb490757b85b306f7ab8fa3b31ba685b2d52d`，
  checksums.json 21 项。
- main 仓库后端核对：ONNX fixtures 对拍通过；`ModelReplayCli` 1 万条最大概率误差 7.15e-7（≤ 1e-5），标签 100% 一致。

| 文件 | SHA-256 |
|---|---|
| `delivery-check.json` | `23c6eea56ce94457a8f8b693a2fe4325e7cd2159b8b0d272a0bb58873a5779d0` |
