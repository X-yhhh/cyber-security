# 路线 B 阶段 7 训练端证据（影子验证基线）

来源运行：`baseline-v4-20260930-1525`（`python -m cyber_training.v2 baseline-v4`，compute → package → verify），代码提交 `7ea8836`。
本次在 macOS（Darwin arm64，Python 3.12.14，依赖版本与 `requirements.lock` 一致）上用同一代码与同一原始数据从 4 个原始 CSV 复现 v4 切分：
原始文件哈希、`d1_raw` 数据指纹、切分指纹 `6e950203…d70d2f4`、选中种子与切分审计 `d1_raw` 内容全部一致，两个 parquet 缓存的字节哈希也与训练主机一致。
D2 未在本机重算（不参与本基线）。win-dev 恢复后可在训练主机上重跑 `baseline-v4 --baseline-stage compute` 复算核对，结果应与 `feature-baseline-stats.json` 除 `source.code_commit`、`source.reproduction` 外完全相同。

只含字段级分箱边界、计数与核对结果，不含数据行、地址、绝对路径或权重；holdout 行位置只参与切分复现核对，不参与任何统计。
交付包本体在本机 `~/Workspace/deliveries/unsw-binary-2026.10.1/`，不入库。下表哈希按仓库中的 LF 字节计算（其余阶段的归档表记录的是训练主机 CRLF 字节）。

| 文件 | 内容 | SHA-256 |
|---|---|---|
| `feature-baseline-stats.json` | 写入 2026.10.1 manifest 的 `feature_baseline_stats` 块（原样） | `6cc7501122c186d4f8eb74de71a54700e0fcc13044d7dd883449cd6412645482` |
| `baseline-summary.md` | 行数、每字段箱数、切分核对与交付自校验摘要 | `7c10656e11af0f1d339a52615a043fced977e8382d42b2ad5c14bd3af07134ce` |
| `reproduction-check.json` | 复现核对明细（绑定项 / 参考项、缺失与异常计数） | `265e014c84fbb7d39ec5ff4210ccdf5865fa966f7ed33fe8a9f6f73fb4ebe6fb` |
| `delivery-check.json` | 2026.10.1 交付自校验（含 manifest 差异键） | `f628d0b1c850f9f6eec706b20c0efe5cea5dcf45b19ef78fa3d8896e202236b5` |
