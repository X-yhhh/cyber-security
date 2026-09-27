# Java 后端模型回放证据（2026-09-27）

本证据记录训练交付目录在 macOS 本机由 Java 后端运行时完成的独立回放。回放只读取离线 CSV 和 ONNX 制品，不连接数据库、网络或真实资产。

## 输入与命令

- 交付目录：`/Users/xyh/Workspace/deliveries/unsw-binary-2026.09.0`
- 输入样本：`replay-sample.csv`，10,000 条
- 运行时：ONNX Runtime Java `1.23.2`，CPU，单线程 batch 上限 1024
- 命令：`java --enable-native-access=ALL-UNNAMED -cp <backend-classpath> com.xyh.cybersecurity.model.ModelReplayCli /Users/xyh/Workspace/deliveries/unsw-binary-2026.09.0`

## 结果

| 门槛 | 实测 | 结果 |
| --- | ---: | --- |
| 回放样本数 | 10,000 | 通过 |
| 最大概率绝对误差 | `9.5367431640625e-7` | 通过（≤ `1e-4`） |
| 平均概率绝对误差 | `4.83393669128418e-9` | 记录 |
| 标签不一致 | 0 | 通过（100% 一致） |
| 逐位概率相同 | 9,757 / 10,000 | 记录 |
| 总运行时间 | 0.264412875 秒 | 记录 |

逐行对照结果写入交付目录 `backend-replay-results.csv`，摘要已追加到 `evaluation-report.md`，并同步更新 `checksums.json` 中的报告哈希。回放证实 Java 运行时与训练端交付输出满足本轮 parity 门槛；它不代表独立发布审批已通过，也不代表模型已经激活。

## 交付文件 SHA-256

| 文件 | SHA-256 |
| --- | --- |
| `model.onnx` | `ce1b3831e58963bcd10ee1aa88ce51d1c0bf8579e34b58871e124955dd3e882b` |
| `model_manifest.json` | `bdd307f7d8c29d92b620661a456f05c58bcaa0e85ccec9787567bfd6d0a6d87f` |
| `replay-sample.csv` | `8c4ea301d857a622d1f18aecc38635da052c3789da3e971824fbae744f894188` |
| `backend-replay-results.csv` | `4c11f989df565f0a0b6668422646990e8dd23b9bd933ccf69380f08d629339a5` |
| `evaluation-report.md` | `fa0f9f89752bb455eb219f22d84faf7e9829a387bf078acff63a4be015a1c6ab` |
| `checksums.json` | `3f818b6dc87291731a81dcd1978789c3c14728938e5fd58269e5d960ce07784a` |
