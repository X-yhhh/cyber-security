# 模型版本库

本目录长期保存每一版模型的导出文件（ONNX 及其 manifest、预处理、校准）。规则：

- **ONNX 只在本机**：`*.onnx` 被 Git 忽略（GitHub LFS 额度不足，2026-10-21 用户决定），只保存在本机仓库的 `models/` 下；`registry.json`、manifest、`preprocessing.json`、`calibration.json`、`SHA256SUMS` 进 Git，用于核对本机文件。新克隆的仓库里没有 ONNX，`verify` 会报文件缺失。请自行备份本机 `models/`。

- **只追加**：一个模型版本（以 manifest 中的模型版本号区分）对应一个子目录，入库后文件设为只读，字节永不改写。新权重、新 manifest，或者只改了绑定的评价计划，都必须用新版本号重新入库。
- **退役不删除**：退役只把 `registry.json` 里的状态改为 `retired`，并记录时间和原因；目录与文件永久保留，历史推理记录可以按 `manifest_sha256` 追溯到原文件。
- **唯一写入口**：入库、退役和核验只用 [`scripts/models/model_store.py`](../scripts/models/model_store.py)，不要手工增删改本目录。

## 目录结构

```
models/
  registry.json              版本索引：版本号、契约版本、各文件 SHA-256、来源、状态、退役原因
  <模型版本号>/
    model-manifest.json      v5 manifest（旧 v4 为 model_manifest.json）
    model.onnx               后端加载的 ONNX（v5 为 opset 17，已内置数值预处理）
    preprocessing.json       train 拟合的预处理参数与类别词表
    calibration.json         校准参数（v5，可选）
    source-model.onnx        训练端导出、转换前的原件（opset 15，可选）
    SHA256SUMS               本目录逐文件摘要
```

## 用法

```bash
# 冻结完成后入库（--origin 写仓库相对路径或 ~ 开头的来源说明）
python3 -B scripts/models/model_store.py add --source <冻结目录> --origin <来源说明> --note "<说明>"

# 退役：只改状态，不删文件
python3 -B scripts/models/model_store.py retire --version <模型版本号> --reason "<原因>"

# 核验：索引与目录一一对应、每个文件字节未变
python3 -B scripts/models/model_store.py verify
```

入库前会按 manifest 声明的摘要核对 `model.onnx`、`preprocessing.json` 和 `calibration.json`，任何一项不符都拒绝写入。同一版本号再次入库时，内容一致视为幂等，内容不同则拒绝。

## 与后端挂载的关系

本目录是存档与唯一来源，**不是**后端挂载的根目录。后端只读取 `cyber.guard.artifact-root`（deploy 下为 `DEPLOY_ARTIFACT_ROOT`）下的文件：`GuardArtifacts` 按相对路径读文件并核对 SHA-256，`GuardModelRuntime` 读取 manifest 同目录的 `model.onnx` 并创建 ONNX Runtime 会话。发布新版本时，先把本目录中对应的版本文件只读复制到 artifact-root 下的发布包目录，再走 `/models` 登记、校验和发布组合审批。本目录的 `available`/`retired` 只是存档状态，模型是否在用以业务库中的发布组合与资产绑定为准。
