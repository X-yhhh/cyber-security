# 阶段 2：CIC-IDS2017 数据审核与冻结模型基线

> 文档性质：已完成的历史审查与验证集基线报告，不是当前候选数据的训练批准或新模型结果。当前 gate 与实施顺序以[训练仓库路线](../model-readiness-roadmap.md)为准；阶段二运行证据和失败状态保留在本目录。

本目录对应应用路线计划 A2～A4，不是 A5 新模型训练。前端、线上部署、处置执行器、CSE-CIC-IDS2018 评分和任何 holdout 预测均不在本次执行范围内。

## 冻结与数据边界

- `label-rules-cic2017-v1.json` 是按官方说明及 Engelen CNS 2022 修订标签写成的本项目流级规则；`label-freeze-v1.json` 绑定哈希。本轮用户允许只读文件 + SHA-256 替代提交门禁，审计后再提交；没有提交或推送。
- 原始 PCAP、排序头部 PCAP、旁路、SQLite、JSONL、模型交付包只保存在 Git 外。原始公开抓包可能含载荷；工具生成的头部文件和标签旁路不保存载荷内容。
- v4 特征必须由应用仓库同源 `sensor extract` 产生，标签旁路只是关联依据。不能把 CICFlowMeter CSV 的字段改名当成 v4，也不能把 v4 IP 字节和当作 TCP 载荷长度。
- 只采用 responder/IPv4/TCP/初始 SYN 可见流。单条长连接或仅有一组的类别不能拆到 train/validation/holdout 冒充独立样本。
- `threshold-method-v2.md` 和对应冻结记录在 CIC validation 评分之前固定门槛计算方法；公式常数是项目选择，不是模型效果保证。

## 执行入口

设置 `PYTHONPATH=src`，使用受控的数据和交付目录。完整准备由 `scripts/phase2_prepare_cic2017.py` 驱动：等待下载 `.ok` 标记，重新核验 MD5/SHA-256，审查全部接口和时间，稳定排序，仅对两台登记服务器提取/标注。规则与工具二进制哈希不符时拒绝复用。

```sh
python -m cyber_training.phase2 label --records records.jsonl --audit audit.label-audit.jsonl \
  --rules docs/phase2/label-rules-cic2017-v1.json --freeze docs/phase2/label-freeze-v1.json \
  --out day-host.labelled.jsonl --index index.sqlite --report day-host.labels.json
python -m cyber_training.phase2 review --data "$CIC_DATA_DIR" \
  --rules docs/phase2/label-rules-cic2017-v1.json --out "$PHASE2_RUN_DIR/dataset-review.json"
python -m cyber_training.phase2 split --review "$PHASE2_RUN_DIR/dataset-review.json" \
  --input Monday-50.labelled.jsonl --input Monday-51.labelled.jsonl \
  --input Tuesday-50.labelled.jsonl --input Tuesday-51.labelled.jsonl \
  --input Wednesday-50.labelled.jsonl --input Wednesday-51.labelled.jsonl \
  --input Thursday-50.labelled.jsonl --input Thursday-51.labelled.jsonl \
  --input Friday-50.labelled.jsonl --input Friday-51.labelled.jsonl --out "$PHASE2_RUN_DIR/split"
python -m cyber_training.phase2 baseline --split "$PHASE2_RUN_DIR/split" \
  --delivery "$MODEL_DELIVERY_V4_DIR" --out "$PHASE2_RUN_DIR/validation-baseline.json"
python -m cyber_training.phase2 freeze-thresholds --baseline "$PHASE2_RUN_DIR/validation-baseline.json" \
  --out "$PHASE2_RUN_DIR/restoration-gates.json"
```

正式门槛采用交付 manifest 已验证的 Windows Python 3.12 / ONNX Runtime 1.23.2 基线。macOS 上较新运行时只做诊断；准备器输出 `awaiting_validated_runtime_baseline` 时，需把仅 validation 文件及切分登记传入 Windows 复核，holdout 不传、不读。

### 跨平台复核交接

`export-validation` 只复制 validation、切分登记和诊断基线到新的独占目录，并生成文件 SHA-256 清单，不遍历其他分区。传输该目录后，在 Windows 先校验，再将结果写到包外的新路径，保持交接包不可变：

```sh
python -m cyber_training.phase2 export-validation --split "$PHASE2_RUN_DIR/split" \
  --diagnostic "$PHASE2_RUN_DIR/validation-baseline.json" --out "$TRANSFER_DIR"
python -m cyber_training.phase2 verify-validation-bundle --bundle "$TRANSFER_DIR"
python -m cyber_training.phase2 baseline --split "$TRANSFER_DIR" \
  --delivery "$MODEL_DELIVERY_V4_DIR" --out "$WINDOWS_BASELINE_FILE"
python -m cyber_training.phase2 compare-baselines \
  --diagnostic "$TRANSFER_DIR/diagnostic-baseline.json" --validated "$WINDOWS_BASELINE_FILE" \
  --out "$RUNTIME_COMPARISON_FILE"
python -m cyber_training.phase2 freeze-thresholds --baseline "$WINDOWS_BASELINE_FILE" \
  --out "$RESTORATION_GATES_FILE"
```

仅在比对 `status=passed` 后执行最后的冻结。切分、validation、模型、manifest、范围、方法身份及混淆矩阵必须一致，聚合指标容差为 `1e-5`，逐类样本数与判定比例须相同；该结果不代替逐样本概率对拍。失败时保留诊断，不修改基线来消除差异。传输包哈希证明本次传输完整性，不证明第三方真实性。目录有额外文件、符号链接、身份不符或切分未通过均拒绝。

也可使用 `scripts/phase2_finish_cic2017.py --data ... --delivery ... --out ...` 等待准备完成后顺序执行。所有正式结果文件不覆盖；失败前缀不能当成功数据复用。只在验证输入与输出哈希后恢复已完成步骤，部分写入失败需保留证据并用新的输出位置重做。

## 如何判断“兼容且可用于训练”

审核器不仅看文件可读：记录来源、许可、大小/哈希、日期、完整链路、公开攻击窗口对应流量、全部诊断、标签/排除计数、作者修正版数量对比及无效记录的具体原因。镜像 MD5 一致加内容交叉核验不是官方原件签名，报告明确保留此证据边界。

排序不改时间值、头部长度或 MTU。`oversize_tcp_packets` 是整份抓包流表的 D11 归一化计数，不是入模坏样本数；它与 `post_close_packets` 都须结合流关闭规则解释。`window_not_ready` 是每主机各地址族 100 流窗口预热。已证实的单向续段 `initiatorRawPackets=0` 对应 `spkts>=1` 门禁，保持 rejected/excluded；其他拒绝保持阻塞。

切分先排除冲突标签，合并重复/六位小数近重复连接组，再去精确重复并分组分层。报告全部冻结攻击类的缺口，而非只检查幸存类别。按用户明确批准，Heartbleed 单独列为不可评估类别，其样本不进入任何训练/验证/测试分区；evaluation-scope-v1.json 及冻结哈希限定该例外，其他类别没有自动豁免。`ready` 才允许正式冻结门槛；`blocked_category_coverage` 仍可运行 validation **诊断**基线，但不能把诊断当作阶段出口通过。holdout 的分布统计用于切分审核，不包含模型预测或效果指标。

CLI 和自动流程共用适用性阻塞检查；仅类别覆盖缺口允许继续诊断切分，来源/端点不符、容量丢弃或未解释异常不能通过换入口绕过。正式冻结会再次核对方法文件及基线模型身份，并从混淆矩阵重新计算 Wilson 区间，拒绝基线 JSON 中不一致或非有限的计数/区间；不改变事先冻结的数值公式。

本数据只支持限定范围内的离线二分类研究。旧模型 validation 失效不等于 PCAP 无法用于新模型训练；反过来，特征兼容也不保证现有模型可用。未覆盖类别、少样本类别、2017 年单一实验域与少量主机限制必须写入最终能力边界。

## 验证

```sh
PYTHONPATH=src PHASE2_BASELINE_DELIVERY="$MODEL_DELIVERY_V4_DIR" python -m pytest \
  tests/test_phase2_labels.py tests/test_phase2_split.py tests/test_phase2_baseline.py tests/test_phase2_review.py
```

跨平台白名单交接、拒绝篡改及身份/计数漂移回归：`PYTHONPATH=src python -m pytest tests/test_phase2_transfer.py`。

实际 ONNX 测试仅用交付包 fixtures，验证字段顺序、判定一致和只读 validation；fixture 判定作为测试标签，不是效果评估。Windows Python 3.12 使用同一代码快照和真实 ONNX 验证，原训练仓库代码与运行产物保留。POSIX `000`/Windows 只读属性不是密码学封存，训练流程仍须遵守未解锁、不评分及追加审计规则。

## 2026-10-01 原范围全量运行结果（保留中间阻塞历史）

五天抓包完整性与内容检查、十组提取/标注均已执行，见 `phase2-download-verification-20261001.json` 与 `cic2017-dataset-review.json`。确定标签 428,991 条，精确去重 148,341 条，切分后 280,650 条。`cic2017-split.json` 为 `blocked_category_coverage`，唯一未获豁免的缺失类别是 XSS；18 个达到包数条件候选中 17 个 max_lifetime、1 个攻击边界，证据见 `phase2-xss-coverage-review-20261001.json`。其他类别偏差见 `phase2-category-exclusions-20261001.json`。

现有 `2026.10.2` 在 41,820 条 validation 的 macOS 诊断 FPR 1.2723%、召回 38.0367%、Macro-F1 0.33076；只反映当前范围，不能当作正式 Windows 基线。Windows 26 个 v7 文件哈希相同、16 项工具测试通过。正式 validation 交接及阈值冻结因切分门禁未通过而停止；`cic2017-gate-verification.json` 记录实际拒绝且没有生成门槛文件。

holdout 仅生成/封存，0 次预测，CSE-2018 未读取，无拟合或阈值变化。XSS 不可评估例外尚未授权；后续即使获批范围变化，也必须登记当前 validation 已暴露的事实，保留 v1/v2 冻结方法及所有旧切分，不重新声称首次评分前冻结。

## 用户批准 XSS 例外后的最终结果

`evaluation-scope-v2.json`/对应 freeze 绑定 Heartbleed 和 XSS 两类例外，明确记录首次 validation 已暴露；没有改动标签、v4、数值方法 v2 或切分种子。v2 重新生成的三个分区内容哈希均与原结果一致，状态 ready，证据在 `final-v2/scope-amendment-check.json`。因此无须为了范围登记变化重抽数据；重抽反而可能引入评分后挑选。

Windows 正式基线在 Python 3.12.10 / ORT 1.23.2 运行：41,820 条、FPR 1.2723%、召回 38.0367%、Macro-F1 0.33076；Mac/Windows 计数、逐类比例一致，聚合误差 <1e-5。门槛正式冻结为 L2 FPR≤3%、recall≥80%、Normal≥1000/Attack≥100；L3 FPR≤2%、新独立时段 Normal≥1000。L1 和恢复所需审批/接入条件不变。

最终审查、切分、Windows 基线、跨平台比对、门槛及 SHA-256 清单见 `final-v2/`。A2～A4 已完成，holdout 仍为 0 次预测，CSE-2018 未读取；这不表示旧模型满足门槛或新模型已训练。16 项流程测试在本机与 Windows 均通过。本轮没有 Git 提交/推送、部署或真实处置。
