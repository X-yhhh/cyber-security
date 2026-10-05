# P3 来源组修复与重新冻结

日期：2026-10-05。范围是复用既有原件的离线修复、构建、归组和训练入口核验；不续用已结束的采集授权。本次来源标识修复完成，P3阶段仍未通过，新增模型拟合0次。原始PCAP、旧冻结、历史阶段裁决及既有权重保留。

## 1. 对图片中根因的复核

图片提出的来源粒度问题确实存在：两个受控场景的六轮活动共享一个 `sourceId`。但原冻结 `prefix-corpus-v1/partitions.json` 并未产生任何 `shared_source_context_150s` 归并边。原始包复核的五段组间隔为155.607233—155.682445秒，均超过150秒。

真实合并来自 `whole_parent_quantized_sequence`：每个场景的3轮、共12个parent，都命中同一个完整有序粗粒度特征序列。两种场景分别形成一个防泄漏组，合计4条归并边。全语料另有TAARA一条、旧良性活动三条近重复归并边，共8条；270次parent匹配不等于270个独立活动或归并边。

因此，`split=independent_development` 与“属于防泄漏组”不冲突：前者是角色，后者决定不能拆分的关联单位。不同来源名称、不同PCAP哈希、不同boot均不能单独证明特征序列独立。

## 2. 已实施修复

- [受控构建器](../../scripts/p3/build_attack_prefix.py)按场景与登记轮次生成 `controlled_slowloris_g1..g3` 和 `controlled_slowhttptest_g1..g3`。核对registration、complete、activity和捕获；缺组、重复身份、非法轮次、同PCAP改名或隔离不足在提取前拒绝。
- 保留共同的 `sourceDomainId/contextSourceId`。来源组计数为6，采集域仍为1；这些旁路字段不进入模型张量。
- [冻结器](../../scripts/p3/freeze_prefix_corpus.py)与[统一校验器](../../scripts/p3/verify_prefix_corpus.py)新增来源组/活动/防泄漏组与合并原因摘要。分区版本递增为 `prefix-corpus-partition-v4`，分配种子继续使用v3，避免因报告版本变化重洗角色。
- 完整parent近重复、共同捕获域150秒隔离、角色类别和场景准入保持原规则。校验器从真实文件复算，不能仅改 `trainingAllowed` 获准训练。

本机输入为六份已核验DLT_NULL原件，复用已验证的Mac提取器；生成 `p3-cde-qualified-attack-v2`。特征、上下文、质量、时刻、标签及起点与旧324条观察逐项一致；仅来源元数据和新运行的身份引用变化。所有PCAP哈希未变。

## 3. 新冻结结果

新输出位于忽略目录 `artifacts/p3-source-repair-20261005-01/`，语料目录为 `prefix-corpus-v2`。它是新文件路径，内部版本为 `prefix-corpus-partition-v4`；不覆盖旧文件。

| 项目 | 实际结果 |
|---|---:|
| 合格prefix / parent | 50,606 / 12,751 |
| 攻击 / 良性prefix | 50,100 / 506 |
| 活动 / 防泄漏组 | 28 / 18 |
| 受控来源组 / 受控防泄漏组 | 6 / 2 |
| 独立开发攻击 / 良性组 | 3 / 9 |
| 校准攻击prefix | 0 |
| 跨角色parent / 活动 / 近重复 | 0 / 0 / 0 |
| 新拟合 / 最终测试读取 | 0 / false |

6组的prefix数分别为36、36、36、72、72、72。新旧分区的全部角色、组ID和归并边相同，P6封存清单逐字节不变。整体完整性通过，但训练入口保持拒绝。

## 4. 后续工作的准确边界

当前仍有三类实质约束：独立开发攻击组3个而门槛为5；校准无攻击样本；当前五个来源场景各只有一个防泄漏组，不能各自覆盖四个互斥开发角色。把已有组挪到校准会减少独立开发组，复制、换名或按parent拆组均不能同时解决。

后续先版本化区分行为场景和来源域，明确逐场景声明及角色分配，再补充对应的真实独立活动；来源明细与失败场景仍须逐项报告。若保持现有五个来源场景全部覆盖四角色的规则，必须取得每个来源场景各自额外的合格活动，不能把其他来源改名补位。新的受控活动需有实际不同且预登记的请求/业务轨迹、长期困难良性对照和当前采集授权；只有标识、开始时间或随机抖动不同不足以解除现有近重复关系。

本次没有擅自改变场景口径、近重复判据或最低组数，也没有执行新采集。原有P3-D预算、逐场景80%目标、零正常机会误伤、E5和新ONNX跨平台对拍继续有效；P6封存材料仍不进入开发。代码修复和数据完整性通过均不等于模型可行性或自动执行资格通过。

## 5. 双平台验证与保护核验

本机22项相关回归通过；Windows的同一组22项回归及4项既有训练准入回归通过，共26项。归组回归覆盖不同来源名下的相同序列、共同域150秒内的不同序列、以及共同域隔离充分的不同序列，分别证明近重复仍合并、上下文仍合并、满足隔离的不同序列可分开。

Windows使用既有原生提取器实际重建324条受控观察；按本次[机器可读验证记录](source-repair-verification.json)列明的字段，逐条比较特征、上下文、质量、时间、标签、起点与来源元数据，保留重复记录，仅排除每次运行重新生成的身份引用。两端语义多重集哈希相同。6份原始PCAP也逐份核对SHA-256一致。

50,606条完整冻结语料通过归档与逐文件哈希校验后，在Windows由实际训练模块 `cyber_training.host_guard.prefix_corpus.verify` 重新校验，结果与Mac完全相同。两端CLI的 `--require-training` 均退出2；这是数据准入拒绝，完整性检查本身通过。此验证没有调用模型拟合或候选导出。

| 核验项 | 结果 |
|---|---|
| 324条受控观察的两端语义SHA-256 | `131793edc475363c931563dfee424692ff9b66cc378c803da08cbcca3bf154f8` |
| 新语料readiness SHA-256 | `11e66f4f6acacf4ec124682efded52bf83f4c0f68dfda7aa879799fcff08a91e` |
| Mac校验器与Windows训练镜像SHA-256 | `b42d75e1d4c998312a6518a65f4da4b5bc235a9c4ade02916a6a33e71721cb7c` |
| Windows实际验证环境 | Python 3.12.10，`training/windows-cuda` |
| Windows既有保护文件 | 17个逐份哈希不变，包含phase2、训练数据入口和采集脚本 |
| 原冻结、P6封存清单、历史裁决和候选文件 | 已绑定的文件哈希不变；未读取P6原件、特征、标签或分数 |

Windows离线输出位于 `.cache/p3-source-repair-20261005-01/`：`prefix-windows` 是原生重建，`prefix-corpus-v2` 是传入的同一完整冻结集。代码在两个既有工作区内修改，HEAD未改变，修复前文件已分别备份；没有把代码同步描述为Git发布。

## 6. 复现入口

在应用仓库根目录执行；输出目录必须不存在：

```sh
python3 -m unittest discover -s scripts/p3 -p 'test_build_attack_prefix.py' -v
python3 -m unittest discover -s scripts/p3 -p 'test_freeze_prefix_corpus.py' -v
python3 scripts/p3/build_attack_prefix.py \
  --root artifacts/p3-guardextract-20261005/windows-replay/captures \
  --extractor artifacts/p3-guardextract-20261005/guardextract-mac \
  --output artifacts/p3-source-repair-20261005-01/prefix-mac
python3 scripts/p3/freeze_prefix_corpus.py \
  --qualified artifacts/p1-p3-completion-20261004/prefix-cic2017-v4 \
  --qualified artifacts/p1-p3-completion-20261004/prefix-cic2018-v3 \
  --qualified artifacts/p1-p3-completion-20261004/prefix-taara-v1 \
  --qualified artifacts/p3-cde-20261004/qualified-benign-v1 \
  --qualified artifacts/p3-source-repair-20261005-01/prefix-mac \
  --benign-root artifacts/p1-p3-resolution-20261004/benign \
  --qualification artifacts/p1-p3-resolution-20261004/source-qualification-v2/summary.json \
  --reservation artifacts/p1-p3-resolution-20261004/sources/role-reservation.json \
  --output artifacts/p3-source-repair-20261005-01/prefix-corpus-v2
python3 scripts/p3/verify_prefix_corpus.py \
  --dataset artifacts/p3-source-repair-20261005-01/prefix-corpus-v2 \
  --require-training
```

最后一条预期退出2：完整性通过，数据准入仍被真实组数/角色条件拒绝，不是程序异常。Windows训练仓库对应的只读准入核验为：

```sh
.venv/Scripts/python.exe scripts/p3/verify_prefix_corpus.py \
  --dataset .cache/p3-source-repair-20261005-01/prefix-corpus-v2 \
  --require-training
```

精确哈希、两端结果、测试命令和保护文件核验见[机器可读验证记录](source-repair-verification.json)。

无需重启。没有删除用户文件、提交或推送；未改变活动v4服务、数据库、前端、系统防护和模型权重。
