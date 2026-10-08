# P3 数据准备与多分类模型

更新于 2026-10-07。**计划 `p3-multiclass-20261006-v1` 的 P3-A（A1–A6）、P3-B、P3-C 已完成；A7 可选未执行。P3-B 累计拟合上限经书面调整为 33 次并已用尽，完整框架与双端对拍通过（见 5.7）。P3-C 冻结了 opset 17 候选与 P6 评估计划（见 5.8），该阶段未读取 test。随后 P6 已完成首次冻结评价，G1/G2 通过、L3 慢速全部漏检，详见开发路线；评价后诊断发现候选依赖主机侧上下文，按“模型问题回 P3”处理，重训预算待授权，见 [P6 诊断](../p6/README.md)。** 本文件是 P3 的执行入口：记录输入、步骤、出口和当前进度。规则见 [数据与模型方案](../数据与模型方案.md)，指标见 [验证与验收](../验证与验收.md)，阶段依赖见 [开发路线](../开发路线.md)。

旧 prefix 慢速路线已终止，摘要见第 6 节。

## 1. 范围

入站 IPv4/TCP 流量 5 类分类：`normal`、`port_scan`、`brute_force`、`dos_flood`、`dos_slow`。类别映射、标签规则、切分和训练规则分别见 [数据与模型方案](../数据与模型方案.md) 第 1、3、4、5 节，本文不重复。

P3 的产物是冻结候选（ONNX、manifest、阈值和策略参数），交给 P6 在 L1 test 上做 G1/G2。P3-A 为数据准备处理原件、关联标签并封存；冻结后至 P6 前不读取 L1 test，不用其训练、选型或调阈值。

## 2. 输入登记

原始数据和提取结果只放在受控目录，不进 Git。大小与 SHA-256 在 A1 登记到 run 清单。

| 数据 | 内容 | 用途 | 位置与状态 |
|---|---|---|---|
| CIC-IDS2017 五天 PCAP | Monday 良性；Tuesday 暴力破解；Wednesday 慢速与洪泛 DoS；Thursday 端口扫描（Infiltration 期间）；Friday 端口扫描与 DDoS | L1 | Mac 受控 scratch 目录，约 52GB；下载时 MD5 与官方一致 |
| CIC-IDS2017 CNS2022 修正标签 | 五天逐流标签 | L1 标签依据 | 同上目录 |
| CSE-CIC-IDS2018 Wednesday-14 | 受害主机 PCAP，brute_force | L2 | `win-dev` 训练仓库 `data/raw/cse2018/`，SHA-256 与下载记录一致；旧 L2 诊断已查看过，报告中标注 |
| CSE-CIC-IDS2018 DoS/DDoS 日期 | Thursday-15、Friday-16、Tuesday-20、Wednesday-21 受害主机 PCAP | L2 | 缺失，A7 补下载 |
| P3-B 受控采集 | 慢速攻击 8 组、困难良性 11 批 | L3 | `win-dev` 的 `.cache/p3-cde-run-20261006-074800`（只保留原件、账本和健康记录） |

2026-10-07 用 CNS2022 标签做的只读统计（TCP、官方工具的流计数，仅作规划参考，以 A3/A4 的实际提取为准）：

| 项目 | 数量级 |
|---|---|
| brute_force | 约 6,900 |
| dos_slow | 约 5,600 |
| dos_flood | 约 26 万 |
| port_scan | 周五约 16 万，周四内部扫描约 7 万 |
| Attempted（排除） | 约 1.2 万 |
| 内部→内部正常入站 | 约 2.3 万，集中在 192.168.10.50（SSH/FTP/SMB）与 192.168.10.3（LDAP/Kerberos/SMB）；正常 80 端口访问每天约 7 条 |

外部攻击全部显示为 172.16.0.1 → 192.168.10.50（NAT），因此采用逐流关联标签；正常网页访问几乎为零，因此按服务器视角补充（规则见 [数据与模型方案 3.1、3.2](../数据与模型方案.md#3-特征提取与标签)）。

## 3. 执行步骤

### P3-A 数据准备（Mac 执行，L3 在 `win-dev` 执行）

| 步骤 | 内容 | 产物 | 出口检查 |
|---|---|---|---|
| A1 环境与登记 | 编译 `guardextract` 并跑 golden 回归；登记全部输入的大小与 SHA-256；为每个视角生成提取配置（本机地址、密钥、keyEpoch），配置与密钥放受控目录 | 可执行文件、配置、输入清单（均带哈希） | golden 通过；输入哈希与下载记录一致 |
| A2 标签工具 | 编写 CNS2022 逐流关联脚本：五元组 + 首包时间关联、按 3.2 顺序判定、冲突与未关联统计；编写发布时段交叉核对 | 关联脚本与单元测试 | 用合成样例覆盖 3.2 表中每一种情况 |
| A3 Tuesday 试提取 | 以 192.168.10.50 与 192.168.10.3 为本机提取 Tuesday，再选少量外部网站做网页补充试提取；运行关联 | Tuesday 特征、标签、排除统计、关联命中率、提取耗时 | 攻击流关联命中率与未命中原因可解释；首包时间容差确定；网页补充可行（任意地址作本机能正确识别入站）；每类抽查 ≥ 50 条 |
| A4 全量提取 | 用 A3 冻结的参数提取 Monday、Wednesday、Thursday、Friday（含周四端口扫描受害内部主机视角），并完成网页补充的抽样提取 | 每天每视角的特征、标签与诊断 | 5 类都有样本；排除量和原因有统计；质量问题都有处理记录 |
| A5 切分与冻结 | 按时间块切分 train / validation / test（攻击活动 60/20/20；正常流量 10 分钟块轮流分配；完整连接与边界前后 30 秒保护区相交即剔除）；网页补充同样按时间块切分；test 单独存放并启用访问日志 | 切分清单、三份数据集与哈希 | 同一连接不跨集合；三个集合都有 5 类；test 中正常连接 ≥ 4,000；冻结后不再改 |
| A6 L3 重新提取 | 在 `win-dev` 对受控 PCAP 用同一提取器和标签规则重新生成：慢速攻击为 `dos_slow`，困难良性为 `normal` | L3 测试集 | 只用于测试 |
| A7 L2 补数据（可选） | 从 CSE2018 官方存储按单个受害主机条目下载 DoS/DDoS 日期；与 Wednesday-14 一起提取和打标签 | L2 测试集 | 只用于测试；不在关键路径 |

### P3-B 训练与选型（`win-dev` 执行）

| 步骤 | 内容 | 出口检查 |
|---|---|---|
| B1 训练入口 | 在训练分支新增多分类模块，复用保留的 `p3-preprocess-v2` 与 ONNX 导出；实现样本权重（每条连接权重和为 1，再做有限类别平衡）；重写 `scripts/run_step.cmd` 指向新入口 | 小数据冒烟通过 |
| B2 训练与模型选择 | XGBoost、LightGBM 各训练，主种子 42 加 2 个种子；在 validation 上比较各类指标 | 全部运行留记录；所有拟合（含 smoke、中断与重跑）计入 run 外只追加台账，超出本轮书面上限即拒绝 |
| B3 阈值选择 | 在 validation 上选 `alertThreshold`（误报率 ≤ 1%）；按“来源 × 类别”汇总模拟，为每类选 `autoThreshold` 与 `minDistinctFlows` | 参数锁定 |
| B4 有效性检查 | 各类及各原始场景指标与混淆矩阵；分数区分度（不得退化为常数分）；捷径检查（分别去掉 `serviceClass`、本机上下文特征对比，特征重要性）；误报率按内部/网页等权口径并列两个分项；查清 CIC 洪泛连接 offload 大包的来源；设定规则引擎阈值并与模型对比 | validation 攻击检出率 ≥ 85% 且误报率 ≤ 2% 才进入 P3-C；达不到时在 P3 内调整，不动 test |
| B5 导出与对拍 | 导出双输出 ONNX（`attack_score` + `family_scores`，`categorical_codes` 为 int64）；保存原生非 pickle 模型及 train/validation 全量框架概率；Windows 与 Mac 分别用 ONNX 对照原生框架概率 | train、validation 全量最大分差 ≤ 1e-4，类别翻转 0 |

### P3-C 冻结候选

| 步骤 | 内容 |
|---|---|
| C1 | 打包 ONNX、manifest（类别顺序、阈值、预处理）、规则版本、切分清单、validation 报告与逐文件哈希；`candidateOnly=true` |
| C2 | 登记 P6 评估计划：test 数据、门槛、最多评估 3 次；在读取 test 前冻结 |
| C3 | 更新本文件与 [开发路线](../开发路线.md) 状态 |

### 代码位置

| 内容 | 位置 |
|---|---|
| 提取配置生成、标签关联、切分脚本 | main 仓库 `scripts/p3/*multiclass*.py`（新增当前入口，旧 prefix 脚本只作历史复现） |
| 训练、选型、导出、对拍 | `training/windows-cuda` 分支 `src/cyber_training/host_guard/`（`multiclass_train`、`multiclass_audit`、`verify_multiclass`、`multiclass_reproduce`） |
| 候选接口探针（零拟合） | main 仓库 `scripts/p3/probe_candidate_interface.py`，后端 `GuardCandidateProbeTest`（需 `-Dguard.probe.dir`）；见 [后续实施计划 T1.7](../后续实施计划.md#t1-工具参数化零拟合) |
| 原始数据、特征、模型、报告 | 两台机器的受控目录，不进 Git |

### 授权点

| 授权 | 范围 |
|---|---|
| ① | A1–A6：编写提取与标签脚本，在 Mac 提取 CIC2017，在 `win-dev` 重新提取 L3；只做本地计算 |
| ② | A7：从 CSE2018 官方存储下载 DoS/DDoS 日期的受害主机条目 |
| ③ | B1–B5：编写训练代码，在 `win-dev` 训练与导出 |
| ④ | P3-C，以及 main 与训练分支的 Git 提交（每次单独确认） |

### 主要风险

| 风险 | 应对 |
|---|---|
| 逐流关联命中率低或时间偏差大 | A3 实测命中率并定容差；未命中按原因统计，不靠放宽规则凑数 |
| 正常样本少、类型单一 | 多视角提取 + 网页补充；报告各集合样本量 |
| 模型学到“80 端口 = 攻击”等捷径 | 网页补充、B4 捷径检查、L3 困难良性外部检验 |
| 洪泛类可判定覆盖率低（Hulk 约 9%） | 报告覆盖率；G3 在 Mac 实时抓包上实测；必要时另行评估契约的 offload 规则 |
| 洪泛与扫描连接量巨大 | 每活动样本上限 + 样本权重 |
| 慢速 DoS 早期快照与正常长连接相似 | 使用 final 快照与来源上下文；仍不达标则降为只告警 |
| 13GB 级 PCAP 提取耗时 | 按 A3 实测估算，必要时按天并行 |

## 4. Windows 训练入口

- 训练代码位于 `training/windows-cuda` 分支 `host_guard/`：B1 新增 `multiclass_train`（主矩阵）、`multiclass_audit`（零拟合审计）、`verify_multiclass`（双端核验与拟合清点），收口时新增 `multiclass_reproduce`（单次受控复现 `fit` 与零拟合 `verify`）。已提交为训练分支 `ca1dd34`，同一提交删除了旧 prefix/UNSW 训练资产。
- `scripts/run_step.cmd`：`B1` 跑 14 项回归；`B5R` 是唯一可拟合入口，且受台账限制；B0/B2/B3/B4/B5 只输出审计说明并拒绝。`multiclass_train.run()` 保持禁用。
- 每次拟合前先写代码/依赖清单并向 `.cache/p3b-20261007/fit-ledger.jsonl` 预留名额（预留即计数，失败不退还）；run 目录保存配置、数据与旁路哈希、种子、原生模型、框架概率、ONNX 与指标；全部运行都保留。

## 5. 当前进度

| 子阶段 | 状态 |
|---|---|
| 输入盘点 | 已完成（2026-10-07） |
| P3-A | A1–A6 已完成（2026-10-07），A7 可选未执行 |
| P3-B | **已收口（2026-10-07）**：主矩阵 13 fit + 零拟合审计 + 1 次授权复现；累计 33/33 次，B5 完整框架对拍与双端对拍通过；候选 `candidateOnly`、全部类别 `alert_only` |
| P3-C | **已完成（2026-10-07）**：冻结候选包、逐文件哈希和 P6 评估计划；全部类别仍只告警 |

### 5.1 A1–A6 完成记录

本轮使用既有 rc.2 因果提取器和 43+3 特征，未改 P1/P2、未启动训练或新采集、未改变服务或防火墙。新增源码与本轮状态文档已随 P3-B 收口一并提交。

| 步骤 | 实测结果 |
|---|---|
| A1 | 五天 PCAP 的大小、SHA-256 与下载 MD5 登记完成；CNS2022 原件哈希一致。Mac/Windows 提取二进制已登记，golden 20 场景、55 条观察通过 |
| A2 | 六档标签判定、UTC 时间、双向五元组关联、冲突排除与官方发布时段交叉核对完成；首包容差冻结为 1,000 微秒 |
| A3 | Tuesday `.50` 的 9,203 条 parent 全部关联：9,183 条首包时间精确一致，20 条相差 1–100 微秒；FTP 3,972/3,972 CSV 行关联，SSH 2,960/2,961。剩余 SSH CSV 行是已有 parent 区间内的续段，不补标签。每类 50 条共 250 条样本由 Codex 审阅，记录没有独立人工签字 |
| A4 | 完成 95 个视角：五天 `.50/.3` 共 10 个、Thursday 额外内部扫描主机 10 个、网页补充 75 个（40 个服务器）；五类均有样本，质量缺陷与排除原因已记录 |
| A5 | 首次冻结（`host-guard-split/1`）验收未通过：按连接数分位切分使 Slowhttptest、周五主 PortScan 和 Hulk 首段在 validation 中为零。2026-10-07 改用 `host-guard-split/2` 重做预核对并重新冻结（见 5.2）；旧冻结目录改名 `frozen-split1-superseded` 留档，其中 test 保持封存、从未读取，也不再使用 |
| A6 | Windows 对既有 19 个受控活动重新提取，8 组慢速攻击与 11 批困难良性；核验原件、任务端点/数量及完整健康哈希链，全部登记为 L3 test-only，不继承旧开发角色 |

### 5.2 L1 冻结数量（`host-guard-split/2`）

以下为连接数，不是快照数：

| 类别 | train | validation | test |
|---|---:|---:|---:|
| normal | 22,391 | 7,079 | 11,511 |
| 其中内部正常 | 6,350 | 1,735 | 1,880 |
| 其中网页补充 | 16,041 | 5,344 | 9,631 |
| port_scan | 106,572 | 64,286 | 26,712 |
| brute_force | 3,525 | 1,254 | 1,652 |
| dos_flood | 25,467 | 6,890 | 11,453 |
| dos_slow | 1,245 | 434 | 421 |
| 合计 | 159,200 | 79,943 | 51,749 |

对应快照数 train / validation / test 为 234,841 / 106,129 / 79,177。

各原始攻击场景的切分（连接数，train / validation / test）：

| 场景 | 方法 | 连接数 |
|---|---|---|
| Tuesday FTP-Patator | 按活跃时长 | 2,102 / 600 / 951 |
| Tuesday SSH-Patator | 按活跃时长 | 1,423 / 654 / 701 |
| Wednesday Slowloris | 按活跃时长 | 839 / 316 / 205 |
| Wednesday Slowhttptest | 按活跃时长 | 406 / 118 / 216 |
| Wednesday Hulk | 按活跃时长 | 8,994 / 2,254 / 2,190 |
| Wednesday GoldenEye | 按活跃时长 | 1,778 / 599 / 1,094 |
| Thursday 内部端口扫描 | 整段分配（7 段） | 39,129 / 16,755 / 16,433 |
| Friday PortScan | 整段分配（8 段） | 67,443 / 47,531 / 10,279 |
| Friday DDoS | 按活跃时长 | 14,695 / 4,037 / 8,169 |

主要排除连接：全快照质量不合格 269,639，切分保护区 10,531（split/1 为 70,330），网站全局上限 16,481，不纳入类型的主机时段 6,415，Attempted 6,730，未关联 NAT 来源 1,166，标签冲突 143，物理身份冲突 8。

**可判定覆盖率**（至少一个质量合格快照的连接比例，按关联到的原始标签统计）：

| 场景 | 覆盖率 | 场景 | 覆盖率 |
|---|---:|---|---:|
| Hulk | 9.3% | Slowloris | 100% |
| DDoS | 30.4% | Slowhttptest | 99.3% |
| Friday PortScan | 78.8% | FTP / SSH | 94.7% / 95.9% |
| GoldenEye | 91.4% | Thursday 内部扫描 | 99.97% |
| 内部正常 | 65.1% | 网页补充 | 100% |

洪泛类低覆盖的原因是 `offloadSuspected`（IP 包长 > MTU）：服务器返回的 HTTP 响应在抓包点被合并成大包。dos_flood 的 G1 成绩只代表可判定的约 19% 连接；Mac 实时抓包是否出现同样情况列为 G3 必验项（[验收第 4 节](../验证与验收.md#4-硬门槛)）。

### 5.3 L3 与产物位置

| L3 类别 | 合格连接 | 合格快照 |
|---|---:|---:|
| dos_slow | 29 | 334 |
| normal | 42 | 237 |

原困难良性有 66 条连接，其中 24 条没有合格快照，按质量规则排除。受控源已在旧路线中查看过，不能宣称为全新独立 holdout；这些回环任务也不代表实网有效性。

产物引用相对各自仓库根目录，全部被 Git 忽略：

| 产物 | 位置 |
|---|---|
| Mac 输入登记、视角配置与原始提取 | `.cache/p3-a-20261007/inputs/`、`configs/`、`extract/`；配置目录含受控密钥，不对外复制 |
| L1 冻结清单与数据 | `.cache/p3-a-20261007/frozen/manifest.json`、`split-ledger.jsonl`、`train/dataset.jsonl`、`validation/dataset.jsonl`、`test/dataset.jsonl`；作废的 split/1 冻结在同级 `frozen-split1-superseded/`，不得使用 |
| 标签/未关联/发布时段/回归证据 | `.cache/p3-a-20261007/evidence/`；旧审查尝试保留原件 |
| Windows L3 成功 run | `win-dev` 训练仓库 `.cache/p3-a-l3-20261007-attempt02/`；`manifest.json`、`sealed-test/dataset.jsonl`、各活动标签与健康链引用 |
| Windows 证据的 Mac 副本 | `.cache/p3-a-20261007/evidence/windows-l3/`，仅清单、环境与日志，不含 L3 测试数据 |

L1 数据文件 SHA-256：

| 集合 | SHA-256 |
|---|---|
| train | `9f2a19313725b373b774e796a6523cbec37d46727ceecb55bb925596ad873572` |
| validation | `2e168dfac592207e0448529ff93d8a6ccbcbeec265253dd0354bfc463940d568` |
| test | `eeefc6a566147adbd9faf4433d5f068a4add94fb15b9708608e963dc3a70d53a` |

哈希在封存时计算；冻结后只核对 manifest、权限和访问日志，不打开 test。Mac test 文件及目录权限为 `000`，`test-access.jsonl` 目前仅有封存事件；P6 使用 `access_multiclass_test.py` 绑定候选、清单与计划，最多 3 次并记录访问。Windows L3 已设只读属性和初始访问日志，P6 接续其评估访问入口。权限/只读属性不是对同账户或管理员的强制保密边界。

### 5.4 验证与局限

标签抽样已由项目负责人于 2026-10-07 审阅确认，记录为 `evidence/label-review-human-confirmation.json`（不改写已绑定在冻结清单中的 Codex 审阅记录）。

2026-10-07 A5 返工后的独立核验记录为 `.cache/p3-a-20261007/evidence/a5-rework-verification.json`（10 项检查通过：哈希、无跨集合连接、每场景每集合 ≥ 50、内部正常 ≥ 1,000、test 封存未读、旧冻结 test 仍封存、无模型拟合）；Codex 的首次完成审计改名为 `completion-verification-split1.json` 留档。

以下均通过，实际输出保存在 `evidence/regression.json` 与 Windows golden 日志：

- 在 `sensor/` 执行 `CGO_ENABLED=0 go test ./internal/hostguard ./cmd/guardextract ./cmd/guardgolden`。
- 在 `sensor/` 执行 `CGO_ENABLED=0 go run ./cmd/guardgolden -check`：20 场景、55 条观察。
- `python3 scripts/p2/validate_contracts.py`：5 个 Schema、8 个负例、55 条观察。
- `python3 -m unittest discover -s scripts/p3 -p 'test_*.py'`：30 项（多分类准备 23 项、健康观察器 7 项），覆盖六档标签、时间/冲突、运行段识别、整段分配、活跃时长切分与保护区、长连接边界搜索、场景缺集合即失败、输入字段、L3 健康断段与 test 并发拒绝。

Windows 成功 run 前后分支、HEAD、335 项既有工作区状态完整清单相同，结束时没有 python/guardextract/guardgolden 进程。

局限：网页流量的时间特征来自客户端抓包视角；CIC2017 各集合仍共用攻击工具；历史 PCAP 的抓包丢失不能全面证明。Wednesday 的未关联攻击 CSV 行可由已有同 tuple parent 覆盖区间解释为续段差异；Thursday 多数未关联行没有适用入站 parent，但具体 PCAP 原因尚未证明。官方网页粗时段与 CNS 修正时段的差异已登记，不据此改写逐流标签。抽样审阅不等于独立人工批准。

P3-B 首轮执行见 5.6，修复收口见 5.7；A7 保持可选。尚无 G1–G3 成绩或生产自动能力。

### 5.5 后期待查项

以下不影响 P3-B 继续，按负责人决定先登记，项目收尾阶段再回头检查补充：

| 项目 | 现状 | 后期处理 |
|---|---|---|
| Thursday 657 条未关联连接 | 原因未证明，数量占比很小 | 收尾时抽查 PCAP，补充原因说明 |
| 网页补充的客户端视角偏差 | 已在报告局限中说明 | 只记录，不处理 |
| L3 受控数据曾被旧路线查看 | 不能称全新独立测试集 | 只记录，不处理 |

### 5.6 P3-B 首轮执行与未收口项（2026-10-07，已由 5.7 收口）

Windows `run-main-v3` 的 13 个 fit 已结束。当前研究候选为 `main-lightgbm-seed42`，保持 `candidateOnly=true`、全部类别 `alert_only`，未进入 P3-C，未提交或推送。

- 零拟合审计修正了攻击检出率口径（误分到其他攻击类仍算检出），未改变候选选择；validation 四类等权检出率 98.5961%、macro-F1 0.993117、内部/网页正常 FPR 均为 0。
- B3 原策略把内部/网页类别当成来源，已判作废。新预览按真实资产/传感器/启动/捕获范围/peerKey/keyEpoch 和服务作用域隔离，10 秒证据有效期，每条 parent 最新快照替换旧分。仅模拟研究命中，不代表通过在线 T1–T9。
- 两项消融的 macro-F1 下降约 0.000124/0.002549，未触发本轮 0.10 判据。原始分数分布、常数类基线、树分裂次数重要性、种子波动及逐场景混淆矩阵均已生成。
- 仅规则检出率 78.3213%、FPR 0.535557%；仅模型 98.5961%/0；OR 并用 98.5981%/0.535557%。并用不能纠正规则误报，规则默认只告警。
- B5 原候选 Windows validation 框架/ONNX 最大分差 1.370907e-6，类别翻转 0。原 ONNX 类别输入为 float32，与契约 int64 不符；另存仅增加 Cast 的修复图，Mac validation 相对原图分差与翻转均为 0。Windows 原图与 Mac 修复图全量 validation/train 最大分差分别为 5.364419e-7/1.192093e-7，类别翻转均为 0。Windows train 原生模型/概率未保存，不能以两端 ONNX 一致替代完整 train 框架对拍。
- 图片路线限定累计 30 次拟合，但历史主矩阵、重启与 smoke 的已完成事件已至少 32 次，另有不完整尝试。此前执行未实施跨 run 预算检查，属于本轮过程偏差；全部保留，已禁用继续拟合入口。本文不采用其他文档的“不限次数”描述覆盖本轮更具体的上限。
- 单流参照 ONNX 对拍最大分差约 0.0259，未通过，不能作为可交付候选；其框架参照成绩单独保留。

证据均在忽略目录，不进 Git：Windows `.cache/p3b-20261007/run-main-v3/`、`audit-windows-v1/`、`fit-inventory.json`；Mac `.cache/p3b-20261007/audit-mac-v2/`、`verification-v1/`。后者包含报告、策略、规则、消融及修复图。本轮只读取冻结 train/validation；Mac test 权限仍为 `000`，访问日志仍仅封存事件，L3 未读取。

**首轮出口（历史）：validation 数值门槛已达到，但完整 train 框架对拍缺失、累计拟合超限，未收口。** 两项均未通过静默重训或读取 test 补救，而是按 5.7 由负责人书面裁决后处理。

### 5.7 P3-B 修复收口（2026-10-07）

负责人同日书面裁决：采用"口径修订 + 单次复现"路径；本轮累计拟合上限由 30 调整为 33，smoke、中断与工程故障重跑全部计入，预留即计数；只复现 `main-lightgbm-seed42` 1 次。

首轮根因：训练入口只做 validation 的 ONNX 对拍，未保存原生模型和 train 框架概率；`maxFits=30` 只写在单个 run 的计划里，没有跨 run 台账，计划也没有代码哈希。run-main 的 13 次 ONNX 导出全部失败（opset/Slice）后改代码重跑为 run-main-v3，run-main-v2 中断于第 1 个 fit。32 次构成为 13 + 1 + 13 + smoke 5，矩阵中不同配置只有 13 个。

`multiclass_reproduce fit` 先核验 v3 参照模型/输出哈希、冻结数据与旁路哈希、预处理参数与 v3 逐项相同，再写代码/依赖清单并向台账预留（32→33）。第二次预留会被拒绝。

| 检查 | 结果 |
|---|---|
| 复现 | LightGBM 4.7.0 CPU、8 线程、deterministic；bestIteration 499 |
| 与 v3 一致性 | train 234,841 行、validation 106,129 行的 ONNX 输出与 v3 原 ONNX 逐位相同，因此沿用 5.6 的 validation 成绩、消融与种子波动 |
| 原生模型 | LightGBM 文本格式，无 pickle；重新加载后概率差 0 |
| 框架 vs ONNX | Windows 与 Mac 均为 train 3.47e-6、validation 1.36e-6，类别翻转 0 |
| Mac vs Windows ONNX | train 1.19e-7、validation 5.36e-7，类别翻转 0 |
| 输入契约 | 导出图 `categorical_codes` 原生 int64，取代审计时另存的 Cast 修复图 |
| validation 复算 | 告警阈值 0.9999186682701111，两端一致；检出率 98.5961%、macro-F1 0.993117、内部/网页 FPR 0；规则对比、来源预览、分数分布、分裂次数与首轮审计逐项相同 |
| offload 来源 | Wednesday/Friday 原始包中，受害 Web 服务大于 MTU 的帧共 572,767 个，99.95% 为服务器响应，最大载荷约 8 MSS，与 5.2 的解释一致；具体 TSO/GSO/GRO 机制仍为 G3 必验 |
| 回归 | Windows、Mac 各 14 项通过；test 访问日志哈希不变，目录权限仍为 `000`，L3 未读取 |

交付候选为 Windows `.cache/p3b-20261007/run-reproduce-v1/` 的 `model.onnx`（`5a5f8ab3…`）、`preprocessing.json`、`native-model.txt`。Mac 副本与核验分别在 `windows-evidence/run-reproduce-v1/`、`verification-reproduce-mac-v1/`，收口报告在 `closeout-v2/`。32>30 的历史超限作为过程偏差保留，不改写首轮计划；单流参照模型仍排除。训练代码已提交为训练分支 `ca1dd34`。

**当时出口：P3-B 已收口，validation 门槛与 B5 对拍均通过。** 候选保持 `candidateOnly`、全部类别 `alert_only`；后续 P3-C 见 5.8。

### 5.8 P3-C 冻结候选（2026-10-07）

使用 `PYTHONPATH=.cache/p3b-20261007/audit-deps python3 -B scripts/p3/freeze_multiclass_candidate.py --output .cache/p3c-20261007/candidate-v2` 从 B5 复现制品生成冻结包。`candidate-v1/` 原样留存；v2 补齐了评估计划对策略、类别映射、预处理、训练代码清单、提取器及指标定义的哈希绑定。原 B5 图保持原样，包内 `source-model.onnx` 仅用于溯源；绑定 manifest 的 `model.onnx` 将默认 ONNX opset 从 15 转为唯一的 17，`ai.onnx.ml` 仍为 3。ONNX checker、Mac ONNX Runtime 1.27.0 均通过。候选包位于忽略目录，不进 Git；`checksums.json` 登记 15 个文件的 SHA-256 与大小，自身不计入以避免循环哈希。

| 核验 | 冻结结果 |
|---|---|
| 转换后模型 SHA-256 | `5fa8cd1721bc5762aa4adae3befd678562469b37b30eea6c650311ea94255a79` |
| train 全量 234,841 行 | 与 B5 原图最大输出差 0、类别翻转 0；与保存的框架概率最大差 3.47e-6 |
| validation 全量 106,129 行 | 与 B5 原图最大输出差 0、类别翻转 0；与保存的框架概率最大差 1.36e-6 |
| Windows 运行时 | 同一 SHA 的图在 `win-dev` ONNX Runtime 1.23.2 加载成功；43+43+3 输入及双输出结构一致，固定零值输入与 Mac 1.27.0 最大输出差约 `6e-8`；这仅验证运行时兼容，不代替 P6 的全量双端核验 |
| manifest 与策略 | `model-manifest.json` 按 rc.2 Schema 验证；类别顺序、预处理、无额外校准、规则阈值和各类 `autoThreshold`/`minDistinctFlows` 已绑定；`candidateOnly=true`、全部类别 `alert_only`、自动执行关闭；v2 manifest SHA-256 为 `1b31bdfedec969a66e604072e625ada6569806f558b2f2837f89f2c95bc9f582` |
| P6 计划 | `evaluation-plan.json` SHA-256 为 `d6b0c67bb518c4c2f98b8cf31af63d158d784477bc5d43ad7ee24b52392c68e5`，绑定模型、切分、L1 test、类别映射、策略、预处理、提取器、训练与冻结代码及指标定义哈希；G1 检出率 ≥ 90% / FPR ≤ 2%、G2 macro-F1 ≥ 0.80；最多 3 次，后两次须先登记改动与原因 |
| test 封存 | 未读取；`test-access.jsonl` SHA-256 仍为 `5c34d83ae60cd87277b780268f6ff9d11b1e2d8090f4d799abd58817b4a1d843`，test 目录权限仍为 `000` |

规则与来源预览只是 validation 研究结果，不构成真实授权、在线策略或防火墙能力。P3-C 冻结时 P6 评估程序尚未实现、test 未读；同日随后已完成 [P6 工具](../../scripts/p6/README.md)，在冻结代码哈希、核对 v2 包逐文件哈希和登记后完成首次 L1 评价。G1/G2 与双端对拍通过，test 已用 1/3 次并重封存；L3 慢速 0/29 检出、困难良性 0/42 误报，L2 的 A7 仍可选未执行。当前结果见 [开发路线 P6](../开发路线.md#p6-冻结离线评估)。P3-C 原包与阈值保持不变，不授予发布或自动封禁资格；rc.2 manifest 在 P7 接入前须显式迁移到 P4 当前 rc.3，P5 平台实测仍待完成。

## 6. 已终止的旧 prefix 慢速路线

旧计划 `p3-prefix-cde-20261005-v4` 的任务是：HTTP/80 单连接前缀二分类，只覆盖 slowloris 与 slowhttptest，按四个开发角色做完整策略回放，并要求 E5 收益区间下界 > 0。2026-10-06 终止，原因如下：

- P3-D 按 v6 计划跑完后，阶段出口机械通过，但有效性审查判为**假通过**：Platt 校准斜率贴下界，校准后分数恒约 0.538；模型对受控攻击与困难良性给出相同分数，学到的是来源差异，不是行为差异。
- 单连接前几秒内，慢速攻击与长轮询、慢上传等困难良性本身难以区分；同时叠加的硬门槛过多，独立组一旦暴露就需重新采集，在剩余时间内无法收尾。

保留的成果：

- P2 观测格式与特征；
- `p3-preprocess-v2` 对拍修复；
- P3-B 受控数据（转作 L3）；
- [授权记录](controlled-attack-authorization.json)。

旧计划文件 `cde-plan.json` 已从 docs 移除，可从 Git 历史恢复。运行证据保存在 `win-dev` 的 `.cache/p3-cde-run-20261006-074800`，其中 `p3d-resume-v6-review.md` 为审查记录，SHA-256 `f0528cecc43b5d4bfbe70d4a128621950a55a46398184f24fafb0f7cd72204ea`。旧路线的候选、policy 和成绩不进入新路线。
