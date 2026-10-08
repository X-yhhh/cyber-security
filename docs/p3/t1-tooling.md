# T1 参数化工具与零拟合验证

更新于 2026-10-08。T1.1—T1.6 已实现并验证，T1.7 的已有接口探针结论保留。代码随 2026-10-08 审核修复一并提交（main 与训练分支各自经 PR 合并）；没有新拟合、真实 test/L3 读取、正式新候选或发布组合，没有更改服务、数据库或前端。T2 预算仍待授权，正式冻结和新评价版本登记在 T3 完成。

## 1. 代码归属与验证

- main：`scripts/p3/freeze_multiclass_candidate.py`、`candidate_plan.py`、`single_peer_check.py` 及测试；`scripts/p6/` 的评价、运行时、指标、收口及测试。
- 训练分支：`src/cyber_training/host_guard/multiclass_reproduce.py` 及测试，由临时分支 `Xyhhh/t1-tool-parameters` 经 PR 合入 `training/windows-cuda`。
- Windows：`win-dev`，仓库 `E:/Workspace/ai/experiments/cyber-security-training`，分支 `training/windows-cuda`。仅将三个 Python 文件复制到忽略的 `.cache/t1-tooling-20261008/` 执行零拟合 reference，未改远端跟踪源码。

回归命令（在各自仓库执行，依赖通过受控目录引用）：

```sh
# main，44 项和 28 项合成回归，不打开真实 test
env PYTHONPATH=.cache/p3c-tooling:.cache/p3b-20261007/audit-deps:scripts/p3:scripts/p6 \
  python3 -B -m unittest discover -s scripts/p3 -p 'test_*.py'
env PYTHONPATH=.cache/p3c-tooling:.cache/p3b-20261007/audit-deps:scripts/p3:scripts/p6 \
  python3 -B -m unittest discover -s scripts/p6 -p 'test_*.py'
# 训练 worktree，19 项
env PYTHONPATH=src python3 -B -m unittest discover -s tests -p 'test_multiclass_*.py'
```

覆盖独立新轮次计数、33 次历史保留、计划名须为 test 访问入口登记的 `p3-multiclass-20261006-v1`、P6 入口独立复核单对端证据、预算耗尽、缺参/路径越界、零拟合参照、真实合成 int64 ONNX、rc.3 准备和外部 rc.4 策略封口、哈希篡改拒绝、20 个百分点边界、模型与同类多规则独立资格、收口复算。新包完整冻结只在合成数据上验证，不能据此宣称正式制品已冻结或已取得资格。

## 2. Windows 已生成的 T2 参照

零拟合入口允许已收口 run 的历史 float32 类别图，保存原始预测供复现比对；它不会把原图当作现行契约图，也不会拟合或读取 test。

```powershell
.venv/Scripts/python.exe -B .cache/t1-tooling-20261008/multiclass_reproduce.py reference `
  --reference-run .cache/p3b-20261007/run-main-v3 `
  --target ablation-no-host-context `
  --reference-model-sha256 040e89e205d005cced08c3b4486fe5640913528e4c7739c3ad47a8cbc5658733 `
  --frozen .cache/p3b-20261007/frozen `
  --sidecars .cache/p3b-20261007/sidecars `
  --output .cache/p3b-20261007/run-main-v3/models/ablation-no-host-context
```

此命令本次已执行，不能重复覆盖输出。输出布局为 `[attack_score, family_scores(4)]`，不是五类 softmax 顺序。

| 文件 | shape / SHA-256 |
|---|---|
| `train-onnx.npy` | `[234841, 5]`；`781ad5cf7739b05df3affb6788b2f61f9a21ff7bd9cbf3022a139e49071d8d38` |
| `validation-onnx.npy` | `[106129, 5]`；`a917463bf98566e76cca497675d0c8dfb4fb84c71122be9049429be00b1babad` |
| `reference-bindings.json` | `67c013625f10fbc62483cafe6c3c186e3af4957eba2aedb2c710a6d552377c8f` |

`reference-bindings.json` 记录的复现入口哈希为生成参照时的版本 `1b441826…`；其后该文件只调整了 `split_counts`、verify 中的一处调用，以及审核后把 `fit` 的授权/台账核验提前到建 run 目录之前（现为 `2c9d4eaa…`），参照输出函数逐行相同，参照仍有效。原模型、预处理、run-summary 和第一轮台账的前后 SHA 均未变，台账 count=33；最终远端 Git 工作区干净、没有 Python 进程。完整绑定清单已复制到本机 `.cache/t1-20261008/evidence/reference-bindings.json`，前后复核记录见同目录 `verification.json`。受控证据与 `.npy` 不提交 Git。

## 3. 复现入口与独立预算

`fit` 的所有以下参数必填，缺参立即拒绝；此节只说明接口，不授权拟合：

| 参数 | 语义 |
|---|---|
| `--target`、`--feature-set`、`--seed` | 单一目标名、`full` / `no_host_context`、复现种子；须与参照和授权一致 |
| `--reference-run`、`--reference-outputs` | 原 run 及 reference 输出目录；校验模型、预处理、数据/旁路与输出登记 |
| `--reference-model-sha256`、`--reference-train-sha256`、`--reference-validation-sha256` | 明确引用的模型和两份参考输出 SHA |
| `--run`、`--frozen`、`--sidecars` | 本次新 run 和已有 train/validation 冻结数据、旁路；不读取 test/L3 |
| `--ledger`、`--budget`、`--authorization` | 独立新轮次台账、书面拟合上限、实际授权 JSON |
| `--historical-ledger`、`--historical-ledger-sha256` | 第一轮台账及预期 SHA；路径必须与新台账不同，只读核验 |

授权 JSON 必含 `date`、`by`、`scope`、`countingRule`、`roundId` 五个非空字符串及 `target`、`featureSet`、`seed`、`budget`；后三个运行值和目标须与 CLI 相同。记录必须来自实际授权，不能把示例或任务文档当作授权。

新台账第一条 `round-opened` 绑定授权 SHA、轮次、预算和历史 SHA/count，第二轮不导入历史 33 次参与新预算。复用不同绑定的台账被拒绝；并发通过目录锁互斥，每次拟合前追加 `fit-reserved`，失败也计数，不删除记录腾额度。完成事件引用 summary SHA；summary 的 `reservationLedgerSha256` 是完成事件追加前的台账 SHA，避免互相引用产生循环哈希。

参照预处理须逐项一致；导出图对外保持 43+43+3 输入，类别为 int64，`no_host_context` 在图内只使用 37 个数值列及对应缺失列。差异会记录为新模型，不能继承旧模型成绩。Mac `verify` 的参数为 `--run --output --frozen --sidecars`，零拟合重算 validation 审计并对拍完整 train/validation；分裂次数报告按冻结选列还原特征名，避免消融列错位。

## 4. 准备、开发检查与封口

以下路径是后续正式 run 的调用形态，须由 T2/T3 实际产物替换，当前不存在正式新候选。

```sh
python3 -B scripts/p3/freeze_multiclass_candidate.py prepare \
  --source .cache/p3-round-2/run --source-sha256 SOURCE_ONNX_SHA \
  --frozen .cache/p3-a-20261007/frozen --audit .cache/p3-round-2/mac-audit \
  --extractor .cache/p3-a-20261007/bin/guardextract --plan .cache/p3-round-2/plan.json \
  --scope .cache/p3-round-2/scope.json --model-version NEW_MODEL_VERSION \
  --training-run-id REGISTERED_UUID --output .cache/p3-round-2/prepared
python3 -B scripts/p3/single_peer_check.py \
  --candidate .cache/p3-round-2/run \
  --dataset .cache/p3-a-20261007/frozen/validation/dataset.jsonl \
  --output .cache/p3-round-2/single-peer
python3 -B scripts/p3/freeze_multiclass_candidate.py seal \
  --prepared .cache/p3-round-2/prepared --policy .cache/p3-round-2/candidate-policy.json \
  --single-peer-report .cache/p3-round-2/single-peer/report.json \
  --output .cache/p3-round-2/candidate
```

`prepare` 校验 run 清单、框架/双端审计、特征选列、显式源模型 SHA 和范围，转换为唯一默认 opset 17 并全量对拍 train/validation，按现行 Schema 生成 rc.3 manifest 和真实哈希。`scope.json` 为 Schema 的 `supportedScope` 数组，当前输入仅支持 tcp/inbound，不能借参数宣称未经观测的协议/方向。准备包缺策略，不能进入 P6。

单对端检查接受已登记复现 run 或完整现行候选，仅允许与 manifest SHA 相符的 `validation/dataset.jsonl`。所有 1/5/30 秒窗口设 `hostDistinctPeers=1`、`hostFlowStarts=peerFlowStarts`（同源 null 保留）；按 parentConnection 汇总，任何攻击类别命中均记为检出，保留后续快照命中，标签冲突拒绝。四类中任一缺失或检出率下降 >0.20 即失败，退出码 2；恰好 0.20 通过。正常误报同时报告。实际推理强制 int64 类别接口。

`seal` 接收外部生成的 rc.4 候选冻结层策略（B2 所属），核验计划、模型、策略现行 Schema 和单对端通过报告。策略及各家族均只告警，所有模型/规则自动资格为 false；不能从研究 `policy-preview.json` 直接生成执行资格。单对端证据绑定源模型、预处理、validation、审计阈值和工具哈希；工具修改后须重新检查。封口时各家族告警阈值须与本次开发审计一致。输出必须是 `.cache` / `artifacts` 内未使用目录，不能覆盖旧包。

## 5. 新评价计划与历史兼容

新计划须显式声明 parentConnection、连接首次过阈值、四攻击类和两正常来源等权、G1/G2、最多 3 次、三个不同非空评价 ID、重评规则和 `noTestReadBeforeP6=true`；`automaticEligibility` 为 `recallMin=0.8`、`precisionMin=0.9`、`requiresG3=true`、`sourceMode=model_and_each_rule`。`metricDefinitionSha256` 绑定现行验收正文。

`plan` 须沿用 `p3-multiclass-20261006-v1`：test 访问入口 `access_multiclass_test.py` 按该计划名和全局 3 次额度记账，换名会在 `access_requested` 时被拒，`check_plan` 提前拒绝。全局额度已用 1 次，三个评价 ID 中最多还能用掉两个，第三个只作登记占位。

新口径使用新 `evaluationVersion`，不得复用 `host-guard-evaluation/2026-10-07.1`。T1 实现参数化校验，不替 T3 登记具体版本。prepare 补入真实模型/数据/提取器/预处理等 SHA。哈希方向为“计划 → 策略 → 候选校验清单/P6 登记”：策略含 `evaluationPlanSha256`，新计划不能含 `decisionPolicySha256`，以免出现循环。

P6 prepare/run/closeout 使用计划版本，准入绑定现行 manifest/policy Schema、制品、指标文档与代码哈希。新候选准入还独立复核包内 `single-peer-report.json`：须针对同一源模型（`provenance.sourceModelSha256` 与 `source-model.onnx`）、预处理、validation 与告警阈值，四类降幅都不超过 20 个百分点；不比对当前工具源码哈希，以免冻结后的工具修正使证据失效。资格结构与调用见 [P6 工具说明](../../scripts/p6/README.md)。旧候选只能这样只读复核：

```sh
python3 -B scripts/p6/evaluate.py check \
  --candidate .cache/p3c-20261007/candidate-v2 --legacy-candidate-v2
```

本次实际复核通过：`checked=true`、`testRead=false`，仍为原模型版本和历史评价版本。历史模式固定原包校验清单 SHA 与 `efcbd12` Schema SHA；不开放旧包 prepare/run，不更改已登记的成绩、1/3 test 额度或自动能力边界。
