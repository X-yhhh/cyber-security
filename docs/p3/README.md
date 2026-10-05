# P3 模型与策略可行性

更新：2026-10-05。阶段状态：**blocked**，`trainingAllowed=false`，`p6Ready=false`。

---

## 当前阻塞原因

最新裁决见 [source-repair-verification.json](source-repair-verification.json)。

| 阻塞码 | 说明 |
|---|---|
| `SELECTION_COVERAGE_BELOW_TARGET` | 选型角色完整策略覆盖 4/28（14.3%），目标 ≥80% |
| `FROZEN_POLICY_SCENARIO_COVERAGE_BELOW_TARGET` | Slowhttptest 场景完整策略 4/28 |
| `INSUFFICIENT_INDEPENDENT_ATTACK_ACTIVITIES` | `independent_development` 角色内攻击组 3 个，目标 ≥5 |
| `ROLE_MISSING_CLASS:validation_calibration:1` | 校准角色无攻击样本 |
| `SCENARIO_NOT_PRESENT_IN_ALL_DEVELOPMENT_ROLES` | 受控场景未覆盖四个角色 |
| `MISSING_QUALIFIED_ONSET_AND_PREFIX` | Slowhttptest、2018 Slowloris 起点规则未通过 |
| `MISSING_INDEPENDENT_BENIGN_ACTIVITY_EVALUATION` | 独立开发良性组 0 |
| `FINAL_TEST_UNALLOCATED` | final_test 未分配，P6 准入未授权 |

---

## 已完成工作摘要

**首轮实验（2026-10-04）**：10 次完整拟合，LightGBM 优胜（ROC-AUC 0.9978），Mac/Windows ONNX 对拍通过。完整策略在选型角色覆盖 4/28（14.3%），根因：Slowhttptest 是长保持连接，不产生新建连接，480 次观察首先被新连接速率条件拒绝；598 次被证据过期拒绝。

**P3-A/B/C/E（2026-10-04~05）**：代码修复与回归通过；起点审查完成（2017 Slowhttptest 和 2018 Slowloris 起点规则均未建立）；有界诊断收口（方向性可行，无法确证净收益）。

**受控攻击归档与来源修复（2026-10-05）**：6 组受控 PCAP 成功提取 324 条 prefix；`sourceId` 按场景×轮次拆分修复完成；重新冻结 `prefix-corpus-v2`（50,606 条），双平台 26 项回归通过。`independent_development` 攻击组仍为 3，原因见下节。

完整修复过程见 [source-repair-20261005.md](source-repair-20261005.md)。

---

## 受控活动仍未满足准入的完整根因

**问题 1：近重复归并（`whole_parent_quantized_sequence`）**

`verify_prefix_corpus.py:108-114` 的 `near_vector()` 对 `elapsedMs`（精度 1000ms）、`bytesInbound`（精度 32）等字段粗粒度量化，6 组受控活动使用相同的 `ACTIVITY_SECONDS=90`（`collect_attack_prefix.py:35`），量化后特征序列完全一致，Slowloris 3 组合并为 1 个防泄漏组，Slowhttptest 3 组合并为 1 个防泄漏组。

→ 修复：各组使用不同连接时长，使 `elapsedMs` 落入不同的 1000ms 分桶，需要修改 `collect_attack_prefix.py:35` 并重新采集。

**问题 2：所有受控攻击数据写死进 `independent_development`**

`build_attack_prefix.py:327,404` 把 `split='independent_development'` 写死。`verify_prefix_corpus.py:94-96` 要求四个角色（`train`、`validation_selection`、`validation_calibration`、`independent_development`）每个都必须有攻击样本；`verify_prefix_corpus.py:100-101` 要求每个声明场景在四个角色里都有覆盖。全部进 `independent_development` 导致其他三个角色没有受控攻击样本，触发 `ROLE_MISSING_CLASS` 和 `SCENARIO_NOT_PRESENT_IN_ALL_DEVELOPMENT_ROLES`。

`freeze_prefix_corpus.py:154-159` 从 `priorPlannedRole`（即输入 row 的 `split`）决定最终角色分配，所以 `build_attack_prefix.py` 的输出直接决定角色。

→ 修复：修改 `build_attack_prefix.py`，从 `activity.json` 的 `plannedRole` 字段读取角色，而非写死。同时 `collect_attack_prefix.py` 的 `SCENARIOS` 列表里每个 scenario 需要带 `plannedRole`。

---

## 后续执行路径

### 需要修改的代码（两处）

**1. `scripts/p3/collect_attack_prefix.py`**

- `ACTIVITY_SECONDS = 90`（第 35 行）改为从 scenario 条目读取
- `SCENARIOS` 列表每个条目增加 `targetActivityDurationSeconds` 和 `plannedRole` 字段
- `run_group()` 里用 `scenario['targetActivityDurationSeconds']` 替代 `ACTIVITY_SECONDS`

**2. `scripts/p3/build_attack_prefix.py`**

- 第 327 行和第 404 行的 `split='independent_development'` 改为 `split=activity.get('plannedRole', 'independent_development')`
- `activity.json` 里需要有 `plannedRole` 字段（由采集脚本写入）

### 采集参数（已登记在 [controlled-attack-authorization.json](controlled-attack-authorization.json)）

| 组 | 模式 | 目标时长 | 登记角色 | elapsedMs 分桶 |
|---|---|---:|---|---:|
| g1 | Slowloris | 30 秒 | train | 30 |
| g2 | Slowloris | 60 秒 | validation_calibration | 60 |
| g3 | Slowloris | 90 秒 | independent_development | 90 |
| g1 | Slowhttptest | 45 秒 | validation_selection | 45 |
| g2 | Slowhttptest | 75 秒 | independent_development | 75 |
| g3 | Slowhttptest | 105 秒 | independent_development | 105 |

每组时长不同，量化后 elapsedMs 分桶互不相同，近重复规则不触发。每个场景覆盖 train、validation_calibration/validation_selection、independent_development 三个角色，满足四角色均有攻击样本的要求。independent_development 里：Slowloris g3（1 组）+ Slowhttptest g2/g3（2 组）+ 现有 CIC2017/CIC2018/TAARA（3 组）= 共 6 组，满足 ≥5 要求。

### 执行顺序

```
1. 修改 collect_attack_prefix.py（读取 targetActivityDurationSeconds 和 plannedRole）
2. 修改 build_attack_prefix.py（从 activity.json 读取 plannedRole）
```

```
3. 在 win-dev 重新采集 6 组受控 PCAP（按新参数，组间隔 ≥155 秒）
```

```
4. 运行 build_attack_prefix.py（复用 DLT_NULL 提取器）
```

```
5. 运行 freeze_prefix_corpus.py + verify_prefix_corpus.py --require-training
   核验：四个角色均有攻击样本、每个场景覆盖四角色、independent_development ≥5 组
   trainingAllowed=true 后才进入下一步
```

```
6. P3-D 有界 prefix 实验（win-dev，training/windows-cuda）
   ≤10 次完整拟合，≤4 GPU 小时
   LightGBM 优先 / XGBoost 对照；基础特征 vs 基础+对端上下文
   E5：仅规则 vs 仅模型 vs 模型+策略（独立评价组）
   目标：每个声明场景完整策略 ≥80%，独立组有证据
```

```
7. P3-E 冻结移交
   固定模型、预处理、校准、策略；登记未暴露 P6 活动与访问保护
```

```
8. P6 一次性独立评估（需单独授权）
```

### 停止条件

- `verify_prefix_corpus.py --require-training` 仍报阻塞 → 根据具体阻塞码修正代码或采集参数，不进入 P3-D
- 两轮有界实验无净覆盖收益 → 停止，返回标签/特征/任务范围审查
- 不读取 P6 封存特征/标签/分数

---

## 文件说明

| 文件 | 用途 |
|---|---|
| `source-repair-20261005.md` | 来源修复完整报告，含真实根因和双平台核验结果 |
| `source-repair-verification.json` | 最新双平台核验记录，当前有效裁决 |
| `controlled-attack-authorization.json` | 采集授权，含各组时长和角色登记（v2） |
| `candidate-manifest.json` | 候选模型登记（candidateOnly，alert_only） |
| `candidate-policy.json` | 候选策略登记 |
| `candidate-capability.json` | 候选能力研究提案 |
| `cde-plan.json` | prefix 训练计划 |
| `requirements-windows.lock` | Windows 训练依赖锁 |
