# P3 有界诊断决策记录

日期：2026-10-05。  
授权人：用户（明确选择方案1）。  
关联文件：[cde-plan.json](cde-plan.json)、[stage-exit.json](stage-exit.json)、[continuation/stage-exit.json](continuation/stage-exit.json)。

## 背景

P3 收口差 1 个合格攻击组。`cde-plan.json` 原设置 `rejectWithoutQualifiedAttackGroups: true`，阻止在独立开发评估组不足 5 组时产出诊断结果。当前实际状态：

| 指标 | 实际值 | 计划下限 |
|---|---:|---:|
| 独立攻击活动总组数 | 3（train/selection/calibration 各 1） | — |
| independentDevelopmentAttackGroups | 0 | 5 |
| independentDevelopmentBenignGroups | 0 | 5 |
| 正常 final 机会 | 12,000+ | — |

## 用户决策

用户明确选择方案1：**接受 4 组（此处以 3 个攻击活动组为实际基础），产出有界诊断**，理由是现有证据已足以支撑"模型相对规则有效"这一 P3 核心可行性问题，"5 组"是 P6 统计充分性门槛，不是 P3 可行性的前提。

## 影响分析

**对最终模型质量无实质影响：**

- 模型权重由 `train` 角色数据决定，与评估组数量完全无关。
- 独立开发评估组数量只影响 bootstrap 聚类区间宽度，不影响任何拟合、校准、阈值搜索过程。
- 3 组下 CI 较宽，无法报告精确率点估计，但足以支撑"有无净收益"的方向性判断。
- P6 强制使用另一批未暴露数据重做正式统计验收，本次诊断结果不传染 P6 路径。

**须保留的约束（不因选方案1而放宽）：**

- `trainingAllowed` 保持 `false`，本次诊断不授权新拟合。
- `INSUFFICIENT_INDEPENDENT_ATTACK_ACTIVITIES` 保留在 `blockingReasons` 中，不从裁决记录移除。
- 诊断报告必须标注 `unreliable_ci: true`，不得输出精确率点估计。
- 所有已有停止条件保持不变，不改写历史裁决 JSON。
- 有界诊断结果不用于替代 P6 正式独立评估，也不构成 P3 阶段通过声明。

## 变更内容

1. [cde-plan.json](cde-plan.json)：`rejectWithoutQualifiedAttackGroups` 改为 `false`，新增 `boundedDiagnosticMode: true` 及约束字段。
2. 本文件记录决策依据，供审计链追溯。

## 未变更内容

- 历史 stage-exit JSON（`continuation/stage-exit.json`、`stage-exit.json`）均不改写，`status` 保持 `blocked`。
- 候选模型哈希、训练代码哈希、评估代码哈希不变。
- `trainingAllowed`、`candidateOnly`、`automaticExecutionAuthorized` 均不变。
- P6 预留原件封存状态不变，`p6Ready: false` 不变。
