# 阶段 0 状态冻结与验收记录

日期：2026-10-03（Asia/Shanghai）。状态：**阶段 0 已完成；数据 readiness 与 S3 继续 `BLOCKED`，训练和真实处置未授权。**

本记录是状态与验收证据。后续顺序仍由应用仓库 `docs/模型整改与分阶段开发计划.md` 和训练仓库 `docs/model-readiness-roadmap.md` 规定。本次仅收口阶段 0，不开展候选下载、标签关联、训练或影子采集。

## 1. 验收结果

| 阶段 0 要求 | 结果 | 当前证据与边界 |
|---|---|---|
| 训练保持阻断 | 完成 | readiness/preflight=`BLOCKED`，矩阵 `registered_not_authorized`，`trainingAuthorized=false`、`trainingStartAllowed=false`；两次 Windows 进程快照没有 Python/Optuna 训练进程 |
| 标签与历史切分保留 | 完成 | Monday 1,674 条保持 `Unknown`，新增可训练行数 0；CIC 未确认良性、CSE 旧 Normal 不准入；审查摘要及历史切分指纹登记哈希，未改原文件 |
| 模型与后端边界明确 | 完成 | 本机开发库 V18，活动部署 `2026.10.2`，`action_execution` 总数 0；历史 `approved/active` 不等于生产批准；执行仍返回 `503 ACTION_EXECUTION_UNAVAILABLE` |
| 传感器严格契约与授权范围 | 完成 | v4 规格/契约哈希保持不变；既有测试验证未知配置、非 v4 契约和白名单外接口拒绝；本次没有打开网卡或扩张授权 |
| 前端反映已有 API 状态 | 完成 | 检查控制台与 API 源码，训练任务只读，无训练启动或动作执行/回滚调用；已有本机模型生命周期命令保留，未伪造 readiness 或生产状态 |
| 两仓库计划和证据一致 | 完成 | 训练仓库阶段 0 出口修正为状态冻结一致，候选 pilot 留在阶段 1～2；两端保存同一冻结摘要及相同字节的矩阵/readiness/preflight/Monday 审查证据 |

数据阻断与阶段 0 完成分别记录：阶段 0 的出口是事实和约束一致，**不是取得可训练数据**。没有许可与逐流真值、独立分区或足量可信样本时，后续仍须停在相应数据阶段。

## 2. 冻结状态和门槛

- 当前 S3 没有训练授权；本次没有运行训练、预测、Optuna、holdout 读取或模型导出。
- L1-P/L2 可信新 Normal/Attack 均为 `0/0`；独立规则场景 `0/10`；L3 授权收集计划未建立。旧基准结果和开发库活动模型不能替代这些证据。
- L1-P：逐来源 Macro-F1≥`0.92`、FNR≤`5%`、FPR≤`1.5%`、PR-AUC≥`0.93`、ROC-AUC≥`0.99`。
- L2：逐来源 FPR≤`3%`、Recall≥`80%`、可信 Normal≥`1,000`、可信 Attack≥`100`。
- L3：FPR≤`2%`、至少两个独立时段、累计 `8` 个授权资产小时、可信 Normal≥`1,000`，继续满足 L2 Recall。
- 自动处置独立要求：冻结场景 `10/10`，以及授权、幂等、TTL、审计、目标操作系统回滚和单独审批；当前未达到。
- 原 S3 矩阵使用更严格的开发停止条件 FNR≤`4%`、FPR≤`1.5%`。矩阵保持原字节；它不是新训练授权，也没有替换 L1-P 最终验收标准。来源、字段或范围变化后须另建新矩阵并审批。
- v4 规格 SHA-256 为 `dbba110432c2c381ec291e2ec373601256c7ca990efa3e7bdad405c25120c6f1`；契约 JSON SHA-256 为 `803faa2b535e26158da57e14139d06223cf0c67103ab6cd1360983ae75494461`。

## 3. 证据路径

本目录的 [冻结摘要](evidence/freeze-20261003.json) 记录两端路径、文件 SHA-256、Git 基线、运行态和验证结果。[原始 S3 矩阵](evidence/s3-experiment-matrix-v1.json) 从已有训练工作区只读取出，哈希与 preflight 登记值一致。

| 证据 | 应用仓库路径 | Windows 训练仓库路径 |
|---|---|---|
| 状态冻结摘要 | `docs/phase0/evidence/freeze-20261003.json` | 同路径 |
| 原始 S3 矩阵 | `docs/phase0/evidence/s3-experiment-matrix-v1.json` | 同路径 |
| readiness v4 | `docs/phase3-optimization-evidence/phase3-dataset-readiness-v4.json` | `docs/phase0/evidence/phase3-dataset-readiness-v4.json` |
| 最新 S3 preflight | `docs/phase3-optimization-evidence/s3-preflight-20261003-v3.json` | `docs/phase0/evidence/s3-preflight-20261003-v3.json` |
| Monday 人工复核摘要 | `docs/phase3-optimization-evidence/cic-monday-human-review-acceptance-v1.json` | `docs/phase0/evidence/cic-monday-human-review-acceptance-v1.json` |

同步的是现有去敏审查摘要，不是新建标签或重新运行数据审查。摘要引用的原始 pilot、review package 和数据文件继续保存在原受控位置；本阶段未复制、重新读取或重算这些数据。历史 UNSW/CIC/CSE 证据仍保留，旧指标不能附到新权重。

## 4. 验证

1. 以 Temurin JDK `25.0.2`、Maven `3.9.13` 执行现有 `FeatureContractModelGateTest` 与 `FeatureContractValidatorTest`，共 `22` 项，失败/错误/跳过均为 `0`。
2. 现有 `ModelAndResponseLedgerIntegrationTest` 中执行失败关闭和审批审计两项通过。最初使用的共享测试库已有其他阶段 V19，因此不据此声称 V18 兼容；随后在临时源码副本仅更换测试 schema 名，独立空库 `cyber_security_phase0_20261003_061458` 完成 V1-V18 迁移，两项再次通过，执行记录为 0。项目测试源码未改动。
3. `go test ./internal/agent ./internal/uplink` 通过；这是离线配置与上报组件测试，没有运行真实抓包。
4. 对开发 MySQL 使用只读事务核实 V18、活动本机模型、执行记录及已停用实验源/已吊销机器凭据。核实实际 Java 进程、发布 JAR、回环监听和 `/actuator/health`、`/actuator/health/readiness`，均为 `UP`。
5. 核对冻结文件之间的 SHA-256 绑定、两仓库文档链接与门槛、远端导入字节、既有未跟踪文件保留及 `git diff --check`。

## 5. 未验证项与交付边界

- `historicalPipelineGuarded=false`：现有 preflight 尚未接入所有历史训练入口。当前阻断由未授权矩阵、状态证据和操作边界维持；不能宣称任意历史命令已经被程序强制禁止。实际训练入口的不可绕过 guard 属于后续训练工程。
- Windows 传感器、真实防火墙执行与回滚、L2/L3 新真值和候选来源准入均未完成。本次没有访问 holdout 特征、运行模型评分或产生新的模型效果结论。
- 前端仅核对源码调用边界，未重新进行浏览器验收；本次没有前端改动。开发服务未变更或重启。
- 临时测试源码副本及上述新建测试 schema 保留用于复查；没有删除数据库、数据或用户文件。
- 本记录及冻结摘要采集时，两仓库仅有文档/证据工作区修改，尚未提交或推送；后续经用户授权的提交与推送以 Git 历史为准。阶段 0 没有发布或变更模型/策略/账号，远端已有未跟踪开发文件保留。

阶段 0 后的入口是阶段 1 候选来源初筛。阶段 0 完成不授权训练、自动处置或扩展采集范围。
