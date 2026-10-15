# 网络威胁检测与受控防御平台 - 前端系统 (SecOps Console)

本项目基于 **Vue 3 稳定版 + Vite 6 + TypeScript + Tailwind CSS** 构建，采用**白纸墨字、细边框面板、墨色交互**的控制台风格（视觉基线 v2）。各功能模块对齐系统的设计契约（《项目详细设计》《功能模块设计》《接口设计》《数据库设计》）；完整视觉与代码约定见 [前端设计文档](../docs/前端设计文档.md)。

---

## 1. 核心设计风格规范

实际基线以 `tailwind.config.js` 与 `src/styles/index.css` 为准，完整说明见 [前端设计文档](../docs/前端设计文档.md)。

- **底色与表面**：页面与面板同为白色 `#FFFFFF`，次级表面 `paper.soft #F2F1EE`；一级区块放在面板中（`1px ink-line #E2E0DA` 边框、8px 圆角、无阴影、不嵌套），表内只用发丝线 `ink-hair #EDEBE6`；阴影只给抽屉与弹层（`shadow-panel`）；
- **交互色**：墨色 `ink #14161A`——主按钮、选中菜单项、焦点框、选中文字都用墨色，悬停提亮为 `ink-2`；钴蓝 `signal #2438E8` 只用于品牌标识小方点与“进行中”状态语义；圆角四档（徽标 4px、按钮与输入 6px、面板 8px、胶囊 full）；
- **图标**：lucide 线性图标，线宽 1.5；菜单项、页头、面板标题统一带图标；
- **各页版式**：每页按功能单独设计主视觉（因果链、热力矩阵、发布流水线、会话时间轴、资产看板、日志流等），见前端设计文档第 10.10 节；
- **语义色**：威胁 `threat #E0482A`、警示 `warn #B7791F`、正常 `ok #2F7D5B`，语义映射集中在 `src/data/tones.ts`，未知状态值自动回退为中性；
- **语义标记**：状态用「圆点 + 文字」的 `Tag` 表达；表格状态列可用浅底色胶囊（`Tag pill`）；
- **专业数据排版**：时间戳、ID、IP、端口、哈希、TTL、分数与契约版本用等宽字体 `JetBrains Mono`（`.num`）；中文标签、按钮与表头用常规字体（`.label`）；长 UUID 用 `IdText` 截断为前 8 位并可复制。

---

## 2. 功能模块全景

路由定义见 `src/router/index.ts`。控制台页面挂在 `/console` 下，未登录访问会跳转登录页。

| 路由 | 页面 | 主要功能 | 调用的后端接口（`/api/v1` 下） |
| --- | --- | --- | --- |
| `/` | 首页 | 项目介绍与入口 | 无 |
| `/login` | 登录 | 服务端会话登录，失败显示脱敏消息与 request ID | `/auth/csrf`、`/auth/login`、`/auth/me` |
| `/console/overview` | 态势 | 事件、传感器、审批、模型部署与漂移概览，运行状态 | `/overview`、`/events`、`/sensors`、`/approvals/ledger`、`/model-deployments`、`/model-drift-windows`、`/ops/status` |
| `/console/events` | 告警与事件 | 告警与事件列表 | `/alerts`、`/events` |
| `/console/events/:id` | 事件详情 | 关联告警与时间线（服务端分页）、状态迁移、研判笔记、告警误报/真报标注（`AlertFeedbackDrawer`）、发起处置申请 | `/alerts/{id}`、`/alerts/{id}/feedback`、`/events/{id}`、`/events/{id}/alerts`、`/events/{id}/timeline`、`/events/{id}/transitions`、`/events/{id}/notes`、`/events/{id}/actions`、`/response-policies` |
| `/console/response` | 受控响应 | 审批台账、我的申请、响应策略起草/提交/撤回/批准/驳回/退役 | `/approvals/ledger`、`/approvals/{id}/decision`、`/actions/mine`、`/response-policies` |
| `/console/models` | 模型治理 | 模型候选、校验、发布申请与审批、本机激活、漂移窗口、反馈样本、训练台账 | `/models`、`/models/{id}/validate`、`/models/{id}/release-requests`、`/model-release-requests/{id}/decision`、`/model-deployments`、`/model-deployments/active`、`/model-drift-windows`、`/feedback-samples`、`/training-jobs` |
| `/console/assets` | 资产与传感器 | 资产台账、授权申请与审批、传感器列表 | `/assets`、`/assets/{id}/authorizations`、`/assets/{id}/authorizations/{authorizationId}/approve`、`/sensors` |
| `/console/sources` | 数据源与回放 | 数据源、接入汇总、回放场景（只读）、影子报告与反馈第二人复核（`SourcesShadowPanel`） | `/data-sources`、`/data-sources/ingest-summary`、`/replay-scenarios`、`/data-sources/{id}/shadow-report`、`/feedback-reviews`、`/feedback-samples/{id}/review` |
| `/console/audit` | 审计 | 追加式只读审计查询 | `/audit` |
| `/console/iam` | 身份与角色 | 用户列表、内置角色与权限 | `/users`、`/roles`、`/users/{id}/roles` |
| `/console/observation` | 观测与目标 | 观察批次受理、单条观察快照、推理结论、证据迹（只读） | `/api/v2/observation-batches`、`/observations`、`/detections`、`/evidence-episodes`、`/evidence-episodes/{id}/evidence`、`/assets`、`/budget-targets` |
| `/console/release` | 策略与发布 | 决策策略复核、发布组合登记报告/封存/审批/激活/停用、能力等级、评价运行 | `/api/v2/decision-policies`、`/release-bundles`（含 `imports` `sealings` `decisions` `activations` `suspensions`）、`/capabilities`、`/evaluations`、`/evaluation-plans`、`/models` |
| `/console/execution` | 执行与预算 | 动作台账与回执、人工处置申请与审批与撤销、稳定目标预算账本、自动化停用 | `/api/v2/actions`（含 `receipts` 子资源、`decisions`、`revocations`）、`/budget-targets`、`/automation-stops`、`/assets`、`/evidence-episodes`、`/decisions` |

---

## 3. 数据来源与会话

控制台不内置演示数据，所有页面数据均从后端读取（后端以 MySQL 为事实源）：既有页面走 `/api/v1`，
09—11 三个模块走 host-guard v5 的 `/api/v2`。开发服务器将 `/api/v1` 与 `/api/v2` 代理到 `127.0.0.1:18080`。

- 登录走 `POST /api/v1/auth/login` 建立服务端会话（HttpOnly Cookie）；写请求自动携带 `/auth/csrf` 下发的 CSRF 头。未登录访问 `/console/*` 跳转登录页，会话失效（401）时自动返回登录页。
- 页面按 `/auth/me` 返回的权限决定请求哪些接口、显示哪些操作；最终授权始终由后端判定，无权限区块显示为空或提示，不补示例值。
- 数据库中没有记录时页面如实显示“暂无记录”。
- 已接入的写操作：事件状态迁移、研判笔记、处置申请（带 `Idempotency-Key`）、审批决定、资产授权批准、模型校验/发布申请/发布审批/本机激活、响应策略生命周期、告警标注与第二人复核。
- P4 的 v2 写操作（09—11）：全部带 `Idempotency-Key`，审批/激活/停用类另带 `If-Match: <revision>`。包括决策策略复核、发布组合登记报告/封存/审批/激活/停用、人工处置申请/审批/撤销、自动化停用。前端只按权限隐藏入口，职责分离（自批 403）与状态迁移以后端判定为准。
- **机器侧路由不在控制台范围内**：`/api/v2/machine/**` 要求 `Bearer mch_*` 机器身份并清空浏览器会话，由采集器与执行器调用，浏览器不可用。
- 回放启停与 v1 处置执行器未开放（后端执行端点固定返回 `503 ACTION_EXECUTION_UNAVAILABLE`）。

---

## 4. 本地命令

```bash
cd frontend
npm ci              # 按锁文件安装依赖
npm run dev         # 开发服务器
npm run lint        # ESLint，警告即失败
npm run typecheck   # vue-tsc 类型检查
npm test            # Vitest
npm run build       # 类型检查 + 生产构建
npm run preview     # 预览生产构建
```

API 客户端 `src/api/client.ts` 同时支持两套信封：v1 为 `{ success, data, error, requestId }`，v2 为 `{ requestId, data, error }`；自动携带 CSRF 头与会话 Cookie，写请求注入幂等键，审批类操作注入 `If-Match`。详见[前端设计文档](../docs/前端设计文档.md)。

## 5. F3 非页面交接（2026-10-15）

**已完成**：接口、策略预校验、导航与重定向、合成 msw 状态回写和非页面回归（实现 `e6aad6d`，分支 `Xyhhh/v1-f3`，本次先通过 PR 合入 main）。**还剩**：模型与数据集、发布管理的页面设计与完整表单/详情交互，筛选与待办 `id` 打开、四态/写权限/本人审批隐藏、危险操作确认、真实后端联调。`views/release/ModelsView.vue` 是最小读取载体；`BundlesView.vue` 复用旧 Release/Lab 页面，均不作为正式页面验收结论。lab 详情已迁入 `views/release/LabRunDetailView.vue`；C1 删除旧组件前须先解除桥接层对 `views/console/ReleaseView.vue`、`LabView.vue` 的依赖。

### 接口入口

统一从 `@/api/v2/release` 导入 `releaseApi` 和 DTO；错误沿用 `ApiError` 与 `errText`，写成功后重新读取事实。

| 资源 | 列表 / 详情 | 写入与子资源 |
|---|---|---|
| models | `listModels` / `getModel` | `registerModel`、`updateModel`、`retireModel`、`validateModel`、`getModelValidations` |
| datasets | `listDatasets` / `getDataset` | `registerDataset`、`updateDataset`、`retireDataset` |
| release-bundles | `listBundles` / `getBundle` | `requestBundle`、`importBundleReport`、`sealBundle`、`decideBundle`、`activateBundle`、`suspendBundle`、`retireBundle`、`listBundleBindings` |
| decision-policies | `listPolicies` / `getPolicy` | `draftPolicy`、`deletePolicy`、`reviewPolicy` |
| capabilities | `listCapabilities` / `getCapability` | `registerCapability` |
| evaluation-plans | `listEvaluationPlans` / `getEvaluationPlan` | `registerEvaluationPlan`（支持冻结原件引用与旧结构化登记） |
| evaluations | `listEvaluations` / `getEvaluation` | 只读；评价由组合 imports 或 lab reports 登记，无独立 POST 创建路由 |
| replay-runs | `listReplayRuns` / `getReplayRun` | `createReplayRun`；`startReplayRun` / `completeReplayRun` / `failReplayRun` 供 runner 对接 |
| lab-validation-runs | `listLabRuns` / `getLabRun` | 资格：`decideLabRun` / `revokeLabRun`；子资源：`getLabEvents` / `getLabReportInput` / `getLabQualifications`；`createLabRun` 及生命周期、事实追加、报告导入方法供 runner 对接 |

- 表单字段键可复用 `RELEASE_FIELDS`；`isSha256` 校验 SHA-256，UUID 可复用 `api/v2/detect.ts` 的 `isUuid`。模型校验不接受任意 profile，固定 `MODEL_VALIDATION_PROFILE_ID = host-guard-onnx-v1`。
- 修改资料、退役、删除、审批及 lab 操作的方法要求传当前 `revision`。每次提交默认新建 UUID 幂等键；同一次提交重试可保留显式 key 与原 revision，冲突后重读再提交。`guard.patch/remove` 共用原 CSRF 与错误逻辑，DELETE 不发送 JSON 体。
- `draftPolicy` 接受 JSON 原文或对象；先调用 `validateDecisionPolicy` 可得到 `{valid,issues}`，错误含 JSON Pointer `path`。预校验直接使用仓库 `decision-policy.schema.json` 与 `feature-profile.json`，不复制冻结契约；非法策略同步抛出 `DecisionPolicyValidationError`，不会发送请求。
- 列表查询按集合白名单传值：模型/数据集/策略/组合可搜索和状态筛选；能力/计划可搜索但无状态筛选；评价/研究回放无 `q`；全局目录无 `assetId`。普通集合时间为 UTC 的 `[from,until)`，排序 `createdAt|updatedAt`；lab 列表只传 `cursor/status/limit`，events 用 `after/limit`。导入报告可返回 `passed`，当前后端不支持按该状态筛选。
- 策略/组合真实 DTO 隐藏 `createdBy/requestedBy`；后续需确认安全的本人识别契约，不能依赖 mock 内部 `owners` 隐藏审批。服务端仍会拒绝自批，前端隐藏不授予操作权。

### 导航与兼容地址

发布管理参数为 `tab=bundles|policies|capabilities|validation`；验证记录内为 `record=lab|evaluations`，缺省 lab，以承接后端待办 `tab=validation&id=…`。模型页使用 `tab=models|datasets`。`id` 的自动详情打开尚待正式页面实现。

| 旧地址 | 目标 |
|---|---|
| `/console/release/evaluations` | `/console/release/bundles?tab=validation&record=evaluations` |
| `/console/release/policies` | `/console/release/bundles?tab=policies` |
| `/console/release/lab` | `/console/release/bundles?tab=validation&record=lab` |
| `/console/release` | `/console/release/bundles?tab=bundles` |
| `/console/lab` | `/console/release/bundles?tab=validation&record=lab` |
| `/console/lab/:id` | `/console/release/lab/:id` |

跳转保留有效分段、其他查询参数与锚点，旧路由名保留一个兼容版本；非法或重复分段回退到旧入口对应段。最终路由继续鉴权，lab 详情独立要求 `evaluation.read`，不因归入发布管理而放宽。两个接线载体按分段和权限决定读取，正式页面应保持这一约束。

### 测试与边界

`test/handlers/release.ts` 已加入统一 msw 服务器；测试前调用 `resetReleaseState()`，可用 `releaseRows` / `labRow` 断言写后回读，用 `releaseState.referenced` 模拟 409 引用冲突。夹具和 `owners` 只存在于测试，不含真实制品或执行授权；合成 lab 报告不授予自动资格，也不推断清理成功。

已通过 `npm ci`、`npm run lint`、`npm run typecheck`、`npm test -- --coverage`（30 文件、333 项，原阈值不变）和 `npm run build`。已整合 main 的 F2 菜单与待办中心，并重新运行上述检查（锁文件与依赖未变）；页面由用户从 main 另开分支实现。这些是客户端与合成 API 证据；真实后端、签名制品、数据库和浏览器端到端仍待后续验证。状态与接续范围见[初版任务单 F3](../docs/任务/初版落地任务单.md#f3-模型与数据集发布管理)及[实施记录 6.29](../docs/系统实施记录.md#629-初版-f3接口预校验与导航接线2026-10-15)。
