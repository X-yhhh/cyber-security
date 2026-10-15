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

当前路由以 `src/router/nav.ts` 与 `src/router/index.ts` 为准。控制台页面挂在 `/console` 下，未登录访问会跳转登录页。以下保留历史模块对照，v1 页面与旧入口待 C1 删除；当前菜单及页面交付状态见[初版任务单](../docs/任务/初版落地任务单.md)。

| 路由 | 页面 | 主要功能 | 调用的后端接口（未标版本的历史项为 `/api/v1`） |
| --- | --- | --- | --- |
| `/` | 首页 | 项目介绍与入口 | 无 |
| `/login` | 登录 | v2 服务端会话登录，失败显示脱敏消息与 request ID | `/api/v2/auth/csrf`、`/api/v2/auth/login`、`/api/v2/auth/me` |
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

控制台不内置演示数据，所有页面数据均从后端读取（后端以 MySQL 为事实源）。公共客户端默认 `/api/v2`，待 C1 删除的旧页面显式调用 `/api/v1`。开发服务器将 `/api/v1` 与 `/api/v2` 代理到 `127.0.0.1:18080`。

- 登录走 `POST /api/v2/auth/login` 建立服务端会话（HttpOnly Cookie）；退出与改密也走 v2，三者均带 `Idempotency-Key`。写请求自动携带 `/api/v2/auth/csrf` 下发的 CSRF 头，头名不硬编码。未登录访问 `/console/*` 跳转登录页，会话失效（401）时自动返回登录页。
- 页面按 `/api/v2/auth/me` 返回的权限决定请求哪些接口、显示哪些操作；最终授权始终由后端判定，无权限区块显示为空或提示，不补示例值。
- 数据库中没有记录时页面如实显示“暂无记录”。
- 已接入的写操作：事件状态迁移、研判笔记、处置申请（带 `Idempotency-Key`）、审批决定、资产授权批准、模型校验/发布申请/发布审批/本机激活、响应策略生命周期、告警标注与第二人复核。
- P4 的 v2 写操作（09—11）：全部带 `Idempotency-Key`，审批/激活/停用类另带 `If-Match: <revision>`。包括决策策略复核、发布组合登记报告/封存/审批/激活/停用、人工处置申请/审批/撤销、自动化停用。前端只按权限隐藏入口，职责分离（自批 403）与状态迁移以后端判定为准。
- **机器侧路由不在控制台范围内**：`/api/v2/machine/**` 要求 `Bearer mch_*` 机器身份并清空浏览器会话，由采集器与执行器调用，浏览器不可用。
- 回放启停与 v1 处置执行器未开放（后端执行端点固定返回 `503 ACTION_EXECUTION_UNAVAILABLE`）。

F5 已完成 `api/v2/iam.ts`（用户、绑定、只读审计）、`roles.ts`（角色、权限、成员与冲突提示）、会话切换及 MSW 回归。用户/角色/新审计页面和对应导航尚未完成，按用户确认随页面交接。IAM asset `scopeId` 是内部十进制 ID，不能直接提交资产列表的公开 UUID。

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

API 客户端 `src/api/client.ts` 同时支持两套信封：v1 为 `{ success, data, error, requestId }`，v2 为 `{ requestId, data, error }`；自动携带 CSRF 头与会话 Cookie；v2 业务封装和会话模块注入幂等键，需并发控制的操作注入 `If-Match`。详见[前端设计文档](../docs/前端设计文档.md)。
