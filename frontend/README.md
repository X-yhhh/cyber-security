# 网络威胁检测与受控防御平台 - 前端系统 (SecOps Console)

本项目基于 **Vue 3 稳定版 + Vite 6 + TypeScript + Tailwind CSS** 构建，采用现代化**高保真浅色科技防务风 (Clean Modern Light Cyber-SecOps Theme)** 设计。界面高级、审美统一、布局严谨，各功能模块严格对齐系统的设计契约（《项目详细设计》、《功能模块设计》、《接口设计》、《数据库设计》）。

---

## 1. 核心设计风格规范 (浅色科技主题)

- **底色与表面**：页面主底色为纯净冷灰 `#f8fafc` (Slate 50)，卡片采用纯白 `#ffffff`，辅以 1px 细微边界 `#e2e8f0` 与柔和多层微投影；
- **品牌科技蓝**：主色调选用科技钛青与深钴蓝 `#0284c7` (Sky 600)；
- **安全语义色彩**：
  - **危急 (Critical)**: 背景 `#fef2f2`，边框 `#fecaca`，文字 `#dc2626`
  - **高危 (High)**: 背景 `#fff7ed`，边框 `#fed7aa`，文字 `#ea580c`
  - **中危 (Medium)**: 背景 `#fefce8`，边框 `#fef08a`，文字 `#ca8a04`
  - **低危 (Low)**: 背景 `#f0fdfa`，边框 `#99f6e4`，文字 `#0d9488`
  - **安全 (Safe)**: 背景 `#f0fdf4`，边框 `#bbf7d0`，文字 `#16a34a`
  - **待办 (Pending)**: 背景 `#faf5ff`，边框 `#e9d5ff`，文字 `#9333ea`
- **专业数据排版**：IP 地址、端口、MAC、五元组、哈希、TTL 与特征契约统一采用等宽字体 (`JetBrains Mono`, `Fira Code`) 排版。

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

---

## 3. 数据来源与会话

控制台不内置演示数据，所有页面数据均通过 `/api/v1` 从后端读取（后端以 MySQL 为事实源）。开发服务器将 `/api/v1` 代理到 `127.0.0.1:18080`。

- 登录走 `POST /api/v1/auth/login` 建立服务端会话（HttpOnly Cookie）；写请求自动携带 `/auth/csrf` 下发的 CSRF 头。未登录访问 `/console/*` 跳转登录页，会话失效（401）时自动返回登录页。
- 页面按 `/auth/me` 返回的权限决定请求哪些接口、显示哪些操作；最终授权始终由后端判定，无权限区块显示为空或提示，不补示例值。
- 数据库中没有记录时页面如实显示“暂无记录”。
- 已接入的写操作：事件状态迁移、研判笔记、处置申请（带 `Idempotency-Key`）、审批决定、资产授权批准、模型校验/发布申请/发布审批/本机激活、响应策略生命周期、告警标注与第二人复核。回放启停与处置执行器未开放（后端执行端点固定返回 `503 ACTION_EXECUTION_UNAVAILABLE`）。

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

API 客户端 `src/api/client.ts` 遵循后端 `ApiEnvelope`（`{ success, data, error, requestId }`），自动携带 CSRF 头、会话 Cookie 与 `X-Request-Id`。
