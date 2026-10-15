/**
 * 测试用 msw 服务器：汇总各分组处理器，并记录每个请求的方法与路径，
 * 供“无权限地址不发数据请求”一类断言使用。F1—F5 把自己的分组处理器加入 `handlers`。
 */
import { setupServer } from 'msw/node'
import { authHandlers } from './auth'
import { detectHandlers } from './detect'
import { summaryHandlers } from './summary'
import { statsHandlers } from './stats'
import { releaseHandlers } from './release'
import { responseHandlers } from './response'
import { todoHandlers } from './todos'
import { iamHandlers } from './iam'
import { assetsHandlers } from './assets'

export const handlers = [...authHandlers, ...summaryHandlers, ...detectHandlers, ...statsHandlers, ...releaseHandlers, ...responseHandlers, ...todoHandlers, ...iamHandlers, ...assetsHandlers]

export const server = setupServer(...handlers)

/** 已发出的请求，形如 `GET /api/v2/summary`（不含查询串）。 */
export const requests: string[] = []
server.events.on('request:start', ({ request }) => {
  requests.push(`${request.method} ${new URL(request.url).pathname}`)
})

/** 会话与外壳探针之外的请求，即页面发出的数据请求。 */
export const SHELL_REQUESTS = new Set(['GET /api/v2/auth/me', 'GET /health/ready'])
export const dataRequests = () => requests.filter((r) => !SHELL_REQUESTS.has(r))
