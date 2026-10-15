/**
 * lab 验证详情与 G3 报告（原演示最小集 FE-2）及共享组件；C1 删除旧 v2 视图后从 views/console 迁来。
 * 以 mock 的 v2 客户端验证请求参数与关键口径文案（lab_auto 仅 lab）。
 */
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { perms, push } = vi.hoisted(() => ({ perms: { value: new Set<string>() }, push: vi.fn() }))

vi.mock('@/api/client', () => ({ guard: { list: vi.fn(), get: vi.fn(), read: vi.fn() } }))
vi.mock('@/api/session', () => ({ can: (p: string) => perms.value.has(p), session: { user: null } }))
vi.mock('vue-router', () => ({
  RouterLink: { props: ['to'], template: '<a><slot /></a>' },
  useRoute: () => ({ params: { id: 'run-1' } }),
  useRouter: () => ({ push }),
}))

import { guard } from '@/api/client'
import { useCursor } from '@/composables/cursor'
import FamilyScores from '@/components/FamilyScores.vue'
import LabRunDetailView from './LabRunDetailView.vue'

const global = {
  stubs: {
    PageHead: { props: ['title'], template: '<header>{{ title }}</header>' },
    Tag: { props: ['label'], template: '<span class="tag">{{ label }}</span>' },
    Drawer: { props: ['open', 'title'], template: '<section v-if="open" class="drawer"><slot /></section>' },
  },
}

beforeEach(() => {
  vi.clearAllMocks()
  perms.value = new Set()
})

const report = {
  sessionId: 'run-1', status: 'passed', passed: true, runStatus: 'completed', evidenceKind: 'lab',
  classes: [
    { family: 'dos_flood', status: 'passed', sources: ['model'], scenarioIds: ['dos_flood-1'], trialAutoEligible: false, firstAlertLatencyMs: 596, firstApplicationLatencyMs: null },
    { family: 'brute_force', status: 'passed', sources: ['model'], scenarioIds: ['brute_force-1'], trialAutoEligible: true, firstAlertLatencyMs: 305, firstApplicationLatencyMs: 2542 },
  ],
  scenarios: [
    { scenarioId: 'brute_force-1', family: 'brute_force', source: 'model', ruleId: null, status: 'passed', completed: true, alertLatencyMs: 990, issueLatencyMs: 3310, applicationLatencyMs: 7370, cleanupLatencyMs: 687900, qualifiedCoverage: 1, commands: [{ commandId: 'c1', issuedAt: null, appliedAt: null, clearedAt: null, installation: 'verified', cleanup: 'verified' }], missing: [] },
    { scenarioId: 'normal-1', family: 'normal', source: 'model', ruleId: null, status: 'passed', completed: true, alertLatencyMs: null, issueLatencyMs: null, applicationLatencyMs: null, cleanupLatencyMs: null, qualifiedCoverage: 1, commands: [], missing: [] },
  ],
  normal: { passed: true, perHour: 0, cumulativeMs: 2984446, singleAssetUnionMs: 803134, verifiedFalseBlocks: 0, falseBlocksTtlRestored: true },
  limitations: ['L2 not evaluated'], missingClasses: [], unlinkedCommandIds: [], unlinkedDecisionIds: [], unverifiedItems: [],
  latencyIsReportOnly: true, subjectSha256: 's'.repeat(64), evaluationPlanSha256: 'p'.repeat(64), inputSha256: 'i'.repeat(64), sessionSha256: 'x'.repeat(64),
}
const run = {
  id: 'run-1', eligibilityStatus: 'active', effectiveEligibility: 'expired', blockedReason: null, runStatus: 'completed', timedOut: false, revision: 3,
  assetId: 'a1', bundleId: 'bundle-1', sessionSha256: 'x'.repeat(64), manifestSha256: 'm'.repeat(64), evidenceKind: 'lab',
  validUntil: '2026-10-13T14:50:45Z', startedAt: '2026-10-13T12:53:23Z', endedAt: '2026-10-13T13:09:13Z', stopRequestedAt: null, cleanupStatus: 'not_asserted', executionAuthority: false,
}

describe('lab 验证详情与 G3（FE-2）', () => {
  it('详情：等级只来自已登记来源，lab_auto 标注仅 lab，未登记类别显示只告警', async () => {
    perms.value = new Set(['evaluation.read'])
    vi.mocked(guard.read).mockImplementation((path: string) => {
      if (path === 'lab-validation-runs/run-1') return Promise.resolve(run)
      if (path === 'lab-validation-runs/run-1/qualifications') return Promise.resolve({ sessionId: 'run-1', bundleId: 'bundle-1', bundleUsable: true, sources: [{ family: 'brute_force', source: 'model', level: 'lab_auto', evaluationId: 'eval-1', subjectSha256: 's'.repeat(64) }] })
      if (path === 'lab-validation-runs/run-1/events') return Promise.resolve({ items: [{ eventId: 'e1', sequence: 1, sha256: 'h', fact: { evaluationId: 'eval-1', status: 'passed', qualificationEffect: 'registered', signatureVerified: true } }], nextAfter: null })
      return Promise.reject(new Error(path))
    })
    vi.mocked(guard.get).mockResolvedValue({ id: 'eval-1', runKind: 'canary', runnerIdentity: 'mac-lab-runner', status: 'passed', payload: report, createdAt: '2026-10-13T13:12:16Z' })
    const w = mount(LabRunDetailView, { global })
    await flushPromises()
    expect(guard.get).toHaveBeenCalledWith('evaluations', 'eval-1')
    expect(guard.list).not.toHaveBeenCalled()
    expect(w.text()).toContain('G3 联合闭环 · 通过')
    expect(w.text()).toContain('不适用于真实主机')
    const rows = w.findAll('tbody tr').map((r) => r.text())
    expect(rows.find((r) => r.startsWith('暴力破解'))).toContain('lab 自动（仅 lab）')
    expect(rows.find((r) => r.startsWith('洪泛 DoS'))).toContain('只告警')
    expect(rows.find((r) => r.startsWith('洪泛 DoS'))).toContain('不封禁')
    expect(w.text()).toContain('L2 not evaluated')
    // 报告导入事实不带 kind，按 evaluationId 识别。
    expect(w.text()).toContain('报告导入 1')
    expect(w.text()).toContain('来源等级已登记')
    w.unmount()
  })

  it('未登记等级时按 sessionId 在评价运行中查找报告', async () => {
    perms.value = new Set(['evaluation.read'])
    vi.mocked(guard.read).mockImplementation((path: string) => {
      if (path === 'lab-validation-runs/run-1') return Promise.resolve(run)
      if (path === 'lab-validation-runs/run-1/qualifications') return Promise.resolve({ sessionId: 'run-1', bundleId: 'bundle-1', bundleUsable: true, sources: [] })
      return Promise.resolve({ items: [], nextAfter: null })
    })
    vi.mocked(guard.list).mockResolvedValue({ items: [
      { id: 'other', payload: { sessionId: 'run-2' }, createdAt: '2026-10-13T13:00:00Z' },
      { id: 'mine', runnerIdentity: 'r', payload: { ...report, passed: false, status: 'failed' }, createdAt: '2026-10-13T13:12:16Z' },
    ], nextCursor: null })
    const w = mount(LabRunDetailView, { global })
    await flushPromises()
    expect(guard.list).toHaveBeenCalledWith('evaluations', { limit: 200 })
    expect(w.text()).toContain('G3 联合闭环 · 未通过')
    expect(w.text()).toContain('本会话未登记任何来源等级')
    w.unmount()
  })
})

describe('共享组件', () => {
  it('四类分数缺失时显示「—」，否则按固定顺序并标出最高类', () => {
    expect(mount(FamilyScores, { props: { scores: null } }).text()).toBe('—')
    const w = mount(FamilyScores, { props: { scores: { dos_slow: 0.7, port_scan: 0.1, brute_force: 0.15, dos_flood: 0.05 } } })
    const items = w.findAll('li').map((li) => li.text())
    expect(items[0]).toContain('端口扫描')
    expect(items[3]).toContain('慢速 DoS')
    expect(w.findAll('li')[3].find('span').classes()).toContain('text-ink')
  })

  it('游标「上一页」从第二页回到第一页时不带游标', async () => {
    const load = vi.fn((cursor?: string) => Promise.resolve({ items: [cursor ?? 'first'], nextCursor: cursor ? null : 'c-2' }))
    const c = useCursor<string>(load)
    await flushPromises()
    await c.forward()
    expect(c.items.value).toEqual(['c-2'])
    await c.back()
    expect(load).toHaveBeenLastCalledWith(undefined)
    expect(c.items.value).toEqual(['first'])
  })
})
