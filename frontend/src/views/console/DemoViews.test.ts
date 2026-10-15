/**
 * 演示最小集（FE-1—FE-3）：来源 × 类别判定、lab 验证与 G3 报告、健康与审计。
 * 以 mock 的 v2 客户端验证请求参数、权限门控与关键口径文案（lab_auto 仅 lab、replay_healthy 不代表现场）。
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
import DecisionsView from './DecisionsView.vue'
import LabView from './LabView.vue'
import LabRunDetailView from '@/views/release/LabRunDetailView.vue'
import HealthView from './HealthView.vue'

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

const decision = (id: string, decision: string, family: string, source: string, ruleId = '', reasonCode: string | null = null) => ({
  id, episodeId: `ep-${id}`, assetId: 'a1', bundleId: 'b1', decisionRevision: 1, decisionContractVersion: 'host-guard-decision/2026-10-08.1',
  decision, reasonCode, budgetTargetId: null, budgetRevision: null, evidenceSha256: 'e'.repeat(64), decidedAt: '2026-10-13T12:55:44Z', createdAt: '2026-10-13T12:55:44Z',
  evidence: { family, source, ruleId, scope: 'peer_service', environment: 'lab', reasonCode, capabilityId: null,
    selectedObservations: [{ observationId: `obs-${id}-0000`, family, source, ruleId, asOf: '2026-10-13T12:55:43Z' }], triggerObservationId: `obs-${id}-0000` },
})

describe('判定与来源（FE-1）', () => {
  it('无 detection.read 时不请求判定', () => {
    const w = mount(DecisionsView, { global })
    expect(guard.list).not.toHaveBeenCalled()
    expect(w.text()).toContain('detection.read')
    w.unmount()
  })

  it('按 类别 × 来源 分别计数，模型与规则不混算；点击单元格带入筛选', async () => {
    perms.value = new Set(['detection.read'])
    vi.mocked(guard.list).mockResolvedValueOnce({
      items: [
        decision('d1', 'block_candidate', 'brute_force', 'model'),
        decision('d2', 'alert', 'brute_force', 'model', '', 'TARGET_REF_STALE'),
        decision('d3', 'alert', 'brute_force', 'rule', 'brute-starts', 'QUALITY_UNSUPPORTED'),
        decision('d4', 'observe', 'dos_slow', 'model', '', 'QUALITY_UNSUPPORTED'),
      ],
      nextCursor: 'c-2',
    })
    const w = mount(DecisionsView, { global })
    await flushPromises()
    expect(guard.list).toHaveBeenCalledWith('decisions', { cursor: undefined, limit: 200 })
    expect(w.text()).toContain('已加载最近 4 条判定')
    const headers = w.findAll('thead th').map((th) => th.text())
    expect(headers).toEqual(['类别', '模型', '规则 brute-starts'])
    const model = w.get('button[aria-label="查看暴力破解·模型的判定"]').text()
    expect(model).toContain('告警 1')
    expect(model).toContain('候选 1')
    expect(model).toContain('目标引用过期')
    const rule = w.get('button[aria-label="查看暴力破解·规则 brute-starts的判定"]').text()
    expect(rule).toContain('告警 1')
    expect(rule).toContain('候选 0')

    await w.get('button[aria-label="查看暴力破解·规则 brute-starts的判定"]').trigger('click')
    expect(w.findAll('tbody tr')).toHaveLength(1)
    expect(w.get('tbody tr').text()).toContain('规则 brute-starts')
    await w.get('tbody tr').trigger('click')
    expect(w.get('.drawer').text()).toContain('自动门在「质量不达标」处拒绝')
    expect(w.get('.drawer').text()).toContain('触发观察')
    w.unmount()
  })

  it('再加载时带游标并追加样本', async () => {
    perms.value = new Set(['detection.read'])
    vi.mocked(guard.list)
      .mockResolvedValueOnce({ items: [decision('d1', 'alert', 'port_scan', 'model')], nextCursor: 'c-2' })
      .mockResolvedValueOnce({ items: [decision('d2', 'alert', 'port_scan', 'model')], nextCursor: null })
    const w = mount(DecisionsView, { global })
    await flushPromises()
    await w.findAll('button').find((b) => b.text().startsWith('再加载'))!.trigger('click')
    await flushPromises()
    expect(guard.list).toHaveBeenLastCalledWith('decisions', { cursor: 'c-2', limit: 200 })
    expect(w.text()).toContain('已加载最近 2 条判定')
    expect(w.text()).toContain('已到最早一条')
    w.unmount()
  })
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

describe('lab 验证与 G3（FE-2）', () => {
  it('列表按运行状态筛选时从第一页重读，并打开详情', async () => {
    perms.value = new Set(['evaluation.read'])
    vi.mocked(guard.read).mockResolvedValue({ items: [run], nextCursor: null })
    const w = mount(LabView, { global })
    await flushPromises()
    expect(guard.read).toHaveBeenCalledWith('lab-validation-runs', { cursor: undefined, status: '', limit: 50 })
    expect(w.text()).toContain('15 分 50 秒')
    await w.get('select').setValue('completed')
    await flushPromises()
    expect(guard.read).toHaveBeenLastCalledWith('lab-validation-runs', { cursor: undefined, status: 'completed', limit: 50 })
    await w.get('tbody tr').trigger('click')
    expect(push).toHaveBeenCalledWith({ name: 'lab-detail', params: { id: 'run-1' } })
    w.unmount()
  })

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

describe('健康与审计（FE-3）', () => {
  const dataReads = () => vi.mocked(guard.read).mock.calls.map((c) => c[0] as string).filter((p) => p !== 'summary')

  const window = {
    id: 'w1', assetId: 'a1', sensorId: 's1', captureScopeId: 'c1', sequence: 891, observerSessionId: 'o1',
    intervalStart: '2026-10-13T13:09:05Z', intervalEnd: '2026-10-13T13:09:06Z', receivedAt: '2026-10-13T13:09:06Z',
    verificationStatus: 'replay_healthy', serverVerifiedHealthy: false, failureReason: null, freshness: 'stale', healthState: 'stale',
    healthBasis: 'server_verified_file_replay_window', healthVersion: 'host-guard-capture-health/1.1.0', captureSource: 'file_replay', captureGap: false, clockSkewMs: 0,
    counterStart: { packetsSeen: 10, kernelDrops: null, capacityDrops: 0 }, counterEnd: { packetsSeen: 95, kernelDrops: null, capacityDrops: 0 },
  }

  it('只在切到分段时读取；replay_healthy 标注不代表现场采集，过期按新鲜度单独显示', async () => {
    perms.value = new Set(['ops.read'])
    vi.mocked(guard.read).mockImplementation((path: string) => Promise.resolve(path === 'health-windows'
      ? { asOf: 'x', items: [window], nextCursor: null }
      : { asOf: 'x', items: [], nextCursor: null }))
    const w = mount(HealthView, { global })
    await flushPromises()
    // 页头读数另读汇总接口（summary），这里只统计分段数据请求。
    expect(dataReads()).toEqual(['ops/status'])
    ;(w.vm as unknown as { view: string }).view = 'health'
    await flushPromises()
    expect(guard.read).toHaveBeenLastCalledWith('health-windows', { verificationStatus: undefined, cursor: undefined, limit: 50 })
    const row = w.get('tbody tr').text()
    expect(row).toContain('文件回放健康')
    expect(row).toContain('不代表现场采集健康')
    expect(row).toContain('已过期')
    expect(row).toContain('收包 +85')
    expect(row).toContain('内核丢包 不适用')
    await w.get('select').setValue('CAPTURE_GAP')
    await flushPromises()
    expect(guard.read).toHaveBeenLastCalledWith('health-windows', { verificationStatus: 'CAPTURE_GAP', cursor: undefined, limit: 50 })
    w.unmount()
  })

  it('审计需 audit.read；按动作精确筛选', async () => {
    perms.value = new Set(['audit.read'])
    vi.mocked(guard.read).mockResolvedValue({ asOf: 'x', items: [{ id: 'a', occurredAt: '2026-10-13T13:12:16Z', actorType: 'human', action: 'guard.lab.report_imported', resourceType: 'guard', requestId: 'r', outcome: 'success', resourceId: 'c45e4527-0000' }], nextCursor: null })
    const w = mount(HealthView, { global })
    await flushPromises()
    expect(dataReads()).toEqual([])
    expect(w.text()).toContain('ops.read')
    ;(w.vm as unknown as { view: string }).view = 'audit'
    await flushPromises()
    expect(guard.read).toHaveBeenCalledWith('audit', { action: undefined, cursor: undefined, limit: 50 })
    await w.get('form input').setValue('  guard.lab.report_imported ')
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(guard.read).toHaveBeenLastCalledWith('audit', { action: 'guard.lab.report_imported', cursor: undefined, limit: 50 })
    expect(w.text()).toContain('guard.lab.report_imported')
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
