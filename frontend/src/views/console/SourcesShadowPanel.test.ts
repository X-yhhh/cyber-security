import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { getMock, postMock, toastMock, canMock } = vi.hoisted(() => ({ getMock: vi.fn(), postMock: vi.fn(), toastMock: vi.fn(), canMock: vi.fn() }))

vi.mock('@/api/client', () => ({ api: { get: getMock, post: postMock }, ApiError: class extends Error {} }))
vi.mock('@/api/session', () => ({ can: canMock }))
vi.mock('@/composables/toast', () => ({ toast: toastMock }))

import SourcesShadowPanel from './SourcesShadowPanel.vue'

const source = { id: 3, sourceKey: 'mac-sensor', sourceType: 'sensor', environment: 'lab', schemaVersion: 'v4', status: 'active', lastSuccessAt: null }

function report() {
  return {
    reportVersion: 'shadow-report-v1', thresholdsVersion: 'g3-2026.10', generatedAt: '2026-10-08T02:00:00Z', dataSourceId: 3,
    from: '2026-10-01T00:00:00Z', to: '2026-10-08T00:00:00Z', timeZone: 'Asia/Shanghai',
    coverage: {
      sensors: 1, healthWindows: 2000, coveredHours: 150, rangeHours: 168, coverageRatio: 0.893, observedDays: 6, observedWeekdays: 4, observedWeekendDays: 2,
      days: [{ date: '2026-10-01', weekend: false, coveredHours: 23.5, observed: true, modelAlerts: 4 }], gapCount: 2, gapHours: 18, gaps: [],
      flowsSeen: 1000, flowsEmitted: 990, flowsDropped: 10, queueDepthMax: 7,
    },
    records: {
      total: 990, ingestRejected: 5, manualReview: 0, ingestIssueCodes: { FIELD_MISSING: 5 }, notInferred: 5, inferenceStatus: { succeeded: 960 },
      rejectReasons: {}, contractRejected: 3, operationalFailed: 1, contractRejectRate: 0.0081, notInModelScope: 21, scored: 960, scoredAttack: 12,
      scopeAttackRatio: 0.0125, outOfVocabulary: { proto: 2 }, outOfVocabularyRatio: { proto: 0.002 },
    },
    alerts: { modelAlerts: 12, assetsWithAlerts: 1, meanPerAssetDay: 2, maxPerAssetDay: 5, maxDay: '2026-10-03' },
    review: {
      rule: '告警不超过 20 条：全部复核', population: 12, sampleSize: 12, labeled: 1, falsePositive: 1, truePositive: 0, falsePositiveRate: 1,
      sample: [{ alertId: 41, alertKey: 'alt-41', detectedAt: '2026-10-03T01:00:00', severity: 'medium', score: 0.91, label: null, reviewStatus: null }],
    },
    drift: {
      status: 'computed', baselineModelVersionId: 1, baselineVersion: 'unsw-binary-2026.09.0', models: [{ modelVersionId: 1, version: 'unsw-binary-2026.09.0', artifactSha256: 'abc', scored: 960 }],
      samples: 960, minSamples: 500, psi: { dur: 0.35, sbytes: 0.25, proto: 0.01, state: null }, otherRatio: { proto: 0.002 }, invalid: {}, fieldsAboveWarning: ['dur', 'sbytes'], maxPsi: 0.35,
    },
    performance: { batches: 40, p50Ms: 120, p95Ms: 400, p99Ms: 800, maxMs: 1200, deadLetters: 0, consumerRetrying: 0, outboxPending: 0, oldestPendingSeconds: null },
    criteria: [
      { key: 'coverage', title: '连续运行覆盖', threshold: '≥ 7 天且含工作日与非工作日', value: '6 天', status: 'pending', note: '运行时长不足' },
      { key: 'manual_fp', title: '人工抽检误报率', threshold: '≤ 20%', value: '100%', status: 'fail', note: null },
    ],
    verdict: 'fail',
    limitations: ['只覆盖两台登记终端的可见流量，不代表全网。', '正常流量上的误报率不代表攻击检出率。'],
  }
}
const pending = (items: unknown[]) => ({ totalElements: items.length, page: 0, size: 20, items })
const fb = { id: 77, alertId: 41, alertKey: 'alt-41', alertType: 'model', label: 'false_positive', note: '本机在执行备份', reviewedBy: 2, reviewerName: '研判员甲', reviewedAt: '2026-10-03T02:00:00', reviewStatus: 'pending', secondReviewedBy: null, secondReviewerName: null, secondReviewedAt: null, secondReviewReason: null, trainingEligible: false, dataSourceId: 3, assetId: 1 }

function mountPanel() {
  return mount(SourcesShadowPanel, { props: { sources: [source] }, global: { stubs: { teleport: true } } })
}

describe('SourcesShadowPanel', () => {
  beforeEach(() => {
    getMock.mockReset(); postMock.mockReset(); toastMock.mockReset()
    canMock.mockReset().mockImplementation(() => true)
  })

  it('generates the report with UTC instants and renders verdict, criteria, drift and limitations', async () => {
    getMock.mockImplementation((path: string) => Promise.resolve(path.startsWith('/api/v1/feedback-reviews') ? pending([]) : report()))
    const wrapper = mountPanel()
    await flushPromises()
    expect(getMock).not.toHaveBeenCalledWith(expect.stringContaining('shadow-report'))

    await wrapper.get('input[type="datetime-local"]').setValue('2026-10-01T08:00')
    await wrapper.findAll('input[type="datetime-local"]')[1].setValue('2026-10-08T08:00')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const path = getMock.mock.calls.map((c) => c[0] as string).find((p) => p.includes('shadow-report'))!
    const q = new URL(path, 'http://x').searchParams
    expect(path.startsWith('/api/v1/data-sources/3/shadow-report?')).toBe(true)
    expect(q.get('from')).toBe(new Date('2026-10-01T08:00').toISOString())
    expect(q.get('to')).toBe(new Date('2026-10-08T08:00').toISOString())
    expect(q.get('zone')).toBe('Asia/Shanghai')

    const text = wrapper.text()
    expect(text).toContain('未通过')
    expect(text).toContain('g3-2026.10')
    expect(text).toContain('连续运行覆盖')
    expect(text).toContain('人工抽检误报率')
    expect(text).toContain('未达标')
    expect(text).toContain('待定')
    expect(text).toContain('只覆盖两台登记终端的可见流量，不代表全网。')
    expect(text).toContain('正常流量上的误报率不代表攻击检出率。')
    expect(text).toContain('> 0.3')
    expect(text).toContain('> 0.2')
    expect(text).toContain('无法计算')
    expect(text).toContain('2026-10-01')
    expect(text).toContain('影子验证只读汇总，不修改阈值、不换模型、不触发处置。')
    wrapper.unmount()
  })

  it('rejects an inverted range without calling the backend', async () => {
    getMock.mockResolvedValue(pending([]))
    const wrapper = mountPanel()
    await flushPromises()
    await wrapper.get('input[type="datetime-local"]').setValue('2026-10-08T08:00')
    await wrapper.findAll('input[type="datetime-local"]')[1].setValue('2026-10-01T08:00')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(toastMock).toHaveBeenCalledWith('开始时间必须早于结束时间。', 'warn')
    expect(getMock).not.toHaveBeenCalledWith(expect.stringContaining('shadow-report'))
    wrapper.unmount()
  })

  it.each([['approve', '批准用于训练'], ['reject', '驳回']] as const)('sends the %s review decision and refreshes the list', async (decision, button) => {
    getMock.mockResolvedValueOnce(pending([fb])).mockResolvedValue(pending([]))
    postMock.mockResolvedValue({ ...fb, reviewStatus: decision === 'approve' ? 'training_approved' : 'rejected' })
    const wrapper = mountPanel()
    await flushPromises()

    expect(getMock).toHaveBeenCalledWith('/api/v1/feedback-reviews?page=0&size=20')
    expect(wrapper.text()).toContain('复核人不能是标注人')
    await wrapper.get('button[aria-label="复核 alt-41"]').trigger('click')
    expect(wrapper.text()).toContain('本机在执行备份')

    const decide = wrapper.findAll('button').find((b) => b.text() === button)!
    expect(decide.attributes('disabled')).toBeDefined()
    await wrapper.get('[role="dialog"] textarea').setValue('  说明与时间线一致  ')
    await decide.trigger('click')
    await flushPromises()

    expect(postMock).toHaveBeenCalledWith('/api/v1/feedback-samples/77/review', { decision, reason: '说明与时间线一致' })
    expect(getMock).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('没有待你复核的标注。')
    wrapper.unmount()
  })

  it('hides the review queue without feedback.review and opens the label drawer from a sample', async () => {
    canMock.mockImplementation((p: string) => p !== 'feedback.review')
    getMock.mockImplementation((path: string) => Promise.resolve(path.includes('shadow-report') ? report() : path === '/api/v1/alerts/41' ? { id: 41, status: 'new', alertType: 'model' } : []))
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.text()).not.toContain('待我复核')
    expect(getMock).not.toHaveBeenCalledWith(expect.stringContaining('/api/v1/feedback-reviews'))

    await wrapper.get('form').trigger('submit')
    await flushPromises()
    await wrapper.get('button[aria-label="标注 alt-41"]').trigger('click')
    await flushPromises()

    expect(getMock).toHaveBeenCalledWith('/api/v1/alerts/41/feedback')
    expect(wrapper.find('input[value="false_positive"]').exists()).toBe(true)
    wrapper.unmount()
  })
})
