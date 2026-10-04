export type Tone = 'threat' | 'warn' | 'ok' | 'signal' | 'mute'

/** 语义色映射集中在此，避免各页面各自决定颜色。键为后端返回的状态值，未知值回退为 mute。 */
const map = (m: Record<string, Tone>) => new Proxy(m, { get: (t, k: string) => t[k] ?? 'mute' })

export const severityTone = map({ critical: 'threat', high: 'threat', medium: 'warn', low: 'mute' })
export const eventTone = map({ open: 'threat', investigating: 'signal', contained: 'warn', resolved: 'ok', false_positive: 'mute', closed: 'mute' })
export const approvalTone = map({ pending: 'signal', approved: 'ok', rejected: 'threat', expired: 'mute', cancelled: 'mute' })
export const execTone = map({
  queued: 'mute', running: 'signal', succeeded: 'ok', failed: 'threat', timed_out: 'threat', rollback_pending: 'warn', rolled_back: 'mute', rollback_failed: 'threat',
})
/** 人工标注：误报 / 真报；复核状态：待复核 / 可用于训练 / 已驳回。 */
export const feedbackTone = map({ false_positive: 'warn', true_positive: 'threat' })
export const feedbackReviewTone = map({ pending: 'signal', training_approved: 'ok', rejected: 'mute' })
/** 影子验证 G3 逐项判定与总结论。 */
export const criterionTone = map({ pass: 'ok', fail: 'threat', pending: 'signal', not_evaluable: 'warn' })
export const verdictTone = map({ pass: 'ok', fail: 'threat', incomplete: 'warn' })
export const driftTone = map({ computed: 'ok', insufficient_samples: 'warn', baseline_unavailable: 'warn', mixed_artifacts: 'warn', no_samples: 'mute' })
export const statusTone = map({ active: 'ok', approved: 'ok', completed: 'ok', succeeded: 'ok', pending: 'signal', running: 'signal', queued: 'mute', draft: 'mute', offline: 'warn', failed: 'threat', expired: 'mute', revoked: 'threat', disabled: 'mute', retired: 'mute', rejected: 'threat' })
