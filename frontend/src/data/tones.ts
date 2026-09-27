export type Tone = 'threat' | 'warn' | 'ok' | 'signal' | 'mute'

/** 语义色映射集中在此，避免各页面各自决定颜色。键为后端返回的状态值，未知值回退为 mute。 */
const map = (m: Record<string, Tone>) => new Proxy(m, { get: (t, k: string) => t[k] ?? 'mute' })

export const severityTone = map({ critical: 'threat', high: 'threat', medium: 'warn', low: 'mute' })
export const eventTone = map({ open: 'threat', investigating: 'signal', contained: 'warn', resolved: 'ok', false_positive: 'mute', closed: 'mute' })
export const approvalTone = map({ pending: 'signal', approved: 'ok', rejected: 'threat', expired: 'mute', cancelled: 'mute' })
export const execTone = map({
  queued: 'mute', running: 'signal', succeeded: 'ok', failed: 'threat', timed_out: 'threat', rollback_pending: 'warn', rolled_back: 'mute', rollback_failed: 'threat',
})
export const statusTone = map({ active: 'ok', approved: 'ok', completed: 'ok', succeeded: 'ok', pending: 'signal', running: 'signal', queued: 'mute', draft: 'mute', offline: 'warn', failed: 'threat', expired: 'mute', revoked: 'threat', disabled: 'mute', retired: 'mute', rejected: 'threat' })
