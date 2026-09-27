import type { ApprovalStatus, EventStatus, ExecStatus, Severity } from './demo'

type Tone = 'threat' | 'warn' | 'ok' | 'signal' | 'mute'

/** 语义色映射集中在此，避免各页面各自决定颜色。 */
export const severityTone: Record<Severity, Tone> = { critical: 'threat', high: 'threat', medium: 'warn', low: 'mute' }
export const eventTone: Record<EventStatus, Tone> = { open: 'threat', investigating: 'signal', contained: 'warn', resolved: 'ok', false_positive: 'mute', closed: 'mute' }
export const approvalTone: Record<ApprovalStatus, Tone> = { pending: 'signal', approved: 'ok', rejected: 'threat', expired: 'mute', cancelled: 'mute' }
export const execTone: Record<ExecStatus, Tone> = {
  queued: 'mute', running: 'signal', succeeded: 'ok', failed: 'threat', timed_out: 'threat', rollback_pending: 'warn', rolled_back: 'mute', rollback_failed: 'threat', unavailable: 'warn',
}
