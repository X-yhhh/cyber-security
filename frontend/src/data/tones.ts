export type Tone = 'threat' | 'warn' | 'ok' | 'signal' | 'mute'

/**
 * 语义色映射集中在此，避免各页面各自决定颜色。键为后端返回的状态值，未知值回退为 mute；
 * 失败码类集合可指定回退色（例如未来新增的健康判定码按不健康着色，不显示为中性）。
 */
const map = (m: Record<string, Tone>, fallback: Tone = 'mute') => new Proxy(m, { get: (t, k: string) => t[k] ?? fallback })

export const severityTone = map({ critical: 'threat', high: 'threat', medium: 'warn', low: 'mute' })
export const eventTone = map({ open: 'threat', investigating: 'signal', contained: 'warn', resolved: 'ok', false_positive: 'mute', closed: 'mute' })
export const approvalTone = map({ pending: 'signal', approved: 'ok', rejected: 'threat', expired: 'mute', cancelled: 'mute' })
export const execTone = map({
  queued: 'mute', running: 'signal', succeeded: 'ok', failed: 'threat', timed_out: 'threat', rollback_pending: 'warn', rolled_back: 'mute', rollback_failed: 'threat',
})
/** 人工标注：v1 误报/真报 与 v2 正常/攻击/存疑；复核状态：待复核 / 已复核 / 已驳回。 */
export const feedbackTone = map({ false_positive: 'warn', true_positive: 'threat', benign: 'ok', attack: 'threat', ambiguous: 'warn' })
export const feedbackReviewTone = map({ pending: 'signal', training_approved: 'ok', reviewed: 'ok', rejected: 'mute' })
/** 影子验证 G3 逐项判定与总结论。 */
export const criterionTone = map({ pass: 'ok', fail: 'threat', pending: 'signal', not_evaluable: 'warn' })
export const verdictTone = map({ pass: 'ok', fail: 'threat', incomplete: 'warn' })
export const driftTone = map({ computed: 'ok', insufficient_samples: 'warn', baseline_unavailable: 'warn', mixed_artifacts: 'warn', no_samples: 'mute' })
export const statusTone = map({ active: 'ok', approved: 'ok', completed: 'ok', succeeded: 'ok', pending: 'signal', running: 'signal', queued: 'mute', draft: 'mute', offline: 'warn', failed: 'threat', expired: 'mute', revoked: 'threat', disabled: 'mute', retired: 'mute', rejected: 'threat' })

/* ------------------------------------------------------------------ *
 * host-guard v5（P4）状态语义色。
 *
 * 新增集合一律在此集中映射，页面不各自判色；未知值经 Proxy 回退为 mute。
 * signal 仍表示「进行中/需关注但非威胁」，不代表安全。
 * ------------------------------------------------------------------ */

/** 观察/推理：接收成功不等于推理成功，两者分别着色。 */
export const observationTone = map({ accepted: 'ok', rejected: 'threat', duplicate: 'mute' })
export const inferenceTone = map({ succeeded: 'ok', not_applicable: 'mute', rejected: 'threat', failed: 'threat', expired: 'mute' })

/** 决策结论：observe 为中性，alert 与 block_candidate 分别对应告警与阻断候选。 */
export const decisionTone = map({ observe: 'mute', alert: 'warn', block_candidate: 'threat' })

/** 动作终态：desiredState 与 observedState 分开显示，未核实的执行不记为已生效。 */
export const actionStateTone = map({
  pending: 'signal', dispatched: 'signal', active: 'signal', revoked: 'mute',
  applied: 'ok', cleared: 'mute', failed: 'threat', rejected: 'mute',
  uncertain: 'warn', recovery_failed: 'threat', expired: 'mute',
})

/** 发布组合：candidate → evaluated → approved → active。 */
export const bundleTone = map({ candidate: 'mute', evaluated: 'signal', approved: 'ok', active: 'ok', suspended: 'warn', retired: 'mute', rejected: 'threat' })

/** 决策策略：draft → reviewed → retired。 */
export const policyReviewTone = map({ draft: 'mute', reviewed: 'ok', retired: 'mute', rejected: 'threat' })

/** 能力等级：越高越需要独立证据，研究级不冒充已验证。 */
export const capabilityTone = map({ research: 'mute', alert_only: 'signal', lab_auto: 'warn', authorized_auto: 'ok', suspended: 'threat' })
/** F3 模型与数据集：校验状态与数据集状态共用；评价运行（导入报告 passed/failed）与研究回放的状态。 */
export const catalogTone = map({ pending: 'signal', validated: 'ok', failed: 'threat', retired: 'mute', active: 'ok' })
export const evaluationTone = map({ pending: 'mute', running: 'signal', completed: 'ok', passed: 'ok', failed: 'threat' })
export const replayTone = map({ queued: 'mute', running: 'signal', completed: 'ok', failed: 'threat' })

/** 目标预算标识核验状态。 */
export const identityTone = map({ verified: 'ok', unverified: 'warn', rotated: 'warn', conflict: 'threat' })

/** 采集健康窗口核验结果。 */
export const healthTone = map({ healthy: 'ok', degraded: 'warn', gap: 'threat', unknown: 'mute', incomplete: 'warn' })

/** 机器身份生命周期。 */
export const machineClientTone = map({ active: 'ok', revoked: 'mute', expired: 'mute', pending: 'signal' })

/** 推理适用性。 */
export const applicabilityTone = map({ applicable: 'ok', not_applicable: 'mute', unsupported: 'warn' })

/* ------------------------------------------------------------------ *
 * 演示最小集（FE-1—FE-3）。
 * replay_healthy 用 signal 而非 ok：它只证明回放完整，不能与现场健康混为一色。
 * ------------------------------------------------------------------ */
export const healthStateTone = map({ healthy: 'ok', replay_healthy: 'signal', stale: 'warn', unhealthy: 'threat', unknown: 'mute' })
export const verificationTone = map({ healthy: 'ok', replay_healthy: 'signal', COUNTER_UNKNOWN: 'mute', CLOCK_UNTRUSTED: 'mute', HEALTH_DELAY_EXCEEDED: 'warn' }, 'threat')
export const labRunTone = map({ registered: 'mute', running: 'signal', completed: 'ok', interrupted: 'warn', failed: 'threat', cancelled: 'mute', expired: 'mute' })
export const labEligibilityTone = map({ pending: 'signal', active: 'ok', blocked: 'warn', expired: 'mute', revoked: 'threat' })
export const scenarioTone = map({ passed: 'ok', failed: 'threat', incomplete: 'warn' })
/** 来源等级：lab_auto 用 warn 提示「仅 lab 有效」，不与授权环境的自动等级同色。 */
export const qualificationTone = map({ lab_auto: 'warn', authorized_auto: 'ok', alert_only: 'mute' })
export const machineStatusTone = map({ pending: 'signal', active: 'ok', offline: 'warn', suspended: 'warn', revoked: 'threat' })
/** 资产与接入（F4）：停用暂停新命令用 warn，退役为终态用中性；授权与配置的待批用 signal。 */
export const assetStatusTone = map({ active: 'ok', disabled: 'warn', retired: 'mute' })
export const criticalityTone = map({ critical: 'threat', high: 'warn', medium: 'mute', low: 'mute' })
export const authorizationTone = map({ pending: 'signal', active: 'ok', expired: 'mute', revoked: 'mute' })
export const validityTone = map({ valid: 'ok', not_yet_valid: 'signal', expired: 'mute' })
export const configTone = map({ draft: 'mute', pending: 'signal', approved: 'ok', active: 'ok', retired: 'mute', rejected: 'threat' })
export const bindingTone = map({ active: 'ok', suspended: 'warn', retired: 'mute' })
export const auditOutcomeTone = map({ success: 'ok', denied: 'threat', failure: 'threat', rejected: 'threat' })
