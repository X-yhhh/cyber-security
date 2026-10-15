/** F3 的最终分段与兼容跳转；与后端 todos 的 tab=validation 保持一致。 */
import type { LocationQuery, RouteLocation } from 'vue-router'

export const RELEASE_TABS = ['bundles', 'policies', 'capabilities', 'validation'] as const
export type ReleaseTab = typeof RELEASE_TABS[number]
export const VALIDATION_RECORDS = ['evaluations', 'lab'] as const
export type ValidationRecord = typeof VALIDATION_RECORDS[number]

/** 旧地址已有有效分段时保留；裸参数、重复参数或未知值回落到该旧页面对应的分段。 */
export function releaseSelection(query: LocationQuery, fallback: ReleaseTab = 'bundles', fallbackRecord: ValidationRecord = 'evaluations') {
  const selected = typeof query.tab === 'string' ? query.tab : ''
  const alias = selected === 'evaluations' || selected === 'lab' ? selected : undefined
  const tab: ReleaseTab = alias ? 'validation' : RELEASE_TABS.includes(selected as ReleaseTab) ? selected as ReleaseTab : fallback
  const record: ValidationRecord = typeof query.record === 'string' && VALIDATION_RECORDS.includes(query.record as ValidationRecord)
    ? query.record as ValidationRecord : alias ?? fallbackRecord
  return { tab, record }
}

/** 筛选、待办 id 与锚点原样带到新地址；只有分段参数被规范化。 */
export const toRelease = (fallback: ReleaseTab, fallbackRecord?: ValidationRecord) => (to: RouteLocation) => {
  const { tab, record } = releaseSelection(to.query, fallback, fallbackRecord)
  const query: LocationQuery = { ...to.query, tab }
  if (tab === 'validation') query.record = record
  return { path: '/console/release/bundles', query, hash: to.hash }
}
