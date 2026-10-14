import { reactive } from 'vue'
import { fetchSummary, type WorkbenchSummary } from '@/api/v2/summary'

/**
 * 各页读数带共用的汇总计数（GET /api/v2/summary，B2.5）：模块级缓存 30 秒，多个页面切换时不重复请求。
 * 汇总只用于概览读数，读取失败时保持为空对象（读数不显示），不影响页面主体列表；字段缺省即无权限，不补 0。
 */
const state = reactive<{ data: WorkbenchSummary; at: number }>({ data: {}, at: 0 })
let inflight: Promise<void> | null = null

export function useSummary(maxAgeMs = 30_000) {
  if (!inflight && Date.now() - state.at > maxAgeMs) {
    inflight = fetchSummary()
      .then((d) => { state.data = d ?? {}; state.at = Date.now() })
      .catch(() => { /* 读数带降级为不显示，主体列表不受影响 */ })
      .finally(() => { inflight = null })
  }
  return state
}

/** 测试用：清空缓存。 */
export function resetSummaryCache() { state.data = {}; state.at = 0; inflight = null }
