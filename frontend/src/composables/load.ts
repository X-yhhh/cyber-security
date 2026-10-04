import { ref, type Ref } from 'vue'
import { ApiError } from '@/api/client'

/**
 * 页面数据加载：统一持有 loading / error，错误只展示后端脱敏消息与 request-id。
 * 返回的 reload 可在写操作成功后调用以从数据库重新读取，不做本地乐观修改。
 */
export function useLoad<T>(fn: () => Promise<T>, initial: T) {
  const data = ref(initial) as Ref<T>
  const loading = ref(true)
  const error = ref('')
  async function reload() {
    loading.value = true
    error.value = ''
    try {
      data.value = await fn()
    } catch (e) {
      error.value = errText(e)
    } finally {
      loading.value = false
    }
  }
  reload()
  return { data, loading, error, reload }
}

export function errText(e: unknown) {
  if (e instanceof ApiError) return e.requestId ? `${e.message}（request-id ${e.requestId}）` : e.message
  return e instanceof Error && e.message ? e.message : '请求失败'
}

/** 无权限（403）时返回空值，用于页面上的可选区块。 */
export async function optional<T>(p: Promise<T>, empty: T): Promise<T> {
  try { return await p } catch (e) {
    if (e instanceof ApiError && e.status === 403) return empty
    throw e
  }
}
