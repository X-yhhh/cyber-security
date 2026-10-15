import { onMounted, onScopeDispose, ref, shallowRef, watch } from 'vue'
import { session } from '@/api/session'
import { fetchSummary, type WorkbenchSummary } from '@/api/v2/summary'
import { fetchTodos, type TodosResponse } from '@/api/v2/todos'
import { errText } from './load'

export const TODO_POLL_MS = 30_000

/**
 * F2 待办数据与轮询，供后续页面直接接入，不包含布局或路由决策。
 *
 * 挂载且登录、页面可见时立即读取 todos 与 summary，每 30 秒刷新；隐藏时暂停，
 * 恢复可见时立即重读。同一轮请求未结束时复用其 Promise，避免定时器或手动刷新叠加。
 * 两个接口分别暴露错误（含 request-id），失败的数据置空，避免将旧计数当作当前结果。
 * 不使用模块缓存；身份/权限变化立即清空数据，离场和失效轮次的迟到响应不再回写。
 */
export function useTodos() {
  const todos = shallowRef<TodosResponse | null>(null)
  const summary = shallowRef<WorkbenchSummary | null>(null)
  const loading = ref(false)
  const error = ref('')
  const summaryError = ref('')
  let mounted = false
  let generation = 0
  let timer: ReturnType<typeof setInterval> | undefined
  let inflight: Promise<void> | null = null

  const visible = () => document.visibilityState === 'visible'
  let lastVisible = visible()
  function clearTimer() {
    if (timer !== undefined) clearInterval(timer)
    timer = undefined
  }
  function invalidate(clear: boolean) {
    generation++
    inflight = null
    loading.value = false
    if (clear) {
      todos.value = summary.value = null
      error.value = summaryError.value = ''
    }
  }

  function refresh(): Promise<void> {
    if (!mounted || !session.user || !visible()) return Promise.resolve()
    if (inflight) return inflight
    const mine = generation
    loading.value = true
    error.value = summaryError.value = ''
    const current = () => mounted && mine === generation
    const loadTodos = fetchTodos().then(
      (data) => { if (current()) todos.value = data },
      (e: unknown) => { if (current()) { todos.value = null; error.value = errText(e) } },
    )
    const loadSummary = fetchSummary().then(
      (data) => { if (current()) summary.value = data },
      (e: unknown) => { if (current()) { summary.value = null; summaryError.value = errText(e) } },
    )
    inflight = Promise.all([loadTodos, loadSummary]).then(() => {
      if (current()) { loading.value = false; inflight = null }
    })
    return inflight
  }

  function start() {
    clearTimer()
    if (!mounted || !session.user || !visible()) return
    void refresh()
    timer = setInterval(() => { void refresh() }, TODO_POLL_MS)
  }
  function onVisibilityChange() {
    if (lastVisible === visible()) return
    lastVisible = visible()
    clearTimer()
    invalidate(false)
    start()
  }
  watch(() => session.user, () => {
    clearTimer()
    invalidate(true)
    start()
  }, { deep: true, flush: 'sync' })
  onMounted(() => {
    mounted = true
    lastVisible = visible()
    document.addEventListener('visibilitychange', onVisibilityChange)
    start()
  })
  onScopeDispose(() => {
    mounted = false
    clearTimer()
    invalidate(false)
    document.removeEventListener('visibilitychange', onVisibilityChange)
  })
  return { todos, summary, loading, error, summaryError, refresh }
}
