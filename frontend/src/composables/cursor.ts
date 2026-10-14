import { ref, type Ref } from 'vue'
import { errText } from '@/composables/load'

/**
 * v2 游标分页读取：后端不返回总数，用游标栈支持「上一页」。
 * 每次请求用序号作废在途响应，避免切换分段、改筛选或翻页后旧结果覆盖新结果。
 * `immediate=false` 时由调用方在有权限或切到对应分段时再 reset()，避免无权请求。
 */
export function useCursor<T>(load: (cursor?: string) => Promise<{ items: T[]; nextCursor: string | null }>, immediate = true) {
  const items = ref([]) as Ref<T[]>
  const next = ref<string | null>(null)
  const loading = ref(immediate)
  const error = ref('')
  const stack = ref<string[]>([])
  const turning = ref(false)
  let seq = 0

  async function go(cursor?: string) {
    const mine = ++seq
    loading.value = true
    error.value = ''
    try {
      const page = await load(cursor)
      if (mine !== seq) return
      items.value = page.items
      next.value = page.nextCursor
    } catch (e) {
      if (mine !== seq) return
      error.value = errText(e)
      items.value = []
      next.value = null
    } finally {
      if (mine === seq) loading.value = false
    }
  }
  async function forward() {
    if (!next.value) return
    turning.value = true
    try {
      const cursor = next.value
      await go(cursor)
      stack.value.push(cursor)
    } finally { turning.value = false }
  }
  async function back() {
    if (!stack.value.length) return
    turning.value = true
    try {
      stack.value.pop()
      await go(stack.value[stack.value.length - 1])
    } finally { turning.value = false }
  }
  function reset() {
    seq++
    stack.value = []
    items.value = []
    next.value = null
    void go()
  }
  if (immediate) void go()
  return { items, next, loading, error, stack, turning, forward, back, reset }
}
