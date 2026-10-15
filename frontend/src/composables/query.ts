import { watch, type Ref } from 'vue'
import { useRoute, useRouter, type LocationQuery, type LocationQueryValue } from 'vue-router'

type QueryValue = LocationQueryValue | LocationQueryValue[] | undefined

/** 一个 URL 筛选字段：解析须验证类型/枚举；缺省值与暂不适用的字段不写入查询串。 */
interface QueryField<T extends string> {
  state: Ref<T>
  default: T
  parse?: (value: QueryValue, query: LocationQuery) => T
  serialize?: (value: T) => string | undefined
}

/** 只接受单个字符串；缺失、裸参数和重复参数交由页面按缺省值处理。 */
export const queryString = (value: QueryValue) => typeof value === 'string' ? value : ''

/** 比较查询串的语义，避免参数排列顺序不同引起重复导航。 */
const queryKey = (query: LocationQuery) => JSON.stringify(Object.keys(query).sort().map((key) => [key, query[key]]))

/**
 * 筛选 ref 与当前页面 URL 双向同步（F0R.3）。初始化及外部导航先统一回填，页面的读取 watcher 据此重读；
 * 本页写入只用 replace，保留未托管参数与 hash，不把自己省略的非当前分段字段回填成缺省值。
 * 一次回填中的多个字段由 Vue 批量通知；记录同步快照阻止回填反向写 URL，记录在途导航防止慢导航覆盖较新的筛选。
 * 路径改变后停止写入，避免页面离场过渡期间修改下一页的查询串。onHydrate 可同步尚未提交的搜索框等输入。
 */
export function useQueryState<T extends Record<string, string>>(
  fields: { [K in keyof T]: QueryField<T[K]> },
  onHydrate?: () => void,
) {
  const route = useRoute()
  const router = useRouter()
  const path = route.path
  const entries = Object.entries(fields) as [string, QueryField<T[keyof T]>][]
  const values = () => entries.map(([, field]) => field.state.value)
  let synced: string[] = []
  let sequence = 0
  const pending = new Map<string, number>()

  function hydrate(query: LocationQuery) {
    for (const [key, field] of entries) {
      field.state.value = field.parse ? field.parse(query[key], query) : (typeof query[key] === 'string' ? query[key] : field.default) as T[keyof T]
    }
    synced = values()
    onHydrate?.()
  }
  hydrate(route.query)

  watch(() => route.query, (query) => {
    if (route.path === path && !pending.has(queryKey(query))) hydrate(query)
  }, { flush: 'sync' })

  watch(values, async (next) => {
    if (route.path !== path || next.every((value, i) => value === synced[i])) return
    synced = next
    const query: LocationQuery = { ...route.query }
    for (const [key, field] of entries) {
      delete query[key]
      if (field.state.value === field.default) continue
      const encoded = field.serialize ? field.serialize(field.state.value) : field.state.value
      if (encoded !== undefined) query[key] = encoded
    }
    const key = queryKey(query)
    if (key === queryKey(route.query)) return
    const mine = ++sequence
    pending.set(key, mine)
    try { await router.replace({ path, query, hash: route.hash }) }
    finally { if (pending.get(key) === mine) pending.delete(key) }
  })
}
