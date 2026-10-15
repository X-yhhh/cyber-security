import { computed, inject, onScopeDispose, provide, shallowRef, toValue, type InjectionKey, type MaybeRefOrGetter, type ShallowRef } from 'vue'
import { useRoute } from 'vue-router'

interface CrumbLabel { path: string; label: MaybeRefOrGetter<string | null | undefined> }
const key: InjectionKey<ShallowRef<CrumbLabel | undefined>> = Symbol('detail-crumb')

/** 外壳提供详情名称槽；按路径匹配，离场页的异步结果不能覆盖新详情的面包屑。 */
export function provideCrumbLabel() {
  const route = useRoute()
  const current = shallowRef<CrumbLabel>()
  provide(key, current)
  return computed(() => current.value?.path === route.path ? toValue(current.value.label)?.trim() || undefined : undefined)
}

/**
 * 详情页提供可读名称（F0R.5），支持 ref/computed/getter 随数据更新；空值由外壳回退到截断 ID。
 * 作用域销毁时只清除本页登记，避免过渡期间旧页卸载清掉新页标签；没有外壳时可独立渲染。
 */
export function useCrumbLabel(label: MaybeRefOrGetter<string | null | undefined>) {
  const current = inject(key, undefined)
  const route = useRoute()
  if (!current) return
  const entry = { path: route.path, label }
  current.value = entry
  onScopeDispose(() => { if (current.value === entry) current.value = undefined })
}
