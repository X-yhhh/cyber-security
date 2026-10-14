import { computed } from 'vue'
import { useRoute } from 'vue-router'

/**
 * 页面标题与侧栏菜单保持一致：一个视图被多个菜单行复用时（如处置记录与目标预算），标题取当前路由的菜单标题；
 * 没有路由上下文（组件单测直接挂载）时退回视图自身的名称。
 */
export function usePageTitle(fallback: string) {
  const route = useRoute() as ReturnType<typeof useRoute> | undefined
  return computed(() => (typeof route?.meta?.title === 'string' && route.meta.title ? route.meta.title : fallback))
}
