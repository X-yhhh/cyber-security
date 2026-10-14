/**
 * 分段控件的共用无障碍约定（Segmented 与 SectionTabs，任务单 U0.5）：
 * - 容器 `role="tablist"`，选项 `role="tab"` + `aria-selected`；
 * - 漫游 tabindex：只有当前选项可被 Tab 聚焦，其余为 -1；
 * - 方向键左右切换、Home/End 跳到首尾，切换即选中并移动焦点。
 */
export function tabKeydown<T>(e: KeyboardEvent, values: readonly T[], current: T, select: (v: T) => void) {
  if (!values.length) return
  const i = Math.max(0, values.indexOf(current))
  let next: number
  switch (e.key) {
    case 'ArrowRight': next = (i + 1) % values.length; break
    case 'ArrowLeft': next = (i - 1 + values.length) % values.length; break
    case 'Home': next = 0; break
    case 'End': next = values.length - 1; break
    default: return
  }
  e.preventDefault()
  select(values[next])
  const list = (e.currentTarget as HTMLElement | null)?.closest('[role="tablist"]')
  list?.querySelectorAll<HTMLElement>('[role="tab"]')[next]?.focus()
}

/** 带权限条件的分段选项；`anyOf` 缺省或为空表示登录即可（与菜单 nav.ts 的约定一致）。 */
export interface TabOption<T extends string = string> { value: T; label: string; count?: number; anyOf?: readonly string[] }

/** 按会话权限过滤分段选项；页面可据此判断“一个分段都不可见时整页隐藏”。 */
export function visibleTabs<T extends string>(options: readonly TabOption<T>[], permissions: readonly string[] | undefined): TabOption<T>[] {
  return options.filter((o) => !o.anyOf?.length || (permissions ?? []).some((p) => o.anyOf!.includes(p)))
}
