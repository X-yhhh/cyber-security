import { reactive } from 'vue'

/** 系统反馈队列：普通结果短暂展示，错误与警告必须由用户确认；仅接收脱敏文案。 */
export interface Toast { id: number; text: string; tone: 'info' | 'warn' | 'threat' }

export const toasts = reactive<Toast[]>([])
export const alerts = reactive<Toast[]>([])
let seq = 0

/** 关闭指定提示；确认只影响显示，不重试请求或触发业务动作。 */
export function dismissToast(id: number) {
  for (const queue of [toasts, alerts]) {
    const i = queue.findIndex((t) => t.id === id)
    if (i >= 0) queue.splice(i, 1)
  }
}

export function toast(text: string, tone: Toast['tone'] = 'info') {
  if (!text.trim()) return
  // 同时到达的相同错误合并，确认后再次发生仍会重新提示。
  if (tone !== 'info' && alerts.some((t) => t.text === text && t.tone === tone)) return
  const id = ++seq
  if (tone !== 'info') alerts.push({ id, text, tone })
  else {
    toasts.push({ id, text, tone })
    setTimeout(() => dismissToast(id), 6000)
  }
}
