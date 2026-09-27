import { reactive } from 'vue'

/** 轻量提示队列：写操作结果（成功或后端脱敏错误）由提示如实告知。 */
export interface Toast { id: number; text: string; tone: 'info' | 'warn' | 'threat' }

export const toasts = reactive<Toast[]>([])
let seq = 0

export function toast(text: string, tone: Toast['tone'] = 'info') {
  const id = ++seq
  toasts.push({ id, text, tone })
  setTimeout(() => {
    const i = toasts.findIndex((t) => t.id === id)
    if (i >= 0) toasts.splice(i, 1)
  }, 3600)
}
