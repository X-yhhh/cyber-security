import { reactive } from 'vue'

/** 轻量提示队列。演示界面所有写操作都只在本地生效，由提示如实告知。 */
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
