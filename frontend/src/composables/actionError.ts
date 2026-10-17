import { customRef } from 'vue'
import { toast } from './toast'

/**
 * 操作错误同时保留在原表单并进入系统警告弹窗。空串只清理表单，不关闭尚未确认的提示。
 * 每次非空赋值均报告，包括确认后再次提交得到相同错误；并发重复由提示队列合并。
 * 只用于用户操作/提交校验，不用于轮询或输入过程中的实时校验；调用方必须先脱敏。
 */
export function useActionError() {
  let value = ''
  return customRef<string>((track, trigger) => ({
    get() { track(); return value },
    set(next) {
      value = next
      if (next) toast(next, 'threat')
      trigger()
    },
  }))
}
