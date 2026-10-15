import { ref } from 'vue'
import { guard } from '@/api/client'
import { can } from '@/api/session'
import { assetName, type NamedAsset } from '@/api/v2/detect'

/**
 * 威胁检测各页的资产名称与资产筛选选项（前端设计文档第 3.5 节：能显示名称的地方不显示 UUID）。
 *
 * 只在持有 `resource.read` 时读取一次（最多 200 个）；无权限或读取失败时列表为空，
 * 名称退回 ID 前 8 位，不显示占位假值，也不影响页面主列表。
 */
export function useAssetNames() {
  const assets = ref<NamedAsset[]>([])
  if (can('resource.read')) {
    void guard.list<NamedAsset>('assets', { limit: 200 })
      .then((page) => { assets.value = page.items })
      .catch(() => { /* 名称辅助失败不阻塞主列表 */ })
  }
  const label = (id: string | null | undefined) => {
    if (!id) return '—'
    const hit = assets.value.find((a) => a.id === id)
    return hit ? assetName(hit) : id.slice(0, 8)
  }
  return { assets, label }
}
