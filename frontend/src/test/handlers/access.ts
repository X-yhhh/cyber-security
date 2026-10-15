/** F2 合成夹具的权限辅助；只用于 MSW，真实授权始终由后端完成。 */
import { HttpResponse } from 'msw'
import { rolePermissions, type MeFixture } from '@/test/roles'
import { ASSET_1, ASSET_2 } from './detect'

/** auth/me 的资产 scopeId 是内部 ID；夹具用此表映射公开 UUID，不把两者混用。 */
const assetScopes: Record<string, string> = { [ASSET_1]: '1', [ASSET_2]: '2' }

/** undefined 检查功能权限，null 检查全局权限；资产权限与范围必须来自同一个角色绑定。 */
export function fixtureCan(user: MeFixture, permission: string, assetId?: string | null): boolean {
  if (!user.permissions.some((p) => p === permission)) return false
  return user.bindings.some((b) => {
    if (!rolePermissions[b.roleKey].some((p) => p === permission)) return false
    if (b.scopeType === 'global' && b.scopeId === '*') return true
    if (b.scopeType !== 'asset' || !Object.values(assetScopes).includes(b.scopeId)) return false
    return assetId === undefined || (assetId !== null && assetScopes[assetId] === b.scopeId)
  })
}

export const fixtureOk = <T>(data: T, status = 200) => HttpResponse.json({ requestId: 'req-f2', data, error: null }, { status })
export const fixtureFail = (status: number, code: string, message: string) =>
  HttpResponse.json({ requestId: 'req-f2-error', data: null, error: { code, message } }, { status })
export const fixtureUnauthenticated = () => fixtureFail(401, 'UNAUTHENTICATED', '请先登录')
export const fixtureDenied = () => fixtureFail(403, 'SCOPE_DENIED', '无权访问')
export const fixtureNotFound = () => fixtureFail(404, 'RESOURCE_NOT_FOUND', '资源不可见或不存在')
