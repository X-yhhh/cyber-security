/**
 * F2 待办中心 GET /api/v2/todos（接口设计 3.2、权限设计 7.4）。
 *
 * 不接受查询参数；分组、计数、权限/资产裁剪及排除本人待批对象均由后端计算。
 * 三组共用 100 条上限，count 是全量计数，不能用 items.length 覆盖或给缺省类别补 0。
 * route 只提供处理入口，目标页仍须独立鉴权；不在接口层过滤未上线的页面。
 */
import { guard } from '@/api/client'

export type TodoGroupKind = 'approve' | 'triage' | 'other'
export type TodoKind =
  | 'authorization' | 'sensor_config' | 'action' | 'lab' | 'policy' | 'bundle_approval'
  | 'feedback' | 'event' | 'model' | 'bundle_sealing' | 'expiring_authorization' | 'device'

export interface TodoEntry {
  kind: TodoKind
  id: string
  title: string
  /** 全局对象为 null，其余为资产公开 UUID。 */
  assetId: string | null
  /** UTC RFC3339。 */
  createdAt: string
  route: string
}
export interface TodoGroup { kind: TodoGroupKind; count: number; items: TodoEntry[] }
export interface TodosResponse { groups: TodoGroup[]; truncated: boolean }

export const fetchTodos = (): Promise<TodosResponse> => guard.read('todos')
