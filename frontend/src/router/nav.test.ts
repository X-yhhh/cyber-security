/**
 * 菜单快照（任务单 F0 验收）：
 * - 全部 ready 置为 true 后，6 个单角色的可见二级菜单与权限设计第 7.3 节逐格一致；
 * - 当前 ready 配置下的实际菜单；
 * - 合法组合角色取并集；无可见项的一级组整组隐藏。
 */
import { describe, expect, it } from 'vitest'
import { allowed, groups, nav, visibleMenu } from './nav'
import { comboUser, humanRoles, singleRoleUsers, type HumanRole } from '@/test/roles'

/** 权限设计第 7.3 节原表（● 可见）。列顺序：platform_admin、security_analyst、security_reviewer、model_operator、evidence_reviewer、auditor。 */
const MATRIX = `
| 工作台 | ● | ● | ● | ● | ● | ● |
| 观测与推理 |  | ● | ● |  | ● | ● |
| 判定与来源 |  | ● | ● |  | ● | ● |
| 事件研判 |  | ● | ● |  | ● | ● |
| 反馈与复核 |  | ● |  |  | ● |  |
| 处置动作 |  | ● | ● |  |  | ● |
| 目标预算 |  | ● | ● |  |  | ● |
| 数据集与模型 |  |  | ● | ● | ● | ● |
| 评价与回放 |  |  | ● | ● | ● | ● |
| 决策策略 |  |  | ● | ● | ● | ● |
| 能力与发布组合 |  |  | ● | ● | ● | ● |
| lab 验证与 G3 |  |  | ● | ● | ● | ● |
| 资产 | ● |  | ● |  |  |  |
| 资产授权 | ● |  | ● |  |  | ● |
| 传感器与执行器 | ● |  | ● |  |  | ● |
| 运行健康 | ● |  | ● |  |  | ● |
| 审计日志 | ● |  |  |  |  | ● |
| 用户与角色绑定 | ● |  |  |  |  |  |
| 角色与权限目录 | ● |  |  |  |  | ● |
`
const COLUMNS: HumanRole[] = ['platform_admin', 'security_analyst', 'security_reviewer', 'model_operator', 'evidence_reviewer', 'auditor']

const expected: Record<HumanRole, string[]> = Object.fromEntries(COLUMNS.map((r) => [r, [] as string[]])) as Record<HumanRole, string[]>
for (const line of MATRIX.trim().split('\n')) {
  const [title, ...cells] = line.split('|').slice(1, -1).map((c) => c.trim())
  cells.forEach((c, i) => { if (c === '●') expected[COLUMNS[i]].push(title) })
}

/** “可见一级组”行。 */
const expectedGroups: Record<HumanRole, string[]> = {
  platform_admin: ['工作台', '资产与采集', '运行与审计', '系统管理'],
  security_analyst: ['工作台', '威胁检测', '受控响应'],
  security_reviewer: ['工作台', '威胁检测', '受控响应', '模型与发布', '资产与采集', '运行与审计'],
  model_operator: ['工作台', '模型与发布'],
  evidence_reviewer: ['工作台', '威胁检测', '模型与发布'],
  auditor: ['工作台', '威胁检测', '受控响应', '模型与发布', '资产与采集', '运行与审计', '系统管理'],
}

const allReady = nav.map((i) => ({ ...i, ready: true }))
const titles = (menu: ReturnType<typeof visibleMenu>) => menu.flatMap((g) => g.items.map((i) => i.title))

describe('菜单配置', () => {
  it('7 个一级组、18 个二级项加工作台，路由均在 /console 下且唯一', () => {
    expect(groups).toHaveLength(7)
    expect(nav.filter((i) => i.group !== 'workbench')).toHaveLength(18)
    expect(new Set(nav.map((i) => i.path)).size).toBe(nav.length)
    for (const i of nav) {
      expect(i.path).toBe(i.group === 'workbench' ? '/console/workbench' : `/console/${i.group}/${i.key}`)
      if (i.ready) expect(i.component).toBeTypeOf('function')
    }
  })

  it('anyOf 为空表示登录即可，否则需要交集', () => {
    expect(allowed([], [])).toBe(true)
    expect(allowed(['audit.read'], ['ops.read'])).toBe(false)
    expect(allowed(['audit.read', 'iam.manage'], ['iam.manage'])).toBe(true)
    expect(allowed(['audit.read'], undefined)).toBe(false)
  })
})

describe('角色可见性矩阵（权限设计第 7.3 节，全部 ready）', () => {
  it.each(humanRoles)('%s 的二级菜单逐格一致', (role) => {
    const menu = visibleMenu(singleRoleUsers[role].permissions, allReady)
    expect(titles(menu)).toEqual(expected[role])
    expect(menu.map((g) => g.title)).toEqual(expectedGroups[role])
  })

  it('合法组合角色看到两者的并集', () => {
    const menu = visibleMenu(comboUser.permissions, allReady)
    const union = nav.map((i) => i.title).filter((t) => expected.platform_admin.includes(t) || expected.model_operator.includes(t))
    expect(titles(menu)).toEqual(union)
  })

  it('没有任何权限时只剩工作台', () => {
    expect(visibleMenu([], allReady).map((g) => g.title)).toEqual(['工作台'])
  })
})

describe('当前 ready 配置下的实际菜单', () => {
  const current: Record<HumanRole, string[]> = {
    platform_admin: ['工作台', '运行健康', '审计日志'],
    security_analyst: ['工作台', '观测与推理', '判定与来源', '处置动作', '目标预算'],
    security_reviewer: ['工作台', '观测与推理', '判定与来源', '处置动作', '目标预算', '评价与回放', '决策策略', '能力与发布组合', 'lab 验证与 G3', '运行健康'],
    model_operator: ['工作台', '评价与回放', '决策策略', '能力与发布组合', 'lab 验证与 G3'],
    evidence_reviewer: ['工作台', '观测与推理', '判定与来源', '评价与回放', '决策策略', '能力与发布组合', 'lab 验证与 G3'],
    auditor: ['工作台', '观测与推理', '判定与来源', '处置动作', '目标预算', '评价与回放', '决策策略', '能力与发布组合', 'lab 验证与 G3', '运行健康', '审计日志'],
  }

  it.each(humanRoles)('%s', (role) => {
    const menu = visibleMenu(singleRoleUsers[role].permissions)
    expect(titles(menu)).toEqual(current[role])
    // 当前菜单必须是目标矩阵的子集：ready 只会收窄、不会放宽可见性。
    for (const t of current[role]) expect(expected[role]).toContain(t)
  })

  it('未上线的项不出现在菜单中', () => {
    const hidden = nav.filter((i) => !i.ready).map((i) => i.title)
    expect(hidden.length).toBeGreaterThan(0)
    for (const role of humanRoles) {
      for (const t of hidden) expect(titles(visibleMenu(singleRoleUsers[role].permissions))).not.toContain(t)
    }
  })
})
