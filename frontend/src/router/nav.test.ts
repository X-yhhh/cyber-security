/**
 * 菜单快照（任务单 U0.9 验收，取代 F0 的 7 组 18 项断言）：
 * - 全部 ready 置为 true、去掉过渡行后，6 个单角色的可见二级菜单与权限设计第 7.3 节逐格一致；
 * - 当前 ready 配置下的实际菜单（含仍可进入的过渡行）；
 * - 合法组合角色取并集；无可见项的一级组整组隐藏。
 * 之后的页面卡片不得修改 MATRIX 与 expectedGroups，只调整“当前配置”一节。
 */
import { describe, expect, it } from 'vitest'
import { allowed, groups, nav, routeName, visibleMenu } from './nav'
import { comboUser, humanRoles, singleRoleUsers, type HumanRole } from '@/test/roles'

/** 权限设计第 7.3 节原表（● 可见）。列顺序：platform_admin、security_analyst、security_reviewer、model_operator、evidence_reviewer、auditor。 */
const MATRIX = `
| 实时态势 | ● | ● | ● |  | ● | ● |
| 待办中心 | ● | ● | ● | ● | ● | ● |
| 事件研判 |  | ● | ● |  | ● | ● |
| 检测记录 |  | ● | ● |  | ● | ● |
| 误报反馈 |  | ● |  |  | ● |  |
| 处置记录 |  | ● | ● |  |  | ● |
| 模型与数据集 |  |  | ● | ● | ● | ● |
| 发布管理 |  |  | ● | ● | ● | ● |
| 资产 | ● |  | ● |  |  | ● |
| 传感器与执行器 | ● |  | ● |  |  | ● |
| 用户管理 | ● |  |  |  |  |  |
| 角色管理 | ● |  |  |  |  | ● |
| 审计日志 | ● |  |  |  |  | ● |
`
const COLUMNS: HumanRole[] = ['platform_admin', 'security_analyst', 'security_reviewer', 'model_operator', 'evidence_reviewer', 'auditor']

const rows = MATRIX.trim().split('\n').map((line) => line.split('|').slice(1, -1).map((c) => c.trim()))
const expected: Record<HumanRole, string[]> = Object.fromEntries(COLUMNS.map((r) => [r, [] as string[]])) as Record<HumanRole, string[]>
for (const [title, ...cells] of rows) cells.forEach((c, i) => { if (c === '●') expected[COLUMNS[i]].push(title) })

/** “可见一级组”行。 */
const ALL_GROUPS = ['态势', '威胁检测', '响应处置', '模型与发布', '资产与接入', '系统管理']
const expectedGroups: Record<HumanRole, string[]> = {
  platform_admin: ['态势', '资产与接入', '系统管理'],
  security_analyst: ['态势', '威胁检测', '响应处置'],
  security_reviewer: ['态势', '威胁检测', '响应处置', '模型与发布', '资产与接入'],
  model_operator: ['态势', '模型与发布'],
  evidence_reviewer: ['态势', '威胁检测', '模型与发布'],
  auditor: ALL_GROUPS,
}

/** 第 7.2 节菜单清单：路由与 anyOf 逐项照抄。 */
const SPEC: Record<string, { path: string; anyOf: string[] }> = {
  实时态势: { path: '/console/overview/live', anyOf: ['detection.read', 'action.read', 'ops.read'] },
  待办中心: { path: '/console/workbench', anyOf: [] },
  事件研判: { path: '/console/detect/events', anyOf: ['detection.read'] },
  检测记录: { path: '/console/detect/records', anyOf: ['detection.read'] },
  误报反馈: { path: '/console/detect/feedback', anyOf: ['feedback.label', 'feedback.review'] },
  处置记录: { path: '/console/response/actions', anyOf: ['action.read'] },
  模型与数据集: { path: '/console/release/models', anyOf: ['model.manage', 'model.validate', 'dataset.manage', 'bundle.request', 'bundle.approve', 'evaluation.read'] },
  发布管理: { path: '/console/release/bundles', anyOf: ['bundle.request', 'bundle.approve', 'policy.draft', 'policy.approve', 'automation.stop', 'evaluation.read'] },
  资产: { path: '/console/assets/list', anyOf: ['asset.manage', 'authorization.request', 'authorization.approve', 'sensor.manage', 'audit.read'] },
  传感器与执行器: { path: '/console/assets/agents', anyOf: ['sensor.manage', 'authorization.approve', 'ops.read'] },
  用户管理: { path: '/console/system/users', anyOf: ['iam.manage'] },
  角色管理: { path: '/console/system/roles', anyOf: ['iam.manage', 'audit.read'] },
  审计日志: { path: '/console/system/audit', anyOf: ['audit.read'] },
}

const target = nav.filter((i) => !i.legacy)
const allReady = target.map((i) => ({ ...i, ready: true }))
const titles = (menu: ReturnType<typeof visibleMenu>) => menu.flatMap((g) => g.items.map((i) => i.title))

describe('菜单配置（权限设计第 7.2 节）', () => {
  it('6 个一级组、13 行非过渡项，标题、路径与 anyOf 逐项照抄', () => {
    expect(groups.map((g) => g.title)).toEqual(ALL_GROUPS)
    expect(groups.map((g) => g.key)).toEqual(['overview', 'detect', 'response', 'release', 'assets', 'system'])
    expect(target.map((i) => i.title)).toEqual(rows.map(([t]) => t))
    for (const i of target) {
      expect(i.path, i.title).toBe(SPEC[i.title].path)
      expect([...i.anyOf], i.title).toEqual(SPEC[i.title].anyOf)
      if (i.key !== 'workbench') expect(i.path).toBe(`/console/${i.group}/${i.key}`)
    }
  })

  it('路径与路由名唯一；ready 的项都有页面组件', () => {
    expect(new Set(nav.map((i) => i.path)).size).toBe(nav.length)
    expect(new Set(nav.map(routeName)).size).toBe(nav.length)
    expect(routeName(nav.find((i) => i.key === 'workbench')!)).toBe('workbench')
    for (const i of nav) if (i.ready) expect(i.component, i.title).toBeTypeOf('function')
  })

  it('U0 的 6 行加 F6 实时态势、F1R 检测记录、F4 资产两行已上线，其余 3 行未上线', () => {
    const ready = target.filter((i) => i.ready).map((i) => i.title)
    expect(ready).toEqual(['实时态势', '待办中心', '事件研判', '检测记录', '误报反馈', '处置记录', '发布管理', '资产', '传感器与执行器', '审计日志'])
    expect(target.filter((i) => !i.ready).map((i) => i.title)).toEqual(['模型与数据集', '用户管理', '角色管理'])
  })

  it('威胁检测组只剩 3 行且没有过渡行（任务单 F1R）', () => {
    expect(nav.filter((i) => i.group === 'detect').map((i) => [i.title, i.legacy ?? false])).toEqual([
      ['事件研判', false], ['检测记录', false], ['误报反馈', false],
    ])
  })

  it('3 个过渡行挂在新组下、路径不变、继续可进入', () => {
    const legacy = nav.filter((i) => i.legacy).map((i) => [i.title, i.group, i.path, i.ready])
    expect(legacy).toEqual([
      ['评价与回放', 'release', '/console/release/evaluations', true],
      ['决策策略', 'release', '/console/release/policies', true],
      ['lab 验证与 G3', 'release', '/console/release/lab', true],
    ])
  })

  it('anyOf 为空表示登录即可，否则需要交集', () => {
    expect(allowed([], [])).toBe(true)
    expect(allowed(['audit.read'], ['ops.read'])).toBe(false)
    expect(allowed(['audit.read', 'iam.manage'], ['iam.manage'])).toBe(true)
    expect(allowed(['audit.read'], undefined)).toBe(false)
  })
})

describe('角色可见性矩阵（权限设计第 7.3 节，全部 ready、去掉过渡行）', () => {
  it.each(humanRoles)('%s 的二级菜单逐格一致', (role) => {
    const menu = visibleMenu(singleRoleUsers[role].permissions, allReady)
    expect(titles(menu)).toEqual(expected[role])
    expect(menu.map((g) => g.title)).toEqual(expectedGroups[role])
  })

  it('platform_admin 只因 ops.read 看到实时态势；model_operator 看不到实时态势', () => {
    const live = SPEC['实时态势'].anyOf
    expect(singleRoleUsers.platform_admin.permissions.filter((p) => live.includes(p))).toEqual(['ops.read'])
    expect(expected.model_operator).not.toContain('实时态势')
  })

  it('合法组合角色看到两者的并集', () => {
    const menu = visibleMenu(comboUser.permissions, allReady)
    const union = target.map((i) => i.title).filter((t) => expected.platform_admin.includes(t) || expected.model_operator.includes(t))
    expect(titles(menu)).toEqual(union)
  })

  it('没有任何权限时只剩态势 · 待办中心', () => {
    const menu = visibleMenu([], allReady)
    expect(menu.map((g) => g.title)).toEqual(['态势'])
    expect(titles(menu)).toEqual(['待办中心'])
  })
})

describe('当前 ready 配置下的实际菜单', () => {
  const current: Record<HumanRole, string[]> = {
    platform_admin: ['实时态势', '待办中心', '资产', '传感器与执行器', '审计日志'],
    security_analyst: ['实时态势', '待办中心', '事件研判', '检测记录', '误报反馈', '处置记录'],
    security_reviewer: ['实时态势', '待办中心', '事件研判', '检测记录', '处置记录', '发布管理', '评价与回放', '决策策略', 'lab 验证与 G3', '资产', '传感器与执行器'],
    model_operator: ['待办中心', '发布管理', '评价与回放', '决策策略', 'lab 验证与 G3'],
    evidence_reviewer: ['实时态势', '待办中心', '事件研判', '检测记录', '误报反馈', '发布管理', '评价与回放', '决策策略', 'lab 验证与 G3'],
    auditor: ['实时态势', '待办中心', '事件研判', '检测记录', '处置记录', '发布管理', '评价与回放', '决策策略', 'lab 验证与 G3', '资产', '传感器与执行器', '审计日志'],
  }

  it.each(humanRoles)('%s', (role) => {
    const menu = visibleMenu(singleRoleUsers[role].permissions)
    expect(titles(menu)).toEqual(current[role])
    // 非过渡项必须是目标矩阵的子集：ready 只会收窄、不会放宽可见性。
    const legacy = new Set(nav.filter((i) => i.legacy).map((i) => i.title))
    for (const t of current[role]) if (!legacy.has(t)) expect(expected[role]).toContain(t)
  })

  it('F0 时期每个角色可进入的页面在切换后一个不少（过渡行仍可进入）', () => {
    /* F0 的 18 项菜单中当时 ready 的 12 项加工作台 → 现在承载它的行。 */
    const carried: Record<string, string> = {
      工作台: '待办中心', 观测与推理: '检测记录', 判定与来源: '检测记录', 事件研判: '事件研判', 反馈与复核: '误报反馈',
      处置动作: '处置记录', 目标预算: '处置记录', 评价与回放: '评价与回放', 决策策略: '决策策略', 能力与发布组合: '发布管理',
      'lab 验证与 G3': 'lab 验证与 G3', 运行健康: '传感器与执行器', 审计日志: '审计日志',
    }
    const before: Record<HumanRole, string[]> = {
      platform_admin: ['工作台', '运行健康', '审计日志'],
      security_analyst: ['工作台', '观测与推理', '判定与来源', '事件研判', '反馈与复核', '处置动作', '目标预算'],
      security_reviewer: ['工作台', '观测与推理', '判定与来源', '事件研判', '处置动作', '目标预算', '评价与回放', '决策策略', '能力与发布组合', 'lab 验证与 G3', '运行健康'],
      model_operator: ['工作台', '评价与回放', '决策策略', '能力与发布组合', 'lab 验证与 G3'],
      evidence_reviewer: ['工作台', '观测与推理', '判定与来源', '事件研判', '反馈与复核', '评价与回放', '决策策略', '能力与发布组合', 'lab 验证与 G3'],
      auditor: ['工作台', '观测与推理', '判定与来源', '事件研判', '处置动作', '目标预算', '评价与回放', '决策策略', '能力与发布组合', 'lab 验证与 G3', '运行健康', '审计日志'],
    }
    for (const role of humanRoles) {
      const now = titles(visibleMenu(singleRoleUsers[role].permissions))
      for (const t of before[role]) expect(now, `${role} · ${t}`).toContain(carried[t])
    }
  })

  it('未上线的项不出现在菜单中', () => {
    const hidden = nav.filter((i) => !i.ready).map((i) => i.title)
    expect(hidden).toHaveLength(3)
    for (const role of humanRoles) {
      for (const t of hidden) expect(titles(visibleMenu(singleRoleUsers[role].permissions))).not.toContain(t)
    }
  })
})
