/**
 * 视觉基线 v2 通用组件单测（任务单 U0 验收）：
 * Panel 不嵌套、IdText 截断与复制、TrendChart 的 null 点不连线、TodoList 分组与空态、SectionTabs 按权限显示，
 * 以及 Tag 胶囊变体与图表纯函数。
 */
import { mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, nextTick, ref } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import Panel from './Panel.vue'
import IdText from './IdText.vue'
import TrendChart from './TrendChart.vue'
import TodoList, { type TodoGroup } from './TodoList.vue'
import SectionTabs from './SectionTabs.vue'
import Segmented from './Segmented.vue'
import Tag from './Tag.vue'
import { chartPalette, niceMax, segments, toCsv, toneOf } from './chart'
import { session } from '@/api/session'
import { singleRoleUsers } from '@/test/roles'

afterEach(() => { document.body.innerHTML = ''; vi.restoreAllMocks() })

describe('Panel', () => {
  it('标题、说明、右上操作、筛选条与内容各就各位；默认不标嵌套', () => {
    const w = mount(Panel, {
      props: { title: '当前封禁', desc: '只列出仍在生效的动作' },
      slots: { actions: '<button class="act-ghost">导出</button>', toolbar: '<input class="field" aria-label="搜索" />', default: '<p>内容</p>' },
    })
    expect(w.get('section').classes()).toContain('panel')
    expect(w.get('h2').text()).toBe('当前封禁')
    expect(w.text()).toContain('只列出仍在生效的动作')
    expect(w.get('header button').text()).toBe('导出')
    expect(w.find('input[aria-label="搜索"]').exists()).toBe(true)
    expect(w.get('section').attributes('data-nested')).toBeUndefined()
  })

  it('放进另一个 Panel 时标记 data-nested 并警告', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const w = mount(defineComponent(() => () => h(Panel, { title: '外层' }, () => h(Panel, { title: '内层' }, () => '内容'))))
    const [outer, inner] = w.findAll('section')
    expect(outer.attributes('data-nested')).toBeUndefined()
    expect(inner.attributes('data-nested')).toBe('true')
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('面板不允许嵌套'))
  })

  it('flush 时内容区贴边，供表格使用', () => {
    const w = mount(Panel, { props: { title: '列表', flush: true }, slots: { default: '<table class="table" />' } })
    expect(w.get('section').classes()).toEqual(expect.arrayContaining(['panel-flush']))
  })
})

describe('IdText', () => {
  const uuid = '7f3c2a1e-9b4d-4c6e-8a2f-1d0e5b7c9a31'

  it('默认显示前 8 位，悬停与读屏给出完整值', () => {
    const w = mount(IdText, { props: { value: uuid } })
    const text = w.get('[data-id-text]')
    expect(text.text()).toBe('7f3c2a1e…')
    expect(text.attributes('title')).toBe(uuid)
    expect(text.attributes('aria-label')).toBe(uuid)
  })

  it('不超过显示长度的值原样显示；空值显示 — 且无复制按钮', () => {
    expect(mount(IdText, { props: { value: 'abc123' } }).get('[data-id-text]').text()).toBe('abc123')
    const empty = mount(IdText, { props: { value: null } })
    expect(empty.text()).toBe('—')
    expect(empty.find('button').exists()).toBe(false)
  })

  it('复制按钮写入完整值并短暂显示已复制', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } })
    const w = mount(IdText, { props: { value: uuid } })
    await w.get('button').trigger('click')
    await nextTick()
    expect(writeText).toHaveBeenCalledWith(uuid)
    expect(w.get('button').attributes('aria-label')).toBe('已复制')
    vi.unstubAllGlobals()
  })
})

describe('TrendChart', () => {
  const x = ['10:00', '10:05', '10:10', '10:15', '10:20']

  it('null 点断开折线：两段各自成线，孤立点画成圆点，不补 0', () => {
    const w = mount(TrendChart, { props: { title: '入站', x, series: [{ key: 'in', name: '入站', tone: 'signal', points: [3, 5, null, 2, 4] }, { key: 'alert', name: '告警', tone: 'threat', points: [1, null, 2, null, null] }] } })
    const paths = w.findAll('[data-series-path]')
    // 入站：两段（0—1、3—4）合成一条 path，含两个 M；告警：两个孤立点，没有线段。
    expect(paths).toHaveLength(1)
    expect(paths[0].attributes('d')!.match(/M/g)).toHaveLength(2)
    expect(paths[0].attributes('stroke')).toBe(chartPalette.signal)
    expect(w.findAll('[data-series-dot]')).toHaveLength(2)
    expect(w.text()).not.toContain('该时段无数据')
  })

  it('全部为空时只显示该时段无数据，不画线', () => {
    const w = mount(TrendChart, { props: { title: '入站', x, series: [{ key: 'in', name: '入站', points: [null, null, null, null, null] }] } })
    expect(w.findAll('[data-series-path]')).toHaveLength(0)
    expect(w.text()).toContain('该时段无数据')
  })

  it('悬浮读数：方向键移动，无数据的时间点写明该时段无数据', async () => {
    const w = mount(TrendChart, { props: { title: '入站', x, series: [{ key: 'in', name: '入站', points: [3, 5, null, 2, 4] }] }, attachTo: document.body })
    const svg = w.get('svg')
    await svg.trigger('focus')
    expect(w.get('[data-readout]').text()).toContain('10:20')
    await svg.trigger('keydown', { key: 'ArrowLeft' })
    await svg.trigger('keydown', { key: 'ArrowLeft' })
    expect(w.get('[data-readout]').text()).toContain('10:10')
    expect(w.get('[data-readout]').text()).toContain('该时段无数据')
    await svg.trigger('blur')
    expect(w.find('[data-readout]').exists()).toBe(false)
  })

  it('最多 5 条线，导出 CSV 时空值写空单元格', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const series = Array.from({ length: 6 }, (_, i) => ({ key: `s${i}`, name: `类别${i}`, points: [i, null] }))
    const w = mount(TrendChart, { props: { title: '分类', x: ['a', 'b'], series, exportable: true } })
    expect(w.findAll('figcaption li')).toHaveLength(5)
    await w.get('button').trigger('click')
    const csv = w.emitted('export')![0][0] as string
    expect(csv.split('\n')[0]).toBe('时间,类别0,类别1,类别2,类别3,类别4')
    expect(csv.split('\n')[2]).toBe('b,,,,,')
  })

  it('排行条按数值降序，宽度按最大值折算', () => {
    const w = mount(TrendChart, { props: { title: '来源排行', kind: 'rank', items: [{ key: 'a', name: '10.0.0.2', value: 5 }, { key: 'b', name: '10.0.0.9', value: 10 }] } })
    const rows = w.findAll('li')
    expect(rows[0].text()).toContain('10.0.0.9')
    expect(w.findAll('[data-rank-bar]').map((b) => (b.element as HTMLElement).style.width)).toEqual(['100%', '50%'])
  })
})

describe('chart.ts', () => {
  it('niceMax 取 1/2/2.5/5×10ⁿ 上界', () => {
    expect([0, 0.4, 3, 7, 12, 240, 999].map(niceMax)).toEqual([1, 0.5, 5, 10, 20, 250, 1000])
  })
  it('segments 在 null 处断开', () => {
    expect(segments([1, 2, null, 3, null, null, 4, 5])).toEqual([[[0, 1], [1, 2]], [[3, 3]], [[6, 4], [7, 5]]])
  })
  it('toneOf 优先显式值，否则按 key 稳定取色', () => {
    expect(toneOf('x', 'warn')).toBe('warn')
    expect(toneOf('port_scan')).toBe(toneOf('port_scan'))
  })
  it('toCsv 转义逗号与引号', () => {
    expect(toCsv(['名称', '值'], [['a,b', 1], ['say "hi"', null]])).toBe('名称,值\n"a,b",1\n"say ""hi""",\n')
  })
})

describe('TodoList', () => {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', component: { render: () => null } }] })
  const groups: TodoGroup[] = [
    { key: 'other', count: 1, items: [{ id: 'o1', title: '设备异常 · sensor-mac', at: '2026-10-14T02:00:00Z' }] },
    { key: 'approve', count: 3, items: [
      { id: 'a1', title: '待批资产授权', asset: 'mac-01', at: '2026-10-14T03:00:00Z', to: '/console/assets/list' },
      { id: 'a2', title: '待审决策策略', to: '/console/release/bundles', action: '审核' },
    ] },
    { key: 'triage', count: 0, items: [] },
  ]

  it('按待批 → 待研判 → 其他分组，组标题带后端计数，空组不显示', () => {
    const w = mount(TodoList, { props: { groups }, global: { plugins: [router] } })
    const sections = w.findAll('[data-todo-group]')
    expect(sections.map((s) => s.attributes('data-todo-group'))).toEqual(['approve', 'other'])
    expect(sections[0].get('h3').text()).toBe('需要批准3')
    expect(sections[0].findAll('li')).toHaveLength(2)
    expect(sections[0].findAll('a').map((a) => a.text())).toEqual(['进入', '审核'])
    expect(sections[0].text()).toContain('mac-01')
    // 没有目标页的条目不显示进入按钮。
    expect(sections[1].find('a').exists()).toBe(false)
  })

  it('没有任何待办时显示空态；超过上限时写明只返回最近 N 条', () => {
    const empty = mount(TodoList, { props: { groups: [] }, global: { plugins: [router] } })
    expect(empty.get('[data-todo-empty]').text()).toBe('当前没有需要你处理的事项')
    const full = mount(TodoList, { props: { groups, truncated: true }, global: { plugins: [router] } })
    expect(full.text()).toContain('只返回最近 100 条')
    // 有计数但没有条目的组（上限被前面组占满）写明未载入，而不是空着。
    const unloaded = mount(TodoList, { props: { groups: [...groups, { key: 'triage', count: 5, items: [] }], truncated: true }, global: { plugins: [router] } })
    expect(unloaded.get('[data-todo-group="triage"] [data-todo-unloaded]').text()).toContain('不在本次返回的最近 100 条内')
    expect(unloaded.get('[data-todo-group="approve"]').find('[data-todo-unloaded]').exists()).toBe(false)
  })

  it('每组按 pageSize 分页，翻页只换本组条目；不足一页不显示分页条', async () => {
    const many: TodoGroup[] = [
      { key: 'triage', count: 23, items: Array.from({ length: 23 }, (_, i) => ({ id: `t${i}`, title: `待研判 ${i}` })) },
      { key: 'other', count: 2, items: [{ id: 'o1', title: '其他 1' }, { id: 'o2', title: '其他 2' }] },
    ]
    const w = mount(TodoList, { props: { groups: many }, global: { plugins: [router] } })
    const triage = () => w.get('[data-todo-group="triage"]')
    expect(triage().findAll('li')).toHaveLength(10)
    expect(triage().get('[data-todo-pager]').text()).toContain('第 1 / 3 页')
    expect(w.get('[data-todo-group="other"]').find('[data-todo-pager]').exists()).toBe(false)
    const [prev, next] = triage().findAll('[data-todo-pager] button')
    expect(prev.attributes('disabled')).toBeDefined()
    await next.trigger('click')
    expect(triage().findAll('li')[0].text()).toContain('待研判 10')
    await next.trigger('click')
    expect(triage().findAll('li')).toHaveLength(3)
    expect(triage().findAll('[data-todo-pager] button')[1].attributes('disabled')).toBeDefined()
    // 刷新后条目变少，当前页收回到最后一个有效页。
    await w.setProps({ groups: [{ ...many[0], items: many[0].items.slice(0, 12) }] })
    expect(triage().get('[data-todo-pager]').text()).toContain('第 2 / 2 页')
    expect(triage().findAll('li')).toHaveLength(2)
  })
})

describe('SectionTabs 与 Segmented', () => {
  beforeEach(() => { session.user = singleRoleUsers.auditor as unknown as typeof session.user })
  afterEach(() => { session.user = null })

  const options = [
    { value: 'overview' as const, label: '概况' },
    { value: 'auth' as const, label: '授权', anyOf: ['authorization.request', 'authorization.approve'] },
    { value: 'devices' as const, label: '接入设备', anyOf: ['sensor.manage', 'ops.read'] },
  ]

  it('只显示有权限的分段；当前值不可见时切到第一个可见分段', async () => {
    const model = ref<'overview' | 'auth' | 'devices'>('auth')
    const w = mount(SectionTabs<'overview' | 'auth' | 'devices'>, { props: { options, modelValue: model.value, 'onUpdate:modelValue': (v: 'overview' | 'auth' | 'devices') => { model.value = v } } })
    await nextTick()
    expect(w.findAll('[role="tab"]').map((t) => t.text())).toEqual(['概况', '接入设备'])
    expect(model.value).toBe('overview')
  })

  it('一个分段都不可见时不渲染', () => {
    const w = mount(SectionTabs<'auth'>, { props: { options: [options[1]] as never, modelValue: 'auth' } })
    expect(w.find('[role="tablist"]').exists()).toBe(false)
  })

  it.each([['SectionTabs', SectionTabs], ['Segmented', Segmented]] as const)('%s：漫游 tabindex 与方向键切换', async (_name, C) => {
    const model = ref('overview')
    const w = mount(C as typeof Segmented, {
      props: { options: [{ value: 'overview', label: '概况' }, { value: 'devices', label: '接入设备' }] as never, modelValue: model.value, 'onUpdate:modelValue': (v: string) => { model.value = v } },
      attachTo: document.body,
    })
    const tabs = () => w.findAll('[role="tab"]')
    expect(tabs().map((t) => t.attributes('tabindex'))).toEqual(['0', '-1'])
    await tabs()[0].trigger('keydown', { key: 'ArrowRight' })
    expect(model.value).toBe('devices')
    await w.setProps({ modelValue: model.value } as never)
    expect(tabs()[1].attributes('aria-selected')).toBe('true')
    expect(tabs().map((t) => t.attributes('tabindex'))).toEqual(['-1', '0'])
    await tabs()[1].trigger('keydown', { key: 'Home' })
    expect(model.value).toBe('overview')
  })
})

describe('Tag', () => {
  it('pill 变体为浅底色胶囊，默认为圆点 + 文字', () => {
    expect(mount(Tag, { props: { tone: 'ok', label: '已生效', pill: true } }).get('span').classes()).toEqual(expect.arrayContaining(['pill', 'bg-ok-soft', 'text-ok']))
    expect(mount(Tag, { props: { tone: 'ok', label: '已生效' } }).get('span').classes()).not.toContain('pill')
  })
})

describe('页面级展示组件', () => {
  it('StatBand：undefined 不渲染（无权限不补 0），null 显示 —，字符串用小字号', async () => {
    const { default: StatBand } = await import('./StatBand.vue')
    const w = mount(StatBand, { props: { stats: [
      { key: 'a', label: '未结', value: 3, tone: 'threat' },
      { key: 'b', label: '无权限', value: undefined },
      { key: 'c', label: '未知', value: null },
      { key: 'd', label: '最近', value: '2026-10-14 10:00' },
    ] } })
    const cells = w.findAll('[data-stat]')
    expect(cells.map((c) => c.text())).toEqual(['未结3', '未知—', '最近2026-10-14 10:00'])
    expect(cells[0].html()).toContain('text-threat')
  })

  it('DistBar：段宽按数量折算，超过 max 的类别并入其他', async () => {
    const { default: DistBar } = await import('./DistBar.vue')
    const segs = ['a', 'b', 'c'].map((k, i) => ({ key: k, label: k, value: i + 1, tone: 'mute' as const }))
    const w = mount(DistBar, { props: { segments: segs, max: 2 } })
    expect(w.findAll('[data-dist-seg]').map((s) => (s.element as HTMLElement).style.width)).toEqual(['16.666666666666664%', '83.33333333333334%'])
    expect(w.text()).toContain('其他')
    expect(mount(DistBar, { props: { segments: [] } }).text()).toContain('暂无可统计的记录')
  })

  it('ChainNav：节点即分段，点击与方向键切换', async () => {
    const { default: ChainNav } = await import('./ChainNav.vue')
    const model = ref('a')
    const w = mount(ChainNav, { props: { options: [{ value: 'a', label: '批次', icon: 'span' }, { value: 'b', label: '观察', icon: 'span' }] as never, modelValue: model.value, 'onUpdate:modelValue': (v: string) => { model.value = v } } })
    const tabs = w.findAll('[role="tab"]')
    expect(tabs.map((t) => t.attributes('aria-selected'))).toEqual(['true', 'false'])
    await tabs[0].trigger('keydown', { key: 'ArrowRight' })
    expect(model.value).toBe('b')
  })

  it('PipelineSteps：按顺序编号，点击阶段发出 select', async () => {
    const { default: PipelineSteps } = await import('./PipelineSteps.vue')
    const w = mount(PipelineSteps, { props: { title: '发布流水线', steps: [{ key: 'candidate', label: '候选', value: 1 }, { key: 'active', label: '已激活', value: 2 }] } })
    const buttons = w.findAll('button')
    expect(buttons.map((b) => b.text().replace(/\s+/g, ''))).toEqual(['1候选1', '2已激活2'])
    await buttons[1].trigger('click')
    expect(w.emitted('select')![0]).toEqual(['active'])
  })
})
