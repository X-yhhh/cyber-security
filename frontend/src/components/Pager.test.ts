import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import Pager from './Pager.vue'

describe('Pager', () => {
  it('hides itself when everything fits on one page', () => {
    const wrapper = mount(Pager, { props: { total: 20, page: 0, size: 20, label: '证据时间线' } })
    expect(wrapper.find('nav').exists()).toBe(false)
  })

  it('shows totals, disables out-of-range buttons and emits the target page', async () => {
    const wrapper = mount(Pager, { props: { total: 45, page: 0, size: 20, label: '证据时间线' } })
    expect(wrapper.get('nav').attributes('aria-label')).toBe('证据时间线分页')
    expect(wrapper.text()).toContain('共 45 条 · 第 1 / 3 页')
    const [prev, next] = wrapper.findAll('button')
    expect(prev.attributes('disabled')).toBeDefined()
    await next.trigger('click')
    expect(wrapper.emitted('change')).toEqual([[1]])

    await wrapper.setProps({ page: 2 })
    expect(wrapper.findAll('button')[1].attributes('disabled')).toBeDefined()
  })

  it('blocks both directions while a page is loading', () => {
    const wrapper = mount(Pager, { props: { total: 45, page: 1, size: 20, busy: true, label: '关联告警' } })
    for (const button of wrapper.findAll('button')) expect(button.attributes('disabled')).toBeDefined()
  })
})
