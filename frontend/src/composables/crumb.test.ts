/** F0R.5：详情标签跟随数据、按路径隔离，并且旧页销毁不能清除新页登记。 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { defineComponent, h, ref } from 'vue'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { provideCrumbLabel, useCrumbLabel } from './crumb'

const firstLabel = ref<string | undefined>()
const secondLabel = ref<string | undefined>()
const first = ref(true)
const second = ref(false)
const Detail = defineComponent({
  props: { newer: Boolean },
  setup(props) {
    useCrumbLabel(props.newer ? secondLabel : firstLabel)
    return () => h('p', 'detail')
  },
})
const Shell = defineComponent({
  setup() {
    const label = provideCrumbLabel()
    return () => h('div', [h('output', label.value ?? 'fallback'), first.value ? h(Detail) : null, second.value ? h(Detail, { newer: true }) : null])
  },
})
let wrapper: VueWrapper | undefined
async function open() {
  firstLabel.value = secondLabel.value = undefined
  first.value = true
  second.value = false
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/item/:id', component: Shell }] })
  await router.push('/item/one')
  wrapper = mount(defineComponent({ render: () => h(RouterView) }), { global: { plugins: [router] } })
  return router
}
afterEach(() => wrapper?.unmount())

describe('详情面包屑标签', () => {
  it('数据未到或标签为空时回退，加载可读名称后跟随更新，离开后清除', async () => {
    await open()
    expect(wrapper!.get('output').text()).toBe('fallback')
    firstLabel.value = '  端口扫描事件  '
    await flushPromises()
    expect(wrapper!.get('output').text()).toBe('端口扫描事件')
    firstLabel.value = ''
    await flushPromises()
    expect(wrapper!.get('output').text()).toBe('fallback')
    firstLabel.value = '事件标题'
    first.value = false
    await flushPromises()
    expect(wrapper!.get('output').text()).toBe('fallback')
  })

  it('切换详情路径后，旧页迟到的标签不能显示在新详情中', async () => {
    const router = await open()
    firstLabel.value = '旧事件'
    await router.push('/item/two')
    firstLabel.value = '迟到的旧事件'
    await flushPromises()
    expect(wrapper!.get('output').text()).toBe('fallback')
    second.value = true
    secondLabel.value = '新事件'
    await flushPromises()
    expect(wrapper!.get('output').text()).toBe('新事件')
  })

  it('同一外壳内新页登记后旧页卸载不清掉新页标签', async () => {
    await open()
    firstLabel.value = '旧事件'
    secondLabel.value = '新事件'
    second.value = true
    await flushPromises()
    first.value = false
    await flushPromises()
    expect(wrapper!.get('output').text()).toBe('新事件')
  })
})
