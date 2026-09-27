import type { Directive } from 'vue'

/** v-reveal：元素进入视口时淡入上移一次，可用 v-reveal="120" 指定延迟（毫秒）。 */
export const vReveal: Directive<HTMLElement, number | undefined> = {
  mounted(el, binding) {
    el.classList.add('reveal')
    if (binding.value) el.style.transitionDelay = `${binding.value}ms`
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            el.classList.add('in')
            io.disconnect()
          }
        }
      },
      { threshold: 0.15 },
    )
    io.observe(el)
    ;(el as HTMLElement & { _io?: IntersectionObserver })._io = io
  },
  unmounted(el) {
    ;(el as HTMLElement & { _io?: IntersectionObserver })._io?.disconnect()
  },
}
