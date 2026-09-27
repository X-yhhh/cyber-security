/**
 * 首屏叙事的粒子形态生成。
 *
 * 每个章节是一组同长度的目标坐标 / 颜色，场景按滚动进度在相邻两组之间插值。
 * 粒子身份（role）在所有章节中保持不变，这样同一颗"异常流"粒子从感知一路
 * 走到响应和审计，叙事上前后一致。纯函数、确定性随机，便于复现。
 */

export type Role = 'normal' | 'anomaly' | 'rejected' | 'sensor'

export interface ShapeSet {
  positions: Float32Array[]
  colors: Float32Array[]
  roles: Role[]
  /** 研判章节的簇中心，用于绘制关联边 */
  clusters: [number, number, number][]
  edges: [number, number][]
}

// 调色：与 tailwind 设计令牌保持一致
const INK: RGB = [0.08, 0.086, 0.1]
const INK_SOFT: RGB = [0.24, 0.25, 0.28]
const GREY: RGB = [0.44, 0.44, 0.43]
const SIGNAL: RGB = [0.11, 0.18, 0.86]
const THREAT: RGB = [0.84, 0.22, 0.12]

type RGB = [number, number, number]

/** mulberry32：确定性伪随机，保证每次加载形态一致 */
function rng(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export function buildShapes(n: number): ShapeSet {
  const rand = rng(20260927)
  const gauss = () => {
    const u = Math.max(rand(), 1e-6)
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * rand())
  }

  const roles: Role[] = []
  for (let i = 0; i < n; i++) {
    const r = rand()
    roles.push(r < 0.06 ? 'anomaly' : r < 0.14 ? 'rejected' : r < 0.2 ? 'sensor' : 'normal')
  }

  const positions: Float32Array[] = []
  const colors: Float32Array[] = []
  const make = () => ({ p: new Float32Array(n * 3), c: new Float32Array(n * 3) })
  const put = (arr: Float32Array, i: number, x: number, y: number, z: number) => {
    arr[i * 3] = x
    arr[i * 3 + 1] = y
    arr[i * 3 + 2] = z
  }

  // 00 · 边界球：斐波那契球面，所有流量在同一视野中
  {
    const { p, c } = make()
    const golden = Math.PI * (3 - Math.sqrt(5))
    for (let i = 0; i < n; i++) {
      const y = 1 - (i / (n - 1)) * 2
      const rad = Math.sqrt(1 - y * y)
      const th = golden * i
      const R = 1.55 + gauss() * 0.02
      put(p, i, Math.cos(th) * rad * R, y * R, Math.sin(th) * rad * R)
      put(c, i, ...(roles[i] === 'sensor' ? SIGNAL : INK))
    }
    positions.push(p)
    colors.push(c)
  }

  // 01 · 感知：两台主机各自的可见范围（漏斗），彼此不重叠
  {
    const { p, c } = make()
    for (let i = 0; i < n; i++) {
      const side = i % 2 === 0 ? -1 : 1
      const hx = side * 1.45
      if (rand() < 0.5) {
        // 主机本体
        const u = rand() * 2 - 1
        const th = rand() * Math.PI * 2
        const rr = 0.5 * Math.cbrt(rand())
        const s = Math.sqrt(1 - u * u)
        put(p, i, hx + Math.cos(th) * s * rr, u * rr, Math.sin(th) * s * rr)
        put(c, i, ...INK)
      } else {
        // 本机可见流：从主机向外发散的锥体
        const t = rand()
        const spread = 0.15 + t * 0.9
        const a = rand() * Math.PI * 2
        const x = hx + side * (0.55 + t * 1.25)
        put(p, i, x, Math.cos(a) * spread * 0.9, Math.sin(a) * spread * 0.9)
        put(c, i, ...(roles[i] === 'anomaly' ? INK : SIGNAL))
      }
    }
    positions.push(p)
    colors.push(c)
  }

  // 02 · 契约门禁：流 × 特征矩阵；被拒记录从矩阵下方脱落
  {
    const { p, c } = make()
    const cols = 42
    const rows = Math.ceil(n / cols)
    for (let i = 0; i < n; i++) {
      const col = i % cols
      const row = Math.floor(i / cols)
      const x = (col / (cols - 1) - 0.5) * 3.4
      const y = (row / (rows - 1) - 0.5) * 3.0
      if (roles[i] === 'rejected') {
        put(p, i, x + gauss() * 0.05, y * 0.3 - 2.0 - rand() * 0.6, 0.4 + rand() * 0.5)
        put(c, i, ...GREY)
      } else {
        put(p, i, x, y, 0)
        put(c, i, ...(col % 7 === 3 ? SIGNAL : INK))
      }
    }
    positions.push(p)
    colors.push(c)
  }

  // 03 · 冻结模型：四层递减的推理平面，异常样本在出口处被分离
  {
    const { p, c } = make()
    const layers = [
      { x: -1.6, r: 1.3 },
      { x: -0.55, r: 1.0 },
      { x: 0.45, r: 0.72 },
      { x: 1.35, r: 0.45 },
    ]
    for (let i = 0; i < n; i++) {
      if (roles[i] === 'anomaly') {
        put(p, i, 2.25 + gauss() * 0.12, 0.35 + gauss() * 0.12, gauss() * 0.12)
        put(c, i, ...THREAT)
        continue
      }
      const L = layers[i % 4]
      const a = rand() * Math.PI * 2
      const rr = L.r * Math.sqrt(rand())
      put(p, i, L.x + gauss() * 0.015, Math.cos(a) * rr, Math.sin(a) * rr)
      put(c, i, ...(roles[i] === 'rejected' ? GREY : INK))
    }
    positions.push(p)
    colors.push(c)
  }

  // 04 · 研判：告警归并为事件图，中心为高风险事件
  const clusters: [number, number, number][] = [
    [0, 0, 0],
    [1.35, 0.7, -0.3],
    [-1.25, 0.85, 0.2],
    [1.05, -0.95, 0.4],
    [-1.4, -0.7, -0.4],
    [0.2, 1.45, 0.5],
    [-0.1, -1.5, -0.2],
    [2.1, -0.1, 0.3],
    [-2.05, 0.1, 0.1],
  ]
  const edges: [number, number][] = [
    [0, 1], [0, 2], [0, 3], [0, 4], [1, 5], [2, 5], [3, 6], [4, 6], [1, 7], [2, 8], [3, 7], [4, 8],
  ]
  {
    const { p, c } = make()
    for (let i = 0; i < n; i++) {
      const k = roles[i] === 'anomaly' ? 0 : 1 + (i % (clusters.length - 1))
      const [cx, cy, cz] = clusters[k]
      const s = k === 0 ? 0.22 : 0.16
      put(p, i, cx + gauss() * s, cy + gauss() * s, cz + gauss() * s)
      put(c, i, ...(k === 0 ? THREAT : roles[i] === 'rejected' ? GREY : INK))
    }
    positions.push(p)
    colors.push(c)
  }

  // 05 · 受控响应：目标主机外的半透明防护穹顶，异常流被挡在外侧
  {
    const { p, c } = make()
    for (let i = 0; i < n; i++) {
      const role = roles[i]
      if (role === 'anomaly') {
        // 贴着穹顶外沿、偏向单一方向的被阻断流
        const a = (rand() - 0.5) * 1.1
        const b = (rand() - 0.5) * 1.1
        const R = 1.28 + rand() * 0.25
        put(p, i, Math.cos(a) * Math.cos(b) * R, Math.sin(b) * R, Math.sin(a) * Math.cos(b) * R)
        put(c, i, ...THREAT)
      } else if (i % 5 === 0) {
        // 目标主机本体
        const u = rand() * 2 - 1
        const th = rand() * Math.PI * 2
        const rr = 0.32 * Math.cbrt(rand())
        const s = Math.sqrt(1 - u * u)
        put(p, i, Math.cos(th) * s * rr, u * rr, Math.sin(th) * s * rr)
        put(c, i, ...INK)
      } else if (i % 5 < 3) {
        // 防护穹顶
        const u = rand() * 2 - 1
        const th = rand() * Math.PI * 2
        const s = Math.sqrt(1 - u * u)
        put(p, i, Math.cos(th) * s * 1.1, u * 1.1, Math.sin(th) * s * 1.1)
        put(c, i, ...SIGNAL)
      } else {
        // 其余正常流量照常经过，淡化处理
        const u = rand() * 2 - 1
        const th = rand() * Math.PI * 2
        const s = Math.sqrt(1 - u * u)
        const R = 1.9 + rand() * 0.7
        put(p, i, Math.cos(th) * s * R, u * R * 0.6, Math.sin(th) * s * R)
        put(c, i, ...INK_SOFT)
      }
    }
    positions.push(p)
    colors.push(c)
  }

  // 06 · 审计：沿时间轴展开的追加式台账（螺旋），事件节点以朱红标记
  {
    const { p, c } = make()
    for (let i = 0; i < n; i++) {
      const t = i / n
      const x = (t - 0.5) * 5.2
      const a = t * Math.PI * 22
      const r = roles[i] === 'anomaly' ? 0.62 : 0.38
      put(p, i, x, Math.cos(a) * r, Math.sin(a) * r)
      put(c, i, ...(roles[i] === 'anomaly' ? THREAT : roles[i] === 'sensor' ? SIGNAL : INK))
    }
    positions.push(p)
    colors.push(c)
  }

  // 07 · 控制台：八段弧环对应八个工作区，异常流收拢到中心，作为叙事收束
  {
    const { p, c } = make()
    const segs = 8
    for (let i = 0; i < n; i++) {
      if (roles[i] === 'anomaly') {
        const u = rand() * 2 - 1
        const th = rand() * Math.PI * 2
        const rr = 0.18 * Math.cbrt(rand())
        const s = Math.sqrt(1 - u * u)
        put(p, i, Math.cos(th) * s * rr, u * rr, Math.sin(th) * s * rr)
        put(c, i, ...THREAT)
        continue
      }
      const k = i % segs
      // 每段占 45° 中的 36°，留出段间空隙
      const a = ((k + 0.1 + rand() * 0.8) / segs) * Math.PI * 2
      const R = 1.25 + gauss() * 0.035
      const h = gauss() * 0.05
      put(p, i, Math.cos(a) * R, h, Math.sin(a) * R)
      put(c, i, ...(roles[i] === 'sensor' ? SIGNAL : k === 0 ? SIGNAL : roles[i] === 'rejected' ? GREY : INK))
    }
    positions.push(p)
    colors.push(c)
  }

  return { positions, colors, roles, clusters, edges }
}
