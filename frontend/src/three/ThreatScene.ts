import * as THREE from 'three'
import { buildShapes } from './shapes'

/**
 * 首屏 3D 叙事场景。
 *
 * 输入：连续章节进度 progress ∈ [0, chapters-1]（由页面滚动换算）与指针 NDC 坐标。
 * 行为：粒子在相邻章节形态之间用 GPU 插值，并叠加轻微噪声与指针排斥；
 *       章节还驱动整体位移/旋转，使 3D 主体与左右交替的文本版式一同移动。
 * 失败边界：WebGL 不可用时构造函数抛错，由调用方降级为静态版式。
 */

const VERT = /* glsl */ `
  attribute vec3 aTo;
  attribute vec3 aColor;
  attribute vec3 aColorTo;
  attribute float aSeed;
  attribute float aRole;
  uniform float uMix;
  uniform float uTime;
  uniform float uPixel;
  uniform vec2 uPointer;
  uniform float uPointerForce;
  varying vec3 vColor;
  varying float vAlpha;

  void main() {
    // 每颗粒子有自己的延迟，过渡呈"流动"而非整体平移
    float d = aSeed * 0.35;
    float m = smoothstep(d, d + 0.65, uMix);
    vec3 p = mix(position, aTo, m);

    // 过渡中段抬起一段弧线，避免直线穿插
    float arc = sin(m * 3.14159) * (0.25 + aSeed * 0.35);
    p += normalize(p + vec3(0.001)) * arc * 0.35;

    // 静止时的呼吸噪声
    float t = uTime * 0.6 + aSeed * 40.0;
    p += vec3(sin(t), cos(t * 1.3), sin(t * 0.7)) * 0.012;

    vec4 mv = modelViewMatrix * vec4(p, 1.0);
    vec4 clip = projectionMatrix * mv;

    // 指针在屏幕空间排斥粒子，形成可感知的"触碰"
    vec2 ndc = clip.xy / clip.w;
    vec2 dir = ndc - uPointer;
    float dist = length(dir * vec2(1.0, 0.6));
    float push = uPointerForce * smoothstep(0.28, 0.0, dist);
    clip.xy += normalize(dir + 1e-4) * push * 0.09 * clip.w;
    gl_Position = clip;

    float isThreat = step(0.5, aRole) * step(aRole, 1.5);
    float pulse = 1.0 + isThreat * 0.45 * (0.5 + 0.5 * sin(uTime * 3.0 + aSeed * 12.0));
    gl_PointSize = uPixel * (2.1 + aSeed * 1.6) * pulse * (3.2 / -mv.z);

    vColor = mix(aColor, aColorTo, m);
    vAlpha = mix(0.88, 1.0, isThreat) * clamp(3.6 / -mv.z, 0.62, 1.0);
  }
`

const FRAG = /* glsl */ `
  varying vec3 vColor;
  varying float vAlpha;
  void main() {
    vec2 c = gl_PointCoord - 0.5;
    float r = length(c);
    if (r > 0.5) discard;
    float a = smoothstep(0.5, 0.36, r) * vAlpha;
    gl_FragColor = vec4(vColor, a);
  }
`

/** 各章节的整体姿态：x 偏移配合左右交替版式 */
const POSES = [
  { x: 0.9, y: 0, rot: 0.0, tilt: 0.25, scale: 1.0 },
  { x: -0.2, y: 0, rot: 0.5, tilt: 0.1, scale: 0.95 },
  { x: 1.05, y: 0, rot: 0.15, tilt: -0.05, scale: 0.9 },
  { x: -1.0, y: 0, rot: -0.6, tilt: 0.2, scale: 1.0 },
  { x: 1.0, y: 0, rot: 0.9, tilt: 0.3, scale: 1.0 },
  { x: -1.0, y: 0.05, rot: 1.8, tilt: 0.35, scale: 1.1 },
  { x: 0, y: -0.25, rot: 0.2, tilt: 0.6, scale: 0.95 },
  { x: 0.95, y: 0, rot: 0.4, tilt: 0.95, scale: 1.0 },
]

export class ThreatScene {
  readonly chapters: number
  private renderer: THREE.WebGLRenderer
  private scene = new THREE.Scene()
  private camera: THREE.PerspectiveCamera
  private group = new THREE.Group()
  private geo = new THREE.BufferGeometry()
  private mat: THREE.ShaderMaterial
  private edges: THREE.LineSegments
  private ring: THREE.LineLoop
  private shapes = buildShapes(4200)
  private seg = -1
  private progress = 0
  private smooth = 0
  private pointer = new THREE.Vector2(9, 9)
  private pointerTarget = new THREE.Vector2(9, 9)
  private raf = 0
  private clock = new THREE.Clock()
  private reduced: boolean
  private ro: ResizeObserver

  constructor(private canvas: HTMLCanvasElement, private opts: { centered?: boolean } = {}) {
    this.chapters = this.shapes.positions.length
    this.reduced = matchMedia('(prefers-reduced-motion: reduce)').matches
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: 'high-performance' })
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2))
    this.renderer.setClearColor(0x000000, 0)

    this.camera = new THREE.PerspectiveCamera(38, 1, 0.1, 50)
    this.camera.position.set(0, 0, 7)

    const n = this.shapes.roles.length
    const seeds = new Float32Array(n)
    const roles = new Float32Array(n)
    const roleCode = { normal: 0, anomaly: 1, rejected: 2, sensor: 3 } as const
    for (let i = 0; i < n; i++) {
      seeds[i] = Math.random()
      roles[i] = roleCode[this.shapes.roles[i]]
    }
    this.geo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(n * 3), 3))
    this.geo.setAttribute('aTo', new THREE.BufferAttribute(new Float32Array(n * 3), 3))
    this.geo.setAttribute('aColor', new THREE.BufferAttribute(new Float32Array(n * 3), 3))
    this.geo.setAttribute('aColorTo', new THREE.BufferAttribute(new Float32Array(n * 3), 3))
    this.geo.setAttribute('aSeed', new THREE.BufferAttribute(seeds, 1))
    this.geo.setAttribute('aRole', new THREE.BufferAttribute(roles, 1))
    this.geo.boundingSphere = new THREE.Sphere(new THREE.Vector3(), 6)

    this.mat = new THREE.ShaderMaterial({
      vertexShader: VERT,
      fragmentShader: FRAG,
      transparent: true,
      depthWrite: false,
      uniforms: {
        uMix: { value: 0 },
        uTime: { value: 0 },
        uPixel: { value: this.renderer.getPixelRatio() },
        uPointer: { value: this.pointer },
        uPointerForce: { value: 0 },
      },
    })
    this.group.add(new THREE.Points(this.geo, this.mat))

    // 研判章节的事件关联边
    const { clusters, edges } = this.shapes
    const ep = new Float32Array(edges.length * 6)
    edges.forEach(([a, b], k) => ep.set([...clusters[a], ...clusters[b]], k * 6))
    const eg = new THREE.BufferGeometry()
    eg.setAttribute('position', new THREE.BufferAttribute(ep, 3))
    this.edges = new THREE.LineSegments(eg, new THREE.LineBasicMaterial({ color: 0x14161a, transparent: true, opacity: 0 }))
    this.group.add(this.edges)

    // 扫描环：贯穿全部章节的细线，体现持续观测
    const rp: number[] = []
    for (let i = 0; i < 256; i++) {
      const a = (i / 256) * Math.PI * 2
      rp.push(Math.cos(a) * 2.05, 0, Math.sin(a) * 2.05)
    }
    const rg = new THREE.BufferGeometry()
    rg.setAttribute('position', new THREE.Float32BufferAttribute(rp, 3))
    this.ring = new THREE.LineLoop(rg, new THREE.LineDashedMaterial({ color: 0x2438e8, transparent: true, opacity: 0.35, dashSize: 0.04, gapSize: 0.06 }))
    this.ring.computeLineDistances()
    this.group.add(this.ring)

    this.scene.add(this.group)
    this.setSegment(0)

    this.ro = new ResizeObserver(() => this.resize())
    this.ro.observe(canvas)
    this.resize()
    this.loop()
  }

  /** progress 为连续章节序号，例如 2.4 表示第 3 章向第 4 章过渡 40% */
  setProgress(p: number) {
    this.progress = THREE.MathUtils.clamp(p, 0, this.chapters - 1)
  }

  /** 指针位置，NDC 坐标；离开画面时传 null */
  setPointer(x: number | null, y = 0) {
    if (x === null) this.pointerTarget.set(9, 9)
    else this.pointerTarget.set(x, y)
  }

  dispose() {
    cancelAnimationFrame(this.raf)
    this.ro.disconnect()
    this.geo.dispose()
    this.mat.dispose()
    this.edges.geometry.dispose()
    ;(this.edges.material as THREE.Material).dispose()
    this.ring.geometry.dispose()
    ;(this.ring.material as THREE.Material).dispose()
    this.renderer.dispose()
  }

  private setSegment(k: number) {
    if (k === this.seg) return
    this.seg = k
    const { positions, colors } = this.shapes
    const to = Math.min(k + 1, this.chapters - 1)
    const g = this.geo.attributes
    ;(g.position.array as Float32Array).set(positions[k])
    ;(g.aTo.array as Float32Array).set(positions[to])
    ;(g.aColor.array as Float32Array).set(colors[k])
    ;(g.aColorTo.array as Float32Array).set(colors[to])
    g.position.needsUpdate = g.aTo.needsUpdate = g.aColor.needsUpdate = g.aColorTo.needsUpdate = true
  }

  private resize() {
    const w = this.canvas.clientWidth
    const h = this.canvas.clientHeight
    if (!w || !h) return
    this.renderer.setSize(w, h, false)
    this.camera.aspect = w / h
    // 窄屏时拉远镜头，保证主体完整
    this.camera.position.z = w / h < 1 ? 9.5 : 7
    this.camera.updateProjectionMatrix()
  }

  private loop = () => {
    this.raf = requestAnimationFrame(this.loop)
    const dt = Math.min(this.clock.getDelta(), 0.05)
    const t = this.clock.elapsedTime
    const ease = this.reduced ? 1 : 1 - Math.pow(0.001, dt)
    this.smooth += (this.progress - this.smooth) * ease

    const k = Math.min(Math.floor(this.smooth), this.chapters - 2)
    const f = this.smooth - k
    this.setSegment(k)
    this.mat.uniforms.uMix.value = f
    this.mat.uniforms.uTime.value = this.reduced ? 0 : t

    this.pointer.lerp(this.pointerTarget, 1 - Math.pow(0.002, dt))
    const force = this.pointerTarget.x > 5 ? 0 : 1
    const u = this.mat.uniforms.uPointerForce
    u.value += (force - u.value) * (1 - Math.pow(0.01, dt))

    // 章节姿态插值（smoothstep 让停留更稳）
    const a = POSES[k]
    const b = POSES[k + 1]
    const s = f * f * (3 - 2 * f)
    const wide = this.camera.aspect > 1.1 && !this.opts.centered ? 1 : 0
    this.group.position.x = THREE.MathUtils.lerp(a.x, b.x, s) * wide
    this.group.position.y = THREE.MathUtils.lerp(a.y, b.y, s)
    const idle = this.reduced ? 0 : t * 0.04
    const px = this.pointer.x > 5 ? 0 : this.pointer.x
    const py = this.pointer.y > 5 ? 0 : this.pointer.y
    this.group.rotation.y = THREE.MathUtils.lerp(a.rot, b.rot, s) + idle + px * 0.12
    this.group.rotation.x = THREE.MathUtils.lerp(a.tilt, b.tilt, s) - py * 0.08
    this.group.scale.setScalar(THREE.MathUtils.lerp(a.scale, b.scale, s))

    // 事件边只在第 5 章（研判）附近显现
    const edgeVis = Math.max(0, 1 - Math.abs(this.smooth - 4) * 1.6)
    ;(this.edges.material as THREE.LineBasicMaterial).opacity = edgeVis * 0.28
    this.ring.rotation.y = -t * 0.15
    this.ring.rotation.x = Math.sin(this.smooth * 0.9) * 0.6
    const rs = 1 + Math.sin(this.smooth * 1.3) * 0.08
    this.ring.scale.setScalar(rs)

    this.renderer.render(this.scene, this.camera)
  }
}
