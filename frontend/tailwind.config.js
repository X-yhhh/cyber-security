/** @type {import('tailwindcss').Config} */
// 视觉基线 v2（前端设计文档第 3 节，Q10）：页面与面板同为白底、以细边框分组，墨色为主操作与选中色，
// 钴蓝只用于链接悬停、焦点与“进行中”语义，朱红仅用于威胁语义。
// 圆角只有四档（徽标 4px、按钮与输入 6px、面板 8px、胶囊 full），rounded-md/lg/xl 不再提供；
// 阴影只给抽屉与弹层（shadow-panel），页面内区块一律不加阴影。
export default {
  content: ['./index.html', './src/**/*.{vue,ts}'],
  theme: {
    borderRadius: {
      none: '0',
      sm: '4px',
      DEFAULT: '6px',
      panel: '8px',
      full: '9999px',
    },
    extend: {
      colors: {
        paper: { DEFAULT: '#FFFFFF', soft: '#F2F1EE', deep: '#E6E4DD' },
        ink: {
          DEFAULT: '#14161A',
          2: '#3A3D44',
          3: '#6B6E75',
          4: '#9A9CA1',
          line: '#E2E0DA',
          hair: '#EDEBE6',
        },
        signal: { DEFAULT: '#2438E8', soft: '#E6E8FB', deep: '#1728B8' },
        threat: { DEFAULT: '#E0482A', soft: '#FBE9E4' },
        warn: { DEFAULT: '#B7791F', soft: '#F7EEDC' },
        ok: { DEFAULT: '#2F7D5B', soft: '#E3F0EA' },
      },
      boxShadow: {
        panel: '0 12px 32px -12px rgba(20, 22, 26, 0.18), 0 2px 6px rgba(20, 22, 26, 0.06)',
      },
      fontFamily: {
        sans: ['"Inter"', '"PingFang SC"', '"Hiragino Sans GB"', '"Microsoft YaHei"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"SF Mono"', 'Menlo', 'Consolas', 'monospace'],
      },
      letterSpacing: { label: '0.14em' },
      transitionTimingFunction: { out: 'cubic-bezier(0.22, 1, 0.36, 1)' },
    },
  },
  plugins: [],
}
