/** @type {import('tailwindcss').Config} */
// 视觉基线：纯白底 + 墨色文字，单一钴蓝强调色，朱红仅用于威胁语义。
// 刻意去掉大圆角与阴影层级，以细线和留白组织信息。
export default {
  content: ['./index.html', './src/**/*.{vue,ts}'],
  theme: {
    borderRadius: {
      none: '0',
      DEFAULT: '2px',
      sm: '1px',
      full: '9999px',
    },
    extend: {
      colors: {
        paper: { DEFAULT: '#FFFFFF', soft: '#EFEEE9', deep: '#E6E4DD' },
        ink: {
          DEFAULT: '#14161A',
          2: '#3A3D44',
          3: '#6B6E75',
          4: '#9A9CA1',
          line: '#D9D7D0',
          hair: '#E4E2DB',
        },
        signal: { DEFAULT: '#2438E8', soft: '#E6E8FB', deep: '#1728B8' },
        threat: { DEFAULT: '#E0482A', soft: '#FBE9E4' },
        warn: { DEFAULT: '#B7791F', soft: '#F7EEDC' },
        ok: { DEFAULT: '#2F7D5B', soft: '#E3F0EA' },
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
