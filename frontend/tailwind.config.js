/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // 浅色主题底色与表面
        canvas: {
          DEFAULT: '#f8fafc', // slate-50 页面底色
          subtle: '#f1f5f9',  // slate-100 次级底色 / 侧边栏底色
          panel: '#ffffff',   // 纯白卡片面板
          muted: '#e2e8f0',   // slate-200 分割线与弱化边框
          border: '#cbd5e1',  // slate-300 强化边框
        },
        // 品牌与科技蓝
        cyber: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
          DEFAULT: '#0284c7',
        },
        // 安全语义颜色系统（浅色模式）
        threat: {
          critical: {
            bg: '#fef2f2',
            border: '#fecaca',
            text: '#dc2626',
            badge: '#b91c1c'
          },
          high: {
            bg: '#fff7ed',
            border: '#fed7aa',
            text: '#ea580c',
            badge: '#c2410c'
          },
          medium: {
            bg: '#fefce8',
            border: '#fef08a',
            text: '#ca8a04',
            badge: '#a16207'
          },
          low: {
            bg: '#f0fdfa',
            border: '#99f6e4',
            text: '#0d9488',
            badge: '#0f766e'
          },
          safe: {
            bg: '#f0fdf4',
            border: '#bbf7d0',
            text: '#16a34a',
            badge: '#15803d'
          },
          pending: {
            bg: '#faf5ff',
            border: '#e9d5ff',
            text: '#9333ea',
            badge: '#7e22ce'
          }
        }
      },
      fontFamily: {
        sans: ['Inter', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Menlo', 'Monaco', 'Courier New', 'monospace']
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05)',
        'card-hover': '0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -2px rgba(0, 0, 0, 0.05)',
        'panel': '0 10px 15px -3px rgba(0, 0, 0, 0.04), 0 4px 6px -4px rgba(0, 0, 0, 0.02)',
        'glow-cyber': '0 0 15px rgba(2, 132, 199, 0.15)',
      }
    },
  },
  plugins: [],
}
