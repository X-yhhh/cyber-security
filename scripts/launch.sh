#!/usr/bin/env bash
# 用计划任务在交互会话中后台启动 v2 步骤（SSH 断开不影响）。用法：scripts/launch.sh <步骤> [参数...]
# 查看进度：tail -f runs/task-<步骤>.log 以及对应运行目录下的 training.log。
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -W)"
step="$1"; shift || true
task="cyber-v2-${step}"
schtasks //Create //TN "$task" //TR "\"${root}\\scripts\\run_step.cmd\" ${step} $*" //SC ONCE //ST 23:59 //IT //F >/dev/null
schtasks //Run //TN "$task" >/dev/null
echo "started task ${task}; log: runs/task-${step}.log"
