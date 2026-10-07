#!/usr/bin/env bash
# 用计划任务在交互会话中后台启动 v2 步骤（SSH 断开不影响）。用法：scripts/launch.sh <步骤> [参数...]
# 查看进度：tail -f runs/task-<步骤>.log 以及对应运行目录下的 training.log。
# 计划任务只作“立即运行一次”的载体：触发时间设为当天 00:00（已过去），不会在当天晚些时候再次自动触发；
# 启动后再核对“下次运行时间”，若仍有未来触发则禁用（禁用不影响已在运行的实例）。
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -W)"
step="$1"; shift || true
task="cyber-v2-${step}"
schtasks //Create //TN "$task" //TR "\"${root}\\scripts\\run_step.cmd\" ${step} $*" //SC ONCE //ST 00:00 //IT //F >/dev/null 2>&1
schtasks //Run //TN "$task" >/dev/null
next="$(schtasks //Query //TN "$task" //FO CSV //NH | cut -d, -f2 | tr -d '"\r')"
if [ "$next" != "N/A" ]; then
  schtasks //Change //TN "$task" //DISABLE >/dev/null
  echo "warning: ${task} had a future trigger (${next}); disabled it"
fi
echo "started task ${task}; log: runs/task-${step}.log"
