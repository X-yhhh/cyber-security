@echo off
rem 用法：run_step.cmd <步骤> [参数...]
rem 由计划任务调用，使长任务不随 SSH 会话结束；标准输出/错误写入 runs\task-<步骤>.log。
cd /d "%~dp0.."
set PYTHONUNBUFFERED=1
".venv\Scripts\python.exe" -m cyber_training.v2 %* > "runs\task-%1.log" 2>&1
echo exit=%ERRORLEVEL% >> "runs\task-%1.log"
