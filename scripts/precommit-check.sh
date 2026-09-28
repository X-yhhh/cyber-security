#!/usr/bin/env bash
set -euo pipefail

# 只检查已暂存内容；不会读取、修改或清理工作区中的其他文件。
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

git diff --cached --check

bad=0
while IFS= read -r -d '' path; do
  case "$path" in
    *.onnx|*.pkl|*.pt|*.pth|*.joblib|*.safetensors|*.env|*.env.*)
      printf '拒绝暂存制品/环境文件：%s\n' "$path" >&2
      bad=1
      ;;
  esac
done < <(git diff --cached --name-only -z --diff-filter=ACMR)

patch=$(git diff --cached --no-ext-diff --unified=0)
absolute_path_prefix='/Users'
absolute_path_pattern="${absolute_path_prefix}/"
sensitive_fields='password|secret|token'
assignment_pattern='[[:space:]]*[:=]'
if printf '%s\n' "$patch" | rg -n "${absolute_path_pattern}|(?i)(${sensitive_fields})${assignment_pattern}" >/dev/null; then
  printf '%s\n' '拒绝暂存：补丁包含绝对用户路径或疑似凭据赋值。请脱敏后再提交。' >&2
  bad=1
fi

if (( bad != 0 )); then
  exit 1
fi
printf '%s\n' '预提交检查通过：空白、制品、环境文件、绝对路径和疑似凭据扫描均无违规。'
