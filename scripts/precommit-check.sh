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

# docs/验证与验收.md 的原字节被第二轮评价计划的 metricDefinitionSha256 绑定，见 scripts/p6/test_metric_binding.py。
metric_doc='docs/验证与验收.md'
metric_sha='0da3497f8f0ba0eecb16546acbfa3a9e2e6f941ed555ddb35ec678d4e220ec56'
if git diff --cached --name-only --diff-filter=ACMR -- "$metric_doc" | grep -q .; then
  staged_sha=$(git show ":$metric_doc" | shasum -a 256 | cut -d' ' -f1)
  if [[ "$staged_sha" != "$metric_sha" ]]; then
    printf '拒绝暂存：%s 与评价计划绑定的哈希不一致；状态说明请写入开发路线或执行记录。\n' "$metric_doc" >&2
    bad=1
  fi
fi

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
