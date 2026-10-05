#!/bin/sh
# 复用已安装 Python 包装器的运行环境；只为本项目 venv 补全 macOS 动态库路径。
set -eu
executor_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(uname -s)" = Darwin ]; then
    executor_runtime=$(python3 -c 'import sys; print(sys.base_prefix)')
    export DYLD_LIBRARY_PATH="$executor_runtime/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    export DYLD_FRAMEWORK_PATH="$(dirname "$(dirname "$(dirname "$executor_runtime")")")${DYLD_FRAMEWORK_PATH:+:$DYLD_FRAMEWORK_PATH}"
fi
exec "$executor_root/executor/.venv/bin/python" "$@"
