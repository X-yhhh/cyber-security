#!/bin/sh
# A4/B2：从指定提交准备模块缓存及镜像，再断网测试和构建；不下载 Go 安装包。
set -eu
umask 077

usage() {
    echo '用法：sh build_guardlive.sh <40位提交SHA> <本地Go-linux-amd64包绝对路径> <官方SHA-256> <新输出目录绝对路径>'
    echo '可选环境：BUILD_GO（Mac Go 入口）、BUILD_PYTHON（Python 3 入口）；不启动 Docker Desktop。'
}
if [ "$#" -eq 1 ] && [ "$1" = --help ]; then
    usage
    exit 0
fi
if [ "$#" -ne 4 ]; then
    usage >&2
    exit 2
fi

commit=$1
go_archive=$2
go_sha256=$3
output=$4
build_go=${BUILD_GO:-go}
build_python=${BUILD_PYTHON:-python3}

# 在调用 Git、Go、Docker 前检查输入；失败不覆盖已有目录，也不输出包的内容。
"$build_python" - "$commit" "$go_archive" "$go_sha256" "$output" <<'PY'
import hashlib
from pathlib import Path
import re
import sys

commit, archive, expected, output = sys.argv[1:]
if not re.fullmatch(r'[0-9a-f]{40}', commit):
    raise SystemExit('FULL_COMMIT_SHA_REQUIRED')
if not re.fullmatch(r'[0-9a-f]{64}', expected):
    raise SystemExit('GO_SHA256_REQUIRED')
for value in (archive, output):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or ',' in value or any(ord(c) < 32 for c in value):
        raise SystemExit('ABSOLUTE_DOCKER_MOUNT_PATH_REQUIRED')
archive, output = Path(archive), Path(output)
if not archive.is_file():
    raise SystemExit('LOCAL_GO_ARCHIVE_REQUIRED')
with archive.open('rb') as stream:
    if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
        raise SystemExit('GO_SHA256_MISMATCH')
if output.exists() or output.is_symlink() or not output.parent.is_dir():
    raise SystemExit('NEW_OUTPUT_DIRECTORY_REQUIRED')
PY

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(git -C "$script_dir" rev-parse --show-toplevel)
test "$(git -C "$repository" rev-parse --verify "$commit^{commit}")" = "$commit"
mkdir -m 700 "$output"
mkdir -m 700 "$output/source" "$output/modules" "$output/context" "$output/modcache" "$output/evidence"

# 准备或容器失败也留下 JSON 和已有日志；ok=true 必须同时有测试、二进制与 ldd 证据。
finish() {
    status=$?
    trap - 0
    "$build_python" - "$output" "$commit" "$go_sha256" "$status" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root, commit, go_hash, status = Path(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
evidence = root / 'evidence'
def read(name):
    path = evidence / name
    return path.read_text().strip() if path.is_file() else None
test_rc = read('test.rc')
test_rc = int(test_rc) if test_rc is not None else None
binary = evidence / 'guardlive'
binary_hash = None
if binary.is_file():
    with binary.open('rb') as stream:
        binary_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
ldd = read('ldd.txt')
resolved = bool(ldd) and 'not found' not in ldd
report = dict(
    schemaVersion='remote-sensor-build/1', commitSha=commit,
    platform='linux/amd64', network='none', goArchiveSha256=go_hash,
    goVersion=read('go-version.txt'), libpcapVersion=read('libpcap-version.txt'),
    glibcVersion=read('glibc-version.txt'), imageId=read('image-id.txt'),
    sourceArchiveSha256=read('source.sha256'),
    tests=dict(command='go test -count=1 ./...', exitCode=test_rc,
               passed=test_rc == 0, log='test.log'),
    binarySha256=binary_hash, ldd=dict(resolved=resolved, output=ldd),
    exitCode=status,
    ok=status == 0 and test_rc == 0 and binary_hash is not None and resolved)
with (evidence / 'build.json').open('x') as stream:
    json.dump(report, stream, ensure_ascii=False, indent=2)
    stream.write('\n')
print(json.dumps(report, ensure_ascii=False, indent=2))
PY
    exit "$status"
}
trap finish 0

# 第一步先按目标提交的模块清单预热独立缓存，不使用当前工作区的 go.mod。
git -C "$repository" show "$commit:sensor/go.mod" > "$output/modules/go.mod"
git -C "$repository" show "$commit:sensor/go.sum" > "$output/modules/go.sum"
go_version=$(awk '$1 == "go" {print $2}' "$output/modules/go.mod")
test -n "$go_version"
test "$(GOTOOLCHAIN=local "$build_go" env GOVERSION)" = "go$go_version"
(
    cd "$output/modules"
    GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off \
        GOMODCACHE="$output/modcache" "$build_go" mod download
) > "$output/evidence/mod-download.log" 2>&1

# 只取提交原件；后三个目录是 Go 测试跨目录读取的契约与样例。
git -C "$repository" archive --format=tar "$commit" sensor docs/contracts \
    backend/src/main/resources/feature-contract backend/src/test/resources/feature-contract \
    > "$output/source.tar"
tar -xf "$output/source.tar" -C "$output/source"
"$build_python" - "$output" <<'PY'
import hashlib
from pathlib import Path
import sys
root = Path(sys.argv[1])
with (root / 'source.tar').open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
(root / 'evidence/source.sha256').write_text(digest + '\n')
PY
# 镜像准备允许取得 apt 包；缓存仅属于本次输出，容器只读挂载。
cp "$go_archive" "$output/context/go.tar.gz"
cp "$script_dir/Dockerfile" "$output/context/Dockerfile"
docker build --platform linux/amd64 --build-arg "GO_VERSION=$go_version" \
    --build-arg "GO_SHA256=$go_sha256" --tag "cyber-sensor-builder:$commit" \
    "$output/context" > "$output/evidence/image-build.log" 2>&1
docker image inspect --format '{{.Id}}' "cyber-sensor-builder:$commit" > "$output/evidence/image-id.txt"
image_id=$(cat "$output/evidence/image-id.txt")

# 第二步固定镜像 ID、禁止网络；测试不通过就不生成可下发二进制。
docker run --rm --platform linux/amd64 --pull=never --network none \
    --mount "type=bind,source=$output/source,target=/src,readonly" \
    --mount "type=bind,source=$output/modcache,target=/modcache,readonly" \
    --mount "type=bind,source=$output/evidence,target=/out" \
    --env GOFLAGS=-mod=readonly --env GOPROXY=off --env GOTOOLCHAIN=local \
    --env GOMODCACHE=/modcache --env GOWORK=off --env CGO_ENABLED=1 \
    "$image_id" sh -eu -c '
        umask 077
        cp -R /src/. /work/
        cd /work/sensor
        go version > /out/go-version.txt
        dpkg-query -W -f="\${Version}\n" libpcap-dev > /out/libpcap-version.txt
        ldd --version > /out/glibc-version.txt
        if go test -count=1 ./... > /out/test.log 2>&1; then
            printf "0\n" > /out/test.rc
        else
            code=$?
            printf "%s\n" "$code" > /out/test.rc
            exit "$code"
        fi
        CGO_ENABLED=1 go build -trimpath -o /out/guardlive ./cmd/guardlive > /out/build.log 2>&1
        sha256sum /out/guardlive > /out/guardlive.sha256
        ldd /out/guardlive > /out/ldd.txt 2>&1
        ! grep -F "not found" /out/ldd.txt
    ' > "$output/evidence/container.log" 2>&1
