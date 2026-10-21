# A4 第一步：仅在 Mac 构建 Ubuntu amd64 镜像；Go 包由操作者预先取得。
FROM ubuntu:24.04

ARG TARGETARCH
ARG GO_VERSION=1.26.4
ARG GO_SHA256
ENV DEBIAN_FRONTEND=noninteractive

# 不关闭签名校验；502、索引或签名暂时失败时重新更新索引，重试耗尽即失败。
RUN set -eu; \
    test "$TARGETARCH" = amd64; \
    attempt=1; \
    until apt-get -o Acquire::Retries=5 update \
        && apt-get -o Acquire::Retries=5 install -y --no-install-recommends gcc libc6-dev libpcap-dev; do \
        test "$attempt" -lt 10 || exit 1; \
        attempt=$((attempt + 1)); \
        sleep 15; \
    done; \
    rm -rf /var/lib/apt/lists/*

COPY go.tar.gz /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:$PATH \
    GOFLAGS=-mod=readonly \
    GOPROXY=off \
    GOTOOLCHAIN=local \
    GOMODCACHE=/modcache \
    GOWORK=off \
    CGO_ENABLED=1

# 镜像内再次核对外部传入的官方摘要；不通过网络取得 Go 或自动升级工具链。
RUN set -eu; \
    test "${#GO_SHA256}" -eq 64; \
    case "$GO_SHA256" in *[!0-9a-f]*) exit 1 ;; esac; \
    printf '%s  /tmp/go.tar.gz\n' "$GO_SHA256" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz; \
    test "$(go env GOVERSION)" = "go$GO_VERSION"; \
    test "$(go env GOOS)/$(go env GOARCH)" = linux/amd64

WORKDIR /work
