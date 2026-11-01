# syntax=docker/dockerfile:1
# ============================================================
# rdptun-client Docker 镜像（多阶段构建，支持 amd64/arm64）
# ============================================================

# ---- 构建阶段 ----
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

ARG TARGETARCH
ARG CARGO_NET_GIT_FETCH_WITH_CLI=true

# 交叉编译工具链（arm64 在 amd64 runner 上构建时需要）
RUN set -eux; \
    if [ "$TARGETARCH" = "arm64" ]; then \
        apt-get update; \
        apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu; \
        rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /src

# 先复制清单以缓存依赖编译
COPY Cargo.toml Cargo.lock ./
COPY crates/rdptun-cert/Cargo.toml crates/rdptun-cert/
COPY crates/rdptun-proto/Cargo.toml crates/rdptun-proto/
COPY crates/rdptun-server/Cargo.toml crates/rdptun-server/
COPY crates/rdptun-client/Cargo.toml crates/rdptun-client/

# 生成假源文件以便预编译依赖
RUN set -eux; \
    for d in rdptun-cert rdptun-proto rdptun-server rdptun-client; do \
        mkdir -p crates/$d/src; \
        echo '' > crates/$d/src/lib.rs; \
        [ "$d" = rdptun-server ] && echo 'fn main() {}' > crates/$d/src/main.rs; \
        [ "$d" = rdptun-client ] && echo 'fn main() {}' > crates/$d/src/main.rs; \
    done

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    if [ "$TARGETARCH" = "arm64" ]; then \
        rustup target add aarch64-unknown-linux-gnu; \
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc; \
        cargo build --release --target aarch64-unknown-linux-gnu -p rdptun-client || true; \
    else \
        cargo build --release -p rdptun-client || true; \
    fi

# 复制真实源码后正式构建
COPY crates ./crates
COPY etc ./etc

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    if [ "$TARGETARCH" = "arm64" ]; then \
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc; \
        cargo build --release --target aarch64-unknown-linux-gnu -p rdptun-client; \
        cp target/aarch64-unknown-linux-gnu/release/rdptun-client /rdptun-client; \
    else \
        cargo build --release -p rdptun-client; \
        cp target/release/rdptun-client /rdptun-client; \
    fi

# ---- 运行阶段 ----
FROM debian:bookworm-slim

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --uid 10001 --home-dir /data --create-home rdptun

COPY --from=builder /rdptun-client /usr/local/bin/rdptun-client

# 配置持久化目录（dashboard 修改的配置写在这里）
VOLUME ["/data"]
WORKDIR /data

ENV RDPTUN_LISTEN=0.0.0.0:1080 \
    RDPTUN_DASHBOARD=0.0.0.0:8080 \
    RDPTUN_TOFU_STORE=/data/client-known-hosts

USER rdptun

# 1080 = 代理端口；8080 = dashboard
EXPOSE 1080 8080

# 就绪探针：探测上游 RDP 可达性（失败返回 503）
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/rdptun-client"]
CMD ["--config", "/data/client.toml"]
