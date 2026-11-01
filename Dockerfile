# syntax=docker/dockerfile:1
# ============================================================
# rdptun-client Docker 镜像（多架构：amd64 / arm64）
#
# 采用 TARGETPLATFORM 原生构建（arm64 在 QEMU 模拟下编译），
# 避免交叉编译 aws-lc-sys 时 jitterentropy 的头文件/工具链问题。
# ============================================================

FROM rust:1-bookworm AS builder

ARG TARGETARCH

WORKDIR /src

# 复制清单以缓存依赖层
COPY Cargo.toml Cargo.lock ./
COPY crates/rdptun-cert/Cargo.toml crates/rdptun-cert/
COPY crates/rdptun-proto/Cargo.toml crates/rdptun-proto/
COPY crates/rdptun-server/Cargo.toml crates/rdptun-server/
COPY crates/rdptun-client/Cargo.toml crates/rdptun-client/

# 占位源文件，先编译依赖
RUN set -eux; \
    for d in rdptun-cert rdptun-proto rdptun-server rdptun-client; do \
        mkdir -p crates/$d/src; \
        echo '' > crates/$d/src/lib.rs; \
        case "$d" in \
          rdptun-server|rdptun-client) echo 'fn main() {}' > crates/$d/src/main.rs ;; \
        esac; \
    done

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p rdptun-client || true

# 真实源码
COPY crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p rdptun-client \
    && cp target/release/rdptun-client /rdptun-client

# ---- 运行阶段 ----
FROM debian:bookworm-slim

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --uid 10001 --home-dir /data --create-home rdptun

COPY --from=builder /rdptun-client /usr/local/bin/rdptun-client

VOLUME ["/data"]
WORKDIR /data

ENV RDPTUN_LISTEN=0.0.0.0:1080 \
    RDPTUN_DASHBOARD=0.0.0.0:8080 \
    RDPTUN_TOFU_STORE=/data/client-known-hosts

USER rdptun
EXPOSE 1080 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/rdptun-client"]
CMD ["--config", "/data/client.toml"]
