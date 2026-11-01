# syntax=docker/dockerfile:1
# ============================================================
# rdptun-client Docker 镜像（多架构：amd64 / arm64）
#
# amd64 在构建平台上直接编译；arm64 用 aarch64 交叉工具链编译
# （aws-lc-sys 需要 cmake/perl + 目标 libc 头文件）。
# ============================================================

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

ARG TARGETARCH

WORKDIR /src

# 依赖工具：amd64 只需 cmake/perl；arm64 额外要交叉 gcc 与目标架构头文件
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends cmake perl pkg-config; \
    if [ "$TARGETARCH" = "arm64" ]; then \
        dpkg --add-architecture arm64 || true; \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            gcc-aarch64-linux-gnu libc6-dev-arm64-cross; \
    fi; \
    rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/rdptun-cert/Cargo.toml crates/rdptun-cert/
COPY crates/rdptun-proto/Cargo.toml crates/rdptun-proto/
COPY crates/rdptun-server/Cargo.toml crates/rdptun-server/
COPY crates/rdptun-client/Cargo.toml crates/rdptun-client/

RUN set -eux; \
    for d in rdptun-cert rdptun-proto rdptun-server rdptun-client; do \
        mkdir -p crates/$d/src; \
        echo '' > crates/$d/src/lib.rs; \
        case "$d" in \
          rdptun-server|rdptun-client) echo 'fn main() {}' > crates/$d/src/main.rs ;; \
        esac; \
    done

# 目标架构与交叉链接器配置
RUN set -eux; \
    if [ "$TARGETARCH" = "arm64" ]; then \
        rustup target add aarch64-unknown-linux-gnu; \
        mkdir -p .cargo; \
        printf '[target.aarch64-unknown-linux-gnu]\nlinker = "aarch64-linux-gnu-gcc"\n' > .cargo/config.toml; \
    fi

RUN --mount=type=cache,id=cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/src/target \
    set -eux; \
    if [ "$TARGETARCH" = "arm64" ]; then \
        cargo build --release --target aarch64-unknown-linux-gnu -p rdptun-client || true; \
    else \
        cargo build --release -p rdptun-client || true; \
    fi

COPY crates ./crates

# 关键：占位 main.rs 与真实源码同名，必须让 cargo 判定源码已更新，
# 否则会复用占位阶段生成的空二进制。
RUN set -eux; \
    find crates -name '*.rs' -exec touch {} +; \
    touch Cargo.toml crates/*/Cargo.toml

RUN --mount=type=cache,id=cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/src/target \
    set -eux; \
    if [ "$TARGETARCH" = "arm64" ]; then \
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
