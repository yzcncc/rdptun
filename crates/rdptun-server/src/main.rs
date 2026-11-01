//! rdptun-server 入口：加载配置与证书，启动并发 RDP accept 循环。

mod config;
mod server;

use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use tracing::info;

#[derive(Debug, clap::Parser)]
struct Args {
    /// 配置文件（TOML）。
    #[arg(short, long, default_value = "server.toml")]
    config: std::path::PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let cfg = Arc::new(config::load_config(&args.config).context("load config")?);

    info!(
        bind = %cfg.bind,
        target = %cfg.target,
        channel = %cfg.channel,
        nla_user = %cfg.username,
        "rdptun-server starting"
    );

    // 证书：显式配置优先，否则生成/加载 Windows 风格自签名证书。
    let identity = rdptun_cert::load_or_create_identity(
        &cfg.cert_store_dir,
        cfg.machine_name.as_deref(),
        cfg.cert_path.as_deref(),
        cfg.key_path.as_deref(),
    )
    .context("load TLS identity")?;

    let ctx = config::TlsIdentityCtx::from_identity(&identity).context("parse TLS identity")?;
    let tls_acceptor = Arc::new(ctx.make_acceptor().context("build TLS acceptor")?);
    let pub_key = ctx.pub_key;

    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("bind {}", cfg.bind))?;
    info!(addr = %listener.local_addr()?, "listening (looks like a Windows RDP host)");

    let sessions = Arc::new(tokio::sync::Semaphore::new(cfg.max_sessions));

    // CredSSP/connector 状态机含 !Send 的 Rc/生成器 —— 连接必须在
    // LocalSet 上运行（单线程并发，对实验室场景足够；桥接 IO 仍异步）。
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                let (stream, peer) = listener.accept().await?;
                stream.set_nodelay(true).ok();

                let cfg = Arc::clone(&cfg);
                let tls = Arc::clone(&tls_acceptor);
                let sessions = Arc::clone(&sessions);
                let pub_key = pub_key.clone();

                tokio::task::spawn_local(async move {
                    let started = std::time::Instant::now();
                    match server::run_connection(stream, cfg, tls, pub_key, sessions).await {
                        Ok(()) => info!(%peer, elapsed = ?started.elapsed(), "connection finished"),
                        Err(e) => info!(%peer, error = %format!("{e:#}"), elapsed = ?started.elapsed(), "connection ended"),
                    }
                });
            }
        })
        .await
}
