//! rdptun-client 入口：本地 TCP 监听，每条连接建立一次伪装 RDP 会话。

mod config;
mod session;
mod tls;

use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use tracing::info;

#[derive(Debug, clap::Parser)]
struct Args {
    /// 配置文件（TOML）。
    #[arg(short, long, default_value = "client.toml")]
    config: std::path::PathBuf,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let cfg = Arc::new(config::load_config(&args.config).context("load config")?);

    info!(
        listen = %cfg.listen,
        server = %cfg.server,
        channel = %cfg.channel,
        trust = %cfg.trust,
        "rdptun-client starting"
    );

    // CredSSP 状态机含 !Send 生成器 —— 所有会话在 LocalSet（单线程）上并发。
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        let listener = tokio::net::TcpListener::bind(&cfg.listen)
            .await
            .with_context(|| format!("bind {}", cfg.listen))?;
        info!(addr = %listener.local_addr()?, "local proxy listening");

        loop {
            let (sock, peer) = listener.accept().await?;
            let cfg = Arc::clone(&cfg);

            tokio::task::spawn_local(async move {
                let started = std::time::Instant::now();
                match session::tunnel_one_connection(cfg, sock).await {
                    Ok(()) => info!(%peer, elapsed = ?started.elapsed(), "tunnel session finished"),
                    Err(e) => info!(%peer, error = %format!("{e:#}"), elapsed = ?started.elapsed(), "tunnel session failed"),
                }
            });
        }
    })
}
