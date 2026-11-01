//! rdptun-client 入口：本地 TCP 监听 + 内置 Web Dashboard。

mod config;
mod dashboard;
mod session;
mod tls;

use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info, warn};

#[derive(Debug, clap::Parser)]
struct Args {
    /// 配置文件（TOML）。不存在时使用默认值 + 环境变量。
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
    let cfg = config::load_config(&args.config).context("load config")?;

    info!(
        listen = %cfg.listen,
        server = %cfg.server,
        channel = %cfg.channel,
        trust = %cfg.trust,
        dashboard = %cfg.dashboard,
        "rdptun-client starting"
    );

    // CredSSP 状态机含 !Send 生成器 —— 全部任务跑在单线程 LocalSet 上。
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        let (state, cfg_rx) = dashboard::AppState::new(cfg, args.config.clone());

        // Dashboard
        let dash_state = Arc::clone(&state);
        tokio::task::spawn_local(async move {
            if let Err(e) = dashboard::serve(dash_state).await {
                error!(error = %format!("{e:#}"), "dashboard exited");
            }
        });

        run_proxy(state, cfg_rx).await
    })
}

/// 本地监听循环：配置变更（listen 改变）时自动重绑。
async fn run_proxy(state: Arc<dashboard::AppState>, mut cfg_rx: watch::Receiver<u64>) -> Result<()> {
    loop {
        let listen = state.cfg.read().await.listen.clone();

        let listener = match TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                let msg = format!("bind {listen}: {e}");
                error!(%msg);
                state.set_error(msg).await;
                // 等配置变更后再试
                if cfg_rx.changed().await.is_err() {
                    return Ok(());
                }
                continue;
            }
        };

        info!(addr = %listener.local_addr()?, "local proxy listening");
        state.clear_error().await;

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (sock, peer) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(error = %e, "accept failed");
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            continue;
                        }
                    };
                    let cfg = state.cfg.read().await.clone();
                    let stats = Arc::clone(&state.stats);

                    stats.session_started();
                    tokio::task::spawn_local(async move {
                        let started = std::time::Instant::now();
                        match session::tunnel_one_connection(cfg, sock, Arc::clone(&stats)).await {
                            Ok(()) => info!(%peer, elapsed = ?started.elapsed(), "tunnel session finished"),
                            Err(e) => info!(%peer, error = %format!("{e:#}"), elapsed = ?started.elapsed(), "tunnel session failed"),
                        }
                        stats.session_ended();
                    });
                }

                _ = cfg_rx.changed() => {
                    let new_listen = state.cfg.read().await.listen.clone();
                    if new_listen != listen {
                        info!(old = %listen, new = %new_listen, "listen address changed, rebinding");
                        break;
                    }
                }
            }
        }
    }
}
