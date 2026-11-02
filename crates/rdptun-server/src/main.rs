//! rdptun-server 入口：加载配置与证书，启动并发 RDP accept 循环。

mod config;
mod server;

use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use tokio::sync::OwnedSemaphorePermit;
use tracing::{info, warn};

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
                // keepalive + 重传超时：静默死亡的连接能在 ~2 分钟内被发现并回收
                rdptun_proto::net::tune_long_lived(&stream).ok();

                let cfg = Arc::clone(&cfg);
                let tls = Arc::clone(&tls_acceptor);
                let pub_key = pub_key.clone();

                // 许可槽等待期间检测客户端关闭/放弃，避免僵尸连接占着 backlog。
                let permit = match wait_session_slot(&stream, &sessions).await {
                    Ok(p) => p,
                    Err(reason) => {
                        warn!(%peer, %reason, "dropping connection before handshake");
                        continue;
                    }
                };
                let in_use = cfg.max_sessions - sessions.available_permits();
                info!(%peer, in_use, max = cfg.max_sessions, "session slot acquired");

                tokio::task::spawn_local(async move {
                    let started = std::time::Instant::now();
                    match server::run_connection(stream, cfg, tls, pub_key, permit).await {
                        Ok(()) => info!(%peer, elapsed = ?started.elapsed(), "connection finished"),
                        Err(e) => info!(%peer, error = %format!("{e:#}"), elapsed = ?started.elapsed(), "connection ended"),
                    }
                });
            }
        })
        .await
}

/// 等待会话许可槽：
/// - 客户端在等待期间关闭连接（peek 到 EOF）→ 放弃；
/// - 超过 30s 拿不到槽 → 放弃（客户端会快速失败并重试）。
async fn wait_session_slot(
    stream: &tokio::net::TcpStream,
    sessions: &Arc<tokio::sync::Semaphore>,
) -> Result<OwnedSemaphorePermit, String> {
    let mut buf = [0u8; 1];
    loop {
        tokio::select! {
            p = sessions.clone().acquire_owned() => {
                return p.map_err(|_| "server shutting down".to_owned());
            }
            r = stream.peek(&mut buf) => {
                match r {
                    Ok(0) => return Err("client closed while waiting for slot".to_owned()),
                    Ok(_) => { /* 客户端已发送数据（X.224 请求），继续等槽 */ }
                    Err(e) => return Err(format!("peek failed: {e}")),
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                return Err("no session slot within 30s".to_owned());
            }
        }
    }
}
