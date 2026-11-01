//! 客户端配置与 TLS 信任策略。

use std::path::PathBuf;

use anyhow::Context as _;

/// 客户端 TOML 配置。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ClientConfig {
    /// 本地监听地址，如 `127.0.0.1:1080`。
    pub listen: String,
    /// 服务端地址（伪装成 RDP host）。
    pub server: String,
    /// NLA 登录用户名。
    pub username: String,
    /// NLA 登录密码。
    pub password: String,
    /// 隧道 SVC 通道名（须与服务端一致）。默认 `TUNNEL`。
    #[serde(default = "default_channel")]
    pub channel: String,
    /// 伪装的客户端计算机名（mstshash / Client Name）。
    #[serde(default = "default_client_name")]
    pub client_name: String,
    /// 信任模式：`tofu`（默认）| `pin` | `none`。
    #[serde(default = "default_trust")]
    pub trust: String,
    /// `pin` 模式的 SPKI SHA-256 哈希（hex）。
    #[serde(default)]
    pub pin_spki_sha256: Option<String>,
    /// TOFU 记录存储路径。
    #[serde(default = "default_tofu_store")]
    pub tofu_store: PathBuf,
}

fn default_channel() -> String {
    rdptun_proto::DEFAULT_CHANNEL_NAME.to_owned()
}

fn default_client_name() -> String {
    "DESKTOP-RDPTUN".to_owned()
}

fn default_trust() -> String {
    "tofu".to_owned()
}

fn default_tofu_store() -> PathBuf {
    PathBuf::from("cert-store/client-known-hosts")
}

pub fn load_config(path: &std::path::Path) -> anyhow::Result<ClientConfig> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: ClientConfig = toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?;
    rdptun_proto::validate_channel_name(&cfg.channel).context("invalid channel name in config")?;
    Ok(cfg)
}
