//! 客户端配置与 TLS 信任策略。

use std::path::PathBuf;

use anyhow::Context as _;

/// 客户端 TOML 配置。
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ClientConfig {
    /// 本地监听地址，如 `127.0.0.1:1080`。
    pub listen: String,
    /// 服务端地址（伪装成 RDP host）。
    pub server: String,
    /// NLA 登录用户名。
    pub username: String,
    /// NLA 登录密码。
    #[serde(default)]
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
    /// Dashboard 监听地址（`RDPTUN_DASHBOARD` 可覆盖）。默认 127.0.0.1:8080。
    #[serde(default = "default_dashboard")]
    pub dashboard: String,
    /// Dashboard 访问令牌（可选；设置后需 `Authorization: Bearer <token>`）。
    #[serde(default)]
    pub dashboard_token: Option<String>,
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

fn default_dashboard() -> String {
    "127.0.0.1:8080".to_owned()
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".to_owned(),
            server: "127.0.0.1:3389".to_owned(),
            username: String::new(),
            password: String::new(),
            channel: default_channel(),
            client_name: default_client_name(),
            trust: default_trust(),
            pin_spki_sha256: None,
            tofu_store: default_tofu_store(),
            dashboard: default_dashboard(),
            dashboard_token: None,
        }
    }
}

impl ClientConfig {
    /// 从环境变量覆盖（Docker 友好）。
    ///
    /// 支持：RDPTUN_LISTEN / RDPTUN_SERVER / RDPTUN_USERNAME / RDPTUN_PASSWORD /
    /// RDPTUN_CHANNEL / RDPTUN_CLIENT_NAME / RDPTUN_TRUST / RDPTUN_PIN_SPKI_SHA256 /
    /// RDPTUN_TOFU_STORE / RDPTUN_DASHBOARD / RDPTUN_DASHBOARD_TOKEN
    pub fn apply_env(&mut self) {
        fn set(var: &str, dst: &mut String) {
            if let Ok(v) = std::env::var(var) {
                if !v.is_empty() {
                    *dst = v;
                }
            }
        }
        set("RDPTUN_LISTEN", &mut self.listen);
        set("RDPTUN_SERVER", &mut self.server);
        set("RDPTUN_USERNAME", &mut self.username);
        set("RDPTUN_PASSWORD", &mut self.password);
        set("RDPTUN_CHANNEL", &mut self.channel);
        set("RDPTUN_CLIENT_NAME", &mut self.client_name);
        set("RDPTUN_TRUST", &mut self.trust);
        set("RDPTUN_DASHBOARD", &mut self.dashboard);
        if let Ok(v) = std::env::var("RDPTUN_TOFU_STORE") {
            if !v.is_empty() {
                self.tofu_store = PathBuf::from(v);
            }
        }
        if let Ok(v) = std::env::var("RDPTUN_PIN_SPKI_SHA256") {
            if !v.is_empty() {
                self.pin_spki_sha256 = Some(v);
            }
        }
        if let Ok(v) = std::env::var("RDPTUN_DASHBOARD_TOKEN") {
            if !v.is_empty() {
                self.dashboard_token = Some(v);
            }
        }
    }

    /// 校验配置合法性。
    pub fn validate(&self) -> anyhow::Result<()> {
        rdptun_proto::validate_channel_name(&self.channel).context("invalid channel name")?;
        anyhow::ensure!(!self.listen.is_empty(), "listen must not be empty");
        anyhow::ensure!(!self.server.is_empty(), "server must not be empty");
        anyhow::ensure!(
            ["tofu", "pin", "none"].contains(&self.trust.as_str()),
            "trust must be one of: tofu, pin, none"
        );
        if self.trust == "pin" {
            anyhow::ensure!(
                self.pin_spki_sha256.as_deref().is_some_and(|s| !s.is_empty()),
                "trust=pin requires pin_spki_sha256"
            );
        }
        Ok(())
    }
}

/// 加载配置：文件不存在时用默认值；随后应用环境变量覆盖。
pub fn load_config(path: &std::path::Path) -> anyhow::Result<ClientConfig> {
    let mut cfg = match std::fs::read_to_string(path) {
        Ok(raw) => toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(path = %path.display(), "config not found, using defaults + env");
            ClientConfig::default()
        }
        Err(e) => return Err(e).with_context(|| format!("read config {}", path.display())),
    };
    cfg.apply_env();
    cfg.validate()?;
    Ok(cfg)
}

/// 原子写回配置文件（0600，含密码）。
pub fn save_config(path: &std::path::Path, cfg: &ClientConfig) -> anyhow::Result<()> {
    let raw = toml::to_string_pretty(cfg).context("serialize config")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let tmp = path.with_extension("toml.tmp");
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(raw.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(&tmp, &raw)?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}
