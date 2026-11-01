//! rdptun-server 配置与 TLS identity 加载。

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;

/// 服务端 TOML 配置。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServerConfig {
    /// RDP 监听地址，如 `0.0.0.0:3389`。
    #[serde(default = "default_bind")]
    pub bind: String,
    /// 隧道目标（SVC 字节流转发到这个 host:port）。
    pub target: String,
    /// NLA/CredSSP 登录用户名。
    pub username: String,
    /// NLA/CredSSP 登录密码。
    pub password: String,
    /// 隧道 SVC 通道名（≤7 字符）。默认 `TUNNEL`。
    #[serde(default = "default_channel")]
    pub channel: String,
    /// 显式证书路径（PEM）。缺省时自动生成 Windows 风格自签名证书。
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    /// 显式私钥路径（PEM）。
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    /// 自动生成证书的存储目录。
    #[serde(default = "default_cert_store")]
    pub cert_store_dir: PathBuf,
    /// 自签名证书里的机器名（CN）。缺省随机生成 `DESKTOP-XXXXXXX`。
    #[serde(default)]
    pub machine_name: Option<String>,
    /// 并发会话上限。
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// 会话空闲超时（秒）。0 = 不超时。
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// 虚拟桌面大小（伪装黑屏桌面）。
    #[serde(default = "default_desktop")]
    pub desktop_size: (u16, u16),
}

fn default_bind() -> String {
    "0.0.0.0:3389".to_owned()
}

fn default_channel() -> String {
    rdptun_proto::DEFAULT_CHANNEL_NAME.to_owned()
}

fn default_cert_store() -> PathBuf {
    PathBuf::from("cert-store")
}

fn default_max_sessions() -> usize {
    64
}

fn default_idle_timeout() -> u64 {
    0
}

fn default_desktop() -> (u16, u16) {
    (1280, 720)
}

/// 服务端 TLS 上下文：证书链 + 私钥 + CredSSP 用的公钥 BIT STRING。
pub struct TlsIdentityCtx {
    pub certs: Vec<CertificateDer<'static>>,
    pub priv_key: PrivateKeyDer<'static>,
    /// 证书的 subjectPublicKeyInfo.subjectPublicKey 原始字节（CredSSP pubKeyAuth 用）。
    pub pub_key: Vec<u8>,
}

impl TlsIdentityCtx {
    pub fn from_identity(identity: &rdptun_cert::CertIdentity) -> anyhow::Result<Self> {
        use rustls::pki_types::pem::PemObject as _;

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut identity.cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .context("parse certificate PEM")?;

        let priv_key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes()).context("parse private key PEM")?;

        let pub_key = {
            use x509_cert::der::Decode as _;

            let cert = certs.first().context("empty certificate chain")?;
            let cert = x509_cert::Certificate::from_der(cert).map_err(|e| anyhow::anyhow!("parse cert DER: {e}"))?;
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| anyhow::anyhow!("subject public key BIT STRING is not aligned"))?
                .to_owned()
        };

        Ok(Self {
            certs,
            priv_key,
            pub_key,
        })
    }

    /// 构建 rustls 服务端 acceptor（无客户端认证；TLS 1.2/1.3）。
    pub fn make_acceptor(&self) -> anyhow::Result<TlsAcceptor> {
        // 抓包校准（mstsc → WinServer 2019）：
        // - Windows RDP 协商 TLS 1.2（client offer 21 套件，server 选 0xc028 CBC；
        //   rustls 无 CBC suite，取 offer 里也存在的 0xc030 ECDHE-RSA-AES256-GCM，
        //   避免 TLS 1.3 指纹暴露非 Windows 栈）。
        // - 证书链单张 RSA-2048（与本生成器一致）。
        use tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite::{
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        };
        use tokio_rustls::rustls::version::TLS12;

        let provider = tokio_rustls::rustls::crypto::CryptoProvider {
            cipher_suites: vec![
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            ..tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        };

        let mut server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
            .with_protocol_versions(&[&TLS12])
            .expect("TLS12 provider")
            .with_no_client_auth()
            .with_single_cert(self.certs.clone(), self.priv_key.clone_key())
            .context("bad certificate/key")?;

        // 支持 SSLKEYLOGFILE（抓包调试用）。
        server_config.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());

        Ok(TlsAcceptor::from(std::sync::Arc::new(server_config)))
    }
}

/// 加载配置文件。
pub fn load_config(path: &Path) -> anyhow::Result<ServerConfig> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: ServerConfig = toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?;
    rdptun_proto::validate_channel_name(&cfg.channel).context("invalid channel name in config")?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses() {
        let raw = r#"
target = "127.0.0.1:22"
username = "operator"
password = "hunter2"
"#;
        let cfg: ServerConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.bind, "0.0.0.0:3389");
        assert_eq!(cfg.channel, "TUNNEL");
        assert_eq!(cfg.target, "127.0.0.1:22");
    }
}
