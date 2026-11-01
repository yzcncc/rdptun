//! 客户端 TLS 升级：TOFU / pin / 不校验 三种信任模式。

use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types;
use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

use crate::config::ClientConfig;

/// SPKI SHA-256 指纹计算。
pub fn spki_sha256(cert: &pki_types::CertificateDer<'_>) -> Result<String> {
    use x509_cert::der::Decode as _;

    let cert = x509_cert::Certificate::from_der(cert).map_err(|e| anyhow::anyhow!("parse cert: {e}"))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("subject public key BIT STRING is not aligned"))?;

    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(spki_der);
    Ok(hex::encode(hasher.finalize()))
}

/// 从证书提取 CredSSP 需要的 subjectPublicKey 原始字节。
pub fn extract_server_public_key(cert: &pki_types::CertificateDer<'_>) -> Result<Vec<u8>> {
    use x509_cert::der::Decode as _;

    let cert = x509_cert::Certificate::from_der(cert).map_err(|e| anyhow::anyhow!("parse cert: {e}"))?;
    Ok(cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("subject public key BIT STRING is not aligned"))?
        .to_owned())
}

/// TOFU 记录文件（`host:port spki_sha256` 每行一条）。
pub fn tofu_check(config: &ClientConfig, fingerprint: &str) -> Result<bool> {
    if let Ok(record) = std::fs::read_to_string(&config.tofu_store) {
        for line in record.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(host), Some(fp)) = (parts.next(), parts.next()) {
                if host == config.server {
                    return Ok(fp == fingerprint);
                }
            }
        }
    }
    Ok(true) // first visit: accept
}

pub fn tofu_record(config: &ClientConfig, fingerprint: &str) -> Result<()> {
    let mut existing = std::fs::read_to_string(&config.tofu_store).unwrap_or_default();
    // 覆盖同 host 旧记录
    existing = existing
        .lines()
        .filter(|l| !l.split_whitespace().next().is_some_and(|h| h == config.server))
        .collect::<Vec<_>>()
        .join("\n");
    if !existing.is_empty() {
        existing.push('\n');
    }
    existing.push_str(&format!("{} {fingerprint}\n", config.server));

    if let Some(parent) = config.tofu_store.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config.tofu_store, existing)?;
    Ok(())
}

/// 依据配置构建客户端 TLS 配置，并返回"信任回调"——升级后验证 SPKI 指纹。
pub fn make_client_tls_config(config: &ClientConfig) -> Result<(Arc<rustls::ClientConfig>, TrustMode)> {
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    // CredSSP 不支持 TLS 会话恢复（MS-CSSP）。
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.key_log = Arc::new(rustls::KeyLogFile::new());

    let mode = match config.trust.as_str() {
        "none" => TrustMode::None,
        "pin" => TrustMode::Pin(config.pin_spki_sha256.clone().context("pin mode requires pin_spki_sha256")?),
        "tofu" | _ => TrustMode::Tofu,
    };

    Ok((Arc::new(cfg), mode))
}

#[derive(Clone, Debug)]
pub enum TrustMode {
    /// 什么都不检查。
    None,
    /// SPKI SHA-256 必须等于给定值。
    Pin(String),
    /// 首次接受并记录；后续必须匹配。
    Tofu,
}

impl TrustMode {
    /// 升级完成后校验服务器证书。`server_cert` 是叶子证书 DER。
    pub fn verify(&self, config: &ClientConfig, leaf: &pki_types::CertificateDer<'_>) -> Result<()> {
        let fingerprint = spki_sha256(leaf)?;

        match self {
            TrustMode::None => Ok(()),
            TrustMode::Pin(expected) => {
                anyhow::ensure!(
                    &fingerprint == expected,
                    "SPKI pin mismatch: expected {expected}, got {fingerprint}"
                );
                Ok(())
            }
            TrustMode::Tofu => {
                anyhow::ensure!(
                    tofu_check(config, &fingerprint)?,
                    "SPKI fingerprint changed (possible MITM): {fingerprint}; \
                     delete {} to re-trust",
                    config.tofu_store.display()
                );
                tofu_record(config, &fingerprint)?;
                Ok(())
            }
        }
    }
}

/// 跳过一切证书校验的 verifier（信任由 TrustMode 层面的 SPKI 比对承担）。
#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &pki_types::CertificateDer<'_>,
        _intermediates: &[pki_types::CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}
