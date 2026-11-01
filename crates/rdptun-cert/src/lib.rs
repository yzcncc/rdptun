//! Windows 风格的 RDP 自签名证书生成与加载。
//!
//! Windows 终端服务（TermService）在启用 TLS 时，如果没有可用的机器证书，
//! 会自动签发一张自签名证书（"Self-Signed Certificate for Remote Desktop"）：
//!
//! - Subject = Issuer = `CN=<机器名>`
//! - RSA-2048，sha256WithRSAEncryption
//! - KeyUsage: DigitalSignature | KeyEncipherment（critical）
//! - EKU: 仅 ServerAuth（1.3.6.1.5.5.7.3.1）
//! - Basic Constraints: CA = false（End Entity）
//! - 无 SAN 扩展
//! - 有效期约 6 个月
//!
//! 本模块生成相同模板的证书，持久化到磁盘，重启后身份不变，
//! 并在证书临近过期时自动重新签发（模拟 Windows 的自动续期）。

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use rcgen::{ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use tracing::{info, warn};

/// Windows RDP 自签名证书的有效期：约 6 个月。
const VALIDITY_DAYS: i64 = 182;

/// 距离到期多少天以内时视为"需要续期"（Windows 会在临期时重新生成）。
const RENEW_WITHIN_DAYS: i64 = 30;

/// 存放证书身份（PEM 编码的证书链 + 私钥）。
#[derive(Debug, Clone)]
pub struct CertIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

/// 生成一张模仿 Windows TermService 自动签发的 RDP 自签名证书。
///
/// `machine_name` 是出现在 Subject `CN=` 里的"计算机名"。
pub fn generate_self_signed(machine_name: &str) -> anyhow::Result<CertIdentity> {
    let mut params = rcgen::CertificateParams::new(vec![]).context("certificate params")?;

    // Subject = Issuer = CN=<机器名>，无其它 RDN（Windows 模板如此）。
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, machine_name);
    params.distinguished_name = name;

    // KeyUsage: digitalSignature | keyEncipherment（critical）。
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    // EKU: 仅 ServerAuth。
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    // Basic Constraints: End Entity（非 CA）。
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = false;

    // 有效期：notBefore = 现在 - 1 天（容忍时钟偏移），notAfter = +6 个月。
    let (nb, na) = validity_window(VALIDITY_DAYS);
    params.not_before = nb;
    params.not_after = na;

    let key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).context("generate RSA-2048 key")?;

    let cert = params.self_signed(&key).context("self-sign certificate")?;

    Ok(CertIdentity {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// 计算 [今天-1天, 今天+validity_days] 的时间窗口。
fn validity_window(validity_days: i64) -> (time::OffsetDateTime, time::OffsetDateTime) {
    let now = time::OffsetDateTime::now_utc();
    let nb = now - time::Duration::days(1);
    let na = now + time::Duration::days(validity_days);
    (nb, na)
}

/// 解析证书的 notAfter 时间（供到期检查使用）。
fn parse_not_after(cert_pem: &str) -> Option<time::OffsetDateTime> {
    use x509_cert::der::{Decode as _, Encode as _};

    let first = rustls_pemfile::certs(&mut cert_pem.as_bytes()).next()?.ok()?;
    let cert = x509_cert::Certificate::from_der(&first).ok()?;
    let secs = cert
        .tbs_certificate
        .validity
        .not_after
        .to_date_time()
        .unix_duration()
        .as_secs() as i64;
    time::OffsetDateTime::from_unix_timestamp(secs).ok()
}

/// 加载（或首次生成）RDP TLS 身份。
///
/// - 若配置了显式的 `cert_path`/`key_path`：直接使用用户提供的证书。
/// - 否则在 `store_dir` 下维护 `rdptun-cert.pem` / `rdptun-key.pem`：
///   首次生成 Windows 风格自签名证书；临期（< RENEW_WITHIN_DAYS）自动续期。
pub fn load_or_create_identity(
    store_dir: &Path,
    configured_machine_name: Option<&str>,
    explicit_cert: Option<&Path>,
    explicit_key: Option<&Path>,
) -> anyhow::Result<CertIdentity> {
    match (explicit_cert, explicit_key) {
        (Some(cert), Some(key)) => {
            let cert_pem = std::fs::read_to_string(cert)
                .with_context(|| format!("read cert file {}", cert.display()))?;
            let key_pem = std::fs::read_to_string(key)
                .with_context(|| format!("read key file {}", key.display()))?;
            info!("Using configured TLS identity: {} / {}", cert.display(), key.display());
            Ok(CertIdentity { cert_pem, key_pem })
        }
        (None, None) => load_or_generate_auto(store_dir, configured_machine_name),
        _ => anyhow::bail!("cert_path and key_path must be configured together"),
    }
}

fn load_or_generate_auto(store_dir: &Path, configured_machine_name: Option<&str>) -> anyhow::Result<CertIdentity> {
    let cert_path: PathBuf = store_dir.join("rdptun-cert.pem");
    let key_path: PathBuf = store_dir.join("rdptun-key.pem");

    let machine_name = configured_machine_name
        .map(str::to_owned)
        .unwrap_or_else(random_desktop_name);

    if let (Ok(existing_cert), Ok(_existing_key)) = (
        std::fs::read_to_string(&cert_path),
        std::fs::read_to_string(&key_path),
    ) {
        let renew = match parse_not_after(&existing_cert) {
            Some(not_after) => {
                let remaining = (not_after - time::OffsetDateTime::now_utc()).whole_days();
                if remaining < RENEW_WITHIN_DAYS {
                    info!(
                        remaining_days = remaining,
                        "RDP self-signed certificate is expiring, regenerating"
                    );
                    true
                } else {
                    false
                }
            }
            None => {
                warn!("Existing certificate could not be parsed, regenerating");
                true
            }
        };

        if !renew {
            let key_pem = std::fs::read_to_string(&key_path)?;
            info!(
                machine_name = %machine_name,
                store = %store_dir.display(),
                "Loaded persisted RDP self-signed identity"
            );
            return Ok(CertIdentity {
                cert_pem: existing_cert,
                key_pem,
            });
        }
    }

    let identity = generate_self_signed(&machine_name)?;

    std::fs::create_dir_all(store_dir).with_context(|| format!("create store dir {}", store_dir.display()))?;
    write_private(&key_path, &identity.key_pem)?;
    std::fs::write(&cert_path, &identity.cert_pem)
        .with_context(|| format!("write {}", cert_path.display()))?;

    info!(
        machine_name = %machine_name,
        store = %store_dir.display(),
        "Generated Windows-style RDP self-signed certificate"
    );
    Ok(identity)
}

/// 私钥文件用 0600 权限写入。
fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write as _;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        f.write_all(contents.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }
    Ok(())
}

/// 生成 `DESKTOP-XXXXXXX` 风格的随机机器名（与 Windows 默认主机名同构）。
fn random_desktop_name() -> String {
    use rand::Rng as _;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..7)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    format!("DESKTOP-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::{Decode as _, Encode as _};
    use x509_cert::der::asn1::ObjectIdentifier;

    const CN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

    fn common_name(name: &x509_cert::name::Name) -> Option<String> {
        for rdn in name.0.iter() {
            for atv in rdn.0.iter() {
                if atv.oid == CN_OID {
                    let s = atv
                        .value
                        .decode_as::<x509_cert::der::asn1::Utf8StringRef>()
                        .ok()
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    return Some(s);
                }
            }
        }
        None
    }

    #[test]
    fn generated_cert_matches_windows_template() {
        let identity = generate_self_signed("DESKTOP-ABC1234").unwrap();

        let pems: Vec<_> = rustls_pemfile::certs(&mut identity.cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(pems.len(), 1, "exactly one certificate (self-signed leaf)");

        let cert = x509_cert::Certificate::from_der(&pems[0]).unwrap();

        // Subject == Issuer（自签名）
        assert_eq!(cert.tbs_certificate.issuer, cert.tbs_certificate.subject);

        // CN = 机器名
        let cn = common_name(&cert.tbs_certificate.subject).unwrap();
        assert_eq!(cn, "DESKTOP-ABC1234");

        // 签名算法 RSA-SHA256
        assert_eq!(
            cert.signature_algorithm.oid.to_string(),
            "1.2.840.113549.1.1.11",
            "sha256WithRSAEncryption"
        );

        // KeyUsage critical: digitalSignature | keyEncipherment
        let ku = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.extn_id.to_string() == "2.5.29.15")
            .expect("keyUsage extension present");
        assert!(ku.critical, "keyUsage must be critical");

        // EKU: 仅 ServerAuth (1.3.6.1.5.5.7.3.1)
        let eku = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.extn_id.to_string() == "2.5.29.37")
            .expect("extKeyUsage extension present");
        let server_auth_der = x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")
            .to_der()
            .unwrap();
        assert!(eku.extn_value.as_bytes().windows(server_auth_der.len()).any(|w| w == server_auth_der));

        // 有效期 ~6 个月
        let na = time::OffsetDateTime::from_unix_timestamp(cert.tbs_certificate.validity.not_after.to_date_time().unix_duration().as_secs() as i64).unwrap();
        let days = (na - time::OffsetDateTime::now_utc()).whole_days();
        assert!((170..=183).contains(&days), "validity ~6 months, got {days} days");
    }

    #[test]
    fn not_after_roundtrip() {
        let identity = generate_self_signed("DESKTOP-TESTING").unwrap();
        let na = parse_not_after(&identity.cert_pem).unwrap();
        let days = (na - time::OffsetDateTime::now_utc()).whole_days();
        assert!((170..=183).contains(&days));
    }
}
