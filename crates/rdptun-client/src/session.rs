//! 客户端连接：X.224 → TLS（TOFU/pin）→ CredSSP/NLA → 数据阶段 SVC 桥接。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use ironrdp_connector::{ClientConnector, Config as ConnectorConfig, Credentials as ConnectorCredentials};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_async::FramedWrite as _;
use ironrdp_tokio::TokioFramed;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::config::ClientConfig;
use rdptun_proto::{TunnelBridge, TunnelChannel};

/// 擦除具体 TLS 类型的流别名。
pub type OwnedTlsStream = Box<dyn AsyncReadWrite>;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncReadWrite for T {}

/// 已建立的 RDP 会话（finalize 完成后）。
struct RdpSession {
    framed: TokioFramed<OwnedTlsStream>,
    result: ironrdp_connector::ConnectionResult,
    bridge: TunnelBridge,
    channel_name: String,
}

/// 每条本地 TCP 连接：完整 RDP 会话 + 桥接到服务端 target。
pub async fn tunnel_one_connection(cfg: Arc<ClientConfig>, local_sock: TcpStream) -> Result<()> {
    let session = connect_rdp(&cfg).await.context("RDP session setup")?;
    // CredSSP 状态机含 !Send 生成器 —— 整个会话在 LocalSet 上跑。
    run_session(session, local_sock).await
}

/// 连接服务端并完成全部 RDP 握手（含 NLA）。
async fn connect_rdp(cfg: &Arc<ClientConfig>) -> Result<RdpSession> {
    let stream = TcpStream::connect(&cfg.server)
        .await
        .with_context(|| format!("TCP connect to {}", cfg.server))?;
    stream.set_nodelay(true).ok();
    let client_addr: SocketAddr = stream.local_addr()?;

    // 1. 构造 connector（强制 NLA）
    let connector_config = ConnectorConfig {
        desktop_size: ironrdp_connector::DesktopSize {
            width: 1280,
            height: 720,
        },
        monitor_layout: None,
        desktop_scale_factor: 0,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: None,
        monitor_extended_layout: None,
        relative_mouse_input: false,
        enable_tls: false,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        credentials: ConnectorCredentials::UsernamePassword {
            username: cfg.username.clone(),
            password: cfg.password.clone(),
        },
        domain: None,
        client_build: 3790,
        client_name: cfg.client_name.chars().take(15).collect(),
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0x0000_0409, // en-US
        ime_file_name: String::new(),
        connection_type: ironrdp_pdu::gcc::ConnectionType::Lan,
        bitmap: Some(ironrdp_connector::BitmapConfig {
            color_depth: 32,
            lossy_compression: true,
            codecs: ironrdp_pdu::rdp::capability_sets::BitmapCodecs(vec![]),
        }),
        dig_product_id: String::new(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: ironrdp_pdu::rdp::capability_sets::RailSupportLevel::empty(),
        platform: ironrdp_pdu::rdp::capability_sets::MajorPlatformType::UNSPECIFIED,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        enable_audio_capture: false,
        enable_server_pointer: true,
        pointer_software_rendering: false,
        performance_flags: ironrdp_pdu::rdp::client_info::PerformanceFlags::default(),
        compression_type: None,
        license_cache: None,
        timezone_info: ironrdp_pdu::rdp::client_info::TimezoneInfo::default(),
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: false,
    };

    let mut connector = ClientConnector::new(connector_config, client_addr);

    // 注册隧道 SVC 通道（MCS 通道协商前）
    let (tunnel_channel, bridge) = rdptun_proto::new_tunnel_channel(&cfg.channel)?;
    connector.attach_static_channel(tunnel_channel);

    // 2. X.224 协商
    let mut framed = TokioFramed::new(stream);
    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .context("X.224 negotiation")?;

    // 3. TLS 升级（自管 rustls：TOFU/pin 信任模式）
    let (initial_stream, leftover) = framed.into_inner();
    let server_name_host = server_host(&cfg.server);

    let (tls_stream, server_public_key) = tls_upgrade(initial_stream, server_name_host, cfg).await?;

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed: TokioFramed<OwnedTlsStream> =
        TokioFramed::new_with_leftover(tls_stream, leftover);

    // 4. CredSSP/NLA + 终结
    let mut network_client = ironrdp_tokio::reqwest::ReqwestNetworkClient::new();
    let outcome = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut network_client,
        server_name_host.to_owned().into(),
        server_public_key,
        None,
    )
    .await
    .context("CredSSP + finalize")?;

    let result = outcome
        .into_connected()
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;

    info!(server = %cfg.server, channel = %channel_name_of(&cfg.channel), "RDP session established (NLA ok)");

    Ok(RdpSession {
        framed,
        result,
        bridge,
        channel_name: cfg.channel.clone(),
    })
}

fn channel_name_of(name: &str) -> &str {
    name
}

/// TLS 升级并按信任模式校验证书，返回 (流, CredSSP 公钥)。
async fn tls_upgrade<S>(
    stream: S,
    server_name: &str,
    cfg: &Arc<ClientConfig>,
) -> Result<(OwnedTlsStream, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let (tls_cfg, trust) = crate::tls::make_client_tls_config(cfg)?;

    let sni = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|e| anyhow::anyhow!("bad SNI name: {e}"))?;

    let connector = tokio_rustls::TlsConnector::from(tls_cfg);
    let tls_stream = connector.connect(sni, stream).await.context("TLS handshake")?;

    let (_, session) = tls_stream.get_ref();
    let leaf = session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .cloned()
        .context("server sent no certificate")?;

    // 信任模式校验（SPKI SHA-256）
    trust.verify(cfg, &leaf)
        .context("server certificate trust check")?;

    let server_public_key = crate::tls::extract_server_public_key(&leaf)?;

    Ok((Box::new(tls_stream) as OwnedTlsStream, server_public_key))
}

/// 从 `host:port` 提取 SNI host。
fn server_host(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((host, _)) => host,
        None => addr,
    }
}

/// 数据阶段：三个并发流。
///
/// - 本地 TCP → 通道：任务 A 读 socket、包帧，投到通道出站队列；
/// - 会话主循环：从通道出站队列取帧 → 编码 SVC → 发给服务端；
///   同时读服务端 PDU → ActiveStage 处理 → SVC 入站进通道 → 任务 B 写本地 TCP。
async fn run_session(session: RdpSession, local_sock: TcpStream) -> Result<()> {
    let RdpSession {
        framed,
        result,
        bridge,
        channel_name,
    } = session;

    local_sock.set_nodelay(true).ok();
    let (mut local_read, mut local_write) = tokio::io::split(local_sock);

    let (mut reader, mut writer) = ironrdp_tokio::split_tokio_framed(framed);

    let mut active_stage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();

    // 隧道通道处理器的引用（在 static_channels 里，downcast 取出）。
    // take_outbound 需要 &self（内部 Mutex），可安全共享。
    let channel_name_obj = ironrdp_pdu::gcc::ChannelName::from_utf8(&channel_name).context("channel name")?;

    let bridge = Arc::new(bridge);

    // ---- 任务 A：本地 TCP → 通道（包帧后排队）----
    let bridge_a = Arc::clone(&bridge);
    let to_channel = tokio::task::spawn_local(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if bridge_a
                        .send_to_channel(rdptun_proto::encode_frame(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        debug!("local socket closed (read side)");
    });

    // ---- 任务 B：通道 → 本地 TCP（服务端发来的数据写入本地 socket）----
    let bridge_b = Arc::clone(&bridge);
    let from_channel = tokio::task::spawn_local(async move {
        while let Some(data) = bridge_b.recv_from_channel().await {
            if local_write.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = local_write.shutdown().await;
        debug!("local socket closed (write side)");
    });

    // ---- 会话主循环 ----
    let mut image = ironrdp_session::image::DecodedImage::new(
        ironrdp_graphics::image_processing::PixelFormat::RgbA32,
        result.desktop_size.width,
        result.desktop_size.height,
    );
    let _ = &channel_name_obj;

    let mut running = true;
    while running {
        let outputs = tokio::select! {
            frame = reader.read_pdu() => {
                match frame {
                    Ok((action, payload)) => {
                        match active_stage.process(&mut image, action, &payload, None) {
                            Ok(outputs) => outputs,
                            Err(e) => {
                                debug!(error = %format!("{e:#}"), "session process error");
                                running = false;
                                Vec::new()
                            }
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "read failed");
                        running = false;
                        Vec::new()
                    }
                }
            }

            frame = recv_tunnel_outbound(&mut active_stage, &channel_name) => {
                // 本地 TCP → 服务端方向：从隧道通道的出站队列取一帧，
                // 编码成 SVC PDU 发送。
                match frame {
                    Some(data) => {
                        let svc_msg: Vec<ironrdp_svc::SvcMessage> =
                            vec![rdptun_proto::RawTunnelPdu(data).into()];
                        match active_stage.process_svc_messages_by_name(&channel_name_obj, svc_msg) {
                            Ok(encoded) if !encoded.is_empty() => vec![ActiveStageOutput::ResponseFrame(encoded)],
                            Ok(_) => Vec::new(),
                            Err(e) => {
                                debug!(error = %format!("{e:#}"), "encode svc failed");
                                running = false;
                                Vec::new()
                            }
                        }
                    }
                    None => {
                        // 隧道通道关闭（本地 TCP 断开）→ 结束会话。
                        running = false;
                        Vec::new()
                    }
                }
            }
        };

        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => {
                    if writer.write_all(&frame).await.is_err() {
                        running = false;
                        break;
                    }
                }
                ActiveStageOutput::Terminate(reason) => {
                    debug!(?reason, "session terminated");
                    running = false;
                }
                // 图形/指针等输出全部忽略（隧道场景不渲染）。
                _ => {}
            }
        }
    }

    debug!("tunnel session ending");
    to_channel.abort();
    from_channel.abort();

    let (mut inner, _) = writer.into_inner();
    let _ = inner.shutdown().await;

    Ok(())
}

/// 从 ActiveStage 里的隧道通道处理器取出一条出站帧（本地 → 服务端方向）。
async fn recv_tunnel_outbound(stage: &mut ActiveStage, channel_name: &str) -> Option<Vec<u8>> {
    let processor = stage.get_svc_processor_mut::<TunnelChannel>()?;
    // TunnelChannel::take_outbound 是 &self（内部 Mutex），通过 &mut 拿引用即可。
    processor.take_outbound().await
}
