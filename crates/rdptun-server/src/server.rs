//! 并发 RDP 服务端：每连接独立 tokio task，X.224 → TLS → CredSSP/NLA → MCS → 数据阶段。
//!
//! 以 ironrdp-server 的连接流程为模板，但 accept 循环自持（支持并发会话），
//! 并在数据阶段把自定义 SVC 通道桥接到固定 TCP 目标。

use std::sync::Arc;

use anyhow::{Context as _, Result};
use ironrdp_acceptor::{Acceptor, AcceptorResult, BeginResult, DesktopSize};
use ironrdp_async::Framed;
use ironrdp_core::{decode, encode_vec, impl_as_any};
use ironrdp_pdu::input::fast_path::FastPathInput;
use ironrdp_pdu::mcs;
use ironrdp_pdu::rdp::capability_sets::{CapabilitySet, GeneralExtraFlags};
use ironrdp_pdu::rdp::headers::{ShareControlPdu, ShareDataPdu};
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::{Action, PduResult, mcs as mcs_pdu, nego, rdp};
use ironrdp_svc::server_encode_svc_messages;
use ironrdp_tokio::{FramedRead, FramedWrite, TokioFramed, split_tokio_framed};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::ServerConfig;
use rdptun_proto::{TunnelBridge, TunnelChannel};

/// 服务器能力集（对齐 ironrdp-server 的最小集合）。
fn server_capabilities(size: DesktopSize) -> Vec<CapabilitySet> {
    use ironrdp_pdu::rdp::capability_sets as caps;

    vec![
        CapabilitySet::General(caps::General {
            extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED,
            refresh_rect_support: true,
            suppress_output_support: true,
            ..Default::default()
        }),
        CapabilitySet::Bitmap(caps::Bitmap {
            pref_bits_per_pix: 32,
            desktop_width: size.width,
            desktop_height: size.height,
            desktop_resize_flag: true,
            drawing_flags: caps::BitmapDrawingFlags::empty(),
        }),
        CapabilitySet::Order(caps::Order::new(
            caps::OrderFlags::empty(),
            caps::OrderSupportExFlags::empty(),
            2048,
            224,
        )),
        CapabilitySet::SurfaceCommands(caps::SurfaceCommands { flags: caps::CmdFlags::all() }),
        CapabilitySet::Pointer(caps::Pointer {
            color_pointer_cache_size: 2048,
            pointer_cache_size: 2048,
        }),
        CapabilitySet::Input(caps::Input {
            input_flags: caps::InputFlags::SCANCODES
                | caps::InputFlags::MOUSE_RELATIVE
                | caps::InputFlags::MOUSEX
                | caps::InputFlags::FASTPATH_INPUT
                | caps::InputFlags::UNICODE
                | caps::InputFlags::FASTPATH_INPUT_2,
            keyboard_layout: 0,
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 128,
            keyboard_ime_filename: "".into(),
        }),
        CapabilitySet::VirtualChannel(caps::VirtualChannel {
            flags: caps::VirtualChannelFlags::NO_COMPRESSION,
            chunk_size: None,
        }),
        CapabilitySet::MultiFragmentUpdate(caps::MultifragmentUpdate { max_request_size: 8 * 1024 * 1024 }),
        // 空 codec 集：不提供图形编码器能力之外的伪装面。
        CapabilitySet::BitmapCodecs(rdp::capability_sets::BitmapCodecs(vec![])),
    ]
}

/// 单个已认证连接的完整生命周期。
pub async fn run_connection<S>(
    stream: S,
    cfg: Arc<ServerConfig>,
    tls: Arc<tokio_rustls::TlsAcceptor>,
    pub_key: Vec<u8>,
    sessions: Arc<Semaphore>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let _permit = sessions.acquire_owned().await.context("session semaphore closed")?;

    let framed = TokioFramed::new(stream);
    let size = DesktopSize {
        width: cfg.desktop_size.0,
        height: cfg.desktop_size.1,
    };

    let mut acceptor = Acceptor::new(
        // 抓包校准（mstsc offer 0x0b → WinServer confirm 0x08 = PROTOCOL_HYBRID_EX）：
        // Windows 优先 HYBRID_EX，与 ironrdp acceptor 默认一致。
        nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX,
        size,
        server_capabilities(size),
        Some(rdp::client_info::Credentials {
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            domain: None,
        }),
    );

    // 注册隧道 SVC 通道（在握手前 —— MCS Connect Initial 里协商）。
    let (tunnel_channel, bridge) = rdptun_proto::new_tunnel_channel(&cfg.channel)?;
    acceptor.attach_static_channel(tunnel_channel);

    // 1. X.224 协商
    let res = ironrdp_acceptor::accept_begin(framed, &mut acceptor)
        .await
        .context("accept_begin failed")?;

    // 2. TLS 升级
    let upgraded_stream = match res {
        BeginResult::ShouldUpgrade(stream) => {
            let tls_stream = tls
                .accept(stream)
                .await
                .context("TLS handshake failed")?;
            TokioFramed::new(tls_stream)
        }
        BeginResult::Continue(_) => {
            anyhow::bail!("client selected standard RDP security; HYBRID-only server rejects");
        }
    };

    acceptor.mark_security_upgrade_as_done();

    // 3. CredSSP / NLA
    let mut framed = upgraded_stream;
    ironrdp_acceptor::accept_credssp(
        &mut framed,
        &mut acceptor,
        &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
        "rdptun-client".to_owned().into(),
        pub_key,
        None,
    )
    .await
    .context("CredSSP failed")?;

    // 4. 终结握手（能力交换 / Client Info / licensing / 通道连接）
    let (framed, result) = ironrdp_acceptor::accept_finalize(framed, &mut acceptor)
        .await
        .context("accept_finalize failed")?;

    info!(
        user_channel = result.user_channel_id,
        io_channel = result.io_channel_id,
        "RDP session established (NLA ok), bridging to {}",
        cfg.target
    );

    // 5. 数据阶段：SVC 桥接 + 维持会话
    session_loop(framed, result, cfg, bridge).await
}

/// 从隧道通道处理器取出一条待发送数据（target → 客户端方向）。
///
/// 通过 downcast 到 `TunnelChannel` 调用其 `take_outbound()`。
async fn recv_tunnel_outbound(
    static_channels: &ironrdp_svc::StaticChannelSet,
    tunnel_channel_id: u16,
) -> Option<Vec<u8>> {
    let svc = static_channels.get_by_channel_id(tunnel_channel_id)?;
    let processor = svc.channel_processor_downcast_ref::<TunnelChannel>()?;
    processor.take_outbound().await
}

/// RDP 会话数据阶段。
///
/// 三个并发流：
/// - 读：客户端 → SVC `process()`（ironrdp 内部）→ 桥接队列 → 写 target
/// - 写：target → 桥接队列 → 会话循环编码 → 客户端
/// - 黑屏桌面更新（伪装图形流量）+ 心跳
async fn session_loop<S>(
    framed: TokioFramed<S>,
    result: AcceptorResult,
    cfg: Arc<ServerConfig>,
    bridge: TunnelBridge,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (mut reader, mut writer) = split_tokio_framed(framed);

    // 连接目标服务
    let target = tokio::net::TcpStream::connect(&cfg.target)
        .await
        .with_context(|| format!("connect to target {}", cfg.target))?;
    target.set_nodelay(true).ok();
    rdptun_proto::net::tune_long_lived(&target).ok();
    let (mut target_read, mut target_write) = tokio::io::split(target);

    let user_channel_id = result.user_channel_id;
    let io_channel_id = result.io_channel_id;
    // Server Heartbeat PDU 仅在客户端宣告支持（RNS_UD_CS_SUPPORT_HEARTBEAT_PDU）
    // 且协商了 message channel 时发送（与 Windows 行为一致），走 message channel。
    let heartbeat_channel = if result
        .client_early_capability_flags
        .contains(ironrdp_pdu::gcc::ClientEarlyCapabilityFlags::SUPPORT_HEART_BEAT_PDU)
    {
        result.message_channel_id
    } else {
        None
    };

    // 找到隧道通道的 MCS channel id（在 move static_channels 之前）
    let tunnel_channel_id = result
        .static_channels
        .get_channel_id_by_channel_name(&ironrdp_pdu::gcc::ChannelName::from_utf8(&cfg.channel).unwrap())
        .context("tunnel channel not joined by client")?;

    let mut static_channels = result.static_channels;

    debug!(tunnel_channel_id, "tunnel channel ready");

    // 注意：AcceptorResult.static_channels 的处理器已在 acceptor 内部被消费
    // （通道连接序列已经 process 过 start()）。数据阶段的入站 SVC 处理在
    // acceptor 之外进行：我们自己持有 process 的入口。
    // 这里 static_channels 集合包含所有协商通道，但处理入站时我们只关心隧道通道。

    let bridge = Arc::new(bridge);

    // ---- 任务 A：通道 → target（对端发来的数据写入目标 socket）----
    let bridge_a = Arc::clone(&bridge);
    let to_target = tokio::spawn(async move {
        while let Some(data) = bridge_a.recv_from_channel().await {
            if target_write.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = target_write.shutdown().await;
    });

    // ---- 任务 B：target → 通道（目标返回的数据排入会话写队列）----
    let bridge_b = Arc::clone(&bridge);
    let from_target = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // 包长度前缀帧后再入队 —— 对端 process() 按帧边界重组。
                    if bridge_b
                        .send_to_channel(rdptun_proto::encode_frame(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        // target 关闭 → 通知客户端（长度为 0 的帧 = EOF 标记）。
        // 注意：不能发空 SVC PDU（0 字节载荷会被通道分片层丢弃），
        // 所以发送 encode_frame(&[]) —— 4 字节头、载荷为空。
        let _ = bridge_b.send_to_channel(rdptun_proto::encode_frame(&[])).await;
    });

    // ---- 会话主循环 ----
    // 读客户端 PDU；写两类数据：target 转发帧 + 黑屏/心跳伪装帧。
    let mut write_buf = ironrdp_core::WriteBuf::new();
    let mut heartbeat = if heartbeat_channel.is_some() {
        let mut hb = tokio::time::interval(std::time::Duration::from_secs(20));
        hb.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Some(hb)
    } else {
        None
    };

    let mut running = true;
    while running {
        tokio::select! {
            read_res = reader.read_pdu() => {
                match read_res {
                    Ok((action, bytes)) => {
                        match handle_client_pdu(action, &bytes, io_channel_id, user_channel_id, tunnel_channel_id, &mut static_channels, &mut writer).await {
                            Ok(true) => {}            // continue
                            Ok(false) => running = false, // graceful disconnect
                            Err(e) => {
                                debug!(error = %format!("{e:#}"), "client pdu handling error");
                                running = false;
                            }
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "client read failed");
                        running = false;
                    }
                }
            }

            // target → 客户端：桥接任务已把裸数据包成帧放入通道队列，
            // 从隧道通道的处理器出站路径取出并编码发送。
            //
            // 注意：这里不能从 bridge 队列直接取 —— 会话循环与 SVC 处理器的
            // 数据流是单向的。target→通道方向：桥接任务调用
            // TunnelBridge::send_to_channel(data)（裸数据），但真正编码成 SVC
            // 的工作需要访问 static_channels —— 在 select 的这个分支做。
            //
            // 实际方案：bridge.send_to_channel 投递到 TunnelChannel 的
            // tcp_to_channel 队列；我们在这里取出、包帧、编码、发送。
            out = recv_tunnel_outbound(&static_channels, tunnel_channel_id) => {
                match out {
                    Some(frame_bytes) => {
                        let svc_msg: Vec<ironrdp_svc::SvcMessage> =
                            vec![rdptun_proto::RawTunnelPdu(frame_bytes).into()];
                        let encoded = server_encode_svc_messages(svc_msg, tunnel_channel_id, user_channel_id)?;
                        writer.write_all(&encoded).await?;
                    }
                    None => running = false,
                }
            }

            _ = async {
                match heartbeat.as_mut() {
                    Some(hb) => hb.tick().await,
                    None => core::future::pending().await,
                }
            } => {
                // Server Heartbeat PDU（MS-RDPBCGR 2.2.16.1），走 message channel。
                if let Some(hb_channel) = heartbeat_channel {
                    let pdu = rdp::heartbeat::HeartbeatPdu {
                        security_header: rdp::headers::BasicSecurityHeader {
                            flags: rdp::headers::BasicSecurityHeaderFlags::HEARTBEAT,
                        },
                        period: 20,
                        count1: 3,
                        count2: 6,
                    };
                    if let Ok(data) = encode_heartbeat(&pdu, user_channel_id, hb_channel) {
                        if writer.write_all(&data).await.is_err() {
                            running = false;
                        }
                    }
                }
            }
        }
    }

    debug!("session ending");
    to_target.abort();
    from_target.abort();
    let (mut inner, _) = writer.into_inner();
    let _ = inner.shutdown().await;

    Ok(())
}

/// 处理一个客户端 PDU。返回 `false` 表示客户端请求断开。
async fn handle_client_pdu<W>(
    action: Action,
    bytes: &[u8],
    io_channel_id: u16,
    user_channel_id: u16,
    tunnel_channel_id: u16,
    static_channels: &mut ironrdp_svc::StaticChannelSet,
    writer: &mut W,
) -> Result<bool>
where
    W: FramedWrite + Unpin,
{
    let _ = user_channel_id;
    match action {
        Action::FastPath => {
            // 输入事件：忽略（伪装桌面不接受输入），但解析以保持行为真实。
            let _input: FastPathInput = decode(bytes)?;
            Ok(true)
        }
        Action::X224 => {
            let message = decode::<X224<mcs::McsMessage<'_>>>(bytes)?;
            match message.0 {
                mcs::McsMessage::SendDataRequest(data) => {
                    if data.channel_id == io_channel_id {
                        handle_io_channel(data).await
                    } else if let Some(svc) = static_channels.get_by_channel_id_mut(data.channel_id) {
                        // SVC 入站（隧道通道等）：交由通道处理器 —— TunnelChannel
                        // 的 process() 会把载荷投递给桥接任务写入 target。
                        let response_pdus = svc.process(&data.user_data).context("svc process")?;
                        let encoded = server_encode_svc_messages(response_pdus, data.channel_id, user_channel_id)?;
                        writer.write_all(&encoded).await?;
                        Ok(true)
                    } else {
                        debug!(channel_id = data.channel_id, "data on unknown channel");
                        Ok(true)
                    }
                }
                mcs::McsMessage::DisconnectProviderUltimatum(disconnect) => {
                    debug!(?disconnect.reason, "client disconnect");
                    Ok(false)
                }
                _ => Ok(true),
            }
        }
    }
}

/// I/O 通道上的 Share Control/Share Data PDU。
async fn handle_io_channel(data: mcs::SendDataRequest<'_>) -> Result<bool> {
    let control: rdp::headers::ShareControlHeader = decode(data.user_data.as_ref())?;
    match control.share_control_pdu {
        ShareControlPdu::Data(header) => match header.share_data_pdu {
            ShareDataPdu::ShutdownRequest => {
                debug!("client shutdown request");
                Ok(true) // send shutdown response then disconnect
            }
            ShareDataPdu::ShutdownDenied => Ok(false),
            _ => Ok(true),
        },
        _ => Ok(true),
    }
}

/// 编码 Server Heartbeat PDU 到 MCS SendDataIndication。
fn encode_heartbeat(
    pdu: &rdp::heartbeat::HeartbeatPdu,
    user_channel_id: u16,
    io_channel_id: u16,
) -> Result<Vec<u8>> {
    let user_data = encode_vec(pdu)?;
    let indication = mcs_pdu::SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: io_channel_id,
        user_data: user_data.into(),
    };
    Ok(encode_vec(&X224(indication))?)
}
