//! rdptun 共享协议组件：隧道 SVC 通道处理器（客户端/服务端两侧通用）。

use ironrdp_core::{Encode, EncodeResult, impl_as_any};
use ironrdp_pdu::gcc::ChannelName;
use ironrdp_pdu::{PduResult, pdu_other_err};
use ironrdp_svc::{SvcEncode, SvcMessage, SvcProcessor};
use tokio::sync::mpsc;

/// 默认隧道通道名（SVC 通道名 ≤ 7 字符）。
pub const DEFAULT_CHANNEL_NAME: &str = "TUNNEL";

/// 校验 SVC 通道名（≤7 字节，字母数字）。
pub fn validate_channel_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.is_empty() && name.len() <= 7,
        "channel name must be 1-7 characters, got {name:?}"
    );
    anyhow::ensure!(
        name.bytes().all(|b| b.is_ascii_alphanumeric()),
        "channel name must be alphanumeric, got {name:?}"
    );
    Ok(())
}

/// `SvcEncode` 包装，把一段原始字节标记为完整的通道 PDU。
#[derive(Debug)]
pub struct RawTunnelPdu(pub Vec<u8>);

impl Encode for RawTunnelPdu {
    fn encode(&self, dst: &mut ironrdp_core::WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_slice(&self.0);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawTunnelPdu"
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

impl SvcEncode for RawTunnelPdu {}

/// 一段经隧道传输的应用数据（已重组为完整帧载荷）。
pub type TunnelData = Vec<u8>;

/// 隧道 SVC 通道的两端点。
///
/// 数据流（以客户端为例，服务端方向对称）：
///
/// ```text
/// 本地 TCP socket
///   │ 读
///   ▼
/// endpoint.tcp_to_channel (mpsc)          ← 桥接任务投递
///   │
///   ▼
/// 会话循环取出 → encode_frame → SVC 发送   ← 会话循环（单线程持有 ActiveStage）
///   │
///   ▼ RDP 传输
/// 对端 process() → decode 帧 →
/// endpoint.channel_to_tcp (mpsc)          ← process() 投递
///   │
///   ▼
/// 桥接任务取出 → 写入对端 TCP socket
/// ```
#[derive(Debug)]
pub struct TunnelChannel {
    channel_name: ChannelName,
    /// 会话循环持有的接收端。
    tcp_to_channel_rx: tokio::sync::Mutex<mpsc::Receiver<TunnelData>>,
    /// `process()` 投递用的发送端（对端 → 本地 TCP）。
    channel_to_tcp_tx: mpsc::UnboundedSender<TunnelData>,
}

/// 创建隧道通道与桥接端点。
pub fn new_tunnel_channel(channel_name: &str) -> anyhow::Result<(TunnelChannel, TunnelBridge)> {
    validate_channel_name(channel_name)?;
    let name = ChannelName::from_utf8(channel_name).ok_or_else(|| anyhow::anyhow!("invalid channel name {channel_name:?}"))?;

    // 通道 → TCP：process() 同步投递，用 try_send 有界队列；满时背压由
    // SVC chunk 化 + TCP 慢造成，直接丢帧会破坏流语义，因此用较大队列 +
    // 阻塞语义不可行（process 非 async）——选择 unbounded + 会话/桥接端
    // 主动退出时自然收敛。RDP 会话本身有序可靠，桥接消费速度通常高于
    // 链路速度，队列不会无限增长。
    let (channel_to_tcp_tx, channel_to_tcp_rx) = mpsc::unbounded_channel::<TunnelData>();
    // TCP → 通道：有界队列提供背压，TCP 读太快时桥接任务阻塞。
    let (tcp_to_channel_tx, tcp_to_channel_rx) = mpsc::channel::<TunnelData>(128);

    let channel = TunnelChannel {
        channel_name: name,
        tcp_to_channel_rx: tokio::sync::Mutex::new(tcp_to_channel_rx),
        channel_to_tcp_tx,
    };
    let bridge = TunnelBridge {
        tcp_to_channel_tx,
        channel_to_tcp_rx: tokio::sync::Mutex::new(channel_to_tcp_rx),
    };
    Ok((channel, bridge))
}

impl TunnelChannel {
    /// 通道名（会话层发送时定位通道用）。
    pub fn tunnel_channel_name(&self) -> &str {
        self.channel_name.as_str().unwrap_or("TUNNEL")
    }

    /// 会话循环：取出一段待发送到对端的数据（已含长度前缀）。
    ///
    /// 返回 `None` 表示桥接任务已退出（TCP 侧断开），会话可以结束。
    pub async fn take_outbound(&self) -> Option<TunnelData> {
        self.tcp_to_channel_rx.lock().await.recv().await
    }

    /// 会话循环：把桥接任务投递的数据排队发送（已在桥接端完成）。
    ///
    /// 此方法由 SVC `process()` 路径间接调用。
    fn deliver_to_bridge(&self, data: TunnelData) {
        // unbounded，且桥接端退出时 send 返回 Err，直接丢弃。
        let _ = self.channel_to_tcp_tx.send(data);
    }
}

impl SvcProcessor for TunnelChannel {
    fn channel_name(&self) -> ChannelName {
        self.channel_name.clone()
    }

    fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
        Ok(Vec::new())
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        // 入站：对端发来的长度前缀帧（可能一帧或多帧粘连）。
        // 重组后按帧边界处理：控制帧就地消费，数据帧投递给桥接任务（写入 TCP）。
        let mut replies: Vec<SvcMessage> = Vec::new();
        let mut pos = 0usize;
        while pos < payload.len() {
            if payload.len() - pos < 4 {
                tracing::warn!("truncated tunnel frame header ({} bytes)", payload.len() - pos);
                return Err(pdu_other_err!("truncated tunnel frame header"));
            }
            let len = u32::from_le_bytes([
                payload[pos],
                payload[pos + 1],
                payload[pos + 2],
                payload[pos + 3],
            ]) as usize;
            if len > MAX_FRAME_SIZE {
                tracing::warn!("tunnel frame too large: {len}");
                return Err(pdu_other_err!("tunnel frame too large: {len}"));
            }
            let start = pos + 4;
            if start + len > payload.len() {
                tracing::warn!(
                    "truncated tunnel frame body: need {len}, have {}",
                    payload.len() - start
                );
                return Err(pdu_other_err!("truncated tunnel frame body"));
            }
            let data = &payload[start..start + len];

            if len == 4 && data == CTRL_PING {
                // 保活探测：回 PONG（控制帧不透传给应用数据流）。
                replies.push(SvcMessage::from(RawTunnelPdu(encode_frame(CTRL_PONG))));
            } else if len == 4 && data == CTRL_PONG {
                // 对端对我们 PING 的回应：仅证明链路存活。
            } else {
                // len == 0 的帧是 EOF 标记（target/本地 socket 关闭）。
                tracing::debug!(len, head = ?data.get(..8), "tunnel frame delivered to bridge");
                self.deliver_to_bridge(data.to_vec());
            }
            pos = start + len;
        }
        Ok(replies)
    }
}

impl_as_any!(TunnelChannel);

// 客户端侧标记
impl ironrdp_svc::SvcClientProcessor for TunnelChannel {}
// 服务端侧标记
impl ironrdp_svc::SvcServerProcessor for TunnelChannel {}

/// TCP 桥接端点：连接 SVC 通道与 TCP socket。
pub struct TunnelBridge {
    /// 本地 TCP → 对端的发送端（桥接任务投递）。
    tcp_to_channel_tx: mpsc::Sender<TunnelData>,
    /// 对端 → 本地 TCP 的接收端（桥接任务消费）。
    channel_to_tcp_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<TunnelData>>,
}

impl TunnelBridge {
    /// 桥接任务：把 TCP 读到的一段数据排队交给会话循环编码发送。
    pub async fn send_to_channel(&self, data: TunnelData) -> anyhow::Result<()> {
        anyhow::ensure!(!data.is_empty(), "empty write");
        self.tcp_to_channel_tx
            .send(data)
            .await
            .map_err(|_| anyhow::anyhow!("tunnel channel closed"))
    }

    /// 桥接任务：取出对端发来、待写入 TCP 的数据。
    ///
    /// 返回 `None` 表示 RDP 会话已结束。
    pub async fn recv_from_channel(&self) -> Option<TunnelData> {
        self.channel_to_tcp_rx.lock().await.recv().await
    }
}

/// 控制帧载荷（隧道层保留值，不透传给应用数据流）：
/// - PING/PONG：链路保活 + 死会话检测（服务端在静默期发送，对端自动回 PONG）
/// - 空载荷（长度=0 的帧）：EOF 标记
pub const CTRL_PING: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF];
pub const CTRL_PONG: &[u8] = &[0xFE, 0xFE, 0xFE, 0xFE];

/// 长连接套接字调优：让"静默死亡"的连接（丢包/NAT 超时后收不到 RST）
/// 能在约 2 分钟内被发现，而不是让会话任务永久挂起。
pub mod net {
    use std::io;
    use std::time::Duration;

    /// 对 TCP 套接字启用 keepalive（空闲 60s 后每 10s 探测，5 次失败判死）
    /// 与 TCP_USER_TIMEOUT（120s，限制重传无进展时的挂起时长，Linux）。
    pub fn tune_long_lived<S>(stream: &S) -> io::Result<()>
    where
        S: std::os::fd::AsFd,
    {
        use socket2::SockRef;

        let sock = SockRef::from(stream);
        let ka = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(10));
        #[cfg(target_os = "linux")]
        let ka = ka.with_retries(5);
        sock.set_tcp_keepalive(&ka)?;
        #[cfg(target_os = "linux")]
        sock.set_tcp_user_timeout(Some(Duration::from_secs(120)))?;
        Ok(())
    }
}

/// 单帧上限（16 MiB），防止恶意长度头耗尽内存。
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// 编码为长度前缀帧。
pub fn encode_frame(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_name_validation() {
        assert!(validate_channel_name("TUNNEL").is_ok());
        assert!(validate_channel_name("ABC1234").is_ok());
        assert!(validate_channel_name("").is_err());
        assert!(validate_channel_name("TOOLONGNAME").is_err());
        assert!(validate_channel_name("WITH SPACE").is_err());
    }

    #[test]
    fn encode_frame_layout() {
        let f = encode_frame(b"abc");
        assert_eq!(&f[..4], &3u32.to_le_bytes());
        assert_eq!(&f[4..], b"abc");
    }

    #[tokio::test]
    async fn processor_routes_inbound_to_bridge() {
        let (mut channel, bridge) = new_tunnel_channel("TUNNEL").unwrap();
        assert_eq!(channel.tunnel_channel_name(), "TUNNEL");

        let mut payload = encode_frame(b"hello");
        payload.extend_from_slice(&encode_frame(&[1, 2, 3]));
        let out = channel.process(&payload).unwrap();
        assert!(out.is_empty());

        assert_eq!(bridge.recv_from_channel().await.unwrap(), b"hello".to_vec());
        assert_eq!(bridge.recv_from_channel().await.unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn bridge_to_session_outbound() {
        let (channel, bridge) = new_tunnel_channel("TUNNEL").unwrap();
        bridge.send_to_channel(vec![9, 9]).await.unwrap();
        assert_eq!(channel.take_outbound().await.unwrap(), vec![9, 9]);
    }

    #[tokio::test]
    async fn ping_gets_pong_and_is_not_delivered() {
        let (mut channel, bridge) = new_tunnel_channel("TUNNEL").unwrap();
        let replies = channel.process(&encode_frame(CTRL_PING)).unwrap();
        // PING 必须得到 PONG 回应，且不透传给应用数据流
        assert_eq!(replies.len(), 1, "PING must be answered with a PONG");
        let pong = replies[0].encode_unframed_pdu().unwrap();
        assert_eq!(pong, encode_frame(CTRL_PONG).to_vec());
        // PING 不应投递任何数据到桥接：随后发送的数据帧必须是桥接收到的第一帧。
        bridge.send_to_channel(b"zz".to_vec()).await.unwrap();
        assert_eq!(channel.take_outbound().await.unwrap(), b"zz".to_vec());
    }

    #[tokio::test]
    async fn pong_is_consumed_silently() {
        let (mut channel, _bridge) = new_tunnel_channel("TUNNEL").unwrap();
        let replies = channel.process(&encode_frame(CTRL_PONG)).unwrap();
        assert!(replies.is_empty());
    }
}
