# rdptun

把 TCP 隧道伪装成 **Microsoft RDP 流量**：对外呈现为一个开启了 NLA
（Network Level Authentication / CredSSP）的 Windows 远程桌面主机，
端口扫描与主动探测看到的是标准 RDP 服务；握手、登录与微软标准协议
流程完全一致之后，数据在 RDP 静态虚拟通道里透传。

> ⚠️ 仅用于实验室 / 协议研究场景。

## 架构

```
本地应用 ── TCP ── rdptun-client (:1080)
                     │  伪装 mstsc：X.224 → TLS → CredSSP/NLA → MCS → 能力交换
                     │  数据走自定义 SVC 通道 "TUNNEL"
                     ▼
               rdptun-server (:3389)   ← 看起来就是一台 Windows RDP 主机
                     │  完整握手后把 SVC 字节流桥接到固定目标
                     ▼
               target（如 127.0.0.1:22 的 sshd）
```

- **每条本地 TCP 连接 = 一次完整的 RDP 会话**（独立握手、独立 NLA 登录）。
- 服务端并发处理多会话（LocalSet 单线程 + 异步桥接）。
- 数据面：应用字节 → `u32 LE` 长度前缀帧 → SVC chunk（自动协商 ~1600B）
  → RDP/TLS；对端逆序重组。SVC 本身有序可靠，无额外协议开销。

## 伪装面

| 层 | 表现 |
|---|---|
| X.224 协商 | 仅接受 `PROTOCOL_HYBRID\|HYBRID_EX`；对 `PROTOCOL_RDP` 探测回标准 Negotiation Failure（同关闭了传统 RDP 安全的 Windows） |
| TLS | rustls TLS 1.2/1.3；证书为 Windows TermService 风格自签名（CN=机器名、RSA-2048、sha256RSA、KU critical、EKU ServerAuth、无 SAN、6 个月有效期、临期自动续签） |
| NLA | 完整 CredSSP/NTLM（NTLMv2 指纹呈现 Windows 10.0.17763），nmap `rdp-ntlm-info` 可读到 Product_Version |
| 会话期 | 标准 MCS/能力交换/licensing；Server Heartbeat PDU 仅在客户端宣告支持时按 MS-RDPBCGR 2.2.16.1 发送 |

用 `nmap -sV --script rdp-ntlm-info,rdp-enum-encryption -p 3389` 实测：

```
3389/tcp open  ms-wbt-server
| rdp-ntlm-info:
|   Product_Version: 10.0.17763
```

## 构建

```bash
cargo build --release
```

## 运行

```bash
# 服务端（公网机器）
cp etc/server.example.toml server.toml   # 编辑 target/凭证
./target/release/rdptun-server --config server.toml

# 客户端（本地）
cp etc/client.example.toml client.toml   # 编辑 server/凭证
./target/release/rdptun-client --config client.toml

# 使用：连本地端口即可透传到服务端 target
ssh -p 1080 user@127.0.0.1
curl -x '' http://127.0.0.1:1080/        # 任何 TCP 协议
```

## 配置

见 `etc/server.example.toml` / `etc/client.example.toml`。

证书：默认自动生成 Windows 风格自签名证书并持久化；也可指定
`cert_path`/`key_path`（PEM；PFX 先转换）。

信任模式（客户端）：
- `tofu`（默认）：首连记录服务端 SPKI SHA-256，之后不匹配即拒绝（模拟 mstsc 的证书记忆）
- `pin`：必须等于 `pin_spki_sha256`
- `none`：不校验

## 已知取舍

- mstsc 走 NLA 时需输入服务端配置的账号（本地账号格式 `.\user`）；不支持域认证。
- 每连接一次完整握手；SVC chunk ~1600B/PDU，吞吐对实验室场景足够。
- TLS 指纹（JA3）是 rustls 而非 schannel —— 如需对齐可后续调整 cipher suite。
- 会话期图形面：当前服务端不推送黑屏位图更新（mstsc 连上会看到空桌面）。
  流量节奏校准（帧间隔/熵值分布）待接入真实 mstsc 抓包样本后完善。

## 代码结构

```
crates/
  rdptun-cert/    Windows 风格 RDP 自签名证书：生成/持久化/续期
  rdptun-proto/   隧道 SVC 通道处理器（两端共用）+ 帧编解码
  rdptun-server/  并发 acceptor（X.224→TLS→CredSSP→finalize）+ SVC↔target 桥
  rdptun-client/  本地监听 + ClientConnector/ActiveStage 驱动 + SVC↔本地 TCP 桥
```
