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
| X.224 协商 | 客户端 offer `SSL\|HYBRID\|HYBRID_EX` 时返回 `PROTOCOL_HYBRID_EX`（0x08），与实测 WinServer 2019 逐字节一致；对 `PROTOCOL_RDP` 探测回标准 Negotiation Failure |
| TLS | **锁定 TLS 1.2**，优先 ECDHE-RSA-AES256-GCM（对齐 Windows RDP 栈，避免 TLS 1.3 指纹暴露）；证书为 Windows TermService 风格自签名（CN=机器名、RSA-2048、sha256RSA、KU critical、EKU ServerAuth、无 SAN、6 个月有效期、临期自动续签） |
| NLA | 完整 CredSSP/NTLM（NTLMv2 指纹呈现 Windows 10.0.17763），nmap `rdp-ntlm-info` 可读到 Product_Version |
| 会话期 | 标准 MCS/能力交换/licensing；Server Heartbeat PDU 仅在客户端宣告支持时按 MS-RDPBCGR 2.2.16.1 发送（实测 Windows 空闲时也不发周期心跳） |

### 与真实 mstsc↔WinServer 抓包校准结论

用 `tcpdump` 抓取真实 mstsc 连接 Windows Server 2019（含 15 秒高分辨率视频）的
66 秒样本后，逐项比对了服务端行为：

| 项目 | 真实 Windows | rdptun |
|---|---|---|
| X.224 selected protocol | `0x08` (HYBRID_EX) | `0x08` ✓ |
| TLS 版本 | TLS 1.2 | TLS 1.2 ✓ |
| Cipher | ECDHE-RSA-AES256-CBC-SHA (0xc028) | ECDHE-RSA-AES256-GCM (rustls 无 CBC) |
| 证书 | 单张 RSA-2048，742 B DER | 单张 RSA-2048，792 B DER |
| 空闲期心跳 | 无周期心跳 | 同（客户端未宣告则不发送） |
| 会话期包型 | 1460/1701/241 B 为主（图形流） | 隧道数据，无图形流 |

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

## 一键安装

### 服务端（交互式向导）

```sh
curl -fsSL https://raw.githubusercontent.com/yzcncc/rdptun/main/install-server.sh | sh
```

向导会询问监听地址、转发目标、NLA 账号密码、证书方式，然后安装二进制、
写入 `/etc/rdptun/server.toml`（0600）、注册并启动 systemd 服务。

非交互（脚本/CI）：

```sh
RDPTUN_BIND=0.0.0.0:3389 RDPTUN_TARGET=127.0.0.1:22 \
RDPTUN_USER=operator RDPTUN_PASS='secret' \
sh install-server.sh --yes
```

### 客户端（Docker + Dashboard）

```sh
docker run -d --name rdptun-client --restart unless-stopped \
  -p 127.0.0.1:1080:1080 -p 127.0.0.1:8080:8080 \
  -e RDPTUN_SERVER=your.server:3389 \
  -e RDPTUN_USERNAME=operator -e RDPTUN_PASSWORD='secret' \
  -v rdptun-data:/data \
  ghcr.io/yzcncc/rdptun-client:latest  # 或 :0.2.1 / :0.2
```

或 `docker compose up -d`（见 `docker-compose.yml`）。

打开 <http://127.0.0.1:8080> 可：

- 查看活动会话数、累计上下行字节、健康检查失败次数
- 在线修改上游地址/账号/通道并即时生效（无需重启）
- 一键测试上游连通性

健康检查端点：`/healthz`（探测上游 RDP 可达性，供 `HEALTHCHECK` 用）、`/livez`。

## 手动运行

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
- 会话期图形面：当前服务端不推送黑屏位图更新（mstsc 连上会看到空桌面），
  因此会话期服务端方向只有隧道数据，缺少真实 RDP 的图形更新包型（1460/1701B 为主）。
  这是与真实流量最大的剩余差异；要做需实现 bitmap update 编码与帧节奏仿真。
- rustls 不支持 CBC cipher（0xc028），TLS 指纹层面存在这一处可识别差异。
- musl 全静态构建在 `aws-lc-sys` 下运行时段错误，故只发布 glibc 动态版。

## 仓库与发布

- 仓库：<https://github.com/yzcncc/rdptun>（公开）
- Release 产物：`rdptun-vX.Y.Z-linux-{x86_64,aarch64}.tar.gz`
- 容器镜像：`ghcr.io/yzcncc/rdptun-client`（tag：`latest` / `X.Y.Z` / `X.Y`，多架构 amd64+arm64）

CI（GitHub Actions）：
- `ci.yml` — push/PR 跑测试 + 双架构 release 构建
- `release.yml` — 推 `v*` tag 自动构建并上传 Release 资产
- `docker.yml` — 构建多架构镜像并推 GHCR

## 代码结构

```
crates/
  rdptun-cert/    Windows 风格 RDP 自签名证书：生成/持久化/续期
  rdptun-proto/   隧道 SVC 通道处理器（两端共用）+ 帧编解码
  rdptun-server/  并发 acceptor（X.224→TLS→CredSSP→finalize）+ SVC↔target 桥
  rdptun-client/  本地监听 + ClientConnector/ActiveStage 驱动 + SVC↔本地 TCP 桥
```
