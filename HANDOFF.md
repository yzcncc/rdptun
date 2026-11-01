# 交接文档（HANDOFF）

> 本文件面向接手维护的工程师，说明当前状态、全部能力、验证记录与后续工作。

## 1. 项目概况

**rdptun** 是一个把 TCP 隧道伪装成 **Microsoft RDP 流量** 的工具。对外呈现为
一台开启了 NLA（CredSSP）的 Windows 远程桌面主机；完成与微软标准一致的
X.224 → TLS → NLA → MCS → 能力交换 之后，数据在自定义静态虚拟通道（SVC）里透传。

- 仓库：<https://github.com/yzcncc/rdptun>（公开）
- 当前版本：**v0.2.1**
- 技术栈：Rust（IronRDP 生态）+ tokio；客户端内置极简 Web Dashboard；容器化部署
- 许可：MIT OR Apache-2.0

> ⚠️ 定位：实验室 / 协议研究用途。

## 2. 架构

```
本地应用 ── TCP ── rdptun-client (:1080)
                     │  伪装 mstsc：X.224 → TLS1.2 → CredSSP/NLA → MCS → 能力交换
                     │  数据走自定义 SVC 通道 "TUNNEL"
                     ▼
               rdptun-server (:3389)   ← 看起来就是一台 Windows RDP 主机
                     │  完整握手后把 SVC 字节流桥接到固定 target
                     ▼
               target（如 127.0.0.1:22 的 sshd）
```

- **一连接一会话**：每条本地 TCP 连接发起一次完整 RDP 会话（独立 NLA 登录）。
- **数据面**：应用字节 → `u32 LE` 长度前缀帧 → SVC chunk（协商 ~1600 B）→ RDP/TLS；
  对端按帧边界重组。SVC 本身有序可靠。
- **并发模型**：IronRDP 的 CredSSP 状态机含 `!Send` 生成器，因此服务端与客户端
  的连接任务都跑在**单线程 `LocalSet`** 上（异步 IO 仍然并发）。

## 3. 代码结构

```
Cargo.toml                  # workspace
crates/
  rdptun-cert/              # Windows TermService 风格自签名证书：生成/持久化/自动续期
    src/lib.rs
  rdptun-proto/             # 隧道 SVC 通道处理器（客户端/服务端共用）+ 长度前缀帧
    src/lib.rs
  rdptun-server/            # 并发 acceptor + SVC↔target 桥
    src/config.rs           #   TOML 配置 + TLS identity 加载
    src/server.rs           #   X.224→TLS→CredSSP→finalize→session_loop
    src/main.rs             #   accept 循环（LocalSet + spawn_local）
  rdptun-client/            # 本地监听 + Dashboard + SVC↔本地 TCP 桥
    src/config.rs           #   配置（TOML + 环境变量覆盖 + 原子写回）
    src/session.rs          #   ClientConnector/ActiveStage 驱动 + 双向桥接
    src/dashboard.rs        #   内置 HTTP 服务 + 内嵌 HTML UI + 健康检查
    src/tls.rs              #   TOFU/pin/none 三种证书信任模式
    src/main.rs             #   监听循环（支持热重绑）+ 启动 dashboard
    etc/                    # 示例配置
install.sh                  # 客户端/服务端通用安装（下载 release）
install-server.sh           # 服务端交互式向导 + systemd
Dockerfile                  # 多阶段构建（amd64/arm64）
docker-compose.yml
.github/workflows/          # ci.yml / release.yml / docker.yml
```

## 4. 已实现能力

### 4.1 服务端

- 并发接受多个 RDP 会话（`max_sessions` 信号量限制）。
- 仅接受 `HYBRID|HYBRID_EX`，拒绝传统 RDP 安全（回标准 Negotiation Failure）。
- 完整 CredSSP/NTLM NLA，凭证在配置中固定（`username`/`password`）。
- 每连接 SVC 字节流桥接到配置的固定 `target`（host:port）。
- 证书：默认自动生成 Windows 风格自签名（持久化 + 临期续签）；也可指定 PEM。
- stdio 日志 + systemd `journalctl`。

### 4.2 客户端

- 本地 TCP 监听，每条连接建立独立伪装 RDP 会话。
- 证书信任：`tofu`（首连记录 SPKI-SHA256）/ `pin`（固定指纹）/ `none`。
- **内置 Web Dashboard**（默认 `127.0.0.1:8080`，内嵌 HTML，无外部依赖）：
  - `GET /` 管理界面
  - `GET /api/status` 运行状态（会话数、上下行字节、健康失败数、脱敏配置）
  - `POST /api/config` 在线修改上游/账号/通道/监听地址，**即时生效并持久化**（listen 变更会自动重绑）
  - `POST /api/healthcheck` 主动测试上游连通性
  - `GET /healthz` 就绪探针（探测上游 RDP 端口，失败 503）— 供 Docker HEALTHCHECK
  - `GET /livez` 存活探针
  - 可选 `dashboard_token`（Bearer 鉴权；UI 会提示输入并记住）
- 配置来源优先级：TOML 文件 → 环境变量（`RDPTUN_*`）→ Dashboard 修改（写回 TOML）。

### 4.3 交付形态

| 形态 | 说明 |
|---|---|
| Release 二进制 | `rdptun-v0.2.1-linux-{x86_64,aarch64}.tar.gz`，单文件 17 MB，仅依赖 glibc |
| 服务端一键安装 | `install-server.sh` 交互向导 → 写 `/etc/rdptun/server.toml`(0600) → systemd |
| 客户端容器 | `ghcr.io/yzcncc/rdptun-client:latest`（amd64+arm64，含 HEALTHCHECK） |
| 客户端一键安装 | `install.sh`（探测架构、下载 release、可选 `--only server/client`） |

## 5. 验证记录（均已实际执行通过）

功能验证（本机 127.0.0.1 环境，target = 本地 sshd:2222）：

- ✅ SSH 密码登录 + 命令执行（`echo OK`）经伪装 RDP 隧道
- ✅ 10 MB 文件经隧道传输，md5 一致
- ✅ 90 秒持续会话（跨心跳周期）稳定
- ✅ 并发 3 条独立 RDP 会话（每条独立握手）
- ✅ Dashboard 全部 API + UI 页面
- ✅ 配置热更新（改上游 → 立即生效；改 listen → 自动重绑）
- ✅ 健康检查：上游正常 200 / 上游不可达 503
- ✅ Docker 容器内 dashboard + 隧道 + `HEALTHCHECK` 转 `healthy`
- ✅ `install-server.sh` 非交互与交互两种模式，生成的配置可直接启动

伪装面验证（nmap / openssl / 真实抓包比对）：

- ✅ `nmap -sV` → `ms-wbt-server`；`rdp-ntlm-info` → `Product_Version: 10.0.17763`
- ✅ X.224 selected protocol = `0x08`（与 WinServer 2019 一致）
- ✅ TLS 1.2 + ECDHE-RSA-AES256-GCM
- ✅ 证书字段（CN=机器名/自签名/RSA-2048/sha256RSA/KU critical/EKU ServerAuth/无 SAN/6 个月）
- ✅ 对 `PROTOCOL_RDP` 探测回 Negotiation Failure

CI 验证：

- ✅ `ci.yml`：测试 + 双架构 release 构建
- ✅ `release.yml`：v0.2.1 双架构资产上传成功
- ✅ `docker.yml`：多架构镜像推 GHCR 成功（`latest`/`0.2.1`/`0.2`）

## 6. 已知限制与坑

1. **证书/凭据**：NLA 使用固定账号密码（本地账号建议 `.\user` 形式）；不支持域认证/Kerberos。
2. **SVC chunk 上限**：约 1600 B/PDU，吞吐对实验室足够，高带宽场景需评估。
3. **TLS 指纹**：rustls 无 CBC 套件，真实 Windows 选 `0xc028`（CBC），我们是 GCM。
   如需完全对齐需引入支持 CBC 的后端（如 openssl），代价较大。
4. **会话期图形流缺失**：服务端不推送位图更新，会话期缺少真实 RDP 的图形包型。
   这是最大剩余形态差异（详见 §7）。
5. **musl 静态构建**：`aws-lc-sys` 在 musl 下运行段错误，只发布 glibc 版。
   Alpine 部署需替换证书生成的 RSA 后端。
6. **Docker 构建的三个坑（已修，勿回退）**：
   - arm64 不要用交叉编译（`aws-lc-sys` 的 jitterentropy 缺头文件）；
   - 占位 stub 编译后必须 `touch` 真实源码，否则复用空二进制（曾产出 404 KB 假二进制）；
   - 多架构并行必须给 cargo cache mount 加 `id=cargo-*-${TARGETARCH}`，否则解包竞争。
7. **Dashboard 安全**：默认无鉴权、绑定 127.0.0.1。暴露到公网前务必设
   `dashboard_token` 且仅监听内网/本机。
8. **watch 死锁**：`update_config` 里不能在同一表达式内 `borrow()` + `send()`
   （已修复，注释在 `dashboard.rs`，勿改回）。

## 7. 后续可做（按价值排序）

1. **会话期流量形态**：实现黑屏/噪声 bitmap update，按真实节奏（图形包 1460/1701 B 为主）
   发送，并可配置“安静度”，让会话期包型分布接近真实 RDP。
2. **单会话多路复用**：一个 RDP 会话内用 stream-id 承载多条本地 TCP 连接，
   降低握手开销（当前是一连接一会话）。
3. **动态目标**：客户端在虚拟通道内协商 target，服务端支持任意目标转发。
4. **CBC cipher 支持**：评估 openssl 后端，对齐 JA3/JA3S。
5. **可观测性**：Dashboard 增加会话列表、实时吞吐曲线、Prometheus `/metrics`。
6. **服务端也做 Dashboard**：目前只有客户端有 Web 面板。
7. **双因子/多次性凭证**：NLA 凭证轮换、连接级一次性 token。

## 8. 开发与发布流程

```bash
# 本地开发
cargo build --release
cargo test --workspace

# 交叉构建 arm64（需 gcc-aarch64-linux-gnu）
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu

# 发布
git tag vX.Y.Z && git push origin vX.Y.Z     # 触发 release.yml + docker.yml
```

提交前注意：`.gitignore` 已排除 `/etc/server.toml`、`/etc/client.toml`、
`/target`、`/dist`、`/cert-store`、`*.pcap`（避免真实凭据与抓包入库）。

## 9. 关键配置参考

服务端 `server.toml`：

```toml
bind = "0.0.0.0:3389"
target = "127.0.0.1:22"          # 隧道出口
username = "operator"
password = "ChangeMe#2026"
channel = "TUNNEL"                # 1-7 位字母数字，两端一致
cert_store_dir = "cert-store"     # 自动证书目录
machine_name = "DESKTOP-A1B2C3D"  # 证书 CN，可省略（随机）
# cert_path / key_path            # 指定 PEM 时使用
max_sessions = 64
desktop_size = [1280, 720]
```

客户端 `client.toml`：

```toml
listen = "127.0.0.1:1080"
server = "your.server:3389"
username = "operator"
password = "ChangeMe#2026"
channel = "TUNNEL"
client_name = "DESKTOP-RDPTUN"
trust = "tofu"                    # tofu | pin | none
# pin_spki_sha256 = "..."
tofu_store = "cert-store/client-known-hosts"
dashboard = "127.0.0.1:8080"
# dashboard_token = "..."         # 建议公网暴露时设置
```

客户端环境变量（容器友好）：`RDPTUN_LISTEN`、`RDPTUN_SERVER`、`RDPTUN_USERNAME`、
`RDPTUN_PASSWORD`、`RDPTUN_CHANNEL`、`RDPTUN_CLIENT_NAME`、`RDPTUN_TRUST`、
`RDPTUN_PIN_SPKI_SHA256`、`RDPTUN_TOFU_STORE`、`RDPTUN_DASHBOARD`、
`RDPTUN_DASHBOARD_TOKEN`。

## 10. 参考资料

- [MS-RDPBCGR] Remote Desktop Protocol: Basic Connectivity and Graphics Remoting
- [MS-CSSP] Credential Security Support Provider Protocol
- IronRDP（Devolutions）：<https://github.com/Devolutions/IronRDP>（MIT/Apache-2.0）
- 校准用抓包：真实 mstsc → Windows Server 2019（含 15 s 高分辨率视频），
  66 s / 8661 包；结论见 README「与真实 mstsc↔WinServer 抓包校准结论」。
