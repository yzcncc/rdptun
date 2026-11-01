//! 内置 Web Dashboard：查看状态、修改上游配置、触发健康检查。
//!
//! 使用手写的极简 HTTP/1.1 实现，避免引入 Web 框架（保持二进制精简）。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use serde::Serialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, RwLock};
use tracing::{debug, info, warn};

use crate::config::{save_config, ClientConfig};

/// 运行统计。
#[derive(Debug, Default)]
pub struct Stats {
    pub active_sessions: AtomicU64,
    pub total_sessions: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub health_failures: AtomicU64,
}

impl Stats {
    pub fn session_started(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
        self.total_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn session_ended(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_up(&self, n: usize) {
        self.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: usize) {
        self.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// 共享应用状态。
pub struct AppState {
    pub cfg: RwLock<ClientConfig>,
    pub config_path: PathBuf,
    pub stats: Arc<Stats>,
    /// 配置变更代号（每次保存 +1，主循环据此重新绑定监听地址）。
    pub cfg_generation: watch::Sender<u64>,
    pub started: Instant,
    pub last_error: RwLock<Option<String>>,
}

impl AppState {
    pub fn new(cfg: ClientConfig, config_path: PathBuf) -> (Arc<Self>, watch::Receiver<u64>) {
        let (tx, rx) = watch::channel(0u64);
        let state = Arc::new(Self {
            cfg: RwLock::new(cfg),
            config_path,
            stats: Arc::new(Stats::default()),
            cfg_generation: tx,
            started: Instant::now(),
            last_error: RwLock::new(None),
        });
        (state, rx)
    }

    pub async fn set_error(&self, err: impl Into<String>) {
        *self.last_error.write().await = Some(err.into());
    }

    pub async fn clear_error(&self) {
        *self.last_error.write().await = None;
    }
}

/// 启动 Dashboard HTTP 服务。
pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let addr = state.cfg.read().await.dashboard.clone();
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind dashboard {addr}"))?;
    info!(addr = %listener.local_addr()?, "dashboard listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "dashboard accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::task::spawn_local(async move {
            if let Err(e) = handle_conn(stream, state).await {
                debug!(%peer, error = %format!("{e:#}"), "dashboard request failed");
            }
        });
    }
}

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Request {
    fn bearer(&self) -> Option<&str> {
        self.headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| self.query.get("token").map(String::as_str))
    }
}

async fn handle_conn(mut stream: TcpStream, state: Arc<AppState>) -> Result<()> {
    let req = match read_request(&mut stream).await? {
        Some(r) => r,
        None => return Ok(()),
    };

    let (status, ctype, body) = route(&req, &state).await;

    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await.ok();
    Ok(())
}

async fn route(req: &Request, state: &Arc<AppState>) -> (&'static str, &'static str, Vec<u8>) {
    let path = req.path.as_str();

    // 静态页面无需鉴权（不含任何机密）。
    if path == "/" && req.method == "GET" {
        return ("200 OK", "text/html; charset=utf-8", INDEX_HTML.as_bytes().to_vec());
    }

    // 存活探针：只表示进程在跑。
    if path == "/livez" {
        return ("200 OK", "application/json", br#"{"ok":true}"#.to_vec());
    }

    // 就绪探针：探测上游 RDP 端口是否可达（Docker HEALTHCHECK 用）。
    if path == "/healthz" || path == "/api/health" {
        let (ok, payload) = healthcheck(state).await;
        let code = if ok { "200 OK" } else { "503 Service Unavailable" };
        return (code, "application/json", payload);
    }

    // 以下 API 需要鉴权（若配置了 token）。
    if let Some(expected) = state.cfg.read().await.dashboard_token.clone() {
        if req.bearer() != Some(expected.as_str()) {
            return (
                "401 Unauthorized",
                "application/json",
                br#"{"error":"unauthorized"}"#.to_vec(),
            );
        }
    }

    match (req.method.as_str(), path) {
        ("GET", "/api/status") => {
            let body = status_json(state).await;
            ("200 OK", "application/json", body)
        }
        ("POST", "/api/config") => match update_config(req, state).await {
            Ok(msg) => (
                "200 OK",
                "application/json",
                serde_json::json!({ "ok": true, "message": msg }).to_string().into_bytes(),
            ),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                serde_json::json!({ "ok": false, "error": format!("{e:#}") })
                    .to_string()
                    .into_bytes(),
            ),
        },
        ("POST", "/api/healthcheck") => {
            let (ok, payload) = healthcheck(state).await;
            let code = if ok { "200 OK" } else { "503 Service Unavailable" };
            (code, "application/json", payload)
        }
        _ => ("404 Not Found", "application/json", br#"{"error":"not found"}"#.to_vec()),
    }
}

#[derive(Serialize)]
struct StatusView<'a> {
    version: &'a str,
    uptime_secs: u64,
    active_sessions: u64,
    total_sessions: u64,
    bytes_up: u64,
    bytes_down: u64,
    health_failures: u64,
    last_error: Option<String>,
    config: ConfigView,
}

#[derive(Serialize)]
struct ConfigView {
    listen: String,
    server: String,
    username: String,
    /// 密码不回传，只标记是否已设置。
    password_set: bool,
    channel: String,
    client_name: String,
    trust: String,
    dashboard: String,
    dashboard_token_set: bool,
}

async fn status_json(state: &Arc<AppState>) -> Vec<u8> {
    let cfg = state.cfg.read().await;
    let view = StatusView {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started.elapsed().as_secs(),
        active_sessions: state.stats.active_sessions.load(Ordering::Relaxed),
        total_sessions: state.stats.total_sessions.load(Ordering::Relaxed),
        bytes_up: state.stats.bytes_up.load(Ordering::Relaxed),
        bytes_down: state.stats.bytes_down.load(Ordering::Relaxed),
        health_failures: state.stats.health_failures.load(Ordering::Relaxed),
        last_error: state.last_error.read().await.clone(),
        config: ConfigView {
            listen: cfg.listen.clone(),
            server: cfg.server.clone(),
            username: cfg.username.clone(),
            password_set: !cfg.password.is_empty(),
            channel: cfg.channel.clone(),
            client_name: cfg.client_name.clone(),
            trust: cfg.trust.clone(),
            dashboard: cfg.dashboard.clone(),
            dashboard_token_set: cfg.dashboard_token.is_some(),
        },
    };
    serde_json::to_vec(&view).unwrap_or_else(|_| b"{}".to_vec())
}

#[derive(serde::Deserialize)]
struct ConfigPatch {
    listen: Option<String>,
    server: Option<String>,
    username: Option<String>,
    /// 空字符串表示"保持不变"。
    password: Option<String>,
    channel: Option<String>,
    client_name: Option<String>,
    trust: Option<String>,
    pin_spki_sha256: Option<String>,
    dashboard_token: Option<String>,
}

async fn update_config(req: &Request, state: &Arc<AppState>) -> Result<String> {
    let patch: ConfigPatch = serde_json::from_slice(&req.body).context("parse JSON body")?;

    let mut cfg = state.cfg.read().await.clone();

    if let Some(v) = patch.listen.as_deref().filter(|s| !s.is_empty()) {
        cfg.listen = v.to_owned();
    }
    if let Some(v) = patch.server.as_deref().filter(|s| !s.is_empty()) {
        cfg.server = v.to_owned();
    }
    if let Some(v) = patch.username.as_deref() {
        cfg.username = v.to_owned();
    }
    if let Some(v) = patch.password.as_deref().filter(|s| !s.is_empty()) {
        cfg.password = v.to_owned();
    }
    if let Some(v) = patch.channel.as_deref().filter(|s| !s.is_empty()) {
        cfg.channel = v.to_owned();
    }
    if let Some(v) = patch.client_name.as_deref().filter(|s| !s.is_empty()) {
        cfg.client_name = v.to_owned();
    }
    if let Some(v) = patch.trust.as_deref().filter(|s| !s.is_empty()) {
        cfg.trust = v.to_owned();
    }
    if let Some(v) = patch.pin_spki_sha256.as_deref() {
        cfg.pin_spki_sha256 = if v.is_empty() { None } else { Some(v.to_owned()) };
    }
    if let Some(v) = patch.dashboard_token.as_deref() {
        cfg.dashboard_token = if v.is_empty() { None } else { Some(v.to_owned()) };
    }

    cfg.validate().context("invalid configuration")?;
    save_config(&state.config_path, &cfg).context("persist configuration")?;

    let listen_changed = state.cfg.read().await.listen != cfg.listen;
    *state.cfg.write().await = cfg;
    // 注意：不能写成 `send(generation.borrow() + 1)` —— `borrow()` 持有 watch 的内部
    // 读锁，而 `send()` 需要写锁，在同一表达式里会自死锁并冻结整个 runtime。
    let next = *state.cfg_generation.borrow() + 1;
    let _ = state.cfg_generation.send(next);

    Ok(if listen_changed {
        "saved; listener is rebinding to the new address".to_owned()
    } else {
        "saved; new sessions use the updated upstream".to_owned()
    })
}

/// 上游健康检查：TCP 连接 + 简单 RTT。
async fn healthcheck(state: &Arc<AppState>) -> (bool, Vec<u8>) {
    let (server, timeout) = {
        let cfg = state.cfg.read().await;
        (cfg.server.clone(), Duration::from_secs(3))
    };

    let started = Instant::now();
    let result = tokio::time::timeout(timeout, TcpStream::connect(&server)).await;

    let payload = match result {
        Ok(Ok(stream)) => {
            let latency = started.elapsed().as_millis() as u64;
            drop(stream);
            serde_json::json!({
                "ok": true,
                "server": server,
                "latency_ms": latency,
            })
        }
        Ok(Err(e)) => {
            state.stats.health_failures.fetch_add(1, Ordering::Relaxed);
            serde_json::json!({
                "ok": false,
                "server": server,
                "error": format!("{e}"),
            })
        }
        Err(_) => {
            state.stats.health_failures.fetch_add(1, Ordering::Relaxed);
            serde_json::json!({
                "ok": false,
                "server": server,
                "error": "connect timeout",
            })
        }
    };

    (payload["ok"].as_bool().unwrap_or(false), payload.to_string().into_bytes())
}

// ---------- 极简 HTTP/1.1 解析 ----------

async fn read_request(stream: &mut TcpStream) -> Result<Option<Request>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];

    // 读到 header 结束
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            anyhow::bail!("request header too large");
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let raw_path = parts.next().unwrap_or("/").to_owned();

    let (path, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p.to_owned(), parse_query(q)),
        None => (raw_path, HashMap::new()),
    };

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }

    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len);

    Ok(Some(Request {
        method,
        path,
        query,
        headers,
        body,
    }))
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>rdptun client</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
         background:#0f1419; color:#d7dde5; }
  header { padding:16px 24px; border-bottom:1px solid #232b36; display:flex; gap:12px; align-items:center; }
  h1 { font-size:16px; margin:0; font-weight:600; }
  .badge { font-size:12px; padding:2px 8px; border-radius:999px; background:#1b2430; color:#8b9bb0; }
  main { display:grid; grid-template-columns: 1fr 1fr; gap:20px; padding:24px; max-width:1100px; }
  @media (max-width:900px){ main{ grid-template-columns:1fr; } }
  section { background:#151c25; border:1px solid #232b36; border-radius:10px; padding:18px; }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:#7d8ea3; margin:0 0 14px; }
  label { display:block; font-size:12px; color:#8b9bb0; margin:10px 0 4px; }
  input, select { width:100%; box-sizing:border-box; padding:8px 10px; border-radius:7px;
                  border:1px solid #2b3542; background:#0e141b; color:#d7dde5; font:inherit; }
  input:focus, select:focus { outline:none; border-color:#3b82f6; }
  .row { display:flex; gap:10px; }
  .row > div { flex:1; }
  button { margin-top:14px; padding:9px 16px; border-radius:7px; border:0; font:inherit;
           font-weight:600; cursor:pointer; }
  .primary { background:#2563eb; color:#fff; }
  .secondary { background:#1f2937; color:#cbd5e1; }
  button:disabled { opacity:.55; cursor:default; }
  table { width:100%; border-collapse:collapse; }
  td { padding:6px 0; border-bottom:1px solid #1c2430; }
  td:last-child { text-align:right; font-variant-numeric:tabular-nums; }
  .ok { color:#34d399; } .bad { color:#f87171; } .muted { color:#6b7c92; }
  #msg { margin-top:12px; font-size:13px; min-height:18px; }
  #msg.ok { color:#34d399; } #msg.bad { color:#f87171; }
  code { background:#0e141b; padding:2px 6px; border-radius:5px; font-size:12px; }
</style>
</head>
<body>
<header>
  <h1>rdptun client</h1>
  <span class="badge" id="ver">–</span>
  <span class="badge" id="uptime">–</span>
  <span class="badge" id="health">checking…</span>
</header>
<main>
  <section>
    <h2>Upstream / session</h2>
    <label>RDP server (host:port)</label>
    <input id="server" placeholder="203.0.113.10:3389">
    <div class="row">
      <div><label>Username</label><input id="username" autocomplete="username"></div>
      <div><label>Password</label><input id="password" type="password" autocomplete="new-password"
             placeholder="(unchanged)"></div>
    </div>
    <div class="row">
      <div><label>Channel (1–7 chars)</label><input id="channel" placeholder="TUNNEL"></div>
      <div><label>Client name</label><input id="client_name" placeholder="DESKTOP-RDPTUN"></div>
    </div>
    <div class="row">
      <div><label>Local listen</label><input id="listen" placeholder="127.0.0.1:1080"></div>
      <div><label>Trust</label>
        <select id="trust">
          <option value="tofu">tofu</option>
          <option value="pin">pin</option>
          <option value="none">none</option>
        </select>
      </div>
    </div>
    <div class="row">
      <button class="primary" id="save">Save</button>
      <button class="secondary" id="test">Test upstream</button>
    </div>
    <div id="msg"></div>
  </section>

  <section>
    <h2>Status</h2>
    <table>
      <tr><td class="muted">Active sessions</td><td id="active">–</td></tr>
      <tr><td class="muted">Total sessions</td><td id="total">–</td></tr>
      <tr><td class="muted">Bytes up</td><td id="up">–</td></tr>
      <tr><td class="muted">Bytes down</td><td id="down">–</td></tr>
      <tr><td class="muted">Health failures</td><td id="hf">–</td></tr>
      <tr><td class="muted">Last error</td><td id="err" class="muted">–</td></tr>
      <tr><td class="muted">Config file</td><td><code id="cfgpath">–</code></td></tr>
    </table>
    <p class="muted" style="font-size:12px;margin-top:14px">
      Health endpoint: <code>/healthz</code> · Liveness: <code>/livez</code>
    </p>
  </section>
</main>
<script>
let token = localStorage.getItem('rdptun_token') || '';
function authHeaders(extra) {
  const h = Object.assign({}, extra || {});
  if (token) h['Authorization'] = 'Bearer ' + token;
  return h;
}
async function api(path, opts) {
  opts = opts || {};
  opts.headers = authHeaders(opts.headers);
  const r = await fetch(path, opts);
  if (r.status === 401) {
    const t = prompt('Dashboard token:');
    if (t) { token = t; localStorage.setItem('rdptun_token', t); return api(path, opts); }
  }
  return r;
}
function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  const u = ['KB','MB','GB','TB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + ' ' + u[i];
}
function fmtUptime(s) {
  const d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60);
  return (d? d+'d ':'') + (h? h+'h ':'') + m + 'm';
}
let loaded = false;
async function refresh() {
  const r = await api('/api/status');
  if (!r.ok) return;
  const s = await r.json();
  document.getElementById('ver').textContent = 'v' + s.version;
  document.getElementById('uptime').textContent = 'up ' + fmtUptime(s.uptime_secs);
  document.getElementById('active').textContent = s.active_sessions;
  document.getElementById('total').textContent = s.total_sessions;
  document.getElementById('up').textContent = fmtBytes(s.bytes_up);
  document.getElementById('down').textContent = fmtBytes(s.bytes_down);
  document.getElementById('hf').textContent = s.health_failures;
  document.getElementById('err').textContent = s.last_error || '—';
  document.getElementById('cfgpath').textContent = s.config.listen;
  if (!loaded) {
    document.getElementById('server').value = s.config.server;
    document.getElementById('username').value = s.config.username;
    document.getElementById('channel').value = s.config.channel;
    document.getElementById('client_name').value = s.config.client_name;
    document.getElementById('listen').value = s.config.listen;
    document.getElementById('trust').value = s.config.trust;
    loaded = true;
  }
}
async function pollHealth() {
  try {
    const r = await fetch('/healthz');
    const h = await r.json();
    const el = document.getElementById('health');
    if (h.ok) { el.textContent = 'upstream ' + h.latency_ms + 'ms'; el.className = 'badge ok'; }
    else { el.textContent = 'upstream down'; el.className = 'badge bad'; }
  } catch (e) {
    const el = document.getElementById('health');
    el.textContent = 'upstream unreachable'; el.className = 'badge bad';
  }
}
function showMsg(text, ok) {
  const el = document.getElementById('msg');
  el.textContent = text; el.className = ok ? 'ok' : 'bad';
}
document.getElementById('save').onclick = async () => {
  const body = {
    server: document.getElementById('server').value.trim(),
    username: document.getElementById('username').value,
    password: document.getElementById('password').value,
    channel: document.getElementById('channel').value.trim(),
    client_name: document.getElementById('client_name').value.trim(),
    listen: document.getElementById('listen').value.trim(),
    trust: document.getElementById('trust').value,
  };
  const r = await api('/api/config', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
  });
  const j = await r.json().catch(() => ({}));
  if (r.ok) { showMsg(j.message || 'saved', true); document.getElementById('password').value = ''; loaded = false; refresh(); }
  else showMsg(j.error || ('save failed (' + r.status + ')'), false);
};
document.getElementById('test').onclick = async () => {
  showMsg('testing…', true);
  const r = await api('/api/healthcheck', {method:'POST'});
  const j = await r.json().catch(() => ({}));
  if (j.ok) showMsg('upstream reachable, ' + j.latency_ms + ' ms', true);
  else showMsg('upstream failed: ' + (j.error || r.status), false);
};
refresh(); pollHealth();
setInterval(refresh, 3000);
setInterval(pollHealth, 10000);
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_header_terminator() {
        assert_eq!(find_subslice(b"abc\r\n\r\nxyz", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subslice(b"abc", b"\r\n\r\n"), None);
    }

    #[test]
    fn parses_query_string() {
        let q = parse_query("token=abc&x=1");
        assert_eq!(q.get("token").unwrap(), "abc");
        assert_eq!(q.get("x").unwrap(), "1");
    }

    #[test]
    fn percent_decodes() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
    }
}
