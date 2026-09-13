//! WebDAV backend — pure-Rust port of `core/src/curl/CurlWebDavClient.cpp`
//! (libcurl + tinyxml2) onto `reqwest` (rustls) + `quick-xml`.
//!
//! ## C++ → Rust mapping
//!
//! * TLS verification: `CURLOPT_SSL_VERIFYPEER` + `CURLOPT_SSL_VERIFYHOST` map
//!   to `ClientBuilder::danger_accept_invalid_certs(true)` and
//!   `danger_accept_invalid_hostnames(true)`, both driven by
//!   `webdav_verify_peer == false` (libcurl disables both as a pair).
//! * `CURLOPT_CAINFO` (`webdav_ca_cert_path`) maps to
//!   `Certificate::from_pem` + `ClientBuilder::add_root_certificate` (appended
//!   to the platform/webpki roots, matching libcurl's additive CAINFO behavior).
//! * Proxies: `CURLPROXY_SOCKS5_HOSTNAME` → reqwest `socks5h://` URL (remote
//!   DNS resolution through the proxy); `CURLPROXY_HTTP` +
//!   `CURLOPT_HTTPPROXYTUNNEL=1` → reqwest `http://` proxy URL (reqwest always
//!   CONNECT-tunnels https through http proxies, so the tunnel flag needs no
//!   separate knob). Proxy credentials map to `Proxy::basic_auth`.
//! * Timeouts: `CURLOPT_CONNECTTIMEOUT` (15s) → `connect_timeout`,
//!   `CURLOPT_TIMEOUT` (120s) → `timeout`.
//! * Redirects: libcurl does not follow them by default, so the client is built
//!   with `redirect::Policy::none()` — WebDAV verbs (MOVE, PROPFIND, ...) must
//!   not be transparently redirected.
//! * Authentication: `CURLOPT_USERNAME`/`CURLOPT_PASSWORD` with `CURLAUTH_ANY`
//!   → per-request `basic_auth(username, password)` (preemptive Basic, which
//!   libcurl effectively sends too for HTTP/1.1 hosts).
//! * `CURLOPT_ACCEPT_ENCODING` → no direct equivalent; see MISSING-DEP below.
//!
//! MISSING-DEP: reqwest feature "stream" — enables `Response::bytes_stream()`
//!   for chunked download streaming with per-chunk progress. Without it,
//!   `get()` falls back to buffering the whole response body via `.bytes()`
//!   (memory-heavy for large files) and `put()` uses
//!   `Body::from(std::fs::File)` (correct Content-Length, coarse progress).
//! MISSING-DEP: futures-util — required alongside reqwest "stream" for
//!   `StreamExt::next` (download loop) and `futures_util::stream::Stream`
//!   (the `FileBody` upload stream). Both streaming paths are gated on
//!   `#[cfg(feature = "stream")]` and compile out when the feature is absent.
//! MISSING-DEP: reqwest feature "socks" — enables SOCKS5 proxies
//!   (`Proxy::all("socks5h://…")`). `tokio-socks` is already a workspace
//!   dependency, but reqwest needs its own `socks` feature wired to it.
//!   `connect()` returns `Unsupported` for `ProxyType::Socks5` without it.
//! MISSING-DEP: reqwest feature "gzip" — equivalent of
//!   `CURLOPT_ACCEPT_ENCODING` for compressed PROPFIND bodies (optional;
//!   bandwidth optimization only).

#![allow(unexpected_cfgs)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::RANGE;
use reqwest::{Certificate, Client, Method, Proxy, Response, StatusCode};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

#[cfg(feature = "stream")]
use futures_util::StreamExt;
#[cfg(feature = "stream")]
use std::pin::Pin;
#[cfg(feature = "stream")]
use std::task::{Context, Poll};
#[cfg(feature = "stream")]
use tokio::io::AsyncRead;

use crate::client::{CancelCb, ClientError, ProgressCb, SftpClient};
use crate::types::{FileInfo, Protocol, ProxyType, SessionOptions, WebDavScheme};

/// `CURLOPT_CONNECTTIMEOUT` (15 seconds).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// `CURLOPT_TIMEOUT` (120 seconds).
const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Chunk size for the streaming upload body (used by the cfg-gated
/// `feature = "stream"` path; the crate does not expose that feature yet).
#[allow(dead_code)]
const CHUNK_SIZE: usize = 64 * 1024;

/// Mirrors the C++ `propfindBody()` constant.
const PROPFIND_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<d:propfind xmlns:d=\"DAV:\">\
<d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/>\
</d:prop></d:propfind>";

// ---------------------------------------------------------------------------
// Interruption plumbing.
//
// The C++ implementation aborts in-flight transfers through a single shared
// atomic checked from libcurl's progress callback.  Rust `interrupt()` is a
// synchronous `&self` method, so each in-flight operation registers a small
// `CancelSignal` in a registry; `interrupt()` sets the flag and pings the
// `Notify` of every registered operation.  `tokio::select!` on the notify
// aborts the reqwest request future (dropping it closes the connection), and
// the flag is additionally checked inside body loops.
// ---------------------------------------------------------------------------

type CancelRegistry = Arc<Mutex<Vec<CancelSignal>>>;

#[derive(Clone)]
struct CancelSignal {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

/// Registered for the duration of one transfer; unregisters on drop.
struct CancelGuard {
    sig: CancelSignal,
    registry: CancelRegistry,
}

impl CancelGuard {
    fn new(registry: &CancelRegistry) -> Self {
        let sig = CancelSignal {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        };
        registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(sig.clone());
        Self {
            sig,
            registry: Arc::clone(registry),
        }
    }

    fn cancelled(&self) -> bool {
        self.sig.flag.load(Ordering::SeqCst)
    }

    async fn wait(&self) {
        self.sig.notify.notified().await;
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Ok(mut list) = self.registry.lock() {
            list.retain(|s| !Arc::ptr_eq(&s.notify, &self.sig.notify));
        }
    }
}

fn interrupt_all(registry: &CancelRegistry) {
    let list = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for sig in list.iter() {
        sig.flag.store(true, Ordering::SeqCst);
        sig.notify.notify_one();
    }
}

// ---------------------------------------------------------------------------
// Path / URL helpers (direct ports of the C++ anonymous-namespace helpers).
// ---------------------------------------------------------------------------

fn normalize_webdav_scheme(scheme: WebDavScheme) -> WebDavScheme {
    match scheme {
        WebDavScheme::Http => WebDavScheme::Http,
        _ => WebDavScheme::Https,
    }
}

fn default_port_for_scheme(scheme: WebDavScheme) -> u16 {
    match normalize_webdav_scheme(scheme) {
        WebDavScheme::Http => 80,
        WebDavScheme::Https => 443,
    }
}

fn scheme_storage_name(scheme: WebDavScheme) -> &'static str {
    match normalize_webdav_scheme(scheme) {
        WebDavScheme::Http => "http",
        WebDavScheme::Https => "https",
    }
}

fn normalize_proxy_type(proxy_type: ProxyType) -> ProxyType {
    match proxy_type {
        ProxyType::Socks5 | ProxyType::HttpConnect => proxy_type,
        _ => ProxyType::None,
    }
}

/// Port of `normalizeRemotePath`: backslashes to slashes, leading slash,
/// collapsed `//`, no trailing slash.
fn normalize_remote_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    let mut p: String = path.replace('\\', "/");
    if !p.starts_with('/') {
        p.insert(0, '/');
    }
    while p.contains("//") {
        p = p.replace("//", "/");
    }
    if p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

/// Port of `normalizeRemoteDirPath`.
fn normalize_remote_dir_path(path: &str) -> String {
    let mut p = normalize_remote_path(path);
    if p != "/" && !p.is_empty() && !p.ends_with('/') {
        p.push('/');
    }
    p
}

/// Port of `normalizeHostAuthority` (brackets bare IPv6 literals).
fn normalize_host_authority(host: &str) -> String {
    if host.contains(':') && !host.contains(']') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn is_unreserved_uri_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~' | b'/')
}

/// Port of `encodePathForUrl` (uppercase percent-encoding, `/` kept literal).
fn encode_path_for_url(path: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(path.len() + 16);
    for b in path.bytes() {
        if is_unreserved_uri_char(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    out
}

/// Port of `trimAscii`.
fn trim_ascii(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_ascii_whitespace())
}

/// Port of `parseUnsignedDec`.
fn parse_unsigned_dec(token: &str) -> Option<u64> {
    if token.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for b in token.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        let digit = u64::from(b - b'0');
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some(value)
}

/// Port of `extractPathFromHref`: strip fragment/query, strip scheme+authority,
/// fall back to "/".
fn extract_path_from_href(href: &str) -> String {
    let mut h = trim_ascii(href).to_string();
    if h.is_empty() {
        return "/".to_string();
    }
    if let Some(pos) = h.find('#') {
        h.truncate(pos);
    }
    if let Some(pos) = h.find('?') {
        h.truncate(pos);
    }
    if let Some(scheme) = h.find("://") {
        let after = &h[scheme + 3..];
        return match after.find('/') {
            Some(slash) => after[slash..].to_string(),
            None => "/".to_string(),
        };
    }
    h
}

/// Replacement for `curl_easy_unescape` (default flags: percent decoding, no
/// `+` → space conversion, invalid sequences kept verbatim).
fn decode_percent(raw: &str) -> String {
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Tolerant HTTP-date parser mirroring the tolerance of `curl_getdate`:
/// RFC 1123 / RFC 850 / asctime / ISO 8601 / raw unix timestamp.
fn parse_http_date(raw: &str) -> Option<u64> {
    let s = trim_ascii(raw);
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<u64>().ok();
    }
    let non_neg = |secs: i64| -> u64 { secs.max(0) as u64 };
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(s) {
        return Some(non_neg(dt.timestamp()));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(non_neg(dt.timestamp()));
    }
    for fmt in [
        "%a, %d %b %Y %H:%M:%S",
        "%a %b %e %H:%M:%S %Y",
        "%A, %d-%b-%y %H:%M:%S",
    ] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(non_neg(naive.and_utc().timestamp()));
        }
    }
    None
}

/// Port of `parseHttpStatusCode` (first run of three digits in a status line).
fn parse_http_status_code(line: &str) -> i32 {
    let b = line.as_bytes();
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i].is_ascii_digit() && b[i + 1].is_ascii_digit() && b[i + 2].is_ascii_digit() {
            return i32::from(b[i] - b'0') * 100
                + i32::from(b[i + 1] - b'0') * 10
                + i32::from(b[i + 2] - b'0');
        }
        i += 1;
    }
    0
}

/// Port of `isDirectChildPath`.
fn is_direct_child_path(parent_path: &str, path: &str) -> Option<String> {
    let parent_dir = normalize_remote_dir_path(parent_path);
    if path == normalize_remote_path(parent_path) {
        return None;
    }
    if !path.starts_with(&parent_dir) {
        return None;
    }
    let mut tail = &path[parent_dir.len()..];
    if tail.ends_with('/') {
        tail = &tail[..tail.len() - 1];
    }
    if tail.is_empty() || tail.contains('/') {
        return None;
    }
    Some(tail.to_string())
}

// ---------------------------------------------------------------------------
// PROPFIND response parsing (quick-xml replaces tinyxml2).
//
// Mirrors the C++ strategy exactly:
//   * scan the document for `response` elements (local names, namespace
//     prefix stripped — equivalent of tinyxml2 `xmlLocalName`);
//   * `href` must be a direct child of `response`;
//   * for every direct `propstat` child with a 2xx `status`, apply its direct
//     `prop` child; if no 2xx propstat existed, fall back to a direct `prop`
//     child of the response;
//   * `resourcetype` > `collection` (direct child) sets `is_dir`; a trailing
//     `/` on the raw href also sets `is_dir`;
//   * duplicate paths are merged (is_dir OR-ed, size/mtime fill in gaps).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct WebDavResource {
    path: String,
    is_dir: bool,
    has_size: bool,
    size: u64,
    has_mtime: bool,
    mtime: u64,
}

#[derive(Debug, Clone, Default)]
struct PropData {
    is_dir: bool,
    has_size: bool,
    size: u64,
    has_mtime: bool,
    mtime: u64,
}

#[derive(Debug)]
enum Capture {
    Href(String),
    Status(String),
    Size(String),
    Mtime(String),
}

impl Capture {
    fn push_str(&mut self, s: &str) {
        match self {
            Capture::Href(buf)
            | Capture::Status(buf)
            | Capture::Size(buf)
            | Capture::Mtime(buf) => buf.push_str(s),
        }
    }
}

fn xml_err(e: quick_xml::Error) -> String {
    format!("Could not parse WebDAV PROPFIND response (XML error: {e}).")
}

fn merge_resource(resources: &mut Vec<WebDavResource>, parsed: WebDavResource) {
    if let Some(existing) = resources.iter_mut().find(|r| r.path == parsed.path) {
        existing.is_dir |= parsed.is_dir;
        if !existing.has_size && parsed.has_size {
            existing.has_size = true;
            existing.size = parsed.size;
        }
        if !existing.has_mtime && parsed.has_mtime {
            existing.has_mtime = true;
            existing.mtime = parsed.mtime;
        }
    } else {
        resources.push(parsed);
    }
}

/// Parses one `<d:response>…</d:response>` event chunk (already owned).
fn parse_response_chunk(events: &[quick_xml::events::Event<'static>]) -> Option<WebDavResource> {
    enum PropOwner {
        Pstat(usize),
        Response,
    }

    let mut depth: i32 = 0;
    let mut href: Option<String> = None;
    // (status code, prop data) per direct propstat child.
    let mut pstats: Vec<(i32, Option<PropData>)> = Vec::new();
    let mut cur_pstat: Option<usize> = None;
    let mut cur_prop: Option<(PropData, PropOwner)> = None;
    let mut response_prop: Option<PropData> = None;
    let mut in_resourcetype = false;
    let mut capture: Option<Capture> = None;

    for ev in events {
        match ev {
            quick_xml::events::Event::Start(e) | quick_xml::events::Event::Empty(e) => {
                let name = e.local_name();
                let d = depth;
                let is_empty = matches!(ev, quick_xml::events::Event::Empty(_));
                match (name.as_ref(), d) {
                    (b"href", 1) => capture = Some(Capture::Href(String::new())),
                    (b"propstat", 1) => {
                        pstats.push((0, None));
                        cur_pstat = Some(pstats.len() - 1);
                    }
                    (b"status", 2) => {
                        if cur_pstat.is_some() {
                            capture = Some(Capture::Status(String::new()));
                        }
                    }
                    (b"prop", 2) => {
                        if let Some(idx) = cur_pstat {
                            cur_prop = Some((PropData::default(), PropOwner::Pstat(idx)));
                        }
                    }
                    (b"prop", 1) => {
                        cur_prop = Some((PropData::default(), PropOwner::Response));
                    }
                    (b"resourcetype", 3) if cur_prop.is_some() => in_resourcetype = true,
                    (b"collection", 4) if in_resourcetype => {
                        if let Some((prop, _)) = &mut cur_prop {
                            prop.is_dir = true;
                        }
                    }
                    (b"getcontentlength", 3) if cur_prop.is_some() => {
                        capture = Some(Capture::Size(String::new()));
                    }
                    (b"getlastmodified", 3) if cur_prop.is_some() => {
                        capture = Some(Capture::Mtime(String::new()));
                    }
                    _ => {}
                }
                if !is_empty {
                    depth += 1;
                }
            }
            quick_xml::events::Event::Text(t) => {
                if let Ok(s) = t.unescape() {
                    if let Some(c) = &mut capture {
                        c.push_str(&s);
                    }
                }
            }
            quick_xml::events::Event::CData(t) => {
                let raw = String::from_utf8_lossy(t);
                if let Ok(s) = quick_xml::escape::unescape(&raw) {
                    if let Some(c) = &mut capture {
                        c.push_str(&s);
                    }
                }
            }
            quick_xml::events::Event::End(e) => {
                depth -= 1;
                match e.local_name().as_ref() {
                    b"href" => {
                        if let Some(Capture::Href(s)) = capture.take() {
                            if href.is_none() {
                                href = Some(s);
                            }
                        }
                    }
                    b"status" => {
                        if let (Some(Capture::Status(s)), Some(idx)) = (capture.take(), cur_pstat) {
                            if let Some(slot) = pstats.get_mut(idx) {
                                slot.0 = parse_http_status_code(&s);
                            }
                        }
                    }
                    b"getcontentlength" => {
                        if let Some(Capture::Size(s)) = capture.take() {
                            if let (Some((prop, _)), Some(value)) =
                                (&mut cur_prop, parse_unsigned_dec(trim_ascii(&s)))
                            {
                                prop.has_size = true;
                                prop.size = value;
                            }
                        }
                    }
                    b"getlastmodified" => {
                        if let Some(Capture::Mtime(s)) = capture.take() {
                            if let (Some((prop, _)), Some(value)) =
                                (&mut cur_prop, parse_http_date(&s))
                            {
                                prop.has_mtime = true;
                                prop.mtime = value;
                            }
                        }
                    }
                    b"resourcetype" => in_resourcetype = false,
                    b"prop" => {
                        if let Some((prop, owner)) = cur_prop.take() {
                            match owner {
                                PropOwner::Pstat(idx) => {
                                    if let Some(slot) = pstats.get_mut(idx) {
                                        slot.1 = Some(prop);
                                    }
                                }
                                PropOwner::Response => response_prop = Some(prop),
                            }
                        }
                    }
                    b"propstat" => cur_pstat = None,
                    _ => {}
                }
            }
            _ => {}
        }
    }

    let href_raw = href?;
    if href_raw.is_empty() {
        return None;
    }
    let mut parsed = WebDavResource {
        path: normalize_remote_path(&decode_percent(&extract_path_from_href(&href_raw))),
        ..Default::default()
    };
    if href_raw.ends_with('/') {
        parsed.is_dir = true;
    }

    let mut consumed_propstat = false;
    for (status, prop) in &pstats {
        if *status >= 200 && *status < 300 {
            if let Some(prop) = prop {
                parsed.is_dir |= prop.is_dir;
                if !parsed.has_size && prop.has_size {
                    parsed.has_size = true;
                    parsed.size = prop.size;
                }
                if !parsed.has_mtime && prop.has_mtime {
                    parsed.has_mtime = true;
                    parsed.mtime = prop.mtime;
                }
            }
            consumed_propstat = true;
        }
    }
    if !consumed_propstat {
        if let Some(prop) = &response_prop {
            parsed.is_dir |= prop.is_dir;
            if !parsed.has_size && prop.has_size {
                parsed.has_size = true;
                parsed.size = prop.size;
            }
            if !parsed.has_mtime && prop.has_mtime {
                parsed.has_mtime = true;
                parsed.mtime = prop.mtime;
            }
        }
    }
    Some(parsed)
}

/// Port of `parsePropfindResponse`.
fn parse_propfind_response(xml: &str) -> Result<Vec<WebDavResource>, String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut resources: Vec<WebDavResource> = Vec::new();
    let mut saw_root = false;

    loop {
        let owned = reader.read_event().map_err(xml_err)?.into_owned();
        let is_response = matches!(&owned, Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"response");
        if matches!(&owned, Event::Start(_) | Event::Empty(_)) {
            saw_root = true;
        }
        if is_response {
            let mut chunk = vec![owned];
            let is_self_closed = matches!(&chunk[0], Event::Empty(_));
            if !is_self_closed {
                // The chunk already contains the opening <response>; Empty
                // (self-closing) tags are self-contained, so only Start/End
                // adjust the depth.
                let mut depth = 1usize;
                loop {
                    let inner = reader.read_event().map_err(xml_err)?.into_owned();
                    match &inner {
                        Event::Start(_) => depth += 1,
                        Event::End(_) => depth -= 1,
                        _ => {}
                    }
                    let done = matches!(&inner, Event::End(e) if e.local_name().as_ref() == b"response")
                        && depth == 0;
                    let eof = matches!(inner, Event::Eof);
                    chunk.push(inner);
                    if done || eof {
                        break;
                    }
                }
            }
            if let Some(resource) = parse_response_chunk(&chunk) {
                merge_resource(&mut resources, resource);
            }
            continue;
        }
        if matches!(owned, Event::Eof) {
            break;
        }
    }

    if !saw_root {
        return Err("WebDAV PROPFIND response is empty.".to_string());
    }
    if resources.is_empty() {
        return Err("WebDAV PROPFIND response does not contain usable resources.".to_string());
    }
    Ok(resources)
}

// ---------------------------------------------------------------------------
// Client state.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ConnOptions {
    /// `{scheme}://{host}:{port}` — the base URL for the session.
    base_url: String,
    username: String,
    password: Option<String>,
}

#[derive(Clone)]
struct ConnState {
    client: Client,
    opts: ConnOptions,
}

/// WebDAV backend client (HTTP/HTTPS).
///
/// Usage mirrors the C++ class: `connect()` builds the reqwest client and
/// probes the server with a `PROPFIND /` (Depth 0), `disconnect()` drops the
/// client.
pub struct WebDavClient {
    state: Option<ConnState>,
    interrupts: CancelRegistry,
}

impl WebDavClient {
    pub fn new() -> Self {
        Self {
            state: None,
            interrupts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn connected_state(&self) -> Result<&ConnState, ClientError> {
        self.state
            .as_ref()
            .ok_or_else(|| ClientError::OperationFailed("Not connected.".to_string()))
    }
}

impl Default for WebDavClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HTTP plumbing.
// ---------------------------------------------------------------------------

fn build_webdav_url(opts: &ConnOptions, remote_path: &str) -> String {
    format!(
        "{}{}",
        opts.base_url,
        encode_path_for_url(&normalize_remote_path(remote_path))
    )
}

fn net_err(what: &str, e: reqwest::Error) -> ClientError {
    ClientError::OperationFailed(format!("WebDAV {what} failed: {e}"))
}

/// Status → error mapping: 401/403 are authentication failures, everything
/// else is an operation failure with a clear message (mirrors
/// `formatHttpFailure`).
fn http_status_err(what: &str, status: StatusCode) -> ClientError {
    let code = status.as_u16();
    match code {
        401 | 403 => ClientError::AuthFailed(format!(
            "{what} failed with HTTP status {code}: authentication rejected."
        )),
        404 => ClientError::OperationFailed(format!(
            "{what} failed with HTTP status {code}: not found."
        )),
        _ => ClientError::OperationFailed(format!("{what} failed with HTTP status {code}.")),
    }
}

fn auth_builder(builder: reqwest::RequestBuilder, opts: &ConnOptions) -> reqwest::RequestBuilder {
    if opts.username.is_empty() {
        builder
    } else {
        // Mirrors C++: password set only when non-empty.
        let password = opts.password.as_deref().filter(|p| !p.is_empty());
        builder.basic_auth(&opts.username, password)
    }
}

/// Port of `performTextRequest` (PROPFIND/MKCOL/DELETE/MOVE).
async fn text_request(
    conn: &ConnState,
    method: Method,
    remote_path: &str,
    body: Option<String>,
    headers: &[(&str, String)],
) -> Result<Response, ClientError> {
    let url = build_webdav_url(&conn.opts, remote_path);
    let mut req = conn.client.request(method, &url);
    req = auth_builder(req, &conn.opts);
    for (key, value) in headers {
        req = req.header(*key, value.as_str());
    }
    if let Some(body) = body {
        req = req.body(body);
    }
    debug!(url = %url, "webdav text request");
    req.send().await.map_err(|e| net_err("request", e))
}

/// Port of `performPropfind`.
async fn propfind(
    conn: &ConnState,
    remote_path: &str,
    depth: i32,
) -> Result<Response, ClientError> {
    text_request(
        conn,
        Method::from_bytes(b"PROPFIND").expect("PROPFIND is a valid method token"),
        remote_path,
        Some(PROPFIND_BODY.to_string()),
        &[
            ("Depth", depth.to_string()),
            ("Content-Type", "application/xml; charset=utf-8".to_string()),
        ],
    )
    .await
}

async fn delete_tolerant(conn: &ConnState, path: &str) -> Result<(), ClientError> {
    let resp = text_request(conn, Method::DELETE, path, None, &[]).await?;
    let status = resp.status();
    if matches!(status.as_u16(), 200 | 204 | 404) {
        return Ok(());
    }
    Err(http_status_err("WebDAV DELETE", status))
}

// ---------------------------------------------------------------------------
// Transfers.
// ---------------------------------------------------------------------------

fn check_cancel(guard: &CancelGuard, should_cancel: &Option<CancelCb>) -> bool {
    if guard.cancelled() {
        return true;
    }
    if let Some(cb) = should_cancel {
        if cb() {
            return true;
        }
    }
    false
}

fn call_progress(progress: &Option<ProgressCb>, done: u64, total: u64) {
    if let Some(cb) = progress {
        cb(done, total);
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_response_body(
    resp: Response,
    file: &mut tokio::fs::File,
    done: &mut u64,
    total: Option<u64>,
    guard: &CancelGuard,
    progress: &Option<ProgressCb>,
    should_cancel: &Option<CancelCb>,
) -> Result<(), ClientError> {
    #[cfg(feature = "stream")]
    {
        let mut stream = resp.bytes_stream();
        loop {
            let chunk = tokio::select! {
                _ = guard.wait() => return Err(ClientError::Cancelled),
                item = stream.next() => item,
            };
            let Some(chunk) = chunk else { break };
            let chunk = chunk.map_err(|e| net_err("GET", e))?;
            file.write_all(&chunk).await.map_err(ClientError::Io)?;
            *done += chunk.len() as u64;
            if check_cancel(guard, should_cancel) {
                return Err(ClientError::Cancelled);
            }
            call_progress(progress, *done, total.unwrap_or(*done));
        }
    }
    #[cfg(not(feature = "stream"))]
    {
        // Fallback when the reqwest `stream` feature is unavailable: buffer the
        // whole body, then write it (progress reported once).
        let bytes = tokio::select! {
            _ = guard.wait() => return Err(ClientError::Cancelled),
            bytes = resp.bytes() => bytes.map_err(|e| net_err("GET", e))?,
        };
        file.write_all(&bytes).await.map_err(ClientError::Io)?;
        *done += bytes.len() as u64;
        if check_cancel(guard, should_cancel) {
            return Err(ClientError::Cancelled);
        }
        call_progress(progress, *done, total.unwrap_or(*done));
    }
    Ok(())
}

/// Port of `performDownloadRequest` + `CurlWebDavClient::get`.
///
/// When `offset > 0` a `Range: bytes={offset}-` header is sent (resume).
/// The server must answer 206 to continue the partial file; if it answers 200
/// (range ignored) the transfer restarts from scratch, and 416 means the local
/// file is already complete.  This is a safe superset of the C++ behavior,
/// which rejected resume outright for WebDAV.
#[allow(clippy::too_many_arguments)]
async fn download(
    conn: &ConnState,
    remote: &str,
    local: &str,
    offset: u64,
    resume_attempt: bool,
    guard: &CancelGuard,
    progress: &Option<ProgressCb>,
    should_cancel: &Option<CancelCb>,
) -> Result<(), ClientError> {
    let url = build_webdav_url(&conn.opts, remote);
    let mut builder = conn.client.get(&url);
    builder = auth_builder(builder, &conn.opts);
    if offset > 0 {
        let range = format!("bytes={offset}-");
        builder = builder.header(RANGE, range.as_str());
    }
    let resp = tokio::select! {
        _ = guard.wait() => return Err(ClientError::Cancelled),
        resp = builder.send() => resp.map_err(|e| net_err("GET", e))?,
    };
    let status = resp.status();

    if resume_attempt && status == StatusCode::RANGE_NOT_SATISFIABLE {
        // The range starts beyond EOF: the local copy is already complete.
        debug!(remote, "webdav resume: 416, local file already complete");
        return Ok(());
    }
    let mut append = resume_attempt && status == StatusCode::PARTIAL_CONTENT;
    if resume_attempt && status == StatusCode::OK {
        // Server ignored the Range header and sent the full body: start over.
        warn!(
            remote,
            "webdav resume: server ignored Range header, restarting"
        );
        append = false;
    } else if !status.is_success() {
        return Err(http_status_err("WebDAV GET", status));
    }

    let content_len = resp
        .content_length()
        .map(|n| if append { offset + n } else { n });
    let mut file = if append {
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(local)
            .await
            .map_err(ClientError::Io)?
    } else {
        tokio::fs::File::create(local)
            .await
            .map_err(ClientError::Io)?
    };
    let mut done = if append { offset } else { 0 };
    call_progress(progress, done, content_len.unwrap_or(0));
    write_response_body(
        resp,
        &mut file,
        &mut done,
        content_len,
        guard,
        progress,
        should_cancel,
    )
    .await?;
    file.flush().await.map_err(ClientError::Io)?;
    call_progress(progress, done, content_len.unwrap_or(done));
    Ok(())
}

/// Streaming upload body (used when the reqwest `stream` feature is enabled):
/// reads the local file in chunks, reports progress, and aborts early when
/// interrupted.  `Vec<u8>: Into<bytes::Bytes>` so no direct `bytes` dependency
/// is needed.
#[cfg(feature = "stream")]
struct FileBody {
    file: tokio::fs::File,
    total: u64,
    done: u64,
    sig: CancelSignal,
    progress: Option<ProgressCb>,
    should_cancel: Option<CancelCb>,
}

#[cfg(feature = "stream")]
impl futures_util::stream::Stream for FileBody {
    type Item = Result<Vec<u8>, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.sig.flag.load(Ordering::SeqCst) {
            return Poll::Ready(None);
        }
        if let Some(cb) = &this.should_cancel {
            if cb() {
                return Poll::Ready(None);
            }
        }
        if this.done >= this.total {
            return Poll::Ready(None);
        }
        let want = std::cmp::min(CHUNK_SIZE as u64, this.total - this.done) as usize;
        let mut buf = vec![0u8; want];
        match Pin::new(&mut this.file).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(0)) => Poll::Ready(None),
            Poll::Ready(Ok(n)) => {
                buf.truncate(n);
                this.done += n as u64;
                if let Some(cb) = &this.progress {
                    cb(this.done, this.total);
                }
                Poll::Ready(Some(Ok(buf)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// SftpClient implementation.
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl SftpClient for WebDavClient {
    fn protocol(&self) -> Protocol {
        Protocol::WebDav
    }

    // `capabilities()` keeps the trait default, which reports
    // `capabilities_for_protocol(Protocol::WebDav)` (listing, transfers,
    // metadata — no resume/permissions/ownership/timestamps), matching the
    // C++ `capabilitiesForProtocol`.

    async fn connect(&mut self, opt: &SessionOptions) -> Result<(), ClientError> {
        info!(host = %opt.host, port = opt.port, "webdav: connecting");
        if opt.host.is_empty() {
            return Err(ClientError::OperationFailed(
                "Host is required.".to_string(),
            ));
        }
        if opt.protocol != Protocol::WebDav {
            return Err(ClientError::OperationFailed(
                "WebDavClient only supports WebDAV protocol.".to_string(),
            ));
        }
        if let Some(jump) = &opt.jump_host {
            if !jump.is_empty() {
                return Err(ClientError::Unsupported(
                    "WebDAV backend does not support SSH jump host.".to_string(),
                ));
            }
        }

        let scheme = normalize_webdav_scheme(opt.webdav_scheme);
        let port = if opt.port == 0 {
            default_port_for_scheme(scheme)
        } else {
            opt.port
        };
        let client = build_reqwest_client(opt, scheme)?;
        let conn = ConnState {
            client,
            opts: ConnOptions {
                base_url: format!(
                    "{}://{}:{port}",
                    scheme_storage_name(scheme),
                    normalize_host_authority(&opt.host)
                ),
                username: opt.username.clone(),
                password: opt.password.clone(),
            },
        };

        // C++ connect probe: PROPFIND "/" at Depth 0 must succeed.
        let resp = propfind(&conn, "/", 0).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(http_status_err("WebDAV connect probe", status));
        }

        self.state = Some(conn);
        info!("webdav: connected");
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.state = None;
        Ok(())
    }

    fn interrupt(&self) {
        interrupt_all(&self.interrupts);
    }

    fn is_connected(&self) -> bool {
        self.state.is_some()
    }

    async fn list(&mut self, remote_path: &str) -> Result<Vec<FileInfo>, ClientError> {
        let conn = self.connected_state()?.clone();
        let base_path = normalize_remote_path(remote_path);

        let resp = propfind(&conn, &base_path, 1).await?;
        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            // Mirrors C++: a missing directory yields an empty listing, no error.
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(http_status_err("WebDAV PROPFIND", status));
        }
        let body = resp.bytes().await.map_err(|e| net_err("PROPFIND", e))?;
        let xml = String::from_utf8_lossy(&body);
        let resources = parse_propfind_response(&xml).map_err(ClientError::OperationFailed)?;

        let mut out: Vec<FileInfo> = Vec::new();
        for r in &resources {
            if let Some(child_name) = is_direct_child_path(&base_path, &r.path) {
                out.push(FileInfo {
                    name: child_name,
                    is_dir: r.is_dir,
                    size: r.size,
                    has_size: r.has_size,
                    mtime: r.mtime,
                    mode: 0,
                    uid: 0,
                    gid: 0,
                });
            }
        }
        // Case-insensitive name sort, ties broken by the raw name (C++ order).
        out.sort_by(|a, b| {
            let al = a.name.to_lowercase();
            let bl = b.name.to_lowercase();
            al.cmp(&bl).then_with(|| a.name.cmp(&b.name))
        });
        debug!(path = %base_path, count = out.len(), "webdav: list complete");
        Ok(out)
    }

    async fn get(
        &mut self,
        remote: &str,
        local: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        let conn = self.connected_state()?.clone();
        let guard = CancelGuard::new(&self.interrupts);
        if resume {
            // C++ rejected resume for WebDAV; we implement it safely via Range
            // (see `download` for the 206/200/416 handling).
            let offset = tokio::fs::metadata(local)
                .await
                .map(|m| m.len())
                .unwrap_or(0);
            if offset == 0 {
                return download(
                    &conn,
                    remote,
                    local,
                    0,
                    false,
                    &guard,
                    &progress,
                    &should_cancel,
                )
                .await;
            }
            debug!(remote, offset, "webdav: resuming download with Range");
            return download(
                &conn,
                remote,
                local,
                offset,
                true,
                &guard,
                &progress,
                &should_cancel,
            )
            .await;
        }
        download(
            &conn,
            remote,
            local,
            0,
            false,
            &guard,
            &progress,
            &should_cancel,
        )
        .await
    }

    async fn put(
        &mut self,
        local: &str,
        remote: &str,
        progress: Option<ProgressCb>,
        _should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        if resume {
            // Mirrors C++: resumed uploads are not supported over WebDAV.
            return Err(ClientError::Unsupported(
                "WebDAV backend does not support resume.".to_string(),
            ));
        }
        let conn = self.connected_state()?.clone();
        let guard = CancelGuard::new(&self.interrupts);
        let total = tokio::fs::metadata(local)
            .await
            .map_err(ClientError::Io)?
            .len();
        let url = build_webdav_url(&conn.opts, remote);
        let mut builder = conn.client.put(&url);
        builder = auth_builder(builder, &conn.opts);

        call_progress(&progress, 0, total);
        let body = {
            #[cfg(feature = "stream")]
            {
                let file = tokio::fs::File::open(local)
                    .await
                    .map_err(ClientError::Io)?;
                let stream = FileBody {
                    file,
                    total,
                    done: 0,
                    sig: guard.sig.clone(),
                    progress: progress.clone(),
                    should_cancel: should_cancel.clone(),
                };
                // Sized body keeps Content-Length on the PUT (CURLOPT_INFILESIZE_LARGE).
                reqwest::Body::sized(reqwest::Body::wrap_stream(stream), total)
            }
            #[cfg(not(feature = "stream"))]
            {
                // Fallback: reqwest streams the blocking File itself with the
                // correct Content-Length; progress is coarse (start + finish).
                let file =
                    tokio::fs::File::from_std(std::fs::File::open(local).map_err(ClientError::Io)?);
                reqwest::Body::from(file)
            }
        };

        let resp = tokio::select! {
            _ = guard.wait() => return Err(ClientError::Cancelled),
            resp = builder.body(body).send() => resp,
        };
        if guard.cancelled() {
            return Err(ClientError::Cancelled);
        }
        let resp = resp.map_err(|e| net_err("PUT", e))?;
        let status = resp.status();
        if !matches!(status.as_u16(), 200 | 201 | 204) {
            return Err(http_status_err("WebDAV PUT", status));
        }
        call_progress(&progress, total, total);
        Ok(())
    }

    async fn exists(&mut self, remote_path: &str) -> Result<Option<bool>, ClientError> {
        match self.stat_inner(remote_path).await? {
            Some(info) => Ok(Some(info.is_dir)),
            None => Ok(None),
        }
    }

    async fn stat(&mut self, remote_path: &str) -> Result<FileInfo, ClientError> {
        match self.stat_inner(remote_path).await? {
            Some(info) => Ok(info),
            None => Err(ClientError::OperationFailed(format!(
                "WebDAV path not found: {remote_path}"
            ))),
        }
    }

    async fn chmod(&mut self, remote_path: &str, mode: u32) -> Result<(), ClientError> {
        let _ = (remote_path, mode);
        Err(ClientError::Unsupported(
            "WebDAV backend does not support chmod.".to_string(),
        ))
    }

    async fn chown(&mut self, remote_path: &str, uid: u32, gid: u32) -> Result<(), ClientError> {
        let _ = (remote_path, uid, gid);
        Err(ClientError::Unsupported(
            "WebDAV backend does not support chown.".to_string(),
        ))
    }

    async fn set_times(
        &mut self,
        remote_path: &str,
        atime: u64,
        mtime: u64,
    ) -> Result<(), ClientError> {
        let _ = (remote_path, atime, mtime);
        Err(ClientError::Unsupported(
            "WebDAV backend does not support timestamp updates.".to_string(),
        ))
    }

    async fn mkdir(&mut self, remote_dir: &str, mode: u32) -> Result<(), ClientError> {
        let _ = mode; // WebDAV has no directory permissions; ignored (C++ does the same).
        let conn = self.connected_state()?.clone();
        let resp = text_request(
            &conn,
            Method::from_bytes(b"MKCOL").expect("MKCOL is a valid method token"),
            remote_dir,
            None,
            &[],
        )
        .await?;
        // C++ treats 405 (collection already exists) as success too.
        if matches!(resp.status().as_u16(), 200 | 201 | 204 | 405) {
            return Ok(());
        }
        Err(http_status_err("WebDAV MKCOL", resp.status()))
    }

    async fn remove_file(&mut self, remote_path: &str) -> Result<(), ClientError> {
        let conn = self.connected_state()?.clone();
        let resp = text_request(&conn, Method::DELETE, remote_path, None, &[]).await?;
        let status = resp.status();
        if matches!(status.as_u16(), 200 | 204) {
            return Ok(());
        }
        Err(http_status_err("WebDAV DELETE", status))
    }

    async fn remove_dir(&mut self, remote_dir: &str) -> Result<(), ClientError> {
        // Deviation from C++ (which issued a single DELETE and relied on the
        // server to recurse): enumerate with PROPFIND Depth 1 and delete
        // children first, then the directory itself.  Servers that ignore
        // Depth still work because the final DELETE is tolerant of 404.
        let conn = self.connected_state()?.clone();
        let root = normalize_remote_path(remote_dir);
        let mut dirs: Vec<String> = vec![root.clone()];
        let mut files: Vec<String> = Vec::new();
        let mut idx = 0;
        while idx < dirs.len() {
            let dir = dirs[idx].clone();
            idx += 1;
            let resp = propfind(&conn, &dir, 1).await?;
            let status = resp.status();
            if status == StatusCode::NOT_FOUND {
                continue;
            }
            if !status.is_success() {
                return Err(http_status_err("WebDAV PROPFIND", status));
            }
            let body = resp.bytes().await.map_err(|e| net_err("PROPFIND", e))?;
            let xml = String::from_utf8_lossy(&body);
            let resources = parse_propfind_response(&xml).map_err(ClientError::OperationFailed)?;
            for r in &resources {
                if is_direct_child_path(&dir, &r.path).is_none() {
                    continue;
                }
                if r.is_dir {
                    dirs.push(r.path.clone());
                } else {
                    files.push(r.path.clone());
                }
            }
        }
        for file in files {
            delete_tolerant(&conn, &file).await?;
        }
        // Children before parents: BFS order guarantees children come after
        // their parent, so reverse order deletes deepest dirs first.
        for dir in dirs.iter().rev() {
            delete_tolerant(&conn, dir).await?;
        }
        Ok(())
    }

    async fn rename(&mut self, from: &str, to: &str, overwrite: bool) -> Result<(), ClientError> {
        let conn = self.connected_state()?.clone();
        let destination = build_webdav_url(&conn.opts, to);
        let headers = [
            ("Destination", destination),
            ("Overwrite", if overwrite { "T" } else { "F" }.to_string()),
        ];
        let resp = text_request(
            &conn,
            Method::from_bytes(b"MOVE").expect("MOVE is a valid method token"),
            from,
            None,
            &headers,
        )
        .await?;
        if matches!(resp.status().as_u16(), 200 | 201 | 204) {
            return Ok(());
        }
        Err(http_status_err("WebDAV MOVE", resp.status()))
    }

    async fn new_connection_like(
        &self,
        _opt: &SessionOptions,
    ) -> Result<Box<dyn SftpClient>, ClientError> {
        // Per the trait contract the returned client is NOT connected.
        Ok(Box::new(WebDavClient::new()))
    }
}

impl WebDavClient {
    /// Port of `CurlWebDavClient::stat` (PROPFIND Depth 0 on the target).
    /// `Ok(None)` means the path does not exist (404), mirroring the C++
    /// behavior of clearing the error for missing paths.
    async fn stat_inner(&mut self, remote_path: &str) -> Result<Option<FileInfo>, ClientError> {
        let conn = self.connected_state()?.clone();
        let target = normalize_remote_path(remote_path);

        let resp = propfind(&conn, &target, 0).await?;
        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(http_status_err("WebDAV PROPFIND", status));
        }
        let body = resp.bytes().await.map_err(|e| net_err("PROPFIND", e))?;
        let xml = String::from_utf8_lossy(&body);
        let resources = parse_propfind_response(&xml).map_err(ClientError::OperationFailed)?;

        // Exact path match preferred; single-resource responses are accepted
        // (some servers collapse Depth 0 responses), everything else is a miss.
        let found = resources.iter().find(|r| r.path == target).or_else(|| {
            if resources.len() == 1 {
                resources.first()
            } else {
                None
            }
        });
        let Some(r) = found else {
            return Ok(None);
        };
        let name = if target == "/" {
            "/".to_string()
        } else {
            target.rsplit('/').next().unwrap_or_default().to_string()
        };
        Ok(Some(FileInfo {
            name,
            is_dir: r.is_dir,
            size: r.size,
            has_size: r.has_size,
            mtime: r.mtime,
            mode: 0,
            uid: 0,
            gid: 0,
        }))
    }
}

// ---------------------------------------------------------------------------
// Client construction (connect support).
// ---------------------------------------------------------------------------

fn with_proxy_auth(proxy: Proxy, opt: &SessionOptions) -> Proxy {
    if let Some(user) = &opt.proxy_username {
        if !user.is_empty() {
            return proxy.basic_auth(user, opt.proxy_password.as_deref().unwrap_or(""));
        }
    }
    proxy
}

fn require_proxy_endpoint(opt: &SessionOptions) -> Result<(), ClientError> {
    if opt.proxy_host.is_empty() || opt.proxy_port == 0 {
        return Err(ClientError::OperationFailed(
            "WebDAV proxy requires host and port.".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "socks")]
fn build_socks5_proxy(opt: &SessionOptions) -> Result<Proxy, ClientError> {
    require_proxy_endpoint(opt)?;
    // socks5h = remote DNS resolution through the proxy
    // (CURLPROXY_SOCKS5_HOSTNAME).
    let proxy =
        Proxy::all(format!("socks5h://{}:{}", opt.proxy_host, opt.proxy_port)).map_err(|e| {
            ClientError::OperationFailed(format!("Could not configure WebDAV SOCKS5 proxy: {e}"))
        })?;
    Ok(with_proxy_auth(proxy, opt))
}

fn build_http_proxy(opt: &SessionOptions) -> Result<Proxy, ClientError> {
    require_proxy_endpoint(opt)?;
    // reqwest always CONNECT-tunnels https through http proxies, which is the
    // CURLPROXY_HTTP + CURLOPT_HTTPPROXYTUNNEL=1 combination.
    let proxy =
        Proxy::all(format!("http://{}:{}", opt.proxy_host, opt.proxy_port)).map_err(|e| {
            ClientError::OperationFailed(format!("Could not configure WebDAV proxy: {e}"))
        })?;
    Ok(with_proxy_auth(proxy, opt))
}

/// Port of `configureCommonCurlHandle` + `CurlWebDavClient::connect`
/// pre-flight checks: timeouts, TLS verification policy, custom CA bundle and
/// proxy configuration.
fn build_reqwest_client(opt: &SessionOptions, scheme: WebDavScheme) -> Result<Client, ClientError> {
    let mut builder = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        // libcurl never follows redirects by default; WebDAV verbs must not
        // be silently redirected either.
        .redirect(reqwest::redirect::Policy::none());

    if matches!(scheme, WebDavScheme::Https) {
        if !opt.webdav_verify_peer {
            // CURLOPT_SSL_VERIFYPEER=0 + CURLOPT_SSL_VERIFYHOST=0.
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }
        if let Some(ca_path) = &opt.webdav_ca_cert_path {
            if !ca_path.is_empty() {
                // CURLOPT_CAINFO: an extra root store on top of the defaults.
                let pem = std::fs::read(ca_path).map_err(ClientError::Io)?;
                let cert = Certificate::from_pem(&pem).map_err(|e| {
                    ClientError::OperationFailed(format!(
                        "Could not load WebDAV CA bundle '{ca_path}': {e}"
                    ))
                })?;
                builder = builder.add_root_certificate(cert);
            }
        }
    }

    match normalize_proxy_type(opt.proxy_type) {
        ProxyType::None => {}
        ProxyType::HttpConnect => {
            let proxy = build_http_proxy(opt)?;
            builder = builder.proxy(proxy);
        }
        ProxyType::Socks5 => {
            #[cfg(feature = "socks")]
            {
                let proxy = build_socks5_proxy(opt)?;
                builder = builder.proxy(proxy);
            }
            #[cfg(not(feature = "socks"))]
            {
                return Err(ClientError::Unsupported(
                    "SOCKS5 proxy support requires the reqwest `socks` feature.".to_string(),
                ));
            }
        }
    }

    builder.build().map_err(|e| {
        ClientError::OperationFailed(format!("Could not build WebDAV HTTP client: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_paths() {
        assert_eq!(normalize_remote_path(""), "/");
        assert_eq!(normalize_remote_path("a/b"), "/a/b");
        assert_eq!(normalize_remote_path(r"a\b"), "/a/b");
        assert_eq!(normalize_remote_path("/a//b/"), "/a/b");
        assert_eq!(normalize_remote_dir_path("/a"), "/a/");
        assert_eq!(normalize_remote_dir_path("/"), "/");
    }

    #[test]
    fn href_extraction() {
        assert_eq!(extract_path_from_href(""), "/");
        assert_eq!(extract_path_from_href("/a/b"), "/a/b");
        assert_eq!(
            extract_path_from_href("https://host:443/a/b?x=1#frag"),
            "/a/b"
        );
        assert_eq!(extract_path_from_href("https://host:443"), "/");
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(decode_percent("%48%65llo%20World"), "Hello World");
        assert_eq!(decode_percent("plain"), "plain");
        assert_eq!(decode_percent("100%25"), "100%");
    }

    #[test]
    fn http_dates() {
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert!(parse_http_date("2024-01-15T10:30:00Z").is_some());
        assert!(parse_http_date("1234567890").is_some());
        assert!(parse_http_date("Sun Nov  6 08:49:37 1994").is_some());
        assert!(parse_http_date("not a date").is_none());
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_http_status_code("HTTP/1.1 207 Multi-Status"), 207);
        assert_eq!(parse_http_status_code("garbage"), 0);
    }

    #[test]
    fn url_building() {
        let opts = ConnOptions {
            base_url: "https://host:443".to_string(),
            username: String::new(),
            password: None,
        };
        assert_eq!(
            build_webdav_url(&opts, "/a b/c"),
            "https://host:443/a%20b/c"
        );
        assert_eq!(build_webdav_url(&opts, ""), "https://host:443/");
    }

    #[test]
    fn direct_child() {
        assert_eq!(is_direct_child_path("/a", "/a/b"), Some("b".to_string()));
        assert_eq!(is_direct_child_path("/", "/x"), Some("x".to_string()));
        assert!(is_direct_child_path("/a", "/a").is_none());
        assert!(is_direct_child_path("/a", "/a/b/c").is_none());
        assert!(is_direct_child_path("/a", "/ab").is_none());
    }

    #[test]
    fn parse_multistatus_sample() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/remote.php/dav/files/user/</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype><d:collection/></d:resourcetype>
        <d:getlastmodified>Mon, 15 Jan 2024 10:30:00 GMT</d:getlastmodified>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
    <d:propstat>
      <d:prop><d:getcontentlength/></d:prop>
      <d:status>HTTP/1.1 404 Not Found</d:status>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/files/user/file%20name.txt</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype/>
        <d:getcontentlength>12345</d:getcontentlength>
        <d:getlastmodified>Mon, 15 Jan 2024 10:30:00 GMT</d:getlastmodified>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;
        let resources = parse_propfind_response(xml).expect("parse");
        assert_eq!(resources.len(), 2);

        let dir = &resources[0];
        assert_eq!(dir.path, "/remote.php/dav/files/user");
        assert!(dir.is_dir);
        assert!(!dir.has_size);
        assert!(dir.has_mtime);
        assert_eq!(dir.mtime, 1_705_314_600);

        let file = &resources[1];
        assert_eq!(file.path, "/remote.php/dav/files/user/file name.txt");
        assert!(!file.is_dir);
        assert!(file.has_size);
        assert_eq!(file.size, 12345);
        assert!(file.has_mtime);
    }

    #[test]
    fn parse_multistatus_empty() {
        assert!(parse_propfind_response("").is_err());
        assert!(parse_propfind_response("<d:multistatus xmlns:d=\"DAV:\"/>").is_err());
    }

    #[test]
    fn parse_unsigned() {
        assert_eq!(parse_unsigned_dec("12345"), Some(12345));
        assert_eq!(parse_unsigned_dec(""), None);
        assert_eq!(parse_unsigned_dec("12a"), None);
        assert_eq!(parse_unsigned_dec("99999999999999999999999999"), None);
    }
}
