//! Automatic route selection for sites with alternate routes (Rust-only
//! feature; no C++ counterpart).
//!
//! A [`SessionOptions`] carrying `routes` describes several endpoints for the
//! same logical server - typically a LAN address plus a remote
//! Cloudflare/cloudflared path. This module turns them into connectable
//! [`RouteCandidate`]s, probes their first hops (`freescp_core::route`),
//! ranks the results (cached in `route-cache.toml`), and drives the
//! connect-time failover loop:
//!
//! 1. `Manual` policy or feature disabled or a single candidate: today's
//!    behavior - connect to the primary (or the pinned route) with no probing
//!    and no failover.
//! 2. `Auto` with more than one candidate: serve the attempt order from the
//!    cache when fresh, else probe all first hops concurrently within the
//!    budget and cache the ranking. Routes whose *full connect* failed
//!    recently are demoted for [`FAILURE_BACKOFF`] even when their TCP probe
//!    succeeds.
//! 3. Attempt in order; only transport-level failures advance to the next
//!    candidate (auth, host-key, and user-cancel errors surface immediately).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use freescp_core::route::{
    probe_targets, rank_probes, ProbeHopKind, ProbeResult, ProbeStatus, ProbeTarget, RoutePolicy,
};
use freescp_core::{default_port_for_proxy_type, ProxyType, SessionOptions};
use serde::{Deserialize, Serialize};

use crate::connect::{tr, ConnectError};

/// Route-ranking cache inside the FreeSCP config directory.
pub const ROUTE_CACHE_FILE: &str = "route-cache.toml";

/// A route whose full connect failed is demoted for this long, even when its
/// first-hop probe still succeeds (the "port open but service broken" case).
pub const FAILURE_BACKOFF: Duration = Duration::from_secs(60);

/// Cache entries not updated for this long are pruned on save.
const CACHE_PRUNE_AGE_SECS: i64 = 30 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Settings + candidates
// ---------------------------------------------------------------------------

/// Settings snapshot for route selection (see `Preferences::route_settings`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSettings {
    pub auto_enabled: bool,
    pub probe_budget: Duration,
    pub cache_ttl: Duration,
}

/// One connectable endpoint: the complete options plus its probe target.
#[derive(Debug, Clone)]
pub struct RouteCandidate {
    /// Empty for the site's primary endpoint.
    pub label: String,
    pub options: SessionOptions,
    /// First hop to probe; `None` when the candidate cannot be measured.
    pub probe: Option<ProbeTarget>,
}

impl RouteCandidate {
    /// Human-facing name: the label, or the host for the primary endpoint.
    pub fn display_label(&self) -> &str {
        if self.label.is_empty() {
            &self.options.host
        } else {
            &self.label
        }
    }
}

/// The route a session ended up using (status display, session record).
#[derive(Debug, Clone, Default)]
pub struct RouteChoice {
    /// Empty for the primary endpoint.
    pub label: String,
    /// The endpoint actually connected to (may differ from the site's primary
    /// host after failover).
    pub host: String,
    pub latency: Option<Duration>,
    pub is_lan: bool,
    /// Display labels of routes that failed before the successful one.
    pub failed_labels: Vec<String>,
}

impl RouteChoice {
    /// Status-line suffix describing the chosen route, e.g.
    /// `" via LAN (3 ms)"`. Empty for the primary endpoint and for
    /// route-less connects (today's status text is unchanged).
    pub fn status_suffix(&self) -> String {
        if self.label.is_empty() {
            return String::new();
        }
        let mut suffix = format!(" via {}", self.label);
        if let Some(latency) = self.latency {
            suffix.push_str(&format!(" ({} ms)", latency.as_millis()));
        }
        suffix
    }
}

/// Builds the candidate list: the primary endpoint first, then each route
/// with inherited fields resolved. Every candidate gets `~/.ssh/config`
/// resolution applied (aliases, ports, identities, ProxyJump), exactly like
/// the primary does today in `connect::start_connect`.
pub fn build_candidates(opt: &SessionOptions) -> Vec<RouteCandidate> {
    let mut candidates = Vec::with_capacity(opt.routes.len() + 1);

    let mut primary = opt.clone();
    primary.routes.clear();
    crate::connect::apply_ssh_config_defaults(&mut primary);
    candidates.push(RouteCandidate {
        label: String::new(),
        probe: probe_target_for(&primary),
        options: primary,
    });

    for (idx, route) in opt.routes.iter().enumerate() {
        // Routes without a label get a stable generated one so cache keys,
        // pins, and status lines stay unambiguous.
        let label = if route.label.trim().is_empty() {
            format!("route {}", idx + 1)
        } else {
            route.label.trim().to_string()
        };
        let mut o = opt.clone();
        o.routes.clear();
        o.route_policy = RoutePolicy::Auto;
        o.route_pin = None;
        o.host = if route.host.trim().is_empty() {
            opt.host.trim().to_string()
        } else {
            route.host.trim().to_string()
        };
        o.port = if route.port != 0 {
            route.port
        } else {
            opt.port
        };
        if let Some(user) = route
            .username
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            o.username = user.to_string();
        }
        if let Some(key) = route
            .private_key_path
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
        {
            o.private_key_path = Some(key.to_string());
        }

        // A route owns its transport: direct unless the route itself
        // configures a proxy or jump host. Inheriting the site's tunnel would
        // route the LAN endpoint through the Cloudflare bastion.
        let use_jump = route
            .jump_host
            .as_deref()
            .map(str::trim)
            .is_some_and(|h| !h.is_empty());
        let use_proxy = route.proxy_type != ProxyType::None && !route.proxy_host.trim().is_empty();
        if use_jump {
            clear_proxy(&mut o);
            o.jump_host = route.jump_host.clone();
            o.jump_port = route.jump_port;
            // Jump credentials may come from the site (same bastion family).
            o.jump_username = route
                .jump_username
                .clone()
                .or_else(|| opt.jump_username.clone());
            o.jump_private_key_path = route
                .jump_private_key_path
                .clone()
                .or_else(|| opt.jump_private_key_path.clone());
        } else if use_proxy {
            clear_jump(&mut o);
            o.proxy_type = route.proxy_type;
            o.proxy_host = route.proxy_host.trim().to_string();
            o.proxy_port = if route.proxy_port != 0 {
                route.proxy_port
            } else {
                default_port_for_proxy_type(route.proxy_type)
            };
            o.proxy_username = route
                .proxy_username
                .clone()
                .or_else(|| opt.proxy_username.clone());
            // The keyring stores one proxy password per site; reused here.
            o.proxy_password = opt.proxy_password.clone();
        } else {
            clear_proxy(&mut o);
            clear_jump(&mut o);
        }

        crate::connect::apply_ssh_config_defaults(&mut o);
        candidates.push(RouteCandidate {
            label,
            probe: probe_target_for(&o),
            options: o,
        });
    }
    candidates
}

fn clear_proxy(o: &mut SessionOptions) {
    o.proxy_type = ProxyType::None;
    o.proxy_host.clear();
    o.proxy_port = 0;
    o.proxy_username = None;
    o.proxy_password = None;
}

fn clear_jump(o: &mut SessionOptions) {
    o.jump_host = None;
    o.jump_port = 22;
    o.jump_username = None;
    o.jump_private_key_path = None;
}

/// First hop that must be reachable for the candidate to connect: the
/// bastion, the proxy, or the target itself.
fn probe_target_for(o: &SessionOptions) -> Option<ProbeTarget> {
    if let Some(jump) = o
        .jump_host
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
    {
        return Some(ProbeTarget {
            label: String::new(),
            host: jump.to_string(),
            port: if o.jump_port == 0 { 22 } else { o.jump_port },
            kind: ProbeHopKind::Jump,
        });
    }
    if o.proxy_type != ProxyType::None && !o.proxy_host.trim().is_empty() {
        return Some(ProbeTarget {
            label: String::new(),
            host: o.proxy_host.trim().to_string(),
            port: if o.proxy_port == 0 {
                default_port_for_proxy_type(o.proxy_type)
            } else {
                o.proxy_port
            },
            kind: ProbeHopKind::Proxy,
        });
    }
    let host = o.host.trim();
    if host.is_empty() {
        return None;
    }
    Some(ProbeTarget {
        label: String::new(),
        host: host.to_string(),
        port: o.port,
        kind: ProbeHopKind::Direct,
    })
}

/// Stable cache key: hash of the sorted candidate descriptors. Editing a
/// site's routes or endpoints naturally produces a new key.
pub(crate) fn cache_key(candidates: &[RouteCandidate]) -> String {
    let mut parts: Vec<String> = candidates
        .iter()
        .map(|c| {
            let transport = if c
                .options
                .jump_host
                .as_deref()
                .map(str::trim)
                .is_some_and(|h| !h.is_empty())
            {
                format!("jump:{}", c.options.jump_host.clone().unwrap_or_default())
            } else if c.options.proxy_type != ProxyType::None {
                format!("proxy:{}", c.options.proxy_host)
            } else {
                "direct".to_string()
            };
            format!(
                "{}|{}|{}|{}",
                c.label, c.options.host, c.options.port, transport
            )
        })
        .collect();
    parts.sort();
    let joined = parts.join(";");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    joined.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ---------------------------------------------------------------------------
// Probe cache (route-cache.toml)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CachedProbe {
    label: String,
    reachable: bool,
    latency_ms: Option<u64>,
    is_lan: bool,
    /// Unix time of the last full-connect failure (backoff tracking).
    failure_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct CacheEntry {
    updated_at_unix: i64,
    last_good: Option<String>,
    probes: Vec<CachedProbe>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct RouteCacheDocument {
    entries: HashMap<String, CacheEntry>,
}

/// Persisted probe rankings, keyed by [`cache_key`]. All mutation methods
/// take the current unix time so tests can control expiry.
#[derive(Debug, Clone, Default)]
pub struct RouteCache {
    entries: HashMap<String, CacheEntry>,
}

impl RouteCache {
    pub fn load(dir: &Path) -> RouteCache {
        let path = dir.join(ROUTE_CACHE_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<RouteCacheDocument>(&text)
                .map(|doc| RouteCache {
                    entries: doc.entries,
                })
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        "Could not parse route cache {}: {e}; starting empty",
                        path.display()
                    );
                    RouteCache::default()
                }),
            Err(_) => RouteCache::default(),
        }
    }

    pub fn save(&self, dir: &Path, now: i64) -> Result<(), String> {
        let mut doc = RouteCacheDocument {
            entries: self.entries.clone(),
        };
        let cutoff = now - CACHE_PRUNE_AGE_SECS;
        doc.entries.retain(|_, e| e.updated_at_unix >= cutoff);
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Could not create config directory {}: {e}", dir.display()))?;
        let text = toml::to_string_pretty(&doc)
            .map_err(|e| format!("Could not serialize route cache: {e}"))?;
        std::fs::write(dir.join(ROUTE_CACHE_FILE), text)
            .map_err(|e| format!("Could not write route cache: {e}"))
    }

    /// Cached probes when the entry is younger than `ttl`, reconstructed as
    /// `ProbeResult`s for [`rank_probes`].
    pub fn fresh_probes(&self, key: &str, ttl: Duration, now: i64) -> Option<Vec<ProbeResult>> {
        let entry = self.entries.get(key)?;
        let ttl_secs = ttl.as_secs().max(1);
        if now - entry.updated_at_unix > ttl_secs as i64 {
            return None;
        }
        Some(
            entry
                .probes
                .iter()
                .map(|p| ProbeResult {
                    label: p.label.clone(),
                    status: if p.reachable {
                        ProbeStatus::Reachable {
                            latency: Duration::from_millis(p.latency_ms.unwrap_or(u64::MAX)),
                            addr: "0.0.0.0".parse().unwrap(),
                            is_lan: p.is_lan,
                        }
                    } else {
                        ProbeStatus::Unreachable("cached".to_string())
                    },
                })
                .collect(),
        )
    }

    pub fn sticky_label(&self, key: &str) -> Option<String> {
        self.entries.get(key).and_then(|e| e.last_good.clone())
    }

    /// Labels whose full connect failed within [`FAILURE_BACKOFF`].
    pub fn backoff_labels(&self, key: &str, now: i64) -> Vec<String> {
        let Some(entry) = self.entries.get(key) else {
            return Vec::new();
        };
        entry
            .probes
            .iter()
            .filter(|p| {
                p.failure_at_unix
                    .is_some_and(|at| now.saturating_sub(at) < FAILURE_BACKOFF.as_secs() as i64)
            })
            .map(|p| p.label.clone())
            .collect()
    }

    pub fn record_probes(&mut self, key: &str, probes: &[ProbeResult], now: i64) {
        let entry = self.entries.entry(key.to_string()).or_default();
        entry.updated_at_unix = now;
        let previous: HashMap<String, CachedProbe> = entry
            .probes
            .iter()
            .map(|p| (p.label.clone(), p.clone()))
            .collect();
        entry.probes = probes
            .iter()
            .map(|r| {
                let mut cached = match &r.status {
                    ProbeStatus::Reachable {
                        latency, is_lan, ..
                    } => CachedProbe {
                        label: r.label.clone(),
                        reachable: true,
                        latency_ms: Some(latency.as_millis() as u64),
                        is_lan: *is_lan,
                        failure_at_unix: None,
                    },
                    _ => CachedProbe {
                        label: r.label.clone(),
                        reachable: false,
                        latency_ms: None,
                        is_lan: false,
                        failure_at_unix: None,
                    },
                };
                // A fresh probe clears stale failures only when it proves the
                // first hop answers again is not enough - the failure marker
                // refers to the full connect. Keep it; the backoff expiry and
                // a later successful connect clear it.
                if let Some(prev) = previous.get(&r.label) {
                    cached.failure_at_unix = prev.failure_at_unix;
                }
                cached
            })
            .collect();
    }

    pub fn record_failure(&mut self, key: &str, label: &str, now: i64) {
        let entry = self.entries.entry(key.to_string()).or_default();
        if let Some(probe) = entry.probes.iter_mut().find(|p| p.label == label) {
            probe.failure_at_unix = Some(now);
        } else {
            entry.probes.push(CachedProbe {
                label: label.to_string(),
                reachable: false,
                latency_ms: None,
                is_lan: false,
                failure_at_unix: Some(now),
            });
        }
    }

    pub fn record_success(&mut self, key: &str, label: &str) {
        let entry = self.entries.entry(key.to_string()).or_default();
        if let Some(probe) = entry.probes.iter_mut().find(|p| p.label == label) {
            probe.failure_at_unix = None;
        }
        entry.last_good = Some(label.to_string());
    }
}

// ---------------------------------------------------------------------------
// Failover classification
// ---------------------------------------------------------------------------

/// Whether a failed connect attempt should advance to the next candidate.
///
/// Classification runs on the already-translated error text: auth and
/// host-key rejections (and user cancels) must surface immediately, while
/// transport-level failures cannot be fixed by retrying the same endpoint.
pub fn should_fail_over(err: &ConnectError) -> bool {
    match err {
        ConnectError::Cancelled => false,
        ConnectError::Failed(msg) => {
            let lower = msg.to_lowercase();
            crate::remote::is_likely_transport_error(&lower)
                || lower.contains("connection refused")
                || lower.contains("could not resolve")
                || lower.contains("unreachable")
        }
    }
}

// ---------------------------------------------------------------------------
// Connect with routing
// ---------------------------------------------------------------------------

/// Progress sink for [`connect_routed`]: status-bar lines while probing and
/// failing over.
pub type RouteReporter = Arc<dyn Fn(&str) + Send + Sync>;

/// Probes the candidates (or serves the order from a fresh cache entry) and
/// connects through the ranked routes, failing over on transport errors.
///
/// `connector` receives complete per-candidate options; tests inject stubs.
/// `report` (optional) receives progress lines for the status bar.
pub async fn connect_routed<T, F, Fut>(
    opt: &SessionOptions,
    settings: &RouteSettings,
    cache_dir: &Path,
    report: Option<RouteReporter>,
    connector: F,
) -> Result<(T, RouteChoice), ConnectError>
where
    F: Fn(SessionOptions) -> Fut,
    Fut: Future<Output = Result<T, ConnectError>>,
{
    let candidates = build_candidates(opt);
    let now = chrono::Utc::now().timestamp();
    let manual = opt.route_policy == RoutePolicy::Manual;

    // The cache file is only read when the auto path actually runs (the
    // quick-connect dialog and route-less sites must not pay for it).
    let mut cache: Option<RouteCache> = None;
    let mut cache_key_opt: Option<String> = None;
    let mut probe_meta: HashMap<String, (Option<Duration>, bool)> = HashMap::new();

    let order: Vec<usize> = if manual || !settings.auto_enabled || candidates.len() < 2 {
        if manual {
            pinned_order(&candidates, opt.route_pin.as_deref())
        } else {
            vec![0]
        }
    } else {
        let mut loaded = RouteCache::load(cache_dir);
        let key = cache_key(&candidates);
        let probes = match loaded.fresh_probes(&key, settings.cache_ttl, now) {
            Some(probes) => probes,
            None => {
                if let Some(report) = &report {
                    report(&tr("Probing routes...", &[]));
                }
                let probes = run_probes(&candidates, settings.probe_budget).await;
                loaded.record_probes(&key, &probes, now);
                if let Err(e) = loaded.save(cache_dir, now) {
                    tracing::warn!("Could not persist route cache: {e}");
                }
                probes
            }
        };
        for probe in &probes {
            probe_meta.insert(probe.label.clone(), (probe.latency(), probe.is_lan()));
        }
        let sticky = loaded.sticky_label(&key);
        let mut order = rank_probes(&probes, sticky.as_deref());
        // Demote routes whose full connect failed recently.
        let backoff: HashSet<String> = loaded.backoff_labels(&key, now).into_iter().collect();
        if !backoff.is_empty() {
            order.sort_by_key(|&idx| backoff.contains(&candidates[idx].label));
        }
        cache_key_opt = Some(key);
        cache = Some(loaded);
        order
    };

    let mut choice = RouteChoice::default();
    let mut last_err: Option<ConnectError> = None;
    for (attempt, &idx) in order.iter().enumerate() {
        let cand = &candidates[idx];
        if attempt > 0 {
            if let Some(prev) = choice.failed_labels.last() {
                if let Some(report) = &report {
                    report(&tr(
                        "Route %1 failed; trying %2...",
                        &[prev.clone(), cand.display_label().to_string()],
                    ));
                }
            }
        }
        match connector(cand.options.clone()).await {
            Ok(value) => {
                if let (Some(key), Some(cache)) = (&cache_key_opt, cache.as_mut()) {
                    cache.record_success(key, &cand.label);
                    if let Err(e) = cache.save(cache_dir, now) {
                        tracing::warn!("Could not persist route cache: {e}");
                    }
                }
                if let Some((latency, is_lan)) = probe_meta.get(&cand.label) {
                    choice.latency = *latency;
                    choice.is_lan = *is_lan;
                }
                choice.label = cand.label.clone();
                choice.host = cand.options.host.clone();
                return Ok((value, choice));
            }
            Err(err) => {
                let more_candidates = attempt + 1 < order.len();
                if more_candidates && should_fail_over(&err) {
                    if let (Some(key), Some(cache)) = (&cache_key_opt, cache.as_mut()) {
                        cache.record_failure(key, &cand.label, now);
                        if let Err(e) = cache.save(cache_dir, now) {
                            tracing::warn!("Could not persist route cache: {e}");
                        }
                    }
                    choice.failed_labels.push(cand.display_label().to_string());
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| ConnectError::Failed("No route to the server.".to_string())))
}

/// Attempt order for the manual policy: the pinned route only.
fn pinned_order(candidates: &[RouteCandidate], pin: Option<&str>) -> Vec<usize> {
    if let Some(pin) = pin.map(str::trim).filter(|p| !p.is_empty()) {
        if let Some(idx) = candidates.iter().position(|c| c.label == pin) {
            return vec![idx];
        }
    }
    vec![0]
}

pub(crate) async fn run_probes(
    candidates: &[RouteCandidate],
    budget: Duration,
) -> Vec<ProbeResult> {
    let mut targets: Vec<ProbeTarget> = Vec::with_capacity(candidates.len());
    let mut labels: Vec<String> = Vec::with_capacity(candidates.len());
    for cand in candidates {
        if let Some(mut target) = cand.probe.clone() {
            target.label = cand.label.clone();
            targets.push(target);
            labels.push(cand.label.clone());
        }
    }
    let results = probe_targets(&targets, budget).await;
    let mut by_label: HashMap<String, ProbeResult> =
        results.into_iter().map(|r| (r.label.clone(), r)).collect();
    labels
        .into_iter()
        .map(|label| {
            by_label.remove(&label).unwrap_or(ProbeResult {
                label,
                status: ProbeStatus::Unprobeable("probe did not run".to_string()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn settings() -> RouteSettings {
        RouteSettings {
            auto_enabled: true,
            probe_budget: Duration::from_millis(200),
            cache_ttl: Duration::from_secs(300),
        }
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "freescp-routing-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn opts_with_routes() -> SessionOptions {
        SessionOptions {
            host: "primary.invalid".to_string(),
            port: 22,
            username: "root".to_string(),
            jump_host: Some("cf-bastion.invalid".to_string()),
            routes: vec![
                freescp_core::route::SessionRoute {
                    label: "LAN".to_string(),
                    host: "192.168.1.50".to_string(),
                    ..Default::default()
                },
                freescp_core::route::SessionRoute {
                    label: "VPN".to_string(),
                    host: "10.8.0.5".to_string(),
                    port: 2222,
                    username: Some("vpnuser".to_string()),
                    ..Default::default()
                },
            ],
            ..SessionOptions::default()
        }
    }

    #[test]
    fn candidates_inherit_and_override() {
        let candidates = build_candidates(&opts_with_routes());
        assert_eq!(candidates.len(), 3);

        // Primary keeps its jump host and is probed at the bastion.
        assert_eq!(candidates[0].label, "");
        assert_eq!(candidates[0].options.host, "primary.invalid");
        assert_eq!(
            candidates[0].options.jump_host.as_deref(),
            Some("cf-bastion.invalid")
        );
        let probe = candidates[0].probe.as_ref().unwrap();
        assert_eq!(probe.kind, ProbeHopKind::Jump);
        assert_eq!(probe.host, "cf-bastion.invalid");

        // LAN route: inherits host? no - own host, inherits port and user,
        // and drops the site's jump (direct transport).
        let lan = &candidates[1];
        assert_eq!(lan.label, "LAN");
        assert_eq!(lan.options.host, "192.168.1.50");
        assert_eq!(lan.options.port, 22);
        assert_eq!(lan.options.username, "root");
        assert_eq!(lan.options.jump_host, None);
        assert_eq!(lan.options.proxy_type, ProxyType::None);
        let probe = lan.probe.as_ref().unwrap();
        assert_eq!(probe.kind, ProbeHopKind::Direct);
        assert_eq!(probe.host, "192.168.1.50");

        // VPN route overrides port + user.
        let vpn = &candidates[2];
        assert_eq!(vpn.options.port, 2222);
        assert_eq!(vpn.options.username, "vpnuser");
    }

    #[test]
    fn cache_key_changes_with_candidates() {
        let a = build_candidates(&opts_with_routes());
        let mut other = opts_with_routes();
        other.routes.remove(0);
        let b = build_candidates(&other);
        assert_ne!(cache_key(&a), cache_key(&b));
        assert_eq!(
            cache_key(&a),
            cache_key(&build_candidates(&opts_with_routes()))
        );
    }

    #[test]
    fn cache_roundtrip_ttl_and_backoff() {
        let dir = temp_dir("cache");
        let key = "k1".to_string();
        let probes = vec![
            ProbeResult {
                label: "LAN".to_string(),
                status: ProbeStatus::Reachable {
                    latency: Duration::from_millis(3),
                    addr: "192.168.1.50".parse().unwrap(),
                    is_lan: true,
                },
            },
            ProbeResult {
                label: "WAN".to_string(),
                status: ProbeStatus::Unreachable("refused".to_string()),
            },
        ];

        let mut cache = RouteCache::load(&dir);
        assert!(cache
            .fresh_probes(&key, Duration::from_secs(300), 1000)
            .is_none());
        cache.record_probes(&key, &probes, 1000);
        let fresh = cache
            .fresh_probes(&key, Duration::from_secs(300), 1000)
            .unwrap();
        assert_eq!(fresh.len(), 2);
        assert!(fresh[0].reachable());
        assert!(fresh[0].is_lan());
        // Expired after the TTL.
        assert!(cache
            .fresh_probes(&key, Duration::from_secs(300), 1000 + 301)
            .is_none());

        cache.record_failure(&key, "LAN", 1100);
        assert_eq!(cache.backoff_labels(&key, 1100 + 30), vec!["LAN"]);
        assert!(cache.backoff_labels(&key, 1100 + 61).is_empty());
        cache.record_success(&key, "LAN");
        assert!(cache.backoff_labels(&key, 1100 + 30).is_empty());
        assert_eq!(cache.sticky_label(&key).as_deref(), Some("LAN"));

        cache.save(&dir, 1200).unwrap();
        let reloaded = RouteCache::load(&dir);
        assert!(reloaded
            .fresh_probes(&key, Duration::from_secs(300), 1200)
            .is_some());
        assert_eq!(reloaded.sticky_label(&key).as_deref(), Some("LAN"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn failure_classification() {
        assert!(should_fail_over(&ConnectError::Failed(
            "Connection timed out.".to_string()
        )));
        assert!(should_fail_over(&ConnectError::Failed(
            "Connection refused by the server.".to_string()
        )));
        assert!(should_fail_over(&ConnectError::Failed(
            "Could not resolve the server hostname.".to_string()
        )));
        assert!(should_fail_over(&ConnectError::Failed(
            "Network unavailable or host unreachable.".to_string()
        )));
        assert!(!should_fail_over(&ConnectError::Failed(
            "Authentication failed.".to_string()
        )));
        assert!(!should_fail_over(&ConnectError::Failed(
            "Host key verification failed.".to_string()
        )));
        assert!(!should_fail_over(&ConnectError::Failed(
            "Permission denied.".to_string()
        )));
        assert!(!should_fail_over(&ConnectError::Cancelled));
    }

    #[tokio::test]
    async fn disabled_or_single_candidate_uses_primary_only() {
        let dir = temp_dir("primary-only");
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let seen = attempts.clone();
        let result = connect_routed(
            &opts_with_routes(),
            &RouteSettings {
                auto_enabled: false,
                ..settings()
            },
            &dir,
            None,
            move |o: SessionOptions| {
                let seen = seen.clone();
                async move {
                    seen.lock().unwrap().push(o.host.clone());
                    Err::<u8, _>(ConnectError::Failed("Connection timed out.".to_string()))
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*attempts.lock().unwrap(), vec!["primary.invalid"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn manual_pin_uses_pinned_route_only() {
        let dir = temp_dir("manual");
        let mut opt = opts_with_routes();
        opt.route_policy = RoutePolicy::Manual;
        opt.route_pin = Some("VPN".to_string());
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let seen = attempts.clone();
        let (value, choice) =
            connect_routed(&opt, &settings(), &dir, None, move |o: SessionOptions| {
                let seen = seen.clone();
                async move {
                    seen.lock().unwrap().push(o.host.clone());
                    Ok::<u8, _>(7)
                }
            })
            .await
            .unwrap();
        assert_eq!(value, 7);
        assert_eq!(choice.label, "VPN");
        assert_eq!(*attempts.lock().unwrap(), vec!["10.8.0.5"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn manual_pin_missing_falls_back_to_primary() {
        let dir = temp_dir("manual-missing");
        let mut opt = opts_with_routes();
        opt.route_policy = RoutePolicy::Manual;
        opt.route_pin = Some("nope".to_string());
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let seen = attempts.clone();
        let (_, choice) =
            connect_routed(&opt, &settings(), &dir, None, move |o: SessionOptions| {
                let seen = seen.clone();
                async move {
                    seen.lock().unwrap().push(o.host.clone());
                    Ok::<u8, _>(1)
                }
            })
            .await
            .unwrap();
        assert_eq!(choice.label, "");
        assert_eq!(*attempts.lock().unwrap(), vec!["primary.invalid"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn transport_failure_fails_over_to_next_route() {
        let dir = temp_dir("failover");
        // Probe budget covers all-unresolvable `.invalid` hosts quickly; the
        // ranking then follows input order (all unreachable), so the loop
        // walks primary -> LAN -> VPN.
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let (seen, counted) = (attempts.clone(), count.clone());
        let (value, choice) = connect_routed(
            &opts_with_routes(),
            &settings(),
            &dir,
            None,
            move |o: SessionOptions| {
                let (seen, counted) = (seen.clone(), counted.clone());
                async move {
                    seen.lock().unwrap().push(o.host.clone());
                    if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err::<u8, _>(ConnectError::Failed("Connection timed out.".to_string()))
                    } else {
                        Ok(42)
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 42);
        assert_eq!(choice.failed_labels, vec!["primary.invalid".to_string()]);
        assert_eq!(
            *attempts.lock().unwrap(),
            vec!["primary.invalid", "192.168.1.50"]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn auth_failure_does_not_fail_over() {
        let dir = temp_dir("auth-stop");
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let seen = attempts.clone();
        let result = connect_routed(
            &opts_with_routes(),
            &settings(),
            &dir,
            None,
            move |o: SessionOptions| {
                let seen = seen.clone();
                async move {
                    seen.lock().unwrap().push(o.host.clone());
                    Err::<u8, _>(ConnectError::Failed("Authentication failed.".to_string()))
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
