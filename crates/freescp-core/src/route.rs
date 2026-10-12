//! Alternate-route model and first-hop probing for automatic route
//! selection (Rust-only feature; no C++ counterpart).
//!
//! A saved site can list alternate [`SessionRoute`] endpoints for the same
//! logical server - e.g. a LAN address plus a remote Cloudflare/cloudflared
//! jump alias. Before connecting, the caller probes each candidate's *first
//! hop* (the address that must be reachable locally: the direct target, the
//! proxy, or the bastion) with a plain TCP connect, ranks the candidates by
//! latency, and tries them in that order with failover.
//!
//! Probing is intentionally cheap:
//!
//! - TCP connect timing only - no SSH handshake, no auth, no `cloudflared`
//!   spawn. "Reachable" therefore means the first hop answered, not that the
//!   full session will succeed; the connect-time failover loop covers that.
//! - DNS resolution time is excluded from the measured latency (resolution
//!   happens first, then the connect of the successful address is timed).
//! - Jump aliases that do not resolve in DNS (a `ProxyCommand`-only bastion
//!   such as `cloudflared access ssh`) are *unprobeable*, not unreachable:
//!   the system `ssh -W` tunnel may still work, so they are ranked below
//!   every measured-reachable route but above routes that are known-bad.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::types::ProxyType;

// ---------------------------------------------------------------------------
// Route model
// ---------------------------------------------------------------------------

/// How a site with alternate routes picks the one to connect through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutePolicy {
    /// Probe all routes, pick the fastest reachable one, fail over on
    /// transport-level connect errors.
    #[default]
    Auto,
    /// Always use the pinned route (`SessionOptions::route_pin`); no
    /// automatic probing or failover.
    Manual,
}

/// Storage name for a route policy (`"auto"` / `"manual"`).
pub const fn route_policy_storage_name(policy: RoutePolicy) -> &'static str {
    match policy {
        RoutePolicy::Auto => "auto",
        RoutePolicy::Manual => "manual",
    }
}

/// Parses a route policy from a persisted string.
///
/// Case-insensitive; empty or unrecognized values fall back to
/// [`RoutePolicy::Auto`].
pub fn route_policy_from_storage_name(raw: &str) -> RoutePolicy {
    if raw.eq_ignore_ascii_case("manual") {
        RoutePolicy::Manual
    } else {
        RoutePolicy::Auto
    }
}

/// One alternate endpoint of a site. Empty/`None`/zero fields inherit the
/// corresponding value from the site's primary fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionRoute {
    /// Short user-assigned name, unique within a site (drives the cache and
    /// the manual pin).
    pub label: String,
    pub host: String,
    /// `0` = inherit the protocol default port.
    pub port: u16,
    /// Overrides the site username when non-empty.
    pub username: Option<String>,
    /// Overrides the site identity file when set.
    pub private_key_path: Option<String>,
    pub proxy_type: ProxyType,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_username: Option<String>,
    pub jump_host: Option<String>,
    pub jump_port: u16,
    pub jump_username: Option<String>,
    pub jump_private_key_path: Option<String>,
}

/// Whether `route` actually changes the endpoint relative to `base`.
pub fn route_overrides_endpoint(route: &SessionRoute, base_host: &str, base_port: u16) -> bool {
    let host = if route.host.trim().is_empty() {
        base_host
    } else {
        route.host.trim()
    };
    let port = if route.port == 0 {
        base_port
    } else {
        route.port
    };
    host != base_host || port != base_port
}

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

/// Which leg of a candidate the probe address belongs to. Only jump aliases
/// get the "DNS failure does not mean unreachable" treatment, because a
/// `ProxyCommand` bastion never needs a DNS address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeHopKind {
    /// The candidate connects straight to `host:port`.
    Direct,
    /// The candidate tunnels through a SOCKS5/HTTP proxy.
    Proxy,
    /// The candidate tunnels through an SSH bastion (`ssh -W`).
    Jump,
}

/// One probe request: the first hop that must be reachable for the candidate
/// to have a chance of connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    /// Echoed back in [`ProbeResult::label`].
    pub label: String,
    pub host: String,
    pub port: u16,
    pub kind: ProbeHopKind,
}

/// Outcome of probing one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeStatus {
    /// The first hop accepted a TCP connection within the budget.
    Reachable {
        /// TCP connect time of the successful address (DNS excluded).
        latency: Duration,
        /// The address that accepted the connection.
        addr: IpAddr,
        /// Best-effort LAN classification of `addr` (display + tie-breaks).
        is_lan: bool,
    },
    /// Known-bad: resolves but refuses/times out, or a direct/proxy host with
    /// no DNS address. Attempted last.
    Unreachable(String),
    /// Cannot be measured (e.g. a jump alias whose reachability is a
    /// `ProxyCommand`). Ranked below reachable routes but still attempted.
    Unprobeable(String),
}

/// Result of probing one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub label: String,
    pub status: ProbeStatus,
}

impl ProbeResult {
    pub fn reachable(&self) -> bool {
        matches!(self.status, ProbeStatus::Reachable { .. })
    }

    /// Measured latency when reachable.
    pub fn latency(&self) -> Option<Duration> {
        match &self.status {
            ProbeStatus::Reachable { latency, .. } => Some(*latency),
            _ => None,
        }
    }

    /// LAN classification when reachable.
    pub fn is_lan(&self) -> bool {
        match &self.status {
            ProbeStatus::Reachable { is_lan, .. } => *is_lan,
            _ => false,
        }
    }
}

/// Probes every target concurrently, each capped at `budget`.
///
/// Returns results in input order.
pub async fn probe_targets(targets: &[ProbeTarget], budget: Duration) -> Vec<ProbeResult> {
    let mut set: JoinSet<(usize, ProbeResult)> = JoinSet::new();
    for (idx, target) in targets.iter().cloned().enumerate() {
        let label = target.label.clone();
        set.spawn(async move {
            let result = timeout(budget, probe_one(target))
                .await
                .unwrap_or_else(|_| ProbeResult {
                    label,
                    status: ProbeStatus::Unreachable("probe timed out".to_string()),
                });
            (idx, result)
        });
    }
    let mut by_input_order: Vec<Option<ProbeResult>> = vec![None; targets.len()];
    while let Some(joined) = set.join_next().await {
        if let Ok((idx, result)) = joined {
            by_input_order[idx] = Some(result);
        }
    }
    by_input_order
        .into_iter()
        .enumerate()
        .map(|(idx, slot)| {
            slot.unwrap_or_else(|| ProbeResult {
                label: targets[idx].label.clone(),
                status: ProbeStatus::Unprobeable("probe did not complete".to_string()),
            })
        })
        .collect()
}

async fn probe_one(target: ProbeTarget) -> ProbeResult {
    let label = target.label.clone();
    let addrs = match resolve(&target.host, target.port).await {
        Some(addrs) if !addrs.is_empty() => addrs,
        _ => {
            let reason = "no address resolves for the probe host".to_string();
            let status = match target.kind {
                // A ProxyCommand bastion (e.g. cloudflared) never needs a DNS
                // address; direct/proxy targets without one cannot connect.
                ProbeHopKind::Jump => ProbeStatus::Unprobeable(reason),
                ProbeHopKind::Direct | ProbeHopKind::Proxy => ProbeStatus::Unreachable(reason),
            };
            return ProbeResult { label, status };
        }
    };
    let mut last_err = String::new();
    for addr in addrs {
        let start = Instant::now();
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_stream) => {
                let latency = start.elapsed();
                let ip = addr.ip();
                return ProbeResult {
                    label,
                    status: ProbeStatus::Reachable {
                        latency,
                        addr: ip,
                        is_lan: is_probably_lan(&ip),
                    },
                };
            }
            Err(err) => last_err = err.to_string(),
        }
    }
    ProbeResult {
        label,
        status: ProbeStatus::Unreachable(last_err),
    }
}

async fn resolve(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    if let Ok(ip) = host.trim().parse::<IpAddr>() {
        return Some(vec![SocketAddr::new(ip, port)]);
    }
    tokio::net::lookup_host((host.trim(), port))
        .await
        .ok()
        .map(|iter| iter.collect())
}

// ---------------------------------------------------------------------------
// Ranking
// ---------------------------------------------------------------------------

/// Sticky last-good margins: the previously used route keeps its front
/// position within its LAN/WAN class unless a challenger is BOTH more than
/// [`STICKY_MIN_GAIN_RATIO`] faster AND more than [`STICKY_MIN_GAIN_MS`]
/// faster (prevents flapping between similar routes). Reachable LAN routes
/// always rank ahead of reachable WAN/tunnel routes regardless of sticky.
pub const STICKY_MIN_GAIN_MS: Duration = Duration::from_millis(5);
pub const STICKY_MIN_GAIN_RATIO: f64 = 0.2;

/// Orders probe results into the attempt order.
///
/// Rules:
/// 1. Reachable **LAN** routes first (sorted by latency), then reachable
///    non-LAN routes (sorted by latency). A reachable LAN path always beats
///    a WAN/tunnel path — sticky last-good must not pull Cloudflare ahead of
///    a live LAN endpoint.
/// 2. Unprobeable routes next (input order), then unreachable (input order).
/// 3. Stickiness: when `sticky` names a reachable route, it moves to the
///    front of *its own LAN/WAN class* unless another route in that class
///    beats it by both [`STICKY_MIN_GAIN_RATIO`] and [`STICKY_MIN_GAIN_MS`].
pub fn rank_probes(results: &[ProbeResult], sticky: Option<&str>) -> Vec<usize> {
    let mut lan: Vec<usize> = Vec::new();
    let mut wan: Vec<usize> = Vec::new();
    let mut unprobeable: Vec<usize> = Vec::new();
    let mut unreachable: Vec<usize> = Vec::new();
    for (idx, result) in results.iter().enumerate() {
        match &result.status {
            ProbeStatus::Reachable { is_lan: true, .. } => lan.push(idx),
            ProbeStatus::Reachable { .. } => wan.push(idx),
            ProbeStatus::Unprobeable(_) => unprobeable.push(idx),
            ProbeStatus::Unreachable(_) => unreachable.push(idx),
        }
    }
    lan.sort_by_key(|&idx| results[idx].latency().unwrap_or(Duration::MAX));
    wan.sort_by_key(|&idx| results[idx].latency().unwrap_or(Duration::MAX));

    apply_sticky_within_class(&mut lan, results, sticky);
    apply_sticky_within_class(&mut wan, results, sticky);

    lan.extend(wan);
    lan.extend(unprobeable);
    lan.extend(unreachable);
    lan
}

/// Stickiness scoped to one latency-sorted class so a WAN last-good never
/// outranks a reachable LAN challenger.
fn apply_sticky_within_class(order: &mut Vec<usize>, results: &[ProbeResult], sticky: Option<&str>) {
    let Some(sticky) = sticky else {
        return;
    };
    let Some(pos) = order.iter().position(|&idx| results[idx].label == sticky) else {
        return;
    };
    let sticky_lat = results[order[pos]].latency().unwrap_or(Duration::MAX);
    let best_other = order
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != pos)
        .map(|(_, &idx)| results[idx].latency().unwrap_or(Duration::MAX))
        .min()
        .unwrap_or(Duration::MAX);
    let sticky_ms = sticky_lat.as_secs_f64() * 1000.0;
    let other_ms = best_other.as_secs_f64() * 1000.0;
    let challenger_wins = other_ms < sticky_ms * (1.0 - STICKY_MIN_GAIN_RATIO)
        && sticky_lat.saturating_sub(best_other) > STICKY_MIN_GAIN_MS;
    if !challenger_wins {
        let idx = order.remove(pos);
        order.insert(0, idx);
    }
}

// ---------------------------------------------------------------------------
// LAN classification
// ---------------------------------------------------------------------------

/// Best-effort "is this address on the local network" classification:
/// loopback, RFC1918 private ranges, CGNAT `100.64.0.0/10`, link-local, and
/// IPv6 ULA / link-local. Display heuristic and tie-break only.
pub fn is_probably_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // CGNAT 100.64/10
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reachable(label: &str, ms: u64, lan: bool) -> ProbeResult {
        ProbeResult {
            label: label.to_string(),
            status: ProbeStatus::Reachable {
                latency: Duration::from_millis(ms),
                addr: if lan {
                    "192.168.1.10".parse().unwrap()
                } else {
                    "203.0.113.10".parse().unwrap()
                },
                is_lan: lan,
            },
        }
    }

    fn unreachable(label: &str) -> ProbeResult {
        ProbeResult {
            label: label.to_string(),
            status: ProbeStatus::Unreachable("refused".to_string()),
        }
    }

    fn unprobeable(label: &str) -> ProbeResult {
        ProbeResult {
            label: label.to_string(),
            status: ProbeStatus::Unprobeable("proxycommand alias".to_string()),
        }
    }

    fn labels<'a>(results: &'a [ProbeResult], order: &[usize]) -> Vec<&'a str> {
        order.iter().map(|&i| results[i].label.as_str()).collect()
    }

    #[test]
    fn route_policy_storage_round_trips() {
        for policy in [RoutePolicy::Auto, RoutePolicy::Manual] {
            assert_eq!(
                route_policy_from_storage_name(route_policy_storage_name(policy)),
                policy
            );
        }
        assert_eq!(route_policy_from_storage_name(""), RoutePolicy::Auto);
        assert_eq!(
            route_policy_from_storage_name("MANUAL"),
            RoutePolicy::Manual
        );
        assert_eq!(route_policy_from_storage_name("bogus"), RoutePolicy::Auto);
    }

    #[test]
    fn route_override_detection() {
        let mut route = SessionRoute::default();
        assert!(!route_overrides_endpoint(&route, "example.com", 22));
        route.host = "192.168.1.50".to_string();
        assert!(route_overrides_endpoint(&route, "example.com", 22));
        route.host = "example.com".to_string();
        route.port = 2222;
        assert!(route_overrides_endpoint(&route, "example.com", 22));
    }

    #[test]
    fn rank_orders_by_latency_with_partitions() {
        let results = vec![
            unreachable("lan-down"),
            reachable("wan", 240, false),
            unprobeable("cloudflare"),
            reachable("lan", 3, true),
        ];
        let order = rank_probes(&results, None);
        assert_eq!(
            labels(&results, &order),
            vec!["lan", "wan", "cloudflare", "lan-down"]
        );
    }

    #[test]
    fn rank_reachable_lan_always_beats_wan() {
        // Even when WAN is faster on the wire, a reachable LAN endpoint is
        // preferred — sticky last-good must not undo that.
        let results = vec![reachable("wan", 5, false), reachable("lan", 40, true)];
        let order = rank_probes(&results, Some("wan"));
        assert_eq!(labels(&results, &order), vec!["lan", "wan"]);

        let results = vec![reachable("wan", 5, false), reachable("lan", 8, true)];
        let order = rank_probes(&results, None);
        assert_eq!(labels(&results, &order), vec!["lan", "wan"]);
    }

    #[test]
    fn rank_sticky_keeps_last_good_without_flapping() {
        // Stickiness is scoped within LAN/WAN class.
        let results = vec![reachable("lan-a", 3, true), reachable("lan-b", 2, true)];
        let order = rank_probes(&results, Some("lan-a"));
        assert_eq!(labels(&results, &order), vec!["lan-a", "lan-b"]);

        // A challenger in the same class that is both 20% and >5 ms faster wins.
        let results = vec![reachable("lan-a", 300, true), reachable("lan-b", 2, true)];
        let order = rank_probes(&results, Some("lan-a"));
        assert_eq!(labels(&results, &order), vec!["lan-b", "lan-a"]);

        // Sticky pointing at an unreachable route is ignored.
        let results = vec![reachable("wan", 20, false), unreachable("lan")];
        let order = rank_probes(&results, Some("lan"));
        assert_eq!(labels(&results, &order), vec!["wan", "lan"]);
    }

    #[test]
    fn lan_classification_table() {
        let lan = [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.1.1",
            "192.168.1.50",
            "169.254.7.7",
            "100.64.0.9",
            "::1",
            "fe80::1",
            "fd00::1234",
        ];
        let wan = [
            "203.0.113.10",
            "8.8.8.8",
            "100.128.0.1", // just past the CGNAT /10
            "2001:db8::1",
        ];
        for ip in lan {
            assert!(is_probably_lan(&ip.parse().unwrap()), "{ip} should be LAN");
        }
        for ip in wan {
            assert!(!is_probably_lan(&ip.parse().unwrap()), "{ip} should be WAN");
        }
    }

    #[tokio::test]
    async fn probe_reachable_loopback_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let targets = vec![ProbeTarget {
            label: "lan".to_string(),
            host: "127.0.0.1".to_string(),
            port,
            kind: ProbeHopKind::Direct,
        }];
        let results = probe_targets(&targets, Duration::from_secs(2)).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "lan");
        assert!(results[0].reachable());
        assert!(results[0].is_lan());
    }

    #[tokio::test]
    async fn probe_closed_port_is_unreachable() {
        // Bind then drop to get a guaranteed-closed port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let targets = vec![ProbeTarget {
            label: "closed".to_string(),
            host: "127.0.0.1".to_string(),
            port,
            kind: ProbeHopKind::Direct,
        }];
        let results = probe_targets(&targets, Duration::from_secs(2)).await;
        assert!(matches!(results[0].status, ProbeStatus::Unreachable(_)));
    }

    #[tokio::test]
    async fn probe_dns_failure_classification_by_kind() {
        let targets = vec![
            ProbeTarget {
                label: "direct".to_string(),
                host: "no-such-host.invalid".to_string(),
                port: 22,
                kind: ProbeHopKind::Direct,
            },
            ProbeTarget {
                label: "jump".to_string(),
                host: "no-such-host.invalid".to_string(),
                port: 22,
                kind: ProbeHopKind::Jump,
            },
        ];
        let results = probe_targets(&targets, Duration::from_secs(5)).await;
        assert!(matches!(results[0].status, ProbeStatus::Unreachable(_)));
        assert!(matches!(results[1].status, ProbeStatus::Unprobeable(_)));
    }

    #[tokio::test]
    async fn probe_budget_caps_unresponsive_target() {
        // TEST-NET-1 is reserved and never answers; whichever way it fails
        // (hang -> budget, or refuse), it must not be reachable.
        let targets = vec![ProbeTarget {
            label: "dead".to_string(),
            host: "192.0.2.1".to_string(),
            port: 22,
            kind: ProbeHopKind::Direct,
        }];
        let start = Instant::now();
        let results = probe_targets(&targets, Duration::from_millis(150)).await;
        assert!(!results[0].reachable());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
