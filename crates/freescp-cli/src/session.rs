//! Target parsing and [`SessionOptions`] construction shared by all
//! subcommands.

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Password};

use freescp_core::{
    capabilities_for_protocol, default_port_for_protocol, default_port_for_proxy_type,
    default_port_for_telnet, protocol_display_name, ssh_config, HostKeyConfirmCb,
    KbdIntPromptResult, KbdIntPromptsCb, KnownHostsPolicy, Protocol, ProxyType, SessionOptions,
};

use crate::cli::ConnectionArgs;

/// A parsed `[user@]host[:port]` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

/// Splits `[user@]host[:port]` into its parts. Bracketed IPv6 literals
/// (`user@[::1]:2222`) are supported.
pub fn parse_target(raw: &str) -> Result<Target> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("empty target (expected [user@]host[:port])");
    }

    let (user, rest) = match raw.rsplit_once('@') {
        Some((user, rest)) if !user.is_empty() => (Some(user.to_string()), rest),
        _ => (None, raw),
    };
    if rest.is_empty() {
        bail!("missing host in target '{raw}'");
    }

    // Bracketed IPv6: `[::1]` or `[::1]:2222`.
    if let Some(stripped) = rest.strip_prefix('[') {
        let Some((host, tail)) = stripped.split_once(']') else {
            bail!("invalid IPv6 target '{raw}': missing ']'");
        };
        if host.is_empty() {
            bail!("invalid IPv6 target '{raw}': empty host");
        }
        let port = match tail {
            "" => None,
            _ => {
                let Some(port) = tail.strip_prefix(':') else {
                    bail!("invalid target '{raw}': unexpected text after ']'");
                };
                Some(parse_port(port, raw)?)
            }
        };
        return Ok(Target {
            user,
            host: host.to_string(),
            port,
        });
    }

    if let Some((host, port)) = rest.rsplit_once(':') {
        if !host.is_empty() && !host.contains(':') {
            return Ok(Target {
                user,
                host: host.to_string(),
                port: Some(parse_port(port, raw)?),
            });
        }
    }

    Ok(Target {
        user,
        host: rest.to_string(),
        port: None,
    })
}

fn parse_port(raw_port: &str, target: &str) -> Result<u16> {
    raw_port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow!("invalid port '{raw_port}' in target '{target}'"))
}

/// The protocol selected by `--protocol`, falling back to `default`.
pub fn resolved_protocol(conn: &ConnectionArgs, default: Protocol) -> Protocol {
    conn.protocol
        .map(|protocol| protocol.to_core())
        .unwrap_or(default)
}

/// Builds the full [`SessionOptions`] for a connection: command-line flags,
/// `~/.ssh/config` fallbacks, credentials and host-key callbacks.
pub fn prepare(
    conn: &ConnectionArgs,
    target: &Target,
    protocol: Protocol,
) -> Result<SessionOptions> {
    let mut options = build_options(conn, target, protocol)?;
    // ~/.ssh/config fills the fields the command line left at their defaults
    // (SFTP/SCP only; the helper ignores other protocols).
    ssh_config::apply_user_config(&mut options);
    attach_callbacks(&mut options, conn);
    prompt_for_password(&mut options, protocol)?;
    Ok(options)
}

fn build_options(
    conn: &ConnectionArgs,
    target: &Target,
    protocol: Protocol,
) -> Result<SessionOptions> {
    let mut options = SessionOptions {
        protocol,
        ..SessionOptions::default()
    };
    options.host = target.host.clone();

    options.port = match target.port.or(conn.port) {
        Some(port) => port,
        None if protocol == Protocol::Telnet => default_port_for_telnet(conn.telnet_tls),
        None => default_port_for_protocol(protocol),
    };

    if let Some(user) = target.user.clone().or_else(|| conn.user.clone()) {
        options.username = user;
    }

    if let Some(identity) = &conn.identity {
        options.private_key_path = Some(identity.to_string_lossy().into_owned());
    }
    if let Some(passphrase) = &conn.passphrase {
        options.private_key_passphrase = Some(passphrase.clone());
    }
    options.password = conn.password.clone().or_else(|| {
        std::env::var("FREESCP_PASSWORD")
            .ok()
            .filter(|password| !password.is_empty())
    });

    if let Some(path) = &conn.known_hosts {
        options.known_hosts_path = Some(path.to_string_lossy().into_owned());
    }
    if let Some(integrity) = conn.integrity {
        options.transfer_integrity_policy = integrity.to_core();
    }
    if let Some(mode) = conn.scp_mode {
        options.scp_transfer_mode = mode.to_core();
    }

    if let Some(proxy) = conn.proxy {
        let proxy_type = proxy.to_core();
        if proxy_type != ProxyType::None {
            let host = conn
                .proxy_host
                .clone()
                .filter(|host| !host.trim().is_empty())
                .ok_or_else(|| anyhow!("--proxy requires --proxy-host"))?;
            options.proxy_type = proxy_type;
            options.proxy_host = host;
            options.proxy_port = conn
                .proxy_port
                .unwrap_or_else(|| default_port_for_proxy_type(proxy_type));
            options.proxy_username = conn.proxy_user.clone();
            options.proxy_password = conn.proxy_password.clone();
        }
    } else if conn.proxy_host.is_some() {
        bail!("--proxy-host requires --proxy <socks5|http-connect>");
    }

    if let Some(spec) = &conn.jump {
        let (user, host, port) = ssh_config::parse_proxy_jump(spec);
        if host.trim().is_empty() {
            bail!("invalid --jump target '{spec}' (expected [user@]host[:port])");
        }
        options.jump_host = Some(host);
        if let Some(port) = port {
            options.jump_port = port;
        }
        if let Some(user) = user {
            options.jump_username = Some(user);
        }
    }
    if let Some(key) = &conn.jump_key {
        if options.jump_host.is_none() {
            bail!("--jump-key requires --jump");
        }
        options.jump_private_key_path = Some(key.to_string_lossy().into_owned());
    }

    if protocol == Protocol::Telnet {
        options.telnet_tls = conn.telnet_tls;
        options.telnet_verify_peer = !conn.insecure;
        options.telnet_auto_login = true;
        if let Some(term) = &conn.term_type {
            options.telnet_terminal_type = term.clone();
        }
    } else if conn.telnet_tls {
        bail!("--telnet-tls only applies to the telnet protocol (use `freescp console`)");
    }

    if conn.insecure {
        options.ftps_verify_peer = false;
        options.webdav_verify_peer = false;
    }

    Ok(options)
}

/// Installs TOFU host-key handling and keyboard-interactive (OTP/2FA)
/// callbacks for SSH-based protocols.
fn attach_callbacks(options: &mut SessionOptions, conn: &ConnectionArgs) {
    if !capabilities_for_protocol(options.protocol).supports_known_hosts {
        return;
    }

    let interactive = std::io::stdin().is_terminal();
    if conn.accept_new || interactive {
        options.known_hosts_policy = KnownHostsPolicy::AcceptNew;
        options.hostkey_confirm_cb = Some(hostkey_confirm_callback(conn.accept_new));
    }
    options.hostkey_status_cb = Some(Arc::new(|message: &str| {
        eprintln!("freescp: {message}");
    }));
    options.keyboard_interactive_cb = Some(keyboard_interactive_callback(
        options.username.clone(),
        options.password.clone().unwrap_or_default(),
    ));
}

fn hostkey_confirm_callback(auto_accept: bool) -> HostKeyConfirmCb {
    Arc::new(
        move |host: &str, port: u16, algorithm: &str, fingerprint: &str, can_save: bool| -> bool {
            if auto_accept {
                let note = if can_save {
                    "saved to known_hosts"
                } else {
                    "not saved (no known_hosts path)"
                };
                eprintln!(
                    "freescp: trust on first use: accepting host key for {host}:{port} \
                     ({algorithm} {fingerprint}); {note}"
                );
                return true;
            }
            let save_note = if can_save {
                String::new()
            } else {
                "The key cannot be saved (known_hosts path is not set).\n".to_string()
            };
            let prompt = format!(
                "The authenticity of host '{host}:{port}' can't be established.\n\
                 {algorithm} key fingerprint is {fingerprint}.\n\
                 {save_note}Continue connecting?"
            );
            Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(prompt)
                .default(false)
                .interact()
                .unwrap_or(false)
        },
    )
}

fn keyboard_interactive_callback(username: String, password: String) -> KbdIntPromptsCb {
    Arc::new(
        move |_name: &str,
              _instruction: &str,
              prompts: &[String],
              responses: &mut Vec<String>|
              -> KbdIntPromptResult {
            responses.clear();
            if !std::io::stdin().is_terminal() {
                return KbdIntPromptResult::Unhandled;
            }
            for prompt in prompts {
                let lower = prompt.to_lowercase();
                if !password.is_empty() && lower.contains("password") {
                    responses.push(password.clone());
                    continue;
                }
                if lower.contains("user") || lower.contains("login") || lower.contains("name:") {
                    responses.push(username.clone());
                    continue;
                }
                let secret_like = lower.contains("code")
                    || lower.contains("otp")
                    || lower.contains("token")
                    || lower.contains("passc")
                    || lower.contains("verification");
                let label = prompt.trim().trim_end_matches(':');
                let answer = if secret_like {
                    Password::with_theme(&ColorfulTheme::default())
                        .with_prompt(label)
                        .allow_empty_password(true)
                        .interact()
                } else {
                    Input::<String>::with_theme(&ColorfulTheme::default())
                        .with_prompt(label)
                        .allow_empty(true)
                        .interact_text()
                };
                match answer {
                    Ok(value) => responses.push(value),
                    Err(_) => return KbdIntPromptResult::Cancelled,
                }
            }
            if responses.len() == prompts.len() {
                KbdIntPromptResult::Handled
            } else {
                KbdIntPromptResult::Unhandled
            }
        },
    )
}

/// Prompts for a password on an interactive terminal when neither a password
/// nor a private key is available. Non-interactive runs continue without one
/// (the backend reports the authentication failure).
fn prompt_for_password(options: &mut SessionOptions, protocol: Protocol) -> Result<()> {
    if protocol == Protocol::Telnet {
        return Ok(()); // credentials are typed into the console itself
    }
    let has_password = options
        .password
        .as_deref()
        .is_some_and(|password| !password.is_empty());
    let has_key = options
        .private_key_path
        .as_deref()
        .is_some_and(|key| !key.trim().is_empty());
    if has_password || has_key || !std::io::stdin().is_terminal() {
        return Ok(());
    }
    if options.username.eq_ignore_ascii_case("anonymous") {
        return Ok(());
    }

    let who = if options.username.is_empty() {
        options.host.clone()
    } else {
        format!("{}@{}", options.username, options.host)
    };
    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("{who}'s password"))
        .interact()?;
    options.password = Some(password);
    Ok(())
}

/// Fails when `protocol` cannot transfer files (telnet).
pub fn require_file_protocol(protocol: Protocol) -> Result<()> {
    if protocol == Protocol::Telnet {
        bail!("telnet is an interactive console; use `freescp console` instead");
    }
    Ok(())
}

/// Fails when `protocol` cannot list directories.
pub fn require_listing(protocol: Protocol) -> Result<()> {
    if !capabilities_for_protocol(protocol).supports_listing {
        bail!(
            "{} does not support directory listings",
            protocol_display_name(protocol)
        );
    }
    Ok(())
}

/// Fails when `protocol` cannot transfer files.
pub fn require_transfers(protocol: Protocol) -> Result<()> {
    if !capabilities_for_protocol(protocol).supports_file_transfers {
        bail!(
            "{} does not support file transfers",
            protocol_display_name(protocol)
        );
    }
    Ok(())
}

/// Human-readable `user@host:port (PROTOCOL)` description.
pub fn describe(options: &SessionOptions) -> String {
    let user = if options.username.is_empty() {
        String::new()
    } else {
        format!("{}@", options.username)
    };
    format!(
        "{user}{}:{} ({})",
        options.host,
        options.port,
        protocol_display_name(options.protocol)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{IntegrityArg, ProtocolArg, ProxyArg, ScpModeArg};

    #[test]
    fn parses_plain_host() {
        assert_eq!(
            parse_target("example.com").unwrap(),
            Target {
                user: None,
                host: "example.com".into(),
                port: None
            }
        );
    }

    #[test]
    fn parses_user_host_port() {
        assert_eq!(
            parse_target("deploy@example.com:2222").unwrap(),
            Target {
                user: Some("deploy".into()),
                host: "example.com".into(),
                port: Some(2222)
            }
        );
    }

    #[test]
    fn parses_bracketed_ipv6() {
        assert_eq!(
            parse_target("root@[2001:db8::1]:2222").unwrap(),
            Target {
                user: Some("root".into()),
                host: "2001:db8::1".into(),
                port: Some(2222)
            }
        );
        assert_eq!(parse_target("[::1]").unwrap().host, "::1");
        assert_eq!(parse_target("::1").unwrap().host, "::1");
    }

    #[test]
    fn rejects_invalid_targets() {
        assert!(parse_target("").is_err());
        assert!(parse_target("host:notaport").is_err());
        assert!(parse_target("host:0").is_err());
        assert!(parse_target("host:70000").is_err());
        assert!(parse_target("[::1").is_err());
        assert!(parse_target("user@").is_err());
    }

    fn base_conn() -> ConnectionArgs {
        ConnectionArgs::default()
    }

    #[test]
    fn options_default_to_sftp_port() {
        let target = parse_target("example.com").unwrap();
        let options = build_options(&base_conn(), &target, Protocol::Sftp).unwrap();
        assert_eq!(options.port, 22);
        assert_eq!(options.protocol, Protocol::Sftp);
        assert_eq!(options.host, "example.com");
        assert!(options.username.is_empty());
    }

    #[test]
    fn target_wins_over_flags_for_host_and_port() {
        let mut conn = base_conn();
        conn.user = Some("flag-user".into());
        conn.port = Some(9999);
        let target = parse_target("target-user@example.com:2222").unwrap();
        let options = build_options(&conn, &target, Protocol::Sftp).unwrap();
        assert_eq!(options.port, 2222);
        assert_eq!(options.username, "target-user");

        let target = parse_target("example.com").unwrap();
        let options = build_options(&conn, &target, Protocol::Sftp).unwrap();
        assert_eq!(options.port, 9999);
        assert_eq!(options.username, "flag-user");
    }

    #[test]
    fn telnet_defaults_to_plain_or_tls_port() {
        let target = parse_target("console.example.com").unwrap();
        let options = build_options(&base_conn(), &target, Protocol::Telnet).unwrap();
        assert_eq!(options.port, 23);
        assert!(!options.telnet_tls);

        let mut conn = base_conn();
        conn.telnet_tls = true;
        let options = build_options(&conn, &target, Protocol::Telnet).unwrap();
        assert_eq!(options.port, 992);
        assert!(options.telnet_tls);
        assert!(options.telnet_verify_peer);

        let mut conn = base_conn();
        conn.telnet_tls = true;
        conn.insecure = true;
        let options = build_options(&conn, &target, Protocol::Telnet).unwrap();
        assert!(!options.telnet_verify_peer);
    }

    #[test]
    fn proxy_requires_host() {
        let target = parse_target("example.com").unwrap();
        let mut conn = base_conn();
        conn.proxy = Some(ProxyArg::Socks5);
        assert!(build_options(&conn, &target, Protocol::Sftp).is_err());

        conn.proxy_host = Some("proxy.example.com".into());
        let options = build_options(&conn, &target, Protocol::Sftp).unwrap();
        assert_eq!(options.proxy_type, ProxyType::Socks5);
        assert_eq!(options.proxy_host, "proxy.example.com");
        assert_eq!(options.proxy_port, 1080);
    }

    #[test]
    fn jump_key_requires_jump() {
        let target = parse_target("example.com").unwrap();
        let mut conn = base_conn();
        conn.jump_key = Some("/keys/jump".into());
        assert!(build_options(&conn, &target, Protocol::Sftp).is_err());

        conn.jump = Some("bastion:2200".into());
        let options = build_options(&conn, &target, Protocol::Sftp).unwrap();
        assert_eq!(options.jump_host.as_deref(), Some("bastion"));
        assert_eq!(options.jump_port, 2200);
    }

    #[test]
    fn telnet_tls_flag_rejected_for_file_protocols() {
        let target = parse_target("example.com").unwrap();
        let mut conn = base_conn();
        conn.telnet_tls = true;
        assert!(build_options(&conn, &target, Protocol::Sftp).is_err());
    }

    #[test]
    fn maps_selector_flags() {
        let target = parse_target("example.com").unwrap();
        let mut conn = base_conn();
        conn.protocol = Some(ProtocolArg::Ftp);
        conn.integrity = Some(IntegrityArg::Required);
        conn.scp_mode = Some(ScpModeArg::ScpOnly);
        conn.insecure = true;
        let options = build_options(&conn, &target, Protocol::Ftp).unwrap();
        assert_eq!(
            options.transfer_integrity_policy,
            freescp_core::TransferIntegrityPolicy::Required
        );
        assert_eq!(
            options.scp_transfer_mode,
            freescp_core::ScpTransferMode::ScpOnly
        );
        assert!(!options.ftps_verify_peer);
        assert!(!options.webdav_verify_peer);
    }

    #[test]
    fn password_from_flags_and_env() {
        let target = parse_target("example.com").unwrap();
        let mut conn = base_conn();
        conn.password = Some("secret".into());
        let options = build_options(&conn, &target, Protocol::Sftp).unwrap();
        assert_eq!(options.password.as_deref(), Some("secret"));
    }

    #[test]
    fn describe_includes_protocol_and_user() {
        let target = parse_target("deploy@example.com:2222").unwrap();
        let options = build_options(&base_conn(), &target, Protocol::Sftp).unwrap();
        assert_eq!(describe(&options), "deploy@example.com:2222 (SFTP)");
    }
}
