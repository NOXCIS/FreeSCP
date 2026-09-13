//! Minimal OpenSSH client-configuration (`~/.ssh/config`) reader.
//!
//! Neither the C++ app nor its dependencies ever consulted the user's
//! `ssh_config`; this module adds the subset that matters for two features:
//!
//! 1. **Connect-time resolution** — when the host entered in the connection
//!    dialog / site entry matches a `Host` pattern, fill the fields the
//!    caller left at their defaults (`HostName`, `Port`, `User`,
//!    `IdentityFile`, `ProxyJump`), like the OpenSSH client does.
//! 2. **Site-Manager import** — concrete (non-wildcard) `Host` aliases can be
//!    imported as saved sites.
//!
//! # Supported syntax (ssh_config(5) subset)
//!
//! - `Host` blocks with whitespace-separated pattern lists, `!` negation and
//!   `*` / `?` wildcards. A negated pattern that matches excludes the whole
//!   block, regardless of the other patterns.
//! - Keywords `HostName`, `Port`, `User`, `IdentityFile`, `ProxyJump`
//!   (case-insensitive; `key value`, `key=value` and `key = value` forms;
//!   double-quoted values; `#` comments).
//! - `Include` with absolute, `~`-relative and config-relative paths, with
//!   simple globbing (wildcards expanded one directory level at a time, which
//!   covers `Include config.d/*.conf`); include cycles are guarded against.
//! - `Match` blocks are recognized and their parameters skipped.
//!
//! # Deliberate limitations
//!
//! - OpenSSH's "first obtained value wins" rule is honored across blocks for
//!   `HostName`/`Port`/`User`/`ProxyJump`; `IdentityFile` accumulates across
//!   all matching blocks (also OpenSSH behavior). Within one block the first
//!   occurrence of a keyword wins.
//! - `ProxyCommand` is not parsed here. Jump tunnels go through system
//!   `ssh -W`, which still honors the bastion's `ProxyCommand` when the jump
//!   host is left as an ssh_config alias. When both `ProxyJump` and
//!   `ProxyCommand` are set on the *same* Host block, OpenSSH prefers
//!   `ProxyCommand`; this module only surfaces `ProxyJump` for site import.
//! - `Match` criteria are not evaluated.
//! - Tokens (`%h`, `%d`, …) in values are not expanded.

use std::path::{Path, PathBuf};

/// Maximum `Include` nesting depth (defends against pathological files).
const MAX_INCLUDE_DEPTH: usize = 8;

/// Parameters of one `Host` block (first occurrence of each keyword wins).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshHostBlock {
    /// Raw patterns of the `Host` line, `!` negations included.
    pub patterns: Vec<String>,
    pub host_name: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    /// Every `IdentityFile` of the block, in file order.
    pub identity_files: Vec<String>,
    pub proxy_jump: Option<String>,
}

/// A parsed `ssh_config`: the `Host` blocks in file order (includes inlined).
#[derive(Debug, Clone, Default)]
pub struct SshConfig {
    blocks: Vec<SshHostBlock>,
}

/// Parameters resolved for one host alias, OpenSSH first-match-wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedSshParams {
    /// `HostName` for the alias (`None` = connect to the alias as typed).
    pub host_name: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    /// All `IdentityFile`s across matching blocks, in order, `~` expanded.
    pub identity_files: Vec<String>,
    pub proxy_jump: Option<String>,
}

impl SshConfig {
    /// Parses configuration text. `include_base` is the directory relative
    /// paths in `Include` lines resolve against (the directory of the file
    /// the text comes from, i.e. `~/.ssh` for the user config).
    pub fn parse_str(text: &str, include_base: &Path) -> SshConfig {
        let mut config = SshConfig::default();
        config.parse_lines(text, include_base, 0, &mut Vec::new());
        config
    }

    /// Parses the file at `path`, resolving `Include` relative paths against
    /// its directory. Missing files parse as an empty config.
    pub fn load(path: &Path) -> SshConfig {
        let mut config = SshConfig::default();
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        if let Ok(text) = std::fs::read_to_string(path) {
            config.parse_lines(&text, &base, 0, &mut Vec::new());
        }
        config
    }

    /// The user's `~/.ssh/config`, or `None` when `$HOME` is not set or the
    /// file does not exist.
    pub fn load_user_config() -> Option<SshConfig> {
        let path = user_config_path()?;
        if path.is_file() {
            Some(SshConfig::load(&path))
        } else {
            None
        }
    }

    /// Resolves the parameters for `host` (an alias or a real hostname).
    pub fn resolve(&self, host: &str) -> ResolvedSshParams {
        let mut out = ResolvedSshParams::default();
        for block in &self.blocks {
            if !block_matches(&block.patterns, host) {
                continue;
            }
            if out.host_name.is_none() {
                out.host_name = block.host_name.clone();
            }
            if out.port.is_none() {
                out.port = block.port;
            }
            if out.user.is_none() {
                out.user = block.user.clone();
            }
            if out.proxy_jump.is_none() {
                out.proxy_jump = block.proxy_jump.clone();
            }
            for key in &block.identity_files {
                // OpenSSH deduplicates repeated identity files.
                if !out.identity_files.contains(key) {
                    out.identity_files.push(key.clone());
                }
            }
        }
        out
    }

    /// `(alias, block)` pairs for every concrete (no `!`, `*` or `?`)
    /// `Host` pattern, in file order — the candidates for site import. A
    /// block with several concrete patterns yields one pair per pattern.
    pub fn concrete_aliases(&self) -> Vec<(String, SshHostBlock)> {
        let mut out = Vec::new();
        for block in &self.blocks {
            for pattern in &block.patterns {
                if pattern.contains(['*', '?']) || pattern.starts_with('!') || pattern == "*" {
                    continue;
                }
                out.push((pattern.clone(), block.clone()));
            }
        }
        out
    }

    /// True when no `Host` block was parsed (empty or missing config).
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn parse_lines(
        &mut self,
        text: &str,
        include_base: &Path,
        depth: usize,
        visited: &mut Vec<PathBuf>,
    ) {
        // Index of the block currently being filled; None while inside a
        // `Match` block (whose parameters are skipped) or before the first
        // `Host` line (top-level defaults, also skipped: OpenSSH only allows
        // a few keywords there and hosts cannot be derived from them).
        let mut current: Option<usize> = None;
        for raw_line in text.lines() {
            let line = match tokenize(raw_line) {
                Some(tokens) => tokens,
                None => continue, // blank or comment-only
            };
            let Some((keyword, args)) = split_keyword(&line) else {
                continue; // malformed line
            };
            if args.is_empty() {
                continue;
            }
            match keyword.as_str() {
                "host" => {
                    self.blocks.push(SshHostBlock {
                        patterns: args,
                        ..SshHostBlock::default()
                    });
                    current = Some(self.blocks.len() - 1);
                }
                // A `Match` line ends the previous `Host` block; parameters
                // below it are ignored until the next `Host`.
                "match" => current = None,
                "include" => {
                    if depth < MAX_INCLUDE_DEPTH {
                        for arg in &args {
                            self.include(arg, include_base, depth, visited);
                        }
                    }
                }
                _ => {
                    let Some(idx) = current else { continue };
                    let block = &mut self.blocks[idx];
                    let value = args[0].clone();
                    match keyword.as_str() {
                        "hostname" => {
                            block.host_name.get_or_insert(value);
                        }
                        "port" => {
                            if let Ok(port) = value.parse::<u16>() {
                                block.port.get_or_insert(port);
                            }
                        }
                        "user" => {
                            block.user.get_or_insert(value);
                        }
                        "proxyjump" => {
                            block.proxy_jump.get_or_insert(value);
                        }
                        "identityfile" => {
                            let expanded = expand_tilde(&value)
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_else(|| value.clone());
                            if !block.identity_files.contains(&expanded) {
                                block.identity_files.push(expanded);
                            }
                        }
                        _ => continue, // unsupported keyword: skipped
                    };
                }
            }
        }
    }

    fn include(&mut self, arg: &str, base: &Path, depth: usize, visited: &mut Vec<PathBuf>) {
        let resolved = expand_tilde(arg).unwrap_or_else(|| base.join(arg));
        for path in expand_glob(&resolved) {
            let canonical = match path.canonicalize() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if visited.contains(&canonical) {
                continue; // include cycle
            }
            visited.push(canonical.clone());
            if let Ok(text) = std::fs::read_to_string(&path) {
                let nested_base = path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| base.to_path_buf());
                self.parse_lines(&text, &nested_base, depth + 1, visited);
            }
        }
    }
}

/// `~/.ssh/config`, or `None` when `$HOME` is not set.
pub fn user_config_path() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".ssh").join("config"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Expands a leading `~` / `~user`-shaped `~` to `$HOME` (other users' homes
/// are not resolved, matching the app's scope). Returns `None` for relative
/// paths (the caller decides the base).
pub fn expand_tilde(path: &str) -> Option<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        home_dir().map(|home| home.join(rest))
    } else if path == "~" {
        home_dir()
    } else {
        None
    }
}

/// Fills unset SSH fields on `opt` from the user's `~/.ssh/config`.
///
/// Only applies to SFTP/SCP. Values already set by the UI (non-default port,
/// non-empty user / key / jump host) win; `HostName` always replaces the
/// typed alias when present, matching OpenSSH.
pub fn apply_user_config(opt: &mut crate::types::SessionOptions) {
    use crate::types::Protocol;

    if !matches!(opt.protocol, Protocol::Sftp | Protocol::Scp) {
        return;
    }
    let alias = opt.host.trim();
    if alias.is_empty() {
        return;
    }
    let Some(config) = SshConfig::load_user_config() else {
        return;
    };
    apply_resolved(opt, &config.resolve(alias));
}

/// Applies already-resolved SSH config params to `opt` (see [`apply_user_config`]).
pub fn apply_resolved(opt: &mut crate::types::SessionOptions, resolved: &ResolvedSshParams) {
    use crate::types::default_port_for_protocol;

    if let Some(host_name) = resolved
        .host_name
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
    {
        opt.host = host_name.to_string();
    }
    if let Some(port) = resolved.port {
        if opt.port == default_port_for_protocol(opt.protocol) {
            opt.port = port;
        }
    }
    if opt.username.trim().is_empty() {
        if let Some(user) = resolved
            .user
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            opt.username = user.to_string();
        }
    }
    let key_empty = opt
        .private_key_path
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty();
    if key_empty {
        if let Some(key) = resolved
            .identity_files
            .first()
            .filter(|k| !k.trim().is_empty())
        {
            opt.private_key_path = Some(key.clone());
        }
    }
    let jump_empty = opt
        .jump_host
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty();
    if jump_empty {
        if let Some(spec) = resolved
            .proxy_jump
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let (user, host, port) = parse_proxy_jump(spec);
            if !host.is_empty() {
                opt.jump_host = Some(host);
                if let Some(p) = port {
                    opt.jump_port = p;
                }
                let jump_user_empty = opt
                    .jump_username
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty();
                if jump_user_empty {
                    opt.jump_username = user;
                }
            }
        }
    }
}

/// Parses a `ProxyJump` specifier (`[user@]host[:port]`, IPv6 literals may be
/// bracketed) into its parts. Returns `(user, host, port)`.
pub fn parse_proxy_jump(spec: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = match spec.rsplit_once('@') {
        Some((u, h)) if !u.is_empty() => (Some(u.to_string()), h),
        _ => (None, spec),
    };
    // Bracketed IPv6: `[::1]` or `[::1]:2222`.
    if let Some(stripped) = rest.strip_prefix('[') {
        if let Some((host, tail)) = stripped.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
            return (user, host.to_string(), port);
        }
    }
    match rest.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => {
            (user, host.to_string(), port.parse().ok())
        }
        _ => (user, rest.to_string(), None),
    }
}

/// Splits a raw line into whitespace-separated tokens with `#` comments and
/// double-quote support. Returns `None` for blank / comment-only lines.
fn tokenize(line: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut in_quotes = false;
    let mut token_started = false;
    let mut line_has_content = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                token_started = true;
                line_has_content = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if token_started {
                    tokens.push(std::mem::take(&mut token));
                    token_started = false;
                }
            }
            '#' if !in_quotes && !token_started => {
                break; // comment: rest of the line
            }
            c => {
                token.push(c);
                token_started = true;
                line_has_content = true;
            }
        }
    }
    if token_started {
        tokens.push(token);
    }
    if line_has_content {
        Some(tokens)
    } else {
        None
    }
}

/// Splits a token list into `(lowercase keyword, value arguments)`, accepting
/// the `key=value`, `key = value`, `key= value` and `key =value` forms.
/// `None` when no value follows the keyword.
fn split_keyword(tokens: &[String]) -> Option<(String, Vec<String>)> {
    let first = tokens.first()?;
    let (keyword, inline_value) = match first.split_once('=') {
        Some((k, v)) => (k.to_ascii_lowercase(), Some(v.to_string())),
        None => (first.to_ascii_lowercase(), None),
    };
    let mut args: Vec<String> = tokens[1..].to_vec();
    if let Some(value) = inline_value {
        args.insert(0, value);
    } else if let Some(next) = args.first_mut() {
        // `key = value` / `key =value`: strip a leading `=` from the next
        // token; a bare `=` token is dropped entirely.
        if let Some(stripped) = next.strip_prefix('=') {
            if stripped.is_empty() {
                args.remove(0);
            } else {
                *next = stripped.to_string();
            }
        }
    }
    if args.is_empty() {
        None
    } else {
        Some((keyword, args))
    }
}

/// OpenSSH `Host` list matching: any pattern may match, a matching negated
/// pattern (`!`) excludes the whole block.
fn block_matches(patterns: &[String], host: &str) -> bool {
    let mut matched = false;
    for pattern in patterns {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern.as_str()),
        };
        if glob_match(pattern, host) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// Shell-style glob matching with `*` and `?` only (case-sensitive, like the
/// OpenSSH client).
fn glob_match(pattern: &str, text: &str) -> bool {
    fn inner(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(b'*'), _) => inner(&p[1..], t) || (!t.is_empty() && inner(p, &t[1..])),
            (Some(b'?'), Some(_)) => inner(&p[1..], &t[1..]),
            (Some(_), None) => false,
            (Some(pc), Some(tc)) if pc == tc => inner(&p[1..], &t[1..]),
            _ => false,
        }
    }
    inner(pattern.as_bytes(), text.as_bytes())
}

/// Expands `*`/`?` wildcards in `path` against the filesystem, one directory
/// level at a time (enough for `Include config.d/*.conf`). A literal path is
/// returned as-is; a wildcard pattern that matches nothing yields no paths.
fn expand_glob(path: &Path) -> Vec<PathBuf> {
    if !path.to_string_lossy().contains(['*', '?']) {
        return vec![path.to_path_buf()];
    }
    let mut current = vec![PathBuf::new()];
    for component in path.iter() {
        let component = component.to_string_lossy().into_owned();
        let mut next = Vec::new();
        for base in &current {
            if component.contains(['*', '?']) {
                let dir = if base.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    base.clone()
                };
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if glob_match(&component, &name) {
                            next.push(dir.join(name));
                        }
                    }
                }
            } else {
                next.push(base.join(&component));
            }
        }
        current = next;
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> SshConfig {
        SshConfig::parse_str(text, Path::new("/home/test/.ssh"))
    }

    #[test]
    fn parses_basic_host_block() {
        let c = parse(
            "# comment\nHost myserver\n  HostName 203.0.113.10\n  Port 2222\n  User deploy\n  IdentityFile ~/.ssh/id_deploy\n",
        );
        let r = c.resolve("myserver");
        assert_eq!(r.host_name.as_deref(), Some("203.0.113.10"));
        assert_eq!(r.port, Some(2222));
        assert_eq!(r.user.as_deref(), Some("deploy"));
        assert_eq!(
            r.identity_files,
            vec![format!("{}/.ssh/id_deploy", home_stub())]
        );
        assert!(r.proxy_jump.is_none());
    }

    #[test]
    fn first_match_wins_across_blocks() {
        // OpenSSH takes the first obtained value for a parameter, so
        // specific blocks come first and `Host *` last.
        let c = parse(
            "Host web\n  Port 2200\n\nHost web backup\n  Port 9999\n\nHost *\n  Port 22\n  User default\n",
        );
        let r = c.resolve("web");
        assert_eq!(r.port, Some(2200));
        assert_eq!(r.user.as_deref(), Some("default"));
        let r = c.resolve("other");
        assert_eq!(r.port, Some(22));
        assert_eq!(r.user.as_deref(), Some("default"));
        let r = c.resolve("backup");
        assert_eq!(r.port, Some(9999));
    }

    #[test]
    fn identity_files_accumulate_across_matching_blocks() {
        let c = parse(
            "Host web\n  IdentityFile ~/.ssh/a\n\nHost *\n  IdentityFile ~/.ssh/b\n  IdentityFile ~/.ssh/a\n",
        );
        let r = c.resolve("web");
        assert_eq!(
            r.identity_files,
            vec![
                format!("{}/.ssh/a", home_stub()),
                format!("{}/.ssh/b", home_stub())
            ]
        );
    }

    #[test]
    fn wildcard_and_negation_patterns() {
        let c =
            parse("Host *.internal !bad.internal\n  User hop\n\nHost bad.internal\n  User admin\n");
        assert_eq!(c.resolve("db.internal").user.as_deref(), Some("hop"));
        // Negated pattern excludes the first block; the second applies.
        assert_eq!(c.resolve("bad.internal").user.as_deref(), Some("admin"));
        assert!(c.resolve("example.com").user.is_none());
    }

    #[test]
    fn glob_match_basics() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("web?", "web1"));
        assert!(!glob_match("web?", "web12"));
        assert!(glob_match("*.example.com", "a.example.com"));
        assert!(!glob_match("*.example.com", "example.org"));
        assert!(glob_match("exact", "exact"));
    }

    #[test]
    fn keyword_forms_and_case() {
        let c = parse("HOST quoted\nhostname=\"quoted.example.com\"\nPORT=2022\n  user = spaced\n");
        let r = c.resolve("quoted");
        assert_eq!(r.host_name.as_deref(), Some("quoted.example.com"));
        assert_eq!(r.port, Some(2022));
        assert_eq!(r.user.as_deref(), Some("spaced"));
    }

    #[test]
    fn invalid_port_is_ignored() {
        let c = parse("Host h\n  Port notaport\n  User u\n");
        let r = c.resolve("h");
        assert_eq!(r.port, None);
        assert_eq!(r.user.as_deref(), Some("u"));
    }

    #[test]
    fn match_blocks_are_skipped() {
        let c = parse("Match final all\n  User ignored\n  Port 2222\n\nHost h\n  User kept\n");
        let r = c.resolve("h");
        assert_eq!(r.user.as_deref(), Some("kept"));
        assert_eq!(r.port, None);
    }

    #[test]
    fn parameters_before_first_host_are_skipped() {
        let c = parse("Port 2222\nUser nobody\n\nHost h\n  User kept\n");
        let r = c.resolve("h");
        assert_eq!(r.port, None);
        assert_eq!(r.user.as_deref(), Some("kept"));
    }

    #[test]
    fn proxy_jump_parsed_and_resolved() {
        let c = parse("Host db\n  ProxyJump bastion.example.com:2200\n");
        assert_eq!(
            c.resolve("db").proxy_jump.as_deref(),
            Some("bastion.example.com:2200")
        );
        assert_eq!(c.resolve("other").proxy_jump, None);

        let (user, host, port) = parse_proxy_jump("deploy@bastion:2200");
        assert_eq!(user.as_deref(), Some("deploy"));
        assert_eq!(host, "bastion");
        assert_eq!(port, Some(2200));

        let (user, host, port) = parse_proxy_jump("bastion");
        assert_eq!(user, None);
        assert_eq!(host, "bastion");
        assert_eq!(port, None);

        let (user, host, port) = parse_proxy_jump("root@[2001:db8::1]:2222");
        assert_eq!(user.as_deref(), Some("root"));
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, Some(2222));
    }

    #[test]
    fn concrete_aliases_skip_wildcards_and_negations() {
        let c = parse(
            "Host web1 web2\n  HostName 203.0.113.5\n\nHost *.internal\n  User hop\n\nHost !bad good\n  User u\n",
        );
        let aliases: Vec<String> = c.concrete_aliases().into_iter().map(|(a, _)| a).collect();
        assert_eq!(aliases, ["web1", "web2", "good"]);
        let block = c
            .concrete_aliases()
            .into_iter()
            .find(|(a, _)| a == "web1")
            .unwrap()
            .1;
        assert_eq!(block.host_name.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn include_files_are_inlined() {
        let dir = std::env::temp_dir().join(format!("freescp-sshcfg-{}", std::process::id()));
        let nested = dir.join("conf.d");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            dir.join("config"),
            "Host top\n  User topuser\nInclude conf.d/*.conf\n",
        )
        .unwrap();
        std::fs::write(
            nested.join("10-work.conf"),
            "Host work\n  HostName work.example.com\n",
        )
        .unwrap();
        std::fs::write(nested.join("20-skip.txt"), "Host ignored\n  User nope\n").unwrap();

        let c = SshConfig::load(&dir.join("config"));
        assert_eq!(
            c.resolve("work").host_name.as_deref(),
            Some("work.example.com")
        );
        // The .txt file must not be picked up by the *.conf glob.
        assert!(c.resolve("ignored").user.is_none());
        assert_eq!(c.resolve("top").user.as_deref(), Some("topuser"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn include_cycles_terminate() {
        let dir = std::env::temp_dir().join(format!("freescp-sshcfg-cycle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.conf"), "Include b.conf\nHost a\n  User auser\n").unwrap();
        std::fs::write(dir.join("b.conf"), "Include a.conf\nHost b\n  User buser\n").unwrap();

        let c = SshConfig::load(&dir.join("a.conf"));
        assert_eq!(c.resolve("a").user.as_deref(), Some("auser"));
        assert_eq!(c.resolve("b").user.as_deref(), Some("buser"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tilde_expansion() {
        assert_eq!(
            expand_tilde("~/keys/id"),
            home_dir().map(|h| h.join("keys/id"))
        );
        assert_eq!(expand_tilde("~"), home_dir());
        assert_eq!(expand_tilde("relative/path"), None);
        assert_eq!(expand_tilde("/absolute"), None);
    }

    #[test]
    fn empty_config_resolves_nothing() {
        let c = parse("");
        assert!(c.is_empty());
        assert_eq!(c.resolve("anything"), ResolvedSshParams::default());
    }

    #[test]
    fn apply_resolved_fills_defaults_only() {
        use crate::types::{Protocol, SessionOptions};

        let resolved = ResolvedSshParams {
            host_name: Some("real.example.com".into()),
            port: Some(2222),
            user: Some("deploy".into()),
            identity_files: vec!["/keys/id_ed25519".into()],
            proxy_jump: Some("jump@bastion:2200".into()),
        };

        let mut opt = SessionOptions {
            protocol: Protocol::Sftp,
            host: "alias".into(),
            ..SessionOptions::default()
        };
        apply_resolved(&mut opt, &resolved);
        assert_eq!(opt.host, "real.example.com");
        assert_eq!(opt.port, 2222);
        assert_eq!(opt.username, "deploy");
        assert_eq!(opt.private_key_path.as_deref(), Some("/keys/id_ed25519"));
        assert_eq!(opt.jump_host.as_deref(), Some("bastion"));
        assert_eq!(opt.jump_port, 2200);
        assert_eq!(opt.jump_username.as_deref(), Some("jump"));

        // Explicit UI values win over config (except HostName).
        let mut opt = SessionOptions {
            protocol: Protocol::Sftp,
            host: "alias".into(),
            port: 443,
            username: "ui-user".into(),
            private_key_path: Some("/ui/key".into()),
            jump_host: Some("ui-jump".into()),
            jump_port: 22,
            jump_username: Some("ui-jump-user".into()),
            ..SessionOptions::default()
        };
        apply_resolved(&mut opt, &resolved);
        assert_eq!(opt.host, "real.example.com");
        assert_eq!(opt.port, 443);
        assert_eq!(opt.username, "ui-user");
        assert_eq!(opt.private_key_path.as_deref(), Some("/ui/key"));
        assert_eq!(opt.jump_host.as_deref(), Some("ui-jump"));
        assert_eq!(opt.jump_username.as_deref(), Some("ui-jump-user"));
    }

    /// The tests must not depend on the machine's `$HOME`, so they pin it for
    /// the identity-file expansion assertions.
    fn home_stub() -> String {
        home_dir()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Real-world smoke test against the developer's own `~/.ssh/config`
    /// (run explicitly: `cargo test -p freescp-core --lib -- --ignored
    /// real_world_config --nocapture`).
    #[test]
    #[ignore = "depends on the machine's ~/.ssh/config"]
    fn real_world_config_parses_and_resolves() {
        let Some(config) = SshConfig::load_user_config() else {
            println!("no ~/.ssh/config on this machine");
            return;
        };
        for (alias, _) in config.concrete_aliases() {
            let r = config.resolve(&alias);
            println!(
                "{alias}: host={} port={:?} user={:?} keys={} jump={:?}",
                r.host_name.as_deref().unwrap_or(&alias),
                r.port,
                r.user,
                r.identity_files.len(),
                r.proxy_jump
            );
        }
    }
}
