# FreeSCP

FreeSCP is an SFTP/SCP/FTP/FTPS/WebDAV/SMB file-transfer client with a
pure-Rust core (russh, russh-sftp, suppaftp, reqwest, smb2) and a Slint-based
desktop UI. It runs on Windows, macOS and Linux.

- Repositories:
  - GitHub: https://github.com/NOXCIS/FreeSCP
  - GitLab: https://gitlab.com/Noxcis/FreeSCP
- License: MIT (see `docs/credits/` for third-party credits)

## Features

- SFTP, SCP (with SSH jump hosts, Cloudflare Tunnel/`cloudflared` access via
  `ProxyCommand`, and SOCKS5/HTTP-CONNECT proxies), FTP, FTPS, WebDAV, and
  SMB/CIFS backends (SMB2/SMB3 only; no SMB1, proxy, or jump-host support)
- Embedded Telnet console (plain TCP and TLS) with a VT100/VT220 terminal,
  scrollback, copy/paste, NAWS window resizing, and optional auto-login
- File manager with transfer queue, integrity verification, drag &
  drop, permissions editor, and remote search
- Site manager with SSH config import, connection history, and keychain-backed
  secret storage
- Localizations: English, Spanish, French, Portuguese

## Building

The Rust toolchain version is pinned in [rust-toolchain.toml](rust-toolchain.toml).

```bash
cargo build --workspace
cargo run -p freescp-app
```

Linux needs the usual Slint/GTK dev packages (libxkbcommon, fontconfig, gtk3,
etc.). macOS and Windows need no extra dependencies.

## Command line

The `freescp` CLI (`crates/freescp-cli`) exposes the same core over the same
protocols. Target and remote path are separate arguments
(`[user@]host[:port] path`, never `host:path`):

```bash
cargo build -p freescp-cli

# One-shot commands
freescp ls    user@example.com:2222 /var/log
freescp get   user@example.com:2222 /var/log/syslog ./syslog
freescp put   user@example.com:2222 ./syslog /tmp/syslog
freescp mkdir user@example.com:2222 --parents /tmp/backups
freescp stat  user@example.com:2222 --json /etc/hosts
freescp rm    user@example.com:2222 /tmp/old.log

# Other protocols: -p sftp|scp|ftp|ftps|webdav|smb
freescp ls -p ftp --port 2121 -u user ftp.example.com /pub

# Interactive SFTP-style shell and telnet console
freescp shell user@example.com:2222
freescp console switch.example.com --telnet-tls

# Shell completion script
freescp completions zsh > ~/.zfunc/_freescp
```

SSH host keys are verified against `~/.ssh/known_hosts`: interactive terminals
prompt for unknown hosts, non-interactive runs fail closed unless
`--accept-new` (trust on first use) is given. Passwords come from `--password`
or the `FREESCP_PASSWORD` environment variable, otherwise an interactive
prompt is shown when no key is configured. `~/.ssh/config` (host aliases,
ports, identity files, `ProxyJump`) is honored for SFTP/SCP.

## Testing

```bash
cargo test --workspace            # unit + mock tests
cargo test -p freescp-core        # backends only
```

The SFTP/SCP/FTP/FTPS/WebDAV/SMB/Telnet integration suites self-skip unless
their `FREESCP_IT_*` environment variables are set; the full contract is
documented in [docs/PARITY.md](docs/PARITY.md) and exercised by
[.github/workflows/ci.yml](.github/workflows/ci.yml).

## Packaging

- macOS `.app`/DMG: `scripts/package_mac_rust.sh`
- Linux AppImage: `scripts/package_appimage_rust.sh`

## Translations

Catalogs are generated from the Qt Linguist sources in `translations/`:

```bash
./scripts/convert_translations.sh   # requires lconvert (qt6) and msgfmt (gettext)
```

Outputs `crates/freescp-app/translations/<lang>/LC_MESSAGES/freescp-app.po/.mo`.
