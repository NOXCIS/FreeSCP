# FreeSCP

FreeSCP is a two-panel SFTP/SCP/FTP/FTPS/WebDAV file-transfer client with a
pure-Rust core (russh, russh-sftp, suppaftp, reqwest) and a Slint-based
desktop UI. It is the continuation of the OpenSCP Rust rewrite.

- Repositories:
  - GitHub: https://github.com/Noxcis/freescp
  - GitLab: https://gitlab.com/Noxcis/freescp
- License: MIT (see `docs/credits/` for third-party credits)

## Features

- SFTP, SCP (with SSH jump hosts and SOCKS5/HTTP-CONNECT proxies), FTP, FTPS,
  and WebDAV backends
- Two-panel file manager with transfer queue, integrity verification, drag &
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

## Testing

```bash
cargo test --workspace            # unit + mock tests
cargo test -p freescp-core        # backends only
```

The SFTP/SCP/FTP/FTPS/WebDAV integration suites self-skip unless their
`FREESCP_IT_*` environment variables are set; the full contract is documented
in [docs/PARITY.md](docs/PARITY.md) and exercised by
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
