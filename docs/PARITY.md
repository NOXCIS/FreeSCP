# FreeSCP Rust Rewrite — Feature Parity Checklist

This document tracks feature parity between the legacy C++/Qt tree and the
Rust rewrite (Cargo workspace: `crates/freescp-core`, `crates/freescp-app`).
It is the sign-off checklist for the final milestone: the C++ tree
(`CMakeLists.txt`, `core/`, `ui/`, `tests/`, Qt-specific scripts) is deleted
only after every row here is `done`.

Status reflects what exists on disk at the time of writing (parallel
workstreams land modules incrementally, so rows are updated as they land):

- **done** — module ported and compiling (unit/integration tests where
  applicable). UI rows additionally passed the runtime smoke test: the app
  and the packaged macOS .app launch cleanly.
- **partial** — scaffolding in place (types, trait surface, UI skeleton,
  script skeleton) but behavior incomplete
- **todo** — not started

## Feature parity

| Feature | C++ source | Rust module | Status |
|---|---|---|---|
| SFTP backend ops (list/get/put/stat/chmod/chown/times/mkdir/remove/rename) | `core/src/libssh2/Libssh2SftpClient.cpp` | `crates/freescp-core/src/backends/sftp/` | done |
| SCP backend (exec channel, Auto SFTP fallback, SCP-only mode) | `core/src/libssh2/Libssh2ScpClient.cpp` | `crates/freescp-core/src/backends/scp/` | done |
| FTP/FTPS backend (MLSD+LIST listing, TLS explicit/implicit, custom CA) | `core/src/curl/CurlFtpClient.cpp` | `crates/freescp-core/src/backends/ftp/` | done |
| WebDAV backend (PROPFIND/MKCOL/MOVE/DELETE/PUT/GET) | `core/src/curl/CurlWebDavClient.cpp` | `crates/freescp-core/src/backends/webdav/` | done |
| Shared types, `SessionOptions`, parsers, capabilities | `core/include/freescp/SftpTypes.hpp` | `crates/freescp-core/src/types.rs` | done |
| Async `SftpClient` trait + `ClientError` | `core/include/freescp/SftpClient.hpp` | `crates/freescp-core/src/client.rs` | done |
| Protocol-aware client factory | `core/include/freescp/ClientFactory.hpp` | `crates/freescp-core/src/client_factory.rs` | done |
| Mock backend + core mock tests | `core/src/mock/MockSftpClient.cpp`, `tests/core_mock_tests.cpp` | `crates/freescp-core/src/backends/mock/` | done |
| known_hosts policies (Strict / AcceptNew / Off, hashed entries) | `core/include/freescp/KnownHostsUtils.hpp` + sftp backend | `crates/freescp-core/src/known_hosts.rs` | done |
| TOFU host-key confirmation + one-time connect | `Libssh2SftpClient.cpp` host-key callback | `backends/sftp/` (host-key callback) | done |
| Keyboard-interactive (OTP/2FA) auth | `Libssh2SftpClient.cpp` | `backends/sftp/` + `KbdIntPromptResult` in `types.rs` | done |
| SOCKS5 / HTTP-CONNECT proxy tunneling | `Libssh2SftpClient.cpp` proxy setup | `crates/freescp-core/src/proxy.rs` | done |
| SSH jump host (bastion) tunneling | `Libssh2SftpClient.cpp` (`ssh -W` tunnel) | `crates/freescp-core/src/jumphost.rs` | done |
| Transfer integrity (off/optional/required, `.part` + atomic finalize) | `Libssh2SftpClient.cpp` integrity helpers | `crates/freescp-core/src/integrity.rs` | done |
| Transfer resume (upload + download) | `Libssh2SftpClient.cpp` resume paths | `client.rs` trait (resume params) + sftp backend (`sftp/transfer.rs`) | done |
| Transfer manager + queue dialog (parallel workers, pause/cancel/retry, progress, filters) | `ui/TransferManager.cpp`, `ui/TransferQueueDialog.cpp` | `crates/freescp-app/src/transfer.rs`, `ui/transfer-queue.slint` | done |
| Drag-and-drop copy/move between panes | `ui/DragAwareTreeView.cpp`, `ui/DnDTypes.hpp` | `ui/main-window.slint` (`DragArea`/`DropArea`) + `src/main.rs` (`handle_pane_drop`) | done |
| Two-pane main window, breadcrumbs, toolbar, local panel | `ui/MainWindow.cpp`, `ui/MainWindowLocalOps.cpp` | `ui/main-window.slint`, `src/local_fs.rs` | done |
| Remote panel ops (navigate, refresh, new/rename/delete, permissions) | `ui/MainWindowRemoteOps.cpp`, `ui/RemoteModel.cpp`, `ui/PermissionsDialog.cpp` | `src/remote.rs`, `ui/permissions.slint` | done |
| Connection dialog (all protocols, auth fields, proxy/jump/FTPS controls) | `ui/ConnectionDialog.cpp` | `ui/connection-dialog.slint`, `src/connect.rs` | done |
| Site manager + stable UUID sites + duplicate blocking | `ui/SiteManagerDialog.cpp` | `ui/site-manager.slint`, `src/site_manager.rs` | done |
| Settings keys (general/transfers/sites/security/network) | `ui/SettingsDialog.cpp` | `src/settings.rs` (serde/TOML), `ui/settings.slint` | done |
| Secret store (macOS Keychain, Linux Secret Service) | `ui/SecretStore.cpp` | `src/secrets.rs` (keyring) | done |
| Connection history | `ui/MainWindow.cpp` history | `src/history.rs` | done |
| About dialog | `ui/AboutDialog.cpp` | `ui/about.slint` | done |
| i18n es/fr/pt (every `.slint` `@tr` resolves in all three catalogs; startup installs a real locale so `UI/language` applies; Rust-built dialog text translated too) | `translations/freescp_{es,fr,pt}.ts` | `crates/freescp-app/translations/{es,fr,pt}/LC_MESSAGES/freescp-app.{po,mo}` (Slint gettext + `init_translations!`) | done |
| macOS packaging (.app, signing, notarization, DMG) | `scripts/package_mac.sh`, `scripts/macos.sh` | `scripts/package_mac_rust.sh` | done |
| Linux AppImage packaging | `scripts/package_appimage.sh` | `scripts/package_appimage_rust.sh` | done |
| Flatpak packaging | `packaging/flatpak/com.openscp.OpenSCP.yml` | same file (rewritten for Rust) | done |
| Snap packaging | `packaging/snap/snapcraft.yaml` | same file (rewritten for Rust) | done |
| CI (fmt/clippy/build/test, Ubuntu+macOS integration matrix) | `.github/workflows/ci.yml` (CMake/Qt) | same file (rewritten for Rust) | done |

## Rust-only additions (beyond C++ parity)

- **`~/.ssh/config` support** (`crates/freescp-core/src/ssh_config.rs`): a
  minimal OpenSSH client-config parser (`Host` patterns with `!` negation and
  `*`/`?` wildcards, `HostName`/`Port`/`User`/`IdentityFile`/`ProxyJump`,
  `Include` with globs, `Match` blocks skipped) used two ways:
  - *Connect-time resolution* (`connect.rs::apply_ssh_config_defaults`,
    called from `start_connect`): host aliases resolve to their `HostName`,
    an empty username takes the config `User`, the port applies while still
    at the protocol default, the first `IdentityFile` fills an empty key
    path, and `ProxyJump` configures the jump host when neither proxy nor
    jump is set (bastion aliases resolve through the same rules). SFTP/SCP
    only; quick-connect site persistence runs first, so saved sites keep the
    alias as typed.
  - *Site-Manager import* (`site_manager.rs`, "Import SSH config" button):
    concrete (non-wildcard) `Host` aliases import as SFTP sites carrying the
    config's port/user/key/ProxyJump; same-named existing sites win, so
    re-importing is idempotent.
  The C++ app never read `~/.ssh/config` (its `ssh -W` bastion inherited it
  implicitly from the OpenSSH CLI; the in-process russh bastion does not).

## UI parity sweep (Slint 1.9 → 1.17.1)

An audit against the Qt dialogs found UI elements that were missing from the
Rust/Slint port. The sweep below restored them; Slint was upgraded from 1.9 to
1.17.1 along the way (the newer version adds `Tooltip`, robust `KeyBinding`
shortcuts, and better drag-and-drop support).

- **Main window**: custom menu bar (FreeSCP / File / Help) with hand-rolled
  dropdown popups; the full keyboard-shortcut set (F2 rename, F5 copy, F6
  move, F7 download, F8 upload, F9 new folder, F10 new file, Delete,
  Ctrl/Cmd+F search, F12 transfer queue, Ctrl+Shift+H history, Cmd/Ctrl+,
  settings, Ctrl/Cmd+Q quit, fullscreen toggle), with the F12/history
  shortcuts honoring the strings stored in Settings; clickable breadcrumb
  strips above each path input; tooltips on toolbar buttons and status-bar
  labels; "Warning: unencrypted secrets storage active" status label driven
  from Rust; dynamic window title (`FreeSCP — local/remote (SFTP)` etc.);
  fullscreen mode.
- **Panels**: `Type` column on the left list and `Permissions` column on the
  right list; draggable splitter between panes with persisted geometry;
  context menus open at the pointer position instead of a fixed location.
- **Search dialog**: "Search items" with wildcard/regex pattern help,
  "Search recursively in subfolders" checkbox, and a results dialog (match
  list + Close), mirroring `compilePanelSearchRegex` semantics.
- **History dialog**: three tabs (Recent local paths / Recent remote paths /
  Recent servers) with "Open selected" and "Clear history" (confirmed).
- **Connection dialog**: "Save passwords/passphrases" checkbox (default
  unchecked, disabled when "Save to saved sites" is off), wired into site
  persistence and the secret store (`ConnectionDialog.cpp:254` parity).
- **Site manager**: the inline Add/Edit editor now carries the full
  ConnectionDialog field set (known_hosts path + "Choose…", FTPS/WebDAV
  verify-peer checkboxes + CA bundle paths, jump-host enable checkbox with
  port/user/private-key rows), with protocol-dependent row visibility and a
  port reset on protocol change; proxy rows hide when the proxy type is
  "None". Validation ports the Qt alerts (auto-name from `user@host` on Add,
  "Name required", case-insensitive "Duplicate name" blocking, "Credentials
  not saved" persist-issue reporting). The table sorts by name ascending on
  open with clickable headers (toggle asc/desc), shows full-value cell
  tooltips, keeps/reselects the edited row after save (by stable site id,
  matching the C++ model-index bookkeeping), offers Up/Down/Enter
  keyboard navigation, and the button is labeled "Add" with "Add site" /
  "Edit site" headings. Deleting a site with "Delete secrets on remove"
  enabled also removes its known_hosts entry (site path or
  `~/.ssh/known_hosts` fallback).
- **Settings**: "Restore default sizes" wired (resets geometry/columns with
  confirm + info alerts); "Use stricter Keychain accessibility" gated to
  macOS; confirmation warning when enabling the insecure credentials
  fallback; "language changes take effect after restart" info after Apply.
  Follow-up audit (SettingsDialog.cpp / main.cpp parity):
  - `UI/language` now selects the gettext catalog at startup (like the C++
    `QTranslator` install; "en" is the source language), instead of always
    following the system locale.
  - Apply re-arms the F12/history shortcuts and retargets the live
    session-health timer (`Network/sessionHealthIntervalSec`), and keeps the
    dialog open like the C++ modal Apply button.
  - `Network/remoteWriteabilityTtlMs` drives the writeability cache TTL
    (clamped 1000..=120000 ms) instead of the hardcoded 15 s.
  - `UI/defaultDownloadDir` defaults from the OS download location
    (`dirs::download_dir()`) and is trimmed/falls back to the default when
    the field is empty on Apply.
  - "Queue auto-clear after" minutes spin is disabled while the mode is Off.
- **Transfer queue**: full 11-column table (Name, Status, Progress,
  Transferred, Speed, ETA, Type, Source, Destination, Attempts, Error);
  multi-select rows (Ctrl/Cmd-click); Pause/Resume/Cancel/Retry selected;
  per-task speed limits via "Limit selected"; global speed-limit row with
  Apply; auto-clear row (Off / Completed / Failed-Canceled / All finished +
  minutes, persisted to `queue-ui-state.toml`); row context menu
  (pause/resume/limit/cancel/retry, open destination, copy source/destination
  path to the system clipboard); "Clear finished" split into "Clear
  completed" and "Clear failed/canceled".
- **About dialog**: "Copy diagnostics" (system clipboard) and "Open Licenses
  Folder" buttons wired; "Report an issue" link opens the GitHub issues page.
  Follow-up audit: the author name links to the author page; the version
  string comes from `CARGO_PKG_VERSION`; "Open Licenses Folder" is disabled
  with a "not available" tooltip when no licenses directory is found (as in
  C++); diagnostics include the build's git commit (`build.rs`) and a
  human-readable OS name.
- **Alerts**: Qt-style "Confirm move" prompt before upload-and-delete moves;
  the overwrite-conflict prompt now offers Overwrite / Skip / Overwrite all /
  Skip all (the "all" answers are sticky for the rest of the operation batch
  and reset on retries and new batches).
- **Staging**: startup purges stale `yyyyMMdd-HHmmss` drag-out batches older
  than `Advanced/stagingRetentionDays` (clamped 1..=365) when
  `Advanced/autoCleanStaging` is set, mirroring the deferred cleanup in
  `MainWindow`'s constructor.

### Follow-up sweep (panes, actions, formatting)

A second audit pass against `MainWindow.cpp` / `MainWindowLocalOps.cpp` /
`MainWindowRemoteOps.cpp` / `RemoteModel.cpp` closed the following gaps:

- **Status bar**: every message is cleared again after 5 s unless a newer one
  replaced it, matching the timeout every C++ `showMessage` call passes.
- **Connect gating**: the Connect action (toolbar + File menu) is disabled
  while a session is connected or a connect attempt is in flight
  (`connect-in-progress` property fed from `connect.rs`, port of
  `m_connectInProgress_`), and `connect::open` itself refuses with an alert.
- **Up actions**: enabled only when the pane is not at its root
  (`left-can-go-up` / `right-can-go-up`, port of `canGoUp()`), instead of
  silently doing nothing.
- **Selection-driven actions**: Copy/Move/Delete/Rename on both panes are
  enabled only with a selection (port of `updateDeleteShortcutEnables`); the
  synthetic `..` row never counts as a selection.
- **Context menus**: both row menus now mirror `showLeftContextMenu` /
  `showRightContextMenu` (Up first when applicable, New file/New folder
  always, Rename/Copy/Move/Delete and the permissions entry only with a
  selection; remote adds Upload/Download; the Rust-only "Upload…" left entry
  is gone). Right-clicking an empty listing opens the no-selection menu.
- **Keyboard navigation**: Up/Down/Home/End move the selection in the focused
  pane and Return activates the entry, like `QTreeView` + the C++
  `activated()` hook.
- **Column headers/formatting**: local header is now `Kind` with MIME types
  (`Folder` for directories, `mime_guess` otherwise), remote date column is
  `Date` and remote sizes use Qt's one-decimal `DataSizeIecFormat` text;
  local sizes render like `QFileSystemModel` (`5 bytes`, `1.50 KiB`) and
  directories show `--` in the size cell (the local `Date Modified` column
  keeps the fixed `YYYY-MM-DD HH:MM` format — chrono has no locale database).
- **Search**: the recursive checkbox defaults to off like the C++ prompt; the
  non-recursive branch now matches the panel entries in place (first match
  selected, "Found N match(es) in <panel>." / "No matches found in <panel>."
  status) instead of opening the results list, and an invalid pattern raises
  the "Invalid pattern" alert.
- **Disconnect**: cancels queued/active transfers (`transferMgr_->clearClient`
  in `disconnectSftp`).

### Third sweep (panes offline mode, drag and drop, settings)

A third pass covered the larger items and the remaining Settings/About
deviations:

- **Local/local mode**: the right pane browses local folders until a session
  connects (see the closed backlog below), so the offline workflow matches the
  C++ app.
- **Column sorting**: both listings sort on a header click with an indicator
  and persisted direction, replacing the resize-only headers.
- **Live local listings**: a `notify` watcher refreshes each local pane when
  the folder changes on disk (`QFileSystemModel` behavior).
- **Path fields**: clear buttons and recent-path dropdowns backed by the
  history store (`setClearButtonEnabled` + the C++ recent-path menu).
- **Drag and drop**: pane-to-pane copy/move with folder-row targets,
  Ctrl/Cmd-to-move, remote→local downloads, left→right uploads and
  remote→remote server-side moves (see the closed backlog below).
- **Settings**: the two shortcut fields are `QKeySequenceEdit`-style recorders
  (port of the C++ recorder, including the "Unsupported shortcut" warning and
  the candidate hints), Apply is dirty-gated against the loaded preferences,
  the insecure-fallback checkbox is hidden when a secure secret backend is
  available (`settings::insecure_fallback_available`), the legacy
  `QSettings`/plist store is imported on first run
  (`settings::import_legacy_preferences`), macOS honors
  `Security/macKeychainRestrictive` through a `security-framework`
  `kSecAttrAccessible` write path, and the download destination dialog starts
  at the last used folder / `UI/defaultDownloadDir`.
- **Language selection**: startup installs a real POSIX locale for
  `UI/language` (`install_ui_locale`) before `init_translations!` — GNU gettext
  ignores `LANGUAGE` while the process locale is `C`/`POSIX` (what a
  Finder-launched .app gets), so the catalog used to stay English there. The
  checked-in catalogs also had to be de-Qt-ified: `lconvert` writes
  `msgctxt "MainWindow|"` for context-only entries, while Slint looks the
  context up as the bare `.slint` name (`MainWindow`), so every `@tr` lookup
  missed and the whole UI stayed in the source language. The conversion script
  strips the marker and a test guards the catalogs (`catalogs_use_bare_slint_contexts`,
  `locale_candidates_prefer_the_ui_language_then_a_real_fallback`).
  The pipeline is `lconvert` → context-marker strip →
  `scripts/po_fill_slint_contexts.py` → `msgfmt`: the new step copies the
  translation of the same source text into the `.slint` component context when
  the Rust port repeated a widget the C++ shared between dialogs (the site
  manager reuses the connection fields instead of embedding
  `ConnectionDialog`). Strings that only exist in the Rust port were added to
  the `.ts` sources directly (toolbar tooltips incl. their shortcut suffixes,
  the search and overwrite dialogs, the local-pane `Kind`/`Date Modified`
  headers, the duration units, the Settings hints and the WebDAV fields).
  All 236 `@tr` strings now resolve in es/fr/pt; the authored entries deserve a
  native-speaker pass.
  Rust-built dialog text is translated as well: `connect::translate_alert_text`
  resolves alert titles/messages/button labels against the Qt contexts, and
  `connect::tr(msgid, args)` reuses the C++ msgids with their `%1`… arguments
  for the dynamically composed dialogs (connection failures, unsupported
  jump host/proxy, invalid search pattern, terminal launch errors, duplicate
  site names, credentials not saved, the "No verification" confirmation) and
  the window titles. The overwrite prompts use the exact C++ msgids through
  `tr_main_window` (`«%1» already exists.\nOverwrite?`,
  `“%1” already exists at destination.\nOverwrite?`).
- **Terminal**: "Open in terminal" now builds the real command through
  `terminal.rs`, honoring `Terminal/forceInteractiveLogin` and
  `Terminal/enableSftpCliFallback` (ssh with the `sftp` CLI fallback) instead
  of always opening a local shell at the staging root.
- **About**: the "Used libraries" text is generated for the Rust dependency
  set (russh/russh-sftp, suppaftp, reqwest, Slint, keyring,
  security-framework) with licenses, sites and copyrights.
- **Search results**: the recursive summary reproduces the C++ results dialog
  lines (`Base:`, `Matches:`, `Scan errors:`, `Search canceled by user.`,
  `Results truncated to safety limit.`).

### Consolidated backlog — closed

The cross-cutting items listed here have all landed; the implementation notes
are kept for review:

1. **Multi-selection** (`ExtendedSelection`): Ctrl/Cmd- and Shift-click on both
   panes, Ctrl/Cmd+A, Escape to collapse, multi-row Delete/Copy/Move, and
   Up/Down/Home/End navigation write through a `PaneSelection` model
   (`src/main.rs`) that mirrors Qt's anchor + ranges (the synthetic `..` row
   never counts).
2. **Drag and drop between panes**: every row is a `DragArea` and every pane
   root plus every folder row is a `DropArea` (also the C++ drop-target visuals:
   an inset highlight on the hovered pane and a translucent highlight over the
   hovered folder row). Ctrl/Cmd at press time turns the drop into a move (the
   C++ `preferredPanelDropAction`); left→right(remote) uploads and
   right(remote)→left downloads land in the hovered folder; same-session
   remote→remote drops are server-side renames
   (`move_remote_entries_on_server`, incl. the
   `Drop ignored: nothing to move (N skipped)` guard for self/own-subtree
   targets); local→local moves reuse the copy/move engine with the overwrite
   prompt.
3. **Right pane in local mode**: the right pane browses local folders until a
   session connects (`right-local-mode` / `right_pane_is_local`); "Open right
   folder", both panes' navigation, Copy/Move/Delete/Rename/New file/New folder
   and the local/local drag-and-drop branch work offline, and the pane flips to
   the remote listing on connect (and back on disconnect).
4. **Click-to-sort columns**: both headers toggle asc/desc with a sort
   indicator, sort state is persisted (`sort-column` / `sort-ascending` per
   pane in the window-state file) and the comparator mirrors the C++ model
   order (folders first, then name/size/kind/date columns).
5. **Filesystem watcher** on the local pane(s): the `watcher` module (notify)
   re-points a per-pane watch on every reload and posts
   `UiEvent::LocalDirChanged`; the UI ignores events for a folder the pane has
   since navigated away from, so external changes refresh the listing like
   `QFileSystemModel`.
6. **Path field clear button** (`setClearButtonEnabled`) and per-pane recent-path
   dropdowns fed from the history store (`RECENT_PATH_MENU_LIMIT` rows).
7. **Recursive search summary**: the results header reproduces the C++ dialog
   verbatim — `Base:`, `Matches:`, and the optional `Scan errors: N`,
   `Search canceled by user.` and `Results truncated to safety limit.` lines.

Remaining Settings/About deviations from the C++ build (documented, not yet
implemented):

- Statically written UI text is fully translated; what stays English is text
  that is *assembled at runtime* from parts the catalogs cannot match: the
  status-bar messages built with `format!`/`set_status`, and the
  transfer-conflict prompt's Rust-only wording
  (`File "…" already exists on the server…`). Qt's standard buttons that the
  port passes explicitly (`Yes`/`No`) now have catalog entries; `tr()` output
  resolves on the UI thread only, because Slint keeps its translator in a
  thread-local.
- Qt catalogs spell arguments `%1`; Slint's `@tr` spells them `{}`. Entries that
  take arguments therefore have to be rewritten when they are copied into a
  Slint component context; the two Settings shortcut hints
  (`Unsupported shortcut: {}`, `Supported: {}`) are not in the Qt catalogs at
  all, so they were authored with Slint's `{}` spelling. Rust-side lookups go
  through `connect::tr`, which substitutes `%1`… itself.
- The `.ts` entries added for Rust-only strings (see *Language selection* above)
  were authored during the rewrite and would benefit from a native-speaker
  review pass in all three languages.

Known limitations (documented, not implementable in current Slint):

- OS-level drag-out to Finder/Explorer with the Qt staging/prep overlay is not
  available, and OS drag-in from the file manager into a pane is not wired:
  Slint's `DataTransfer` only carries plain text/images inside the application,
  so external file URLs cannot be read by the `DropArea` handlers (the pane
  drop targets deliberately reject drags that did not start on a pane row).
  Pane-to-pane drag-and-drop (copy/move in every direction, including the
  remote→local download and remote→remote server-side move cases) works.

## Integration test env-var contract (`FREESCP_IT_*`)

All integration suites in `crates/freescp-core/tests/` are env-gated: when the
required variables are unset they print `[SKIP]` and pass (the Rust equivalent
of the C++ exit-code-77 skip). This keeps local `cargo test` frictionless and
lets CI enable suites selectively.

### SFTP suite (`tests/sftp_integration.rs`)

Required:

- `FREESCP_IT_SFTP_HOST` — SSH/SFTP server host
- `FREESCP_IT_SFTP_USER` — username
- One auth method: `FREESCP_IT_SFTP_PASS` (password) or `FREESCP_IT_SFTP_KEY` (path to private key)

Optional:

- `FREESCP_IT_SFTP_PORT` — default `22`
- `FREESCP_IT_SFTP_KEY_PASSPHRASE` — key passphrase
- `FREESCP_IT_SFTP_REMOTE_BASE` → falls back to `FREESCP_IT_REMOTE_BASE` → default `/tmp`

Transport variants (all optional; mirror the C++ `libssh2_integration_tests.cpp`):

- Proxy: `FREESCP_IT_PROXY_TYPE` = `socks5` or `http`; `FREESCP_IT_PROXY_HOST`
  (required when the type is set); `FREESCP_IT_PROXY_PORT` (default `1080` for
  `socks5`, `8080` for `http`); `FREESCP_IT_PROXY_USER` / `FREESCP_IT_PROXY_PASS`
- Jump host: `FREESCP_IT_JUMP_HOST`, `FREESCP_IT_JUMP_PORT` (default `22`),
  `FREESCP_IT_JUMP_USER`, `FREESCP_IT_JUMP_KEY`
- Proxy and jump host are mutually exclusive in one session (same as the C++).

### SCP suite (`tests/scp_integration.rs` — written)

- Primary: `FREESCP_IT_SCP_HOST`, `FREESCP_IT_SCP_USER`, and one of
  `FREESCP_IT_SCP_PASS` / `FREESCP_IT_SCP_KEY`
- Optional: `FREESCP_IT_SCP_PORT`, `FREESCP_IT_SCP_KEY_PASSPHRASE`,
  `FREESCP_IT_SCP_REMOTE_BASE`
- Every `FREESCP_IT_SCP_*` variable falls back to the matching
  `FREESCP_IT_SFTP_*` variable; the remote base additionally falls back to
  `FREESCP_IT_REMOTE_BASE` (default `/tmp`).

### FTP suite (`tests/ftp_integration.rs` — written)

- Required: `FREESCP_IT_FTP_HOST`, `FREESCP_IT_FTP_REMOTE_BASE`
- Optional: `FREESCP_IT_FTP_PORT` (default `21`), `FREESCP_IT_FTP_USER`
  (default `anonymous`), `FREESCP_IT_FTP_PASS`

### FTPS suite (`tests/ftps_integration.rs` — written)

- Required: `FREESCP_IT_FTPS_HOST`, `FREESCP_IT_FTPS_REMOTE_BASE`
- Optional: `FREESCP_IT_FTPS_PORT` (default `990`), `FREESCP_IT_FTPS_USER`
  (default `anonymous`), `FREESCP_IT_FTPS_PASS`, `FREESCP_IT_FTPS_VERIFY_PEER`
  (`1`/`0`, default `1`), `FREESCP_IT_FTPS_CA_CERT`

### WebDAV suite (`tests/webdav_integration.rs`)

- Required: `FREESCP_IT_WEBDAV_HOST`, `FREESCP_IT_WEBDAV_REMOTE_BASE`
- Optional: `FREESCP_IT_WEBDAV_USER`, `FREESCP_IT_WEBDAV_PASS`,
  `FREESCP_IT_WEBDAV_SCHEME`, `FREESCP_IT_WEBDAV_PORT` (default `443`),
  `FREESCP_IT_WEBDAV_VERIFY_PEER` (`1`/`0`, default `1`), `FREESCP_IT_WEBDAV_CA_CERT`

### CI wiring (`.github/workflows/ci.yml`)

- `quick-dev` (push to `dev`): fmt + clippy + `cargo test -p freescp-core
  --tests` + workspace build on Ubuntu. Integration suites self-skip there.
- `pr-main-integration` (PR to `main`): Ubuntu + macOS matrix. Both spin up a
  temporary SSH server on port `2222` (pubkey auth, `internal-sftp`) and run:
  - SFTP suite directly (`FREESCP_IT_SFTP_*`, `FREESCP_IT_REMOTE_BASE`)
  - SCP suite against the same server (SCP env falls back to SFTP vars)
  - SFTP suite through a SOCKS5 tunnel (`ssh -D`, `FREESCP_IT_PROXY_TYPE=socks5`)
  - SFTP suite through an authenticated HTTP CONNECT proxy (helper script,
    `FREESCP_IT_PROXY_TYPE=http` + user/pass)
  - SFTP suite through an SSH jump host (`FREESCP_IT_JUMP_*`, host key seeded
    via `ssh-keyscan`)
  - FTP/FTPS/WebDAV suites run with no env to exercise the skip path (their
    servers are not provisioned in CI, same as the legacy workflow)
- Until a suite file lands, the corresponding CI step prints a "not written
  yet (sibling workstream); skipping" notice instead of failing. All suites
  are now written; the guards remain as harmless no-ops.
