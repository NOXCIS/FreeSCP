//! UI-side controller for the embedded Telnet terminal console.
//!
//! `ConsoleState` owns a [`vt100::Parser`] that turns the bytes coming from
//! `freescp_core::telnet::TelnetSession` into a Slint model of styled rows
//! (see `ui/console.slint` for the view), and encodes keyboard/paste input
//! back into terminal bytes. main.rs owns the wiring:
//!
//! * `UiEvent::ConsoleSession` -> [`insert`], `UiEvent::ConsoleData` ->
//!   [`ConsoleState::feed`] + [`ConsoleState::render`].
//! * `console-*` callbacks -> the matching methods here.
//! * the view's `grid-cols`/`grid-rows` properties -> [`ConsoleState::resize`]
//!   (read whenever the UI event batch ends, since Slint does not reliably fire
//!   `changed` handlers for layout-managed geometry).
//! * cursor/scrollback getters -> window properties after each event batch.
//!
//! Everything runs on the UI thread; the parser, the row models and the
//! session handle are deliberately not `Send`. Live sessions are kept in the
//! thread-local [`CONSOLES`] map rather than in `AppState`, which is cloned
//! into worker callbacks and therefore has to stay `Send`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Instant;

use freescp_core::telnet::TelnetSession;
use freescp_core::SessionOptions;
use slint::{Color, ModelRc, VecModel};

use crate::ui::main_window::{ConsoleRow, ConsoleRun};

/// Lines kept above the visible screen (the Scrollback pill reports this).
const SCROLLBACK_LINES: usize = 1000;

/// Upper bound for keystrokes buffered while no session is installed; the
/// buffer only exists so a not-yet-connected console does not panic or grow.
const MAX_PENDING: usize = 8 * 1024;

/// Default colors (SGR 39/49). Must match `default-fg`/`default-bg` in
/// `ui/console.slint`: blank runs are dropped only when their effective
/// background equals this one.
const DEFAULT_FG: (u8, u8, u8) = (0xe6, 0xe6, 0xe9);
const DEFAULT_BG: (u8, u8, u8) = (0x1a, 0x1a, 0x1d);

/// Keys that produce escape sequences rather than text. The discriminants are
/// shared with the `special-key(int)` callback in `ui/console.slint`; both
/// lists must stay in sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecialKey {
    Escape = 0,
    Return = 1,
    Tab = 2,
    Backtab = 3,
    Backspace = 4,
    Delete = 5,
    Insert = 6,
    Home = 7,
    End = 8,
    PageUp = 9,
    PageDown = 10,
    Up = 11,
    Down = 12,
    Left = 13,
    Right = 14,
    F1 = 15,
    F2 = 16,
    F3 = 17,
    F4 = 18,
    F5 = 19,
    F6 = 20,
    F7 = 21,
    F8 = 22,
    F9 = 23,
    F10 = 24,
    F11 = 25,
    F12 = 26,
}

impl SpecialKey {
    fn from_code(code: i32) -> Option<Self> {
        use SpecialKey::*;
        Some(match code {
            0 => Escape,
            1 => Return,
            2 => Tab,
            3 => Backtab,
            4 => Backspace,
            5 => Delete,
            6 => Insert,
            7 => Home,
            8 => End,
            9 => PageUp,
            10 => PageDown,
            11 => Up,
            12 => Down,
            13 => Left,
            14 => Right,
            15 => F1,
            16 => F2,
            17 => F3,
            18 => F4,
            19 => F5,
            20 => F6,
            21 => F7,
            22 => F8,
            23 => F9,
            24 => F10,
            25 => F11,
            26 => F12,
            _ => return None,
        })
    }

    /// Escape sequence for this key; `application_cursor` follows DECCKM for
    /// the keys whose encoding changes with it (CSI vs SS3).
    fn bytes(self, application_cursor: bool, binary_mode: bool) -> &'static [u8] {
        use SpecialKey::*;
        match self {
            Escape => b"\x1b",
            // RFC 854 wants CR LF on the wire in NVT mode; binary mode sends
            // the raw CR that most servers accept as "end of line".
            Return => {
                if binary_mode {
                    b"\r"
                } else {
                    b"\r\n"
                }
            }
            Tab => b"\t",
            Backtab => b"\x1b[Z",
            Backspace => b"\x7f",
            Delete => b"\x1b[3~",
            Insert => b"\x1b[2~",
            Home => {
                if application_cursor {
                    b"\x1bOH"
                } else {
                    b"\x1b[H"
                }
            }
            End => {
                if application_cursor {
                    b"\x1bOF"
                } else {
                    b"\x1b[F"
                }
            }
            PageUp => b"\x1b[5~",
            PageDown => b"\x1b[6~",
            Up => {
                if application_cursor {
                    b"\x1bOA"
                } else {
                    b"\x1b[A"
                }
            }
            Down => {
                if application_cursor {
                    b"\x1bOB"
                } else {
                    b"\x1b[B"
                }
            }
            Right => {
                if application_cursor {
                    b"\x1bOC"
                } else {
                    b"\x1b[C"
                }
            }
            Left => {
                if application_cursor {
                    b"\x1bOD"
                } else {
                    b"\x1b[D"
                }
            }
            F1 => b"\x1bOP",
            F2 => b"\x1bOQ",
            F3 => b"\x1bOR",
            F4 => b"\x1bOS",
            F5 => b"\x1b[15~",
            F6 => b"\x1b[17~",
            F7 => b"\x1b[18~",
            F8 => b"\x1b[19~",
            F9 => b"\x1b[20~",
            F10 => b"\x1b[21~",
            F11 => b"\x1b[23~",
            F12 => b"\x1b[24~",
        }
    }
}

/// Side effects collected by [`ConsoleCallbacks`] while the parser runs; they
/// are drained right after `Parser::process` (callbacks cannot touch the
/// `ConsoleState` itself, so they write into this shared cell).
#[derive(Default)]
struct ConsoleEvents {
    /// Answers to DSR/DA requests, to be sent to the server.
    replies: Vec<Vec<u8>>,
    /// CSI 8 ; rows ; cols t — the application asking to be resized.
    resize_request: Option<(u16, u16)>,
    /// OSC 0/2 window title.
    title: Option<String>,
    bell: bool,
}

#[derive(Clone)]
struct ConsoleCallbacks {
    events: Rc<RefCell<ConsoleEvents>>,
}

impl vt100::Callbacks for ConsoleCallbacks {
    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        i1: Option<u8>,
        _i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        // Private/intermediate forms (CSI ? ... , CSI > ...) are negotiation
        // replies for a real terminal, not requests aimed at us.
        if i1.is_some() {
            return;
        }
        let first = params
            .first()
            .and_then(|group| group.first())
            .copied()
            .unwrap_or(0);
        match c {
            // DSR: report the cursor position, 1-based as the sequence wants.
            'n' if first == 6 => {
                let (row, col) = screen.cursor_position();
                let reply = format!("\x1b[{};{}R", row + 1, col + 1);
                self.events.borrow_mut().replies.push(reply.into_bytes());
            }
            // DA: identify as a VT102 with advanced video options.
            'c' if first == 0 => {
                self.events.borrow_mut().replies.push(b"\x1b[?6c".to_vec());
            }
            _ => {}
        }
    }

    fn set_window_title(&mut self, _screen: &mut vt100::Screen, title: &[u8]) {
        let Ok(text) = std::str::from_utf8(title) else {
            return;
        };
        let cleaned: String = text.chars().filter(|c| !c.is_control()).take(120).collect();
        if !cleaned.is_empty() {
            self.events.borrow_mut().title = Some(cleaned);
        }
    }

    fn audible_bell(&mut self, _screen: &mut vt100::Screen) {
        self.events.borrow_mut().bell = true;
    }

    fn resize(&mut self, _screen: &mut vt100::Screen, request: (u16, u16)) {
        if request.0 > 0 && request.1 > 0 {
            self.events.borrow_mut().resize_request = Some(request);
        }
    }
}

/// A live Telnet console attached to a tab.
///
/// Telnet has no filesystem, so a console never becomes a `SessionRecord`: it
/// is kept in the UI-thread-local [`CONSOLES`] map, keyed by tab id.
pub struct ConsoleSession {
    /// Options the session was opened with (host/port/user for titles, and the
    /// protocol for the status bar).
    pub options: SessionOptions,
    /// Install time; drives the status-bar elapsed timer.
    pub started_at: Instant,
    /// The screen, scrollback and row models of this tab's terminal.
    pub console: ConsoleState,
}

thread_local! {
    /// Live consoles, keyed by `TabState::id`. Thread-local on purpose: the
    /// vt100 parser, the Slint models and the session handle are all `Rc`-based
    /// (not `Send`), and `AppState` — which is cloned into worker callbacks —
    /// must stay `Send`.
    static CONSOLES: RefCell<HashMap<u64, ConsoleSession>> = RefCell::new(HashMap::new());
}

/// Installs (or replaces) tab `tab_id`'s console session.
pub fn insert(tab_id: u64, session: ConsoleSession) {
    CONSOLES.with(|consoles| consoles.borrow_mut().insert(tab_id, session));
}

/// Runs `f` against tab `tab_id`'s console session; `None` when the tab has
/// none.
pub fn with_session<R>(tab_id: u64, f: impl FnOnce(&mut ConsoleSession) -> R) -> Option<R> {
    CONSOLES.with(|consoles| consoles.borrow_mut().get_mut(&tab_id).map(f))
}

/// Removes tab `tab_id`'s console session, closing its transport. Returns the
/// removed session so the caller can keep the last screen around (dropping the
/// value discards the terminal).
pub fn remove(tab_id: u64) -> Option<ConsoleSession> {
    let mut session = CONSOLES.with(|consoles| consoles.borrow_mut().remove(&tab_id))?;
    if let Some(transport) = session.console.take_session() {
        transport.close();
    }
    Some(session)
}

/// Terminal state + Slint models for one Telnet session.
pub struct ConsoleState {
    parser: vt100::Parser<ConsoleCallbacks>,
    events: Rc<RefCell<ConsoleEvents>>,
    session: Option<TelnetSession>,
    rows_model: Rc<VecModel<ConsoleRow>>,
    row_models: Vec<Rc<VecModel<ConsoleRun>>>,
    /// Last published runs per row, so `render` only touches changed rows.
    row_cache: Vec<Vec<ConsoleRun>>,
    /// Client-to-server bytes typed while no session was installed.
    pending: Vec<u8>,
    cols: u16,
    rows: u16,
    /// Set when the server negotiated BINARY (see `set_binary_mode`).
    binary_mode: bool,
    connected: bool,
    dirty: bool,
    title: Option<String>,
    bell: bool,
    cursor_row: u16,
    cursor_col: u16,
    cursor_visible: bool,
    scrollback_len: usize,
    scrollback_offset: usize,
}

impl ConsoleState {
    /// Creates an empty console sized `cols` x `rows` (the view reports the
    /// real grid size as soon as it is laid out).
    pub fn new(cols: u16, rows: u16) -> Self {
        let cols = cols.max(2);
        let rows = rows.max(1);
        let events = Rc::new(RefCell::new(ConsoleEvents::default()));
        let parser = vt100::Parser::new_with_callbacks(
            rows,
            cols,
            SCROLLBACK_LINES,
            ConsoleCallbacks {
                events: events.clone(),
            },
        );
        let mut state = Self {
            parser,
            events,
            session: None,
            rows_model: Rc::new(VecModel::default()),
            row_models: Vec::new(),
            row_cache: Vec::new(),
            pending: Vec::new(),
            cols,
            rows,
            binary_mode: false,
            connected: false,
            dirty: true,
            title: None,
            bell: false,
            cursor_row: 0,
            cursor_col: 0,
            cursor_visible: false,
            scrollback_len: 0,
            scrollback_offset: 0,
        };
        state.reset_rows();
        state
    }

    /// The row model to install on `ConsoleView.rows` once per session.
    pub fn rows_model(&self) -> ModelRc<ConsoleRow> {
        ModelRc::new(self.rows_model.clone())
    }

    /// Installs a freshly connected session and tells it our grid size.
    pub fn attach(&mut self, session: TelnetSession) {
        session.resize(self.cols, self.rows);
        self.pending.clear();
        self.session = Some(session);
        self.connected = true;
    }

    /// Removes the session (disconnect); the last screen stays visible.
    pub fn take_session(&mut self) -> Option<TelnetSession> {
        self.connected = false;
        self.session.take()
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Marks the session as gone after `TelnetEvent::Closed`/`Error`.
    pub fn set_closed(&mut self) {
        self.connected = false;
        self.session = None;
    }

    /// Feeds server output through the parser. Call [`Self::render`] once the
    /// event queue is drained so a burst of data costs a single refresh.
    pub fn feed(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.parser.process(bytes);
        self.dirty = true;
        self.apply_events();
    }

    /// Rebuilds the rows that changed and refreshes cursor/scrollback state.
    pub fn render(&mut self) {
        if self.dirty {
            self.dirty = false;
            self.rebuild_rows();
        }
        self.refresh_cursor();
        self.refresh_scrollback();
    }

    /// Applies a grid size reported by the view's `grid-cols`/`grid-rows`
    /// properties (main.rs polls them after layout changes): parser, row models
    /// and NAWS all follow. No-ops when the size is unchanged.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        let cols = cols.max(2);
        let rows = rows.max(1);
        if cols == self.cols && rows == self.rows {
            return;
        }
        self.cols = cols;
        self.rows = rows;
        self.parser.screen_mut().set_size(rows, cols);
        self.reset_rows();
        if let Some(session) = &self.session {
            session.resize(cols, rows);
        }
        self.dirty = true;
    }

    /// Handles the `key-text` callback: printable text plus modifiers.
    pub fn key_text(&mut self, text: &str, ctrl: bool, alt: bool, _shift: bool) {
        if text.is_empty() {
            return;
        }
        let mut out = Vec::with_capacity(text.len() + 1);
        if alt {
            out.push(0x1b);
        }
        if ctrl {
            for ch in text.chars() {
                match u8::try_from(ch as u32).ok().and_then(control_byte) {
                    Some(byte) => out.push(byte),
                    None => {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                }
            }
        } else {
            out.extend_from_slice(text.as_bytes());
        }
        self.send(&out);
        self.scroll_to_bottom();
    }

    /// Handles the `special-key` callback (see [`SpecialKey`]).
    pub fn special_key(&mut self, code: i32) {
        let Some(key) = SpecialKey::from_code(code) else {
            return;
        };
        let bytes = key.bytes(self.parser.screen().application_cursor(), self.binary_mode);
        self.send(bytes);
        self.scroll_to_bottom();
    }

    /// Handles the `paste-requested` callback with clipboard text: newlines
    /// collapse to the Return key bytes and the payload is wrapped when the
    /// application enabled bracketed paste.
    pub fn paste(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let bracketed = self.parser.screen().bracketed_paste();
        let newline = SpecialKey::Return.bytes(false, self.binary_mode);
        let mut out = Vec::with_capacity(text.len() + 16);
        if bracketed {
            out.extend_from_slice(b"\x1b[200~");
        }
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '\r' => {
                    // Collapse a CRLF pair into a single line break.
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    out.extend_from_slice(newline);
                }
                '\n' => out.extend_from_slice(newline),
                _ => {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
            }
        }
        if bracketed {
            out.extend_from_slice(b"\x1b[201~");
        }
        self.send(&out);
        self.scroll_to_bottom();
    }

    /// Moves the view `lines` lines down (negative scrolls up into the
    /// scrollback); the parser clamps to the available history.
    pub fn scroll_lines(&mut self, lines: i32) {
        if lines == 0 {
            return;
        }
        let before = self.parser.screen().scrollback();
        let target = (before as i64 - i64::from(lines)).max(0) as usize;
        self.parser.screen_mut().set_scrollback(target);
        if self.parser.screen().scrollback() != before {
            self.dirty = true;
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        if self.parser.screen().scrollback() != 0 {
            self.parser.screen_mut().set_scrollback(0);
            self.dirty = true;
        }
    }

    /// Clears the local screen and scrollback (the session keeps running).
    pub fn clear(&mut self) {
        self.parser = vt100::Parser::new_with_callbacks(
            self.rows,
            self.cols,
            SCROLLBACK_LINES,
            ConsoleCallbacks {
                events: self.events.clone(),
            },
        );
        self.dirty = true;
    }

    /// Text of an inclusive, normalized selection in cell coordinates; the
    /// view's `sel-*` properties are passed straight through.
    pub fn selection_text(&self, start: (i32, i32), end: (i32, i32)) -> String {
        let (mut start_row, mut start_col) = start;
        let (mut end_row, mut end_col) = end;
        if start_row < 0 || start_col < 0 || end_row < 0 || end_col < 0 {
            return String::new();
        }
        if (end_row, end_col) < (start_row, start_col) {
            std::mem::swap(&mut start_row, &mut end_row);
            std::mem::swap(&mut start_col, &mut end_col);
        }
        let last_row = i32::from(self.rows) - 1;
        let last_col = i32::from(self.cols) - 1;
        let start_row = start_row.min(last_row).max(0) as u16;
        let end_row = end_row.min(last_row).max(0) as u16;
        let start_col = start_col.min(last_col).max(0) as u16;
        // `contents_between` takes an exclusive end column.
        let end_col = (end_col.min(last_col) + 1) as u16;
        if start_row == end_row && start_col >= end_col {
            return String::new();
        }
        let text = self
            .parser
            .screen()
            .contents_between(start_row, start_col, end_row, end_col);
        let mut out = String::with_capacity(text.len());
        for (index, line) in text.split('\n').enumerate() {
            if index > 0 {
                out.push('\n');
            }
            out.push_str(line.trim_end());
        }
        out
    }

    /// Switches the Return key between NVT (`CR LF`) and raw `CR`; wires up
    /// once the codec exposes the negotiated BINARY state.
    #[allow(dead_code)] // exercised by tests until the codec exposes BINARY.
    pub fn set_binary_mode(&mut self, binary: bool) {
        self.binary_mode = binary;
    }

    pub fn cursor(&self) -> (i32, i32) {
        (i32::from(self.cursor_row), i32::from(self.cursor_col))
    }

    pub fn cursor_visible(&self) -> bool {
        // The view hides the cursor itself while disconnected, so this only
        // reports what the parser asked for (DECTCEM).
        self.cursor_visible
    }

    /// `(total scrollback lines, current offset)`; offset 0 = live screen.
    pub fn scrollback(&self) -> (i32, i32) {
        (
            self.scrollback_len.min(i32::MAX as usize) as i32,
            self.scrollback_offset.min(i32::MAX as usize) as i32,
        )
    }

    /// Window title requested by the application (OSC 0/2), if any.
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Consumes the pending bell request. The UI has no sound or taskbar
    /// notification surface for it yet, so the flag exists for callers to read.
    #[allow(dead_code)]
    pub fn take_bell(&mut self) -> bool {
        std::mem::take(&mut self.bell)
    }

    /// Bytes queued while no session was installed (tests, mostly).
    #[cfg(test)]
    fn pending_bytes(&self) -> &[u8] {
        &self.pending
    }

    fn reset_rows(&mut self) {
        let row_models: Vec<Rc<VecModel<ConsoleRun>>> = (0..self.rows)
            .map(|_| Rc::new(VecModel::default()))
            .collect();
        let rows: Vec<ConsoleRow> = row_models
            .iter()
            .map(|model| ConsoleRow {
                runs: ModelRc::new(model.clone()),
            })
            .collect();
        self.rows_model.set_vec(rows);
        self.row_cache = vec![Vec::new(); self.rows as usize];
        self.row_models = row_models;
    }

    fn rebuild_rows(&mut self) {
        let screen = self.parser.screen();
        let cols = self.cols;
        for row in 0..self.rows {
            let runs = build_runs(screen, row, cols);
            let index = row as usize;
            if self.row_cache[index] != runs {
                self.row_models[index].set_vec(runs.clone());
                self.row_cache[index] = runs;
            }
        }
    }

    fn refresh_cursor(&mut self) {
        let screen = self.parser.screen();
        let (row, col) = screen.cursor_position();
        // The parser reports live-screen rows; the view shows them shifted by
        // the scrollback offset, and hides the cursor once it scrolls away.
        let offset = i32::try_from(screen.scrollback()).unwrap_or(0);
        let visible_row = i32::from(row) + offset;
        self.cursor_visible = !screen.hide_cursor() && visible_row < i32::from(self.rows);
        self.cursor_row = visible_row.clamp(0, i32::from(self.rows) - 1) as u16;
        self.cursor_col = col;
    }

    fn refresh_scrollback(&mut self) {
        let screen = self.parser.screen_mut();
        self.scrollback_offset = screen.scrollback();
        // There is no scrollback-length accessor; the offset clamps to it, so
        // ask for the maximum and restore the real offset right after.
        screen.set_scrollback(usize::MAX);
        self.scrollback_len = screen.scrollback();
        screen.set_scrollback(self.scrollback_offset);
    }

    fn apply_events(&mut self) {
        let events = std::mem::take(&mut *self.events.borrow_mut());
        if events.bell {
            self.bell = true;
        }
        if events.title.is_some() {
            self.title = events.title;
        }
        for reply in events.replies {
            self.send(&reply);
        }
        if let Some((rows, cols)) = events.resize_request {
            self.resize(cols, rows);
        }
    }

    /// Sends bytes to the server, or buffers them (bounded) while detached.
    fn send(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(session) = &self.session {
            session.send(bytes);
            return;
        }
        if self.pending.len() + bytes.len() > MAX_PENDING {
            self.pending.clear();
        }
        self.pending.extend_from_slice(bytes);
    }
}

/// Turns cells into runs, dropping blank stretches that would draw nothing
/// (cells keep their positions, so the view needs no filler text).
fn build_runs(screen: &vt100::Screen, row: u16, cols: u16) -> Vec<ConsoleRun> {
    let default_bg = color_of(DEFAULT_BG);
    let mut runs: Vec<ConsoleRun> = Vec::new();
    let mut col: u16 = 0;
    while col < cols {
        let Some(cell) = screen.cell(row, col) else {
            break;
        };
        // The continuation half of a wide glyph is covered by the run that
        // emitted the glyph itself.
        if cell.is_wide_continuation() {
            col += 1;
            continue;
        }
        let cells = if cell.is_wide() { 2 } else { 1 };
        let fg = map_color(cell.fgcolor(), color_of(DEFAULT_FG));
        let bg = map_color(cell.bgcolor(), default_bg);
        let attrs = RunAttrs {
            fg,
            bg,
            bold: cell.bold(),
            italic: cell.italic(),
            dim: cell.dim(),
            inverse: cell.inverse(),
        };
        // With inverse the run draws its background in the foreground color.
        let effective_bg = if attrs.inverse { attrs.fg } else { attrs.bg };
        let text = if cell.has_contents() {
            cell.contents()
        } else {
            " "
        };
        let blank = text.chars().all(|c| c == ' ');
        if blank && effective_bg == default_bg {
            col += cells;
            continue;
        }
        let merge = matches!(
            runs.last(),
            Some(last) if run_attrs(last) == attrs && last.col + last.cells == i32::from(col)
        );
        if merge {
            if let Some(last) = runs.last_mut() {
                last.text.push_str(text);
                last.cells += i32::from(cells);
            }
        } else {
            runs.push(ConsoleRun {
                col: i32::from(col),
                cells: i32::from(cells),
                text: text.to_string().into(),
                fg: attrs.fg,
                bg: attrs.bg,
                bold: attrs.bold,
                italic: attrs.italic,
                dim: attrs.dim,
                inverse: attrs.inverse,
            });
        }
        col += cells;
    }
    runs
}

/// Attributes compared when coalescing neighbouring cells into one run.
#[derive(Clone, Copy, PartialEq)]
struct RunAttrs {
    fg: Color,
    bg: Color,
    bold: bool,
    italic: bool,
    dim: bool,
    inverse: bool,
}

fn run_attrs(run: &ConsoleRun) -> RunAttrs {
    RunAttrs {
        fg: run.fg,
        bg: run.bg,
        bold: run.bold,
        italic: run.italic,
        dim: run.dim,
        inverse: run.inverse,
    }
}

fn color_of(rgb: (u8, u8, u8)) -> Color {
    Color::from_rgb_u8(rgb.0, rgb.1, rgb.2)
}

/// Maps a vt100 color through the xterm-256 palette; `default` is the color
/// for SGR 39/49.
fn map_color(color: vt100::Color, default: Color) -> Color {
    match color {
        vt100::Color::Default => default,
        vt100::Color::Idx(index) => color_of(ansi_256(index)),
        vt100::Color::Rgb(r, g, b) => Color::from_rgb_u8(r, g, b),
    }
}

/// xterm's 256-color palette: 16 system colors, a 6x6x6 cube, 24 greys.
fn ansi_256(index: u8) -> (u8, u8, u8) {
    const SYSTEM: [(u8, u8, u8); 16] = [
        (0x00, 0x00, 0x00),
        (0xcd, 0x00, 0x00),
        (0x00, 0xcd, 0x00),
        (0xcd, 0xcd, 0x00),
        (0x00, 0x00, 0xee),
        (0xcd, 0x00, 0xcd),
        (0x00, 0xcd, 0xcd),
        (0xe5, 0xe5, 0xe5),
        (0x7f, 0x7f, 0x7f),
        (0xff, 0x00, 0x00),
        (0x00, 0xff, 0x00),
        (0xff, 0xff, 0x00),
        (0x5c, 0x5c, 0xff),
        (0xff, 0x00, 0xff),
        (0x00, 0xff, 0xff),
        (0xff, 0xff, 0xff),
    ];
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];

    match index {
        0..=15 => SYSTEM[usize::from(index)],
        16..=231 => {
            let cube = u16::from(index) - 16;
            let r = LEVELS[usize::from(cube / 36)];
            let g = LEVELS[usize::from((cube / 6) % 6)];
            let b = LEVELS[usize::from(cube % 6)];
            (r, g, b)
        }
        _ => {
            let grey = 8 + 10 * (u16::from(index) - 232);
            (grey as u8, grey as u8, grey as u8)
        }
    }
}

/// Ctrl+<key> mapping; `None` means "send the character unchanged".
fn control_byte(byte: u8) -> Option<u8> {
    Some(match byte {
        b'a'..=b'z' => byte - b'a' + 1,
        b'A'..=b'Z' => byte - b'A' + 1,
        b'@' | b' ' => 0x00,
        b'[' => 0x1b,
        b'\\' => 0x1c,
        b']' => 0x1d,
        b'^' => 0x1e,
        b'_' => 0x1f,
        b'?' => 0x7f,
        // Slint may deliver the control character itself (Ctrl+I as Tab and
        // so on), which is already what the server expects.
        0x01..=0x1f | 0x7f => byte,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::Model;

    fn state() -> ConsoleState {
        ConsoleState::new(20, 4)
    }

    fn row(console: &ConsoleState, index: usize) -> Vec<ConsoleRun> {
        console.row_cache[index].clone()
    }

    fn text_of(runs: &[ConsoleRun]) -> String {
        runs.iter().map(|run| run.text.as_str()).collect()
    }

    #[test]
    fn plain_text_becomes_one_run() {
        let mut console = state();
        console.feed(b"hi");
        console.render();
        let runs = row(&console, 0);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].col, 0);
        assert_eq!(runs[0].cells, 2);
        assert_eq!(runs[0].text, "hi");
        assert_eq!(runs[0].fg, color_of(DEFAULT_FG));
        assert_eq!(runs[0].bg, color_of(DEFAULT_BG));
        assert!(!runs[0].bold);
        assert_eq!(console.cursor(), (0, 2));
        assert!(console.cursor_visible());
    }

    #[test]
    fn colours_go_through_the_xterm_palette() {
        let mut console = state();
        console.feed(b"\x1b[1;31mred\x1b[0m \x1b[48;5;196mbg\x1b[0m \x1b[38;2;1;2;3mrgb");
        console.render();
        let runs = row(&console, 0);
        assert_eq!(runs[0].text, "red");
        assert_eq!(runs[0].fg, color_of((0xcd, 0x00, 0x00)));
        assert!(runs[0].bold);
        // 196 = the brightest red in the 6x6x6 cube.
        assert_eq!(runs[1].text, "bg");
        assert_eq!(runs[1].bg, color_of((0xff, 0x00, 0x00)));
        assert_eq!(runs[2].text, "rgb");
        assert_eq!(runs[2].fg, Color::from_rgb_u8(1, 2, 3));
    }

    #[test]
    fn inverse_swaps_colors() {
        let mut console = state();
        console.feed(b"\x1b[7mx");
        console.render();
        let runs = row(&console, 0);
        assert_eq!(runs[0].fg, color_of(DEFAULT_FG));
        assert_eq!(runs[0].bg, color_of(DEFAULT_BG));
        assert!(runs[0].inverse);
    }

    #[test]
    fn blank_gaps_keep_their_cell_positions() {
        let mut console = state();
        console.feed(b"a    b");
        console.render();
        let runs = row(&console, 0);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[1].col, 5);
        assert_eq!(runs[1].text, "b");
    }

    #[test]
    fn wide_glyphs_occupy_two_cells() {
        let mut console = state();
        console.feed("日本".as_bytes());
        console.render();
        let runs = row(&console, 0);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].text, "日本");
        assert_eq!(runs[0].cells, 4);
        assert_eq!(console.cursor(), (0, 4));
    }

    #[test]
    fn row_attribute_changes_split_runs() {
        let mut console = state();
        console.feed(b"\x1b[1mbold\x1b[0mplain");
        console.render();
        let runs = row(&console, 0);
        assert_eq!(runs.len(), 2);
        assert_eq!(text_of(&runs), "boldplain");
        assert!(runs[0].bold);
        assert!(!runs[1].bold);
    }

    #[test]
    fn dsr_and_da_are_answered() {
        let mut console = state();
        console.feed(b"\x1b[2;3H\x1b[6n");
        assert_eq!(console.pending_bytes(), b"\x1b[2;3R");
        console.feed(b"\x1b[c");
        assert_eq!(console.pending_bytes(), b"\x1b[2;3R\x1b[?6c");
        // Private DSR (CSI ? 6 n) is aimed at the real terminal, not at us.
        console.feed(b"\x1b[?6n");
        assert_eq!(console.pending_bytes(), b"\x1b[2;3R\x1b[?6c");
    }

    #[test]
    fn title_and_bell_are_reported() {
        let mut console = state();
        console.feed(b"\x1b]0;my title\x07");
        assert_eq!(console.title(), Some("my title"));
        assert!(!console.take_bell());
        console.feed(b"\x07");
        assert!(console.take_bell());
        assert!(!console.take_bell());
    }

    #[test]
    fn ctrl_letters_become_control_bytes() {
        let mut console = state();
        console.key_text("c", true, false, false);
        console.key_text("D", true, false, false);
        console.key_text(" ", true, false, false);
        console.key_text("a", false, false, false);
        console.key_text("a", false, true, false);
        console.key_text("é", false, false, false);
        assert_eq!(
            console.pending_bytes(),
            [0x03, 0x04, 0x00, b'a', 0x1b, b'a', 0xc3, 0xa9]
        );
    }

    #[test]
    fn special_keys_follow_application_cursor_mode() {
        let mut console = state();
        console.special_key(SpecialKey::Backspace as i32);
        console.special_key(SpecialKey::Backtab as i32);
        console.special_key(SpecialKey::F5 as i32);
        console.special_key(SpecialKey::Up as i32);
        assert_eq!(console.pending_bytes(), b"\x7f\x1b[Z\x1b[15~\x1b[A");
        // DECCKM makes the cursor keys (and Home/End) use SS3.
        console.feed(b"\x1b[?1h");
        console.special_key(SpecialKey::Up as i32);
        console.special_key(SpecialKey::Left as i32);
        console.special_key(SpecialKey::End as i32);
        assert_eq!(
            console.pending_bytes(),
            b"\x7f\x1b[Z\x1b[15~\x1b[A\x1bOA\x1bOD\x1bOF"
        );
    }

    #[test]
    fn return_sends_crlf_unless_binary_mode() {
        let mut console = state();
        console.special_key(SpecialKey::Return as i32);
        assert_eq!(console.pending_bytes(), b"\r\n");
        console.set_binary_mode(true);
        console.special_key(SpecialKey::Return as i32);
        assert_eq!(console.pending_bytes(), b"\r\n\r");
    }

    #[test]
    fn unknown_special_key_codes_are_ignored() {
        let mut console = state();
        console.special_key(99);
        console.special_key(-1);
        assert!(console.pending_bytes().is_empty());
    }

    #[test]
    fn paste_normalises_newlines_and_wraps_when_bracketed() {
        let mut console = state();
        console.paste("one\ntwo\r\nthree");
        assert_eq!(console.pending_bytes(), b"one\r\ntwo\r\nthree");
        console.feed(b"\x1b[?2004h");
        console.paste("x");
        assert_eq!(
            console.pending_bytes(),
            b"one\r\ntwo\r\nthree\x1b[200~x\x1b[201~"
        );
    }

    #[test]
    fn selection_uses_cell_coordinates() {
        let mut console = state();
        console.feed(b"hello world");
        console.render();
        assert_eq!(console.selection_text((0, 0), (0, 4)), "hello");
        assert_eq!(console.selection_text((0, 6), (0, 10)), "world");
        assert_eq!(console.selection_text((0, 4), (0, 0)), "hello");
        assert_eq!(console.selection_text((-1, 0), (0, 4)), "");
        // Trailing blanks are trimmed, the wrapped line keeps no newline.
        console.feed(b" and more");
        console.render();
        assert_eq!(
            console.selection_text((0, 0), (0, 19)),
            "hello world and more"
        );
    }

    #[test]
    fn selection_spans_rows() {
        let mut console = state();
        console.feed(b"one\r\ntwo");
        console.render();
        assert_eq!(console.selection_text((0, 0), (1, 2)), "one\ntwo");
    }

    #[test]
    fn scrollback_moves_the_view_and_snaps_back() {
        let mut console = state();
        for line in 0..10 {
            console.feed(format!("line{}\r\n", line).as_bytes());
        }
        console.render();
        assert!(console.scrollback().0 > 0);
        console.scroll_lines(-3);
        console.render();
        assert_eq!(console.scrollback().1, 3);
        assert!(text_of(&row(&console, 0)).contains("line"));
        console.scroll_lines(1);
        console.render();
        assert_eq!(console.scrollback().1, 2);
        // Typing snaps the view back to the live screen.
        console.key_text("x", false, false, false);
        console.render();
        assert_eq!(console.scrollback().1, 0);
        console.scroll_lines(-5);
        console.scroll_to_bottom();
        assert_eq!(console.scrollback().1, 0);
    }

    #[test]
    fn resize_rebuilds_the_row_model() {
        let mut console = state();
        console.feed(b"hello");
        console.render();
        assert_eq!(console.rows_model.row_count(), 4);
        console.resize(40, 10);
        console.render();
        assert_eq!(console.rows_model.row_count(), 10);
        assert_eq!(console.cols, 40);
        assert_eq!(console.rows, 10);
        assert_eq!(text_of(&row(&console, 0)), "hello");
    }

    #[test]
    fn clear_resets_the_screen_but_keeps_the_size() {
        let mut console = state();
        console.feed(b"hello");
        console.render();
        console.clear();
        console.render();
        assert_eq!(console.rows_model.row_count(), 4);
        assert!(row(&console, 0).is_empty());
        assert_eq!(console.scrollback(), (0, 0));
    }

    #[test]
    fn cursor_visibility_follows_parser_state() {
        let mut console = state();
        console.feed(b"\x1b[?25l");
        console.render();
        assert!(!console.cursor_visible());
        assert!(!console.cursor_visible());
        console.feed(b"\x1b[?25h");
        console.render();
        assert!(console.cursor_visible());
    }

    #[test]
    fn server_requested_resize_is_applied() {
        let mut console = state();
        console.feed(b"\x1b[8;10;30t");
        assert_eq!((console.cols, console.rows), (30, 10));
        assert_eq!(console.rows_model.row_count(), 10);
    }

    #[test]
    fn palette_covers_cube_and_greys() {
        assert_eq!(ansi_256(16), (0, 0, 0));
        assert_eq!(ansi_256(231), (255, 255, 255));
        assert_eq!(ansi_256(232), (8, 8, 8));
        assert_eq!(ansi_256(255), (238, 238, 238));
    }
}
