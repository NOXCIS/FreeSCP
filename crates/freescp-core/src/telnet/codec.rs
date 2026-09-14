//! Telnet byte-stream codec: RFC 854/855/857/858/1073/1091 negotiation plus
//! IAC handling for the interactive console transport.
//!
//! The codec sits between the socket and the terminal emulator:
//!
//! * inbound bytes are fed to [`TelnetCodec::process`], which strips IAC
//!   commands and produces the raw data stream for the terminal
//!   (negotiation replies are queued and must be sent back to the server);
//! * outbound user data is escaped by [`TelnetCodec::encode`] (`0xFF` becomes
//!   `IAC IAC`) so payload bytes are never mistaken for commands;
//! * [`TelnetCodec::resize`] queues a NAWS subnegotiation whenever the server
//!   negotiated `DO NAWS`.

/// Telnet command bytes (RFC 854).
pub const IAC: u8 = 255;
pub const DONT: u8 = 254;
pub const DO: u8 = 253;
pub const WONT: u8 = 252;
pub const WILL: u8 = 251;
pub const SB: u8 = 250;
pub const GA: u8 = 249;
pub const EL: u8 = 248;
pub const EC: u8 = 247;
pub const AYT: u8 = 246;
pub const AO: u8 = 245;
pub const IP: u8 = 244;
pub const BRK: u8 = 243;
pub const DM: u8 = 242;
pub const NOP: u8 = 241;
pub const SE: u8 = 240;

/// Telnet option numbers (RFC 856/857/858/1091/1073).
pub const OPT_BINARY: u8 = 0;
pub const OPT_ECHO: u8 = 1;
pub const OPT_SGA: u8 = 3;
pub const OPT_TTYPE: u8 = 24;
pub const OPT_NAWS: u8 = 31;

/// Subnegotiation payload for TTYPE: `IS` (0) or `SEND` (1).
const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;

/// Upper bound for a single subnegotiation body. Well-formed negotiations are
/// a few bytes (TTYPE, NAWS); a server that never sends `IAC SE` would
/// otherwise grow the buffer without limit, so the body is dropped instead.
const MAX_SUBNEG: usize = 4096;

/// Parse state for the inbound byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    /// Plain data.
    Data,
    /// Previous byte was `IAC`; the next byte decides the command.
    Iac,
    /// Previous byte was `WILL`/`WONT`/`DO`/`DONT`; the next byte is the option.
    Negotiate,
    /// Inside `IAC SB ... IAC SE`; the buffer holds the subnegotiation body.
    SubNegotiation,
    /// Inside a subnegotiation and the previous byte was `IAC` (escape/SE).
    SubNegotiationIac,
}

/// Telnet protocol codec shared by the reader task.
///
/// Negotiation state is tracked so repeated offers do not produce
/// negotiation loops: replies are only emitted when the state actually
/// changes.
pub struct TelnetCodec {
    /// TERMINAL-TYPE reported for `SB TTYPE SEND`.
    terminal_type: String,
    /// `Some(true)` when the server's advertised `WILL <opt>` was accepted
    /// (we replied `DO`); `Some(false)` when we declined (`DONT`).
    server_will: [Option<bool>; 256],
    /// `Some(true)` when we advertised `WILL <opt>` (server replied `DO`);
    /// `Some(false)` when the server declined (`DONT`).
    client_will: [Option<bool>; 256],
    /// Current window size used for NAWS replies.
    size: (u16, u16),
    /// Last window size announced by the server via `SB NAWS`.
    server_size: Option<(u16, u16)>,
    /// Raw negotiation replies queued for the socket.
    replies: Vec<u8>,
    state: ParseState,
    pending: u8,
    subneg: Vec<u8>,
    /// Set when a subnegotiation exceeded [`MAX_SUBNEG`]; its bytes are
    /// discarded and the parser resynchronizes at the next `IAC SE`.
    subneg_overflow: bool,
    /// Whether the previous data byte was `CR` (RFC 854 `CR NUL` filler).
    last_was_cr: bool,
}

impl TelnetCodec {
    /// Creates a codec with the given TERMINAL-TYPE and initial window size.
    pub fn new(terminal_type: impl Into<String>, cols: u16, rows: u16) -> Self {
        TelnetCodec {
            terminal_type: terminal_type.into(),
            server_will: [None; 256],
            client_will: [None; 256],
            size: (cols, rows),
            server_size: None,
            replies: Vec::new(),
            state: ParseState::Data,
            pending: 0,
            subneg: Vec::new(),
            subneg_overflow: false,
            last_was_cr: false,
        }
    }

    /// Feeds raw socket bytes, appending the decoded terminal data (IAC
    /// stripped, `CR NUL` collapsed) to `out`. Negotiation replies are
    /// queued internally and returned by [`TelnetCodec::drain_replies`].
    pub fn process(&mut self, input: &[u8], out: &mut Vec<u8>) {
        for &byte in input {
            match self.state {
                ParseState::Data => self.data_byte(byte, out),
                ParseState::Iac => self.iac_byte(byte, out),
                ParseState::Negotiate => {
                    self.state = ParseState::Data;
                    self.negotiate_byte(byte);
                }
                ParseState::SubNegotiation => {
                    if byte == IAC {
                        self.state = ParseState::SubNegotiationIac;
                    } else if self.subneg_overflow {
                        // Oversized body: swallow until `IAC SE`.
                    } else if self.subneg.len() < MAX_SUBNEG {
                        self.subneg.push(byte);
                    } else {
                        // Hostile/broken server: drop the oversized body and
                        // resynchronize at the next `IAC SE`.
                        self.subneg.clear();
                        self.subneg_overflow = true;
                    }
                }
                ParseState::SubNegotiationIac => {
                    if byte == SE {
                        self.state = ParseState::Data;
                        if self.subneg_overflow {
                            self.subneg_overflow = false;
                        } else {
                            self.finish_subnegotiation();
                        }
                    } else if byte == IAC {
                        // Escaped 0xFF inside the subnegotiation body.
                        if !self.subneg_overflow {
                            if self.subneg.len() < MAX_SUBNEG {
                                self.subneg.push(IAC);
                            } else {
                                self.subneg.clear();
                                self.subneg_overflow = true;
                            }
                        }
                        self.state = ParseState::SubNegotiation;
                    } else {
                        // Malformed: treat the IAC as data and resume.
                        if !self.subneg_overflow {
                            if self.subneg.len() + 2 <= MAX_SUBNEG {
                                self.subneg.push(IAC);
                                self.subneg.push(byte);
                            } else {
                                self.subneg.clear();
                                self.subneg_overflow = true;
                            }
                        }
                        self.state = ParseState::SubNegotiation;
                    }
                }
            }
        }
    }

    /// Takes the queued negotiation replies (raw command bytes, already
    /// IAC-framed) for writing to the socket.
    pub fn drain_replies(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.replies)
    }

    /// Escapes user payload bytes for the wire: every `0xFF` becomes
    /// `IAC IAC`.
    pub fn encode(&self, data: &[u8], out: &mut Vec<u8>) {
        for &byte in data {
            out.push(byte);
            if byte == IAC {
                out.push(IAC);
            }
        }
    }

    /// Resizes the window and queues a NAWS reply when the server negotiated
    /// `DO NAWS`.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.size = (cols, rows);
        if self.client_will[OPT_NAWS as usize] == Some(true) {
            self.queue_naws();
        }
    }

    /// The last `SB NAWS` size announced by the server, if any.
    pub fn server_size(&self) -> Option<(u16, u16)> {
        self.server_size
    }

    fn data_byte(&mut self, byte: u8, out: &mut Vec<u8>) {
        if byte == IAC {
            self.state = ParseState::Iac;
            return;
        }
        // RFC 854: a NUL right after CR is filler and must be dropped.
        if byte == 0 && self.last_was_cr {
            self.last_was_cr = false;
            return;
        }
        self.last_was_cr = byte == b'\r';
        out.push(byte);
    }

    fn iac_byte(&mut self, byte: u8, out: &mut Vec<u8>) {
        self.state = ParseState::Data;
        match byte {
            IAC => {
                // Escaped literal 0xFF.
                self.last_was_cr = false;
                out.push(IAC);
            }
            WILL | WONT | DO | DONT => {
                self.pending = byte;
                self.state = ParseState::Negotiate;
            }
            SB => {
                self.subneg.clear();
                self.state = ParseState::SubNegotiation;
            }
            NOP | GA | EL | EC | AO | IP | BRK | DM | SE => {}
            AYT => {
                // "Are you there" — reply with a plain-text answer.
                self.replies.extend_from_slice(b"FreeSCP telnet client\r\n");
            }
            _ => {
                // Unknown IAC command: ignore.
            }
        }
    }

    fn negotiate_byte(&mut self, option: u8) {
        match self.pending {
            WILL => {
                if Self::want_server_enable(option) {
                    if self.server_will[option as usize] != Some(true) {
                        self.server_will[option as usize] = Some(true);
                        self.replies.extend_from_slice(&[IAC, DO, option]);
                    }
                } else if self.server_will[option as usize] != Some(false) {
                    self.server_will[option as usize] = Some(false);
                    self.replies.extend_from_slice(&[IAC, DONT, option]);
                }
            }
            WONT => {
                if self.server_will[option as usize] == Some(true) {
                    self.server_will[option as usize] = Some(false);
                    self.replies.extend_from_slice(&[IAC, DONT, option]);
                }
            }
            DO => {
                if Self::will_answer(option) {
                    if self.client_will[option as usize] != Some(true) {
                        self.client_will[option as usize] = Some(true);
                        self.replies.extend_from_slice(&[IAC, WILL, option]);
                        if option == OPT_NAWS {
                            self.queue_naws();
                        }
                    }
                } else if self.client_will[option as usize] != Some(false) {
                    self.client_will[option as usize] = Some(false);
                    self.replies.extend_from_slice(&[IAC, WONT, option]);
                }
            }
            DONT => {
                if self.client_will[option as usize] == Some(true) {
                    self.client_will[option as usize] = Some(false);
                    self.replies.extend_from_slice(&[IAC, WONT, option]);
                }
            }
            _ => {}
        }
    }

    fn finish_subnegotiation(&mut self) {
        let subneg = std::mem::take(&mut self.subneg);
        let Some((&option, body)) = subneg.split_first() else {
            return;
        };
        match option {
            OPT_TTYPE if body == [TTYPE_SEND] => {
                self.replies
                    .extend_from_slice(&[IAC, SB, OPT_TTYPE, TTYPE_IS]);
                self.replies
                    .extend_from_slice(self.terminal_type.as_bytes());
                self.replies.extend_from_slice(&[IAC, SE]);
            }
            OPT_NAWS if body.len() == 4 => {
                let cols = u16::from_be_bytes([body[0], body[1]]);
                let rows = u16::from_be_bytes([body[2], body[3]]);
                self.server_size = Some((cols, rows));
            }
            _ => {}
        }
    }

    fn queue_naws(&mut self) {
        let (cols, rows) = self.size;
        self.replies.extend_from_slice(&[IAC, SB, OPT_NAWS]);
        self.replies.extend_from_slice(&cols.to_be_bytes());
        self.replies.extend_from_slice(&rows.to_be_bytes());
        self.replies.extend_from_slice(&[IAC, SE]);
    }

    /// Options we accept when the server offers them (`WILL` -> `DO`).
    fn want_server_enable(option: u8) -> bool {
        matches!(option, OPT_BINARY | OPT_ECHO | OPT_SGA)
    }

    /// Options we offer when the server asks (`DO` -> `WILL`).
    fn will_answer(option: u8) -> bool {
        matches!(option, OPT_BINARY | OPT_SGA | OPT_TTYPE | OPT_NAWS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(parser: &mut TelnetCodec, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut out = Vec::new();
        parser.process(input, &mut out);
        (out, parser.drain_replies())
    }

    #[test]
    fn data_passes_through_unchanged() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (out, replies) = drain(&mut codec, b"hello\r\nworld");
        assert_eq!(out, b"hello\r\nworld");
        assert!(replies.is_empty());
    }

    #[test]
    fn cr_nul_filler_is_dropped() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (out, _) = drain(&mut codec, b"a\r\0b");
        assert_eq!(out, b"a\rb");
    }

    #[test]
    fn iac_iac_produces_literal_ff() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (out, _) = drain(&mut codec, &[b'a', IAC, IAC, b'b']);
        assert_eq!(out, &[b'a', 0xFF, b'b']);
    }

    #[test]
    fn encode_escapes_ff() {
        let codec = TelnetCodec::new("xterm-256color", 80, 24);
        let mut out = Vec::new();
        codec.encode(&[0xFF, b'x'], &mut out);
        assert_eq!(out, &[IAC, IAC, b'x']);
    }

    #[test]
    fn ignores_noop_and_other_commands() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (out, _) = drain(&mut codec, &[b'a', IAC, NOP, b'b', IAC, GA, IAC, EL, b'c']);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn ayt_gets_a_reply() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (out, replies) = drain(&mut codec, &[IAC, AYT]);
        assert!(out.is_empty());
        assert_eq!(replies, b"FreeSCP telnet client\r\n");
    }

    #[test]
    fn accepts_server_will_echo_sga_binary() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (_, replies) = drain(&mut codec, &[IAC, WILL, OPT_ECHO]);
        assert_eq!(replies, &[IAC, DO, OPT_ECHO]);
        // State changed already: a repeated WILL gets no further reply.
        let (_, replies) = drain(&mut codec, &[IAC, WILL, OPT_ECHO]);
        assert!(replies.is_empty());
        let (_, replies) = drain(&mut codec, &[IAC, WILL, OPT_SGA]);
        assert_eq!(replies, &[IAC, DO, OPT_SGA]);
        let (_, replies) = drain(&mut codec, &[IAC, WILL, OPT_BINARY]);
        assert_eq!(replies, &[IAC, DO, OPT_BINARY]);
    }

    #[test]
    fn declines_unknown_server_option() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (_, replies) = drain(&mut codec, &[IAC, WILL, 42]);
        assert_eq!(replies, &[IAC, DONT, 42]);
    }

    #[test]
    fn wont_after_will_gets_dont_ack() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (_, replies) = drain(&mut codec, &[IAC, WILL, OPT_ECHO]);
        assert_eq!(replies, &[IAC, DO, OPT_ECHO]);
        let (_, replies) = drain(&mut codec, &[IAC, WONT, OPT_ECHO]);
        assert_eq!(replies, &[IAC, DONT, OPT_ECHO]);
    }

    #[test]
    fn answers_do_for_supported_options() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (_, replies) = drain(&mut codec, &[IAC, DO, OPT_TTYPE]);
        assert_eq!(replies, &[IAC, WILL, OPT_TTYPE]);
        // NAWS advertises the current size immediately.
        let (_, replies) = drain(&mut codec, &[IAC, DO, OPT_NAWS]);
        let mut expected = vec![IAC, WILL, OPT_NAWS];
        expected.extend_from_slice(&[IAC, SB, OPT_NAWS]);
        expected.extend_from_slice(&80u16.to_be_bytes());
        expected.extend_from_slice(&24u16.to_be_bytes());
        expected.extend_from_slice(&[IAC, SE]);
        assert_eq!(replies, expected);
    }

    #[test]
    fn declines_unknown_do() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (_, replies) = drain(&mut codec, &[IAC, DO, 45]);
        assert_eq!(replies, &[IAC, WONT, 45]);
    }

    #[test]
    fn dont_after_do_gets_wont_ack() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (_, replies) = drain(&mut codec, &[IAC, DO, OPT_TTYPE]);
        assert_eq!(replies, &[IAC, WILL, OPT_TTYPE]);
        let (_, replies) = drain(&mut codec, &[IAC, DONT, OPT_TTYPE]);
        assert_eq!(replies, &[IAC, WONT, OPT_TTYPE]);
    }

    #[test]
    fn ttype_send_is_answered() {
        let mut codec = TelnetCodec::new("vt100", 80, 24);
        let (_, replies) = drain(&mut codec, &[IAC, DO, OPT_TTYPE]);
        assert_eq!(replies, &[IAC, WILL, OPT_TTYPE]);
        let (_, replies) = drain(&mut codec, &[IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE]);
        assert_eq!(
            replies,
            &[IAC, SB, OPT_TTYPE, TTYPE_IS, b'v', b't', b'1', b'0', b'0', IAC, SE]
        );
    }

    #[test]
    fn naws_from_server_is_recorded() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (_, _) = drain(&mut codec, &[IAC, SB, OPT_NAWS, 0, 100, 0, 30, IAC, SE]);
        assert_eq!(codec.server_size(), Some((100, 30)));
    }

    #[test]
    fn subneg_with_escaped_ff_is_tolerated() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        // Unknown option with an escaped IAC inside the body: no panic, no reply.
        let (_, replies) = drain(&mut codec, &[IAC, SB, 99, b'a', IAC, IAC, b'b', IAC, SE]);
        assert!(replies.is_empty());
    }

    #[test]
    fn oversized_subnegotiation_is_dropped_and_resynchronizes() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        // Feed the oversized body without its terminator: the codec must cap
        // the buffer and remember to swallow the rest of the body. (Splitting
        // the input is what makes this discriminating: with the cap removed,
        // `subneg` would still hold the 4.6 KB body here.)
        let mut hostile = vec![IAC, SB, 99];
        hostile.extend(std::iter::repeat_n(b'x', MAX_SUBNEG + 512));
        let (out, _) = drain(&mut codec, &hostile);
        assert!(out.is_empty());
        assert!(codec.subneg_overflow, "oversized body must be dropped");
        assert!(
            codec.subneg.is_empty(),
            "the buffer must not retain the oversized body"
        );
        // The terminator followed by a NAWS body: the parser must be back in
        // data state and still handle real negotiations.
        let (out, _) = drain(
            &mut codec,
            &[IAC, SE, IAC, SB, OPT_NAWS, 0, 100, 0, 30, IAC, SE],
        );
        assert!(out.is_empty());
        assert!(
            !codec.subneg_overflow,
            "the overflow flag must clear at IAC SE"
        );
        assert_eq!(codec.server_size(), Some((100, 30)));
    }

    #[test]
    fn resize_after_naws_negotiation_sends_size() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let (_, _) = drain(&mut codec, &[IAC, DO, OPT_NAWS]);
        let _ = codec.drain_replies();
        codec.resize(120, 40);
        let replies = codec.drain_replies();
        let mut expected = vec![IAC, SB, OPT_NAWS];
        expected.extend_from_slice(&120u16.to_be_bytes());
        expected.extend_from_slice(&40u16.to_be_bytes());
        expected.extend_from_slice(&[IAC, SE]);
        assert_eq!(replies, expected);
    }

    #[test]
    fn resize_without_naws_is_silent() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        codec.resize(120, 40);
        assert!(codec.drain_replies().is_empty());
    }

    #[test]
    fn interleaved_commands_and_data() {
        let mut codec = TelnetCodec::new("xterm-256color", 80, 24);
        let mut out = Vec::new();
        codec.process(b"a", &mut out);
        codec.process(&[IAC, WILL, OPT_ECHO], &mut out);
        codec.process(b"b", &mut out);
        codec.process(&[IAC, IAC], &mut out);
        codec.process(b"c", &mut out);
        assert_eq!(out, &[b'a', b'b', 0xFF, b'c']);
        assert_eq!(codec.drain_replies(), &[IAC, DO, OPT_ECHO]);
    }
}
