//! Command-line surface for the `freescp` binary.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use freescp_core::{Protocol, ProxyType, ScpTransferMode, TransferIntegrityPolicy};

/// Protocol selector (mirrors [`freescp_core::Protocol`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProtocolArg {
    Sftp,
    Scp,
    Ftp,
    Ftps,
    Webdav,
    Smb,
    Telnet,
}

impl ProtocolArg {
    pub fn to_core(self) -> Protocol {
        match self {
            ProtocolArg::Sftp => Protocol::Sftp,
            ProtocolArg::Scp => Protocol::Scp,
            ProtocolArg::Ftp => Protocol::Ftp,
            ProtocolArg::Ftps => Protocol::Ftps,
            ProtocolArg::Webdav => Protocol::WebDav,
            ProtocolArg::Smb => Protocol::Smb,
            ProtocolArg::Telnet => Protocol::Telnet,
        }
    }
}

/// TCP proxy type selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProxyArg {
    None,
    Socks5,
    HttpConnect,
}

impl ProxyArg {
    pub fn to_core(self) -> ProxyType {
        match self {
            ProxyArg::None => ProxyType::None,
            ProxyArg::Socks5 => ProxyType::Socks5,
            ProxyArg::HttpConnect => ProxyType::HttpConnect,
        }
    }
}

/// Transfer integrity policy selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IntegrityArg {
    Off,
    Optional,
    Required,
}

impl IntegrityArg {
    pub fn to_core(self) -> TransferIntegrityPolicy {
        match self {
            IntegrityArg::Off => TransferIntegrityPolicy::Off,
            IntegrityArg::Optional => TransferIntegrityPolicy::Optional,
            IntegrityArg::Required => TransferIntegrityPolicy::Required,
        }
    }
}

/// SCP transfer mode selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScpModeArg {
    Auto,
    ScpOnly,
}

impl ScpModeArg {
    pub fn to_core(self) -> ScpTransferMode {
        match self {
            ScpModeArg::Auto => ScpTransferMode::Auto,
            ScpModeArg::ScpOnly => ScpTransferMode::ScpOnly,
        }
    }
}

/// FreeSCP command-line client.
#[derive(Debug, Parser)]
#[command(
    name = "freescp",
    version,
    about = "Transfer files and open remote consoles over SFTP/SCP/FTP/FTPS/WebDAV/SMB/Telnet",
    long_about = None,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Write machine-readable JSON to stdout where applicable.
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress the transfer progress bar.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Connection flags shared by every subcommand.
#[derive(Args, Debug, Clone, Default)]
pub struct ConnectionArgs {
    /// Remote protocol (default: sftp; console always uses telnet).
    #[arg(short = 'p', long, value_enum)]
    pub protocol: Option<ProtocolArg>,

    /// Remote user name.
    #[arg(short = 'u', long)]
    pub user: Option<String>,

    /// Remote port (default: the protocol's well-known port).
    #[arg(long)]
    pub port: Option<u16>,

    /// Private key file for SSH authentication.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Passphrase for the private key.
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Remote password. Prefer the FREESCP_PASSWORD environment variable; an
    /// interactive prompt is used when neither is set and no key is given.
    #[arg(long)]
    pub password: Option<String>,

    /// Accept and save unknown SSH host keys without prompting (trust on
    /// first use). Without this flag interactive terminals are prompted;
    /// non-interactive runs fail closed.
    #[arg(long)]
    pub accept_new: bool,

    /// Use this known_hosts file instead of ~/.ssh/known_hosts.
    #[arg(long, value_name = "PATH")]
    pub known_hosts: Option<PathBuf>,

    /// Transfer integrity policy (default: optional).
    #[arg(long, value_enum)]
    pub integrity: Option<IntegrityArg>,

    /// SCP transfer mode (default: auto).
    #[arg(long, value_enum)]
    pub scp_mode: Option<ScpModeArg>,

    /// Skip TLS certificate verification (FTPS/WebDAV/telnet over TLS).
    #[arg(long)]
    pub insecure: bool,

    /// TCP proxy type.
    #[arg(long, value_enum)]
    pub proxy: Option<ProxyArg>,

    /// Proxy host.
    #[arg(long, value_name = "HOST")]
    pub proxy_host: Option<String>,

    /// Proxy port (default: 1080 for SOCKS5, 8080 for HTTP CONNECT).
    #[arg(long, value_name = "PORT")]
    pub proxy_port: Option<u16>,

    /// Proxy user name.
    #[arg(long, value_name = "USER")]
    pub proxy_user: Option<String>,

    /// Proxy password.
    #[arg(long, value_name = "PASSWORD")]
    pub proxy_password: Option<String>,

    /// Connect through an SSH jump host ([user@]host[:port]).
    #[arg(short = 'J', long, value_name = "SPEC")]
    pub jump: Option<String>,

    /// Private key file for the jump host.
    #[arg(long, value_name = "PATH")]
    pub jump_key: Option<PathBuf>,

    /// Wrap the telnet session in TLS (secure telnet, default port 992).
    #[arg(long)]
    pub telnet_tls: bool,

    /// TERMINAL-TYPE reported during telnet negotiation.
    #[arg(long, value_name = "TYPE")]
    pub term_type: Option<String>,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List a remote directory.
    Ls(LsArgs),

    /// Download a remote file.
    Get(GetArgs),

    /// Upload a local file.
    Put(PutArgs),

    /// Create a remote directory.
    Mkdir(MkdirArgs),

    /// Remove remote files or empty directories.
    Rm(RmArgs),

    /// Rename or move a remote path.
    Mv(MvArgs),

    /// Show metadata for a remote path.
    Stat(StatArgs),

    /// Change remote permissions.
    Chmod(ChmodArgs),

    /// Change the remote owner/group.
    Chown(ChownArgs),

    /// Test whether a remote path exists (exit code 0 when it does).
    Exists(ExistsArgs),

    /// Start an interactive SFTP-style shell.
    Shell(ShellArgs),

    /// Open an interactive telnet console.
    Console(ConsoleArgs),

    /// Generate a shell completion script.
    Completions(CompletionsArgs),
}

/// Arguments of `freescp ls`.
#[derive(Args, Debug)]
pub struct LsArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Remote directory to list.
    #[arg(default_value = ".")]
    pub path: String,
}

/// Arguments of `freescp get`.
#[derive(Args, Debug)]
pub struct GetArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Remote file to download.
    pub remote: String,

    /// Local destination (default: the remote file name).
    pub local: Option<String>,

    /// Resume a partial download when possible.
    #[arg(long)]
    pub resume: bool,
}

/// Arguments of `freescp put`.
#[derive(Args, Debug)]
pub struct PutArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Local file to upload.
    pub local: String,

    /// Remote destination (default: the local file name).
    pub remote: Option<String>,

    /// Resume a partial upload when possible.
    #[arg(long)]
    pub resume: bool,
}

/// Arguments of `freescp mkdir`.
#[derive(Args, Debug)]
pub struct MkdirArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Remote directory to create.
    pub path: String,

    /// Create missing parent directories as needed.
    #[arg(long)]
    pub parents: bool,

    /// Permission bits in octal (default: 755).
    #[arg(long, default_value = "755", value_name = "MODE")]
    pub mode: String,
}

/// Arguments of `freescp rm`.
#[derive(Args, Debug)]
pub struct RmArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Remote files or empty directories to remove.
    #[arg(required = true)]
    pub paths: Vec<String>,

    /// Ignore missing paths.
    #[arg(short = 'f', long)]
    pub force: bool,
}

/// Arguments of `freescp mv`.
#[derive(Args, Debug)]
pub struct MvArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Existing remote path.
    pub from: String,

    /// New remote path.
    pub to: String,

    /// Refuse to replace an existing destination.
    #[arg(long)]
    pub no_overwrite: bool,
}

/// Arguments of `freescp stat`.
#[derive(Args, Debug)]
pub struct StatArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Remote path to inspect.
    pub path: String,
}

/// Arguments of `freescp chmod`.
#[derive(Args, Debug)]
pub struct ChmodArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Permission bits in octal (e.g. 644).
    pub mode: String,

    /// Remote paths to change.
    #[arg(required = true)]
    pub paths: Vec<String>,
}

/// Arguments of `freescp chown`.
#[derive(Args, Debug)]
pub struct ChownArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Numeric owner id.
    pub uid: u32,

    /// Numeric group id.
    pub gid: u32,

    /// Remote paths to change.
    #[arg(required = true)]
    pub paths: Vec<String>,
}

/// Arguments of `freescp exists`.
#[derive(Args, Debug)]
pub struct ExistsArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,

    /// Remote path to test.
    pub path: String,
}

/// Arguments of `freescp shell`.
#[derive(Args, Debug)]
pub struct ShellArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target to connect to immediately: [user@]host[:port].
    pub target: Option<String>,
}

/// Arguments of `freescp console`.
#[derive(Args, Debug)]
pub struct ConsoleArgs {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    /// Remote target: [user@]host[:port].
    pub target: String,
}

/// Arguments of `freescp completions`.
#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate a completion script for.
    pub shell: clap_complete::Shell,
}
