//! FreeSCP core: protocol-agnostic remote file access.
//!
//! Module map is fixed. Each module is owned by one rewrite workstream:
//! - types.rs          : shared types (Agent: core-types)
//! - client.rs         : `SftpClient` trait + `ClientError` (Agent: core-api)
//! - client_factory.rs : protocol -> backend factory (Agent: core-api)
//! - known_hosts.rs    : known_hosts parsing/hashing helpers (Agent: sftp-helper)
//! - integrity.rs      : transfer integrity hashing (Agent: sftp-helper)
//! - proxy.rs          : SOCKS5 / HTTP-CONNECT tunnels (Agent: proxy-jumphost)
//! - jumphost.rs       : SSH bastion direct-tcpip tunnel (Agent: proxy-jumphost)
//! - backends/         : mock, sftp, scp, ftp, webdav implementations

pub mod client;
pub mod client_factory;
pub mod integrity;
pub mod jumphost;
pub mod known_hosts;
pub mod proxy;
pub mod ssh_config;
pub mod types;

pub mod backends {
    pub mod ftp;
    pub mod mock;
    pub mod scp;
    pub mod sftp;
    pub mod webdav;
}

pub use client::{ClientError, SftpClient};
pub use types::*;
