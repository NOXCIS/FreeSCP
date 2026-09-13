//! Protocol-aware backend factory — async port of
//! `core/src/libssh2/ClientFactory.cpp`.
//!
//! NOTE (integration): the backend modules referenced below
//! (`crate::backends::{sftp, scp, ftp, webdav}`) are written by sibling
//! workstreams with constructors `pub fn new() -> Self`; this module only
//! compiles once those modules land.

use crate::client::{ClientError, SftpClient};
use crate::types::Protocol;

/// Create a disconnected client for `protocol` (port of the C++
/// `CreateClientForProtocol`).
///
/// The C++ factory passed the protocol into the backend constructor (e.g.
/// `CurlFtpClient(Protocol::Ftps)`); the Rust backends instead read the
/// protocol from `SessionOptions` at `connect()` time, so FTP and FTPS share
/// a single constructor and FTPS is distinguished via the `ftps_*` fields of
/// `SessionOptions`.
pub fn create_client(protocol: Protocol) -> Result<Box<dyn SftpClient>, ClientError> {
    let client: Box<dyn SftpClient> = match protocol {
        Protocol::Sftp => Box::new(crate::backends::sftp::RusshSftpClient::new()),
        Protocol::Scp => Box::new(crate::backends::scp::ScpClient::new()),
        Protocol::Ftp | Protocol::Ftps => Box::new(crate::backends::ftp::FtpClient::new()),
        Protocol::WebDav => Box::new(crate::backends::webdav::WebDavClient::new()),
    };
    Ok(client)
}

/// Create a client for `opt.protocol` and connect it (port of the C++
/// `CreateConnectedClient`). Returns the connected client or the connect
/// error.
pub async fn create_connected_client(
    opt: &crate::types::SessionOptions,
) -> Result<Box<dyn SftpClient>, ClientError> {
    let mut client = create_client(opt.protocol)?;
    client.connect(opt).await?;
    Ok(client)
}
