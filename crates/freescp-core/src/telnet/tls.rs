//! rustls configuration for telnet-over-TLS (secure telnet, default port
//! 992).
//!
//! Mirrors the FTPS TLS mapping in `backends/ftp.rs`:
//!
//! * `telnet_verify_peer == false` accepts every certificate and skips
//!   hostname verification;
//! * otherwise the server certificate is validated against
//!   `telnet_ca_cert_path` (PEM bundle) or the first loadable system CA
//!   bundle.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tracing::warn;

use crate::client::ClientError;

/// Well-known system CA bundle locations (same list as the FTPS backend).
const SYSTEM_CA_BUNDLE_CANDIDATES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL alt
    "/etc/ssl/ca-bundle.pem",             // SUSE
    "/etc/ssl/cert.pem",                  // macOS / FreeBSD
    "/usr/local/etc/openssl/cert.pem",    // Homebrew OpenSSL (macOS)
    "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
];

/// Accepts every server certificate and skips hostname verification
/// (`telnet_verify_peer == false`).
#[derive(Debug)]
struct NoCertificateVerifier;

impl ServerCertVerifier for NoCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            ED448,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
        ]
    }
}

/// Loads PEM certificates from a bundle file into the root store, tolerating
/// unparsable entries. Returns the cert count.
fn load_ca_bundle_into(roots: &mut RootCertStore, path: &Path) -> std::io::Result<usize> {
    let mut count = 0usize;
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    for cert in rustls_pemfile::certs(&mut reader) {
        match cert {
            Ok(der) => match roots.add(der) {
                Ok(()) => count += 1,
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "skipping invalid CA certificate")
                }
            },
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skipping unparsable CA entry")
            }
        }
    }
    Ok(count)
}

/// Builds the TLS client config for a telnet session.
pub fn build_tls_config(
    verify_peer: bool,
    ca_cert_path: Option<&str>,
) -> Result<Arc<ClientConfig>, ClientError> {
    let provider = rustls::crypto::ring::default_provider();
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Other(format!("could not build TLS config: {e}")))?;
    if !verify_peer {
        let dangerous = builder.dangerous();
        let config = dangerous
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerifier))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }
    let mut roots = RootCertStore::empty();
    if let Some(ca_path) = ca_cert_path {
        let count = load_ca_bundle_into(&mut roots, Path::new(ca_path)).map_err(|e| {
            ClientError::Io(std::io::Error::new(
                e.kind(),
                format!("Could not read telnet CA certificate bundle '{ca_path}': {e}"),
            ))
        })?;
        if count == 0 {
            return Err(ClientError::Other(format!(
                "Telnet CA certificate bundle '{ca_path}' contains no usable certificates"
            )));
        }
    } else {
        let mut loaded = false;
        for candidate in SYSTEM_CA_BUNDLE_CANDIDATES {
            match load_ca_bundle_into(&mut roots, Path::new(candidate)) {
                Ok(n) if n > 0 => loaded = true,
                Ok(_) => {}
                Err(_) => {}
            }
        }
        if !loaded {
            return Err(ClientError::Other(
                "Telnet certificate verification is enabled but no system CA certificates could be found".into(),
            ));
        }
    }
    let config = builder.with_root_certificates(roots).with_no_client_auth();
    Ok(Arc::new(config))
}
