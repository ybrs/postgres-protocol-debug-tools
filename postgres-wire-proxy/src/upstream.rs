//! Upstream TLS.
//!
//! The proxy terminates TLS for the client and speaks to the backend itself, so
//! when the backend wants TLS the proxy has to be a TLS *client*: send the
//! 8-byte `SSLRequest`, read the server's one-byte answer, and wrap the socket
//! when it agrees.
//!
//! What does not change is the logging: the proxy still reads plaintext on both
//! sides, because it terminates rather than tunnels.

use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

/// What the proxy needs of an upstream socket: bytes in, bytes out. Implemented
/// for anything that qualifies, including the TLS stream.
pub trait UpstreamStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> UpstreamStream for T {}

/// Boxed so that `run_proxy` does not care whether the backend ended up TLS or
/// plaintext: the decision stays in one place, here.
///
/// A trait of its own, rather than `dyn AsyncRead + AsyncWrite`, because a trait
/// object may only have one non-auto trait.
pub type BoxedUpstream = Box<dyn UpstreamStream>;

/// Protocol code a client sends to ask for TLS.
pub const SSL_REQUEST_CODE: u32 = 80877103;

/// The whole `SSLRequest` packet: a length covering itself plus the 4-byte code
/// (0x04d2162f == `SSL_REQUEST_CODE`, which `ssl_request_packet_matches_code`
/// keeps honest).
const SSL_REQUEST_PACKET: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

/// Whether, and how, to ask the backend for TLS.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum UpstreamSslMode {
    /// Never send an SSLRequest; always talk to the backend in plaintext
    Disable,
    /// Ask for TLS; carry on in plaintext if the server refuses or the
    /// handshake fails (default), as libpq's `sslmode=prefer` does
    Prefer,
    /// Require TLS; treat a refusal, or a failed handshake, as fatal
    Require,
}

impl Default for UpstreamSslMode {
    fn default() -> Self {
        // Matches the proxy's behaviour before this option existed: a server
        // that does not ask for TLS is still reachable.
        Self::Prefer
    }
}

/// How to reach the backend, TLS-wise.
#[derive(Clone, Debug)]
pub struct UpstreamSsl {
    pub mode: UpstreamSslMode,
    /// Extra trust anchor(s), as PEM. For a private CA.
    pub ca_cert: Option<PathBuf>,
    /// Name to verify against and send as SNI; defaults to the upstream host.
    pub server_name: Option<String>,
    /// Accept any certificate at all. Encrypts, authenticates nothing.
    pub insecure: bool,
}

impl UpstreamSsl {
    /// Names this mode on one line for the startup banner.
    pub fn describe(&self) -> String {
        match (self.mode, self.insecure) {
            (UpstreamSslMode::Disable, _) => "disable".to_string(),
            (UpstreamSslMode::Prefer, false) => "prefer (verified)".to_string(),
            (UpstreamSslMode::Prefer, true) => "prefer (unverified)".to_string(),
            (UpstreamSslMode::Require, false) => "require (verified)".to_string(),
            (UpstreamSslMode::Require, true) => "require (unverified)".to_string(),
        }
    }
}

/// Connect to the backend, negotiating TLS first when the mode asks for it.
pub async fn connect(
    host: &str,
    port: u16,
    ssl: &UpstreamSsl,
    client_addr: &str,
) -> Result<BoxedUpstream> {
    let mut socket = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("Failed to connect to upstream {host}:{port}"))?;

    if ssl.mode == UpstreamSslMode::Disable {
        info!(
            "[{}] Upstream SSL disabled, talking to the backend in plaintext",
            client_addr
        );
        return Ok(Box::new(socket));
    }

    socket
        .write_all(&SSL_REQUEST_PACKET)
        .await
        .context("Failed to send SSLRequest to upstream")?;
    info!("[{}] Upstream SSL: sent SSLRequest", client_addr);

    let mut answer = [0u8; 1];
    let read = socket
        .read(&mut answer)
        .await
        .context("Failed to read the upstream's answer to SSLRequest")?;
    if read == 0 {
        bail!(
            "Upstream closed the connection instead of answering the SSLRequest \
             (does {host}:{port} speak the PostgreSQL protocol?)"
        );
    }

    match answer[0] {
        b'S' => {
            let server_name = ssl.server_name.clone().unwrap_or_else(|| host.to_string());
            if ssl.insecure {
                warn!(
                    "[{}] Upstream SSL: server agreed to TLS, verifying nothing \
                     (--upstream-tls-insecure)",
                    client_addr
                );
            } else {
                info!(
                    "[{}] Upstream SSL: server agreed to TLS, handshaking (server name {:?})",
                    client_addr, server_name
                );
            }

            // A missing or unusable CA file, or a server name that is neither a
            // DNS name nor an IP address, is a configuration mistake. Retrying
            // in the clear would bury it, so it stays fatal in every mode.
            let config = Arc::new(build_client_config(ssl)?);
            let server_name = ServerName::try_from(server_name.clone()).with_context(|| {
                format!(
                    "Upstream server name {server_name:?} is neither a DNS name nor an IP address"
                )
            })?;
            let connector = tokio_rustls::TlsConnector::from(config);

            match connector.connect(server_name, socket).await {
                Ok(tls) => {
                    info!("[{}] Upstream TLS handshake complete", client_addr);
                    Ok(Box::new(tls))
                }
                Err(err) if ssl.mode == UpstreamSslMode::Prefer => {
                    warn!(
                        "[{}] Upstream TLS handshake failed ({err}); reconnecting in plaintext \
                         because --upstream-ssl-mode=prefer. Pass --upstream-ca-cert <pem> to \
                         trust a private CA, --upstream-tls-insecure to skip verification, or \
                         --upstream-ssl-mode=require to fail instead",
                        client_addr
                    );

                    // The socket the handshake consumed is unusable, so this is
                    // a fresh connection that skips the SSLRequest entirely.
                    let socket = TcpStream::connect((host, port)).await.with_context(|| {
                        format!("Failed to reconnect to upstream {host}:{port} in plaintext")
                    })?;
                    info!("[{}] Upstream SSL: falling back to plaintext", client_addr);
                    Ok(Box::new(socket))
                }
                Err(err) => Err(anyhow!(
                    "Upstream TLS handshake failed: {err}. If {host}:{port} uses a private CA, \
                     pass --upstream-ca-cert <pem>; --upstream-tls-insecure skips verification; \
                     --upstream-ssl-mode=disable talks in plaintext"
                )),
            }
        }
        b'N' => {
            if ssl.mode == UpstreamSslMode::Require {
                bail!("Upstream refused TLS, but --upstream-ssl-mode=require");
            }
            info!(
                "[{}] Upstream SSL: server refused TLS, continuing in plaintext",
                client_addr
            );
            Ok(Box::new(socket))
        }
        other => bail!(
            "Upstream answered the SSLRequest with {:?}, expected 'S' or 'N'",
            other as char
        ),
    }
}

/// Roots to verify the backend against: the bundled Mozilla set, plus a CA file
/// if one was given.
fn build_root_store(ca_cert: Option<&PathBuf>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = ca_cert {
        let file = File::open(path).with_context(|| {
            format!("Failed to open upstream CA certificate {}", path.display())
        })?;
        let certs = rustls_pemfile::certs(&mut BufReader::new(file))
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .with_context(|| {
                format!("Failed to parse upstream CA certificate {}", path.display())
            })?;
        if certs.is_empty() {
            bail!(
                "No PEM certificate found in upstream CA file {}",
                path.display()
            );
        }

        let found = certs.len();
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            bail!(
                "None of the {found} certificate(s) in {} could be used as a trust anchor",
                path.display()
            );
        }
    }

    Ok(roots)
}

fn build_client_config(ssl: &UpstreamSsl) -> Result<ClientConfig> {
    if ssl.insecure {
        // `dangerous()` is rustls' own name for this; the warning above the call
        // is why it never happens silently.
        return Ok(ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
            .with_no_client_auth());
    }

    let roots = build_root_store(ssl.ca_cert.as_ref())?;
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Verifies nothing. Only reachable through `--upstream-tls-insecure`.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
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
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CA `scripts/postgres.sh` uses for its local TLS runs, generated once
    /// with openssl and embedded so the tests need no certificate tooling.
    /// It signs nothing but throwaway development certificates.
    const TEST_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBoTCCAUegAwIBAgIUIduDa5pZ0Ohl8vnY1gLDGb5KSoMwCgYIKoZIzj0EAwIw
JjEkMCIGA1UEAwwbUG9zdGdyZXMgV2lyZSBQcm94eSBUZXN0IENBMB4XDTI2MTAy
NzE2MzQzMloXDTM2MTAyNDE2MzQzMlowJjEkMCIGA1UEAwwbUG9zdGdyZXMgV2ly
ZSBQcm94eSBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQ9jrjEK
DGSDceJHmUt3Kqg1EfsIZXKwRKyGCQujL51380ZPy1a8sAVWf1smjpqZVfCJ+bnW
hw/k92JG8BwfI6NTMFEwHQYDVR0OBBYEFAOOF/EPL17/odGsObzjJ0vBmYTGMB8G
A1UdIwQYMBaAFAOOF/EPL17/odGsObzjJ0vBmYTGMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDSAAwRQIgHFbJQ6ILMS5mAtBWAoScil7CJPUnrJodpoi4GLi7
udsCIQCBGbzipoZe/D4b118NfHB7NdHhj412gke7VfJb3po/+Q==
-----END CERTIFICATE-----
";

    fn temp_file(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("pg-proxy-test-{name}"));
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    #[test]
    fn ssl_request_packet_matches_code() {
        let code = u32::from_be_bytes(SSL_REQUEST_PACKET[4..8].try_into().unwrap());
        assert_eq!(code, SSL_REQUEST_CODE);
        assert_eq!(
            u32::from_be_bytes(SSL_REQUEST_PACKET[0..4].try_into().unwrap()),
            8
        );
    }

    #[test]
    fn default_mode_preserves_plaintext_fallback() {
        assert_eq!(UpstreamSslMode::default(), UpstreamSslMode::Prefer);
    }

    #[test]
    fn bundled_roots_are_loaded_without_a_ca_file() {
        let roots = build_root_store(None).expect("bundled roots");
        assert!(
            roots.len() > 100,
            "expected the Mozilla root set, got {}",
            roots.len()
        );
    }

    #[test]
    fn a_ca_file_is_accepted_as_an_extra_trust_anchor() {
        let path = temp_file("ca.crt", TEST_CA_PEM);
        let with_ca = build_root_store(Some(&path)).expect("CA file accepted");
        let without_ca = build_root_store(None).expect("bundled roots");
        assert_eq!(with_ca.len(), without_ca.len() + 1);
    }

    #[test]
    fn a_missing_ca_file_names_the_path() {
        let path = std::env::temp_dir().join("pg-proxy-test-does-not-exist.crt");
        let err = build_root_store(Some(&path)).expect_err("missing CA file");
        let message = format!("{err:#}");
        assert!(
            message.contains("pg-proxy-test-does-not-exist"),
            "{message}"
        );
    }

    #[test]
    fn a_ca_file_without_certificates_is_an_error() {
        let path = temp_file("empty.crt", "# nothing to see here\n");
        let err = build_root_store(Some(&path)).expect_err("CA file with no certs");
        assert!(
            format!("{err:#}").contains("No PEM certificate found"),
            "{err:#}"
        );
    }

    #[test]
    fn a_ca_file_with_undecodable_pem_is_an_error() {
        let path = temp_file(
            "garbage.crt",
            "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
        );
        let err = build_root_store(Some(&path)).expect_err("undecodable CA file");
        assert!(format!("{err:#}").contains("Failed to parse"), "{err:#}");
    }

    #[test]
    fn insecure_mode_accepts_any_certificate() {
        let ssl = UpstreamSsl {
            mode: UpstreamSslMode::Prefer,
            ca_cert: None,
            server_name: None,
            insecure: true,
        };
        // Builds without touching the roots at all.
        build_client_config(&ssl).expect("insecure config");

        let verifier = AcceptAnyCertificate;
        let cert = CertificateDer::from(vec![0xde, 0xad, 0xbe, 0xef]);
        let name = ServerName::try_from("localhost").unwrap();
        assert!(verifier
            .verify_server_cert(
                &cert,
                &[],
                &name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(0))
            )
            .is_ok());
        assert_eq!(verifier.supported_verify_schemes().len(), 10);
    }

    #[test]
    fn verified_config_uses_the_ca_file() {
        let path = temp_file("verified-ca.crt", TEST_CA_PEM);
        let ssl = UpstreamSsl {
            mode: UpstreamSslMode::Require,
            ca_cert: Some(path),
            server_name: Some("localhost".to_string()),
            insecure: false,
        };
        build_client_config(&ssl).expect("verified config");
        assert_eq!(ssl.describe(), "require (verified)");
    }

    #[test]
    fn describe_names_the_trust_decision() {
        let base = UpstreamSsl {
            mode: UpstreamSslMode::Prefer,
            ca_cert: None,
            server_name: None,
            insecure: false,
        };
        assert_eq!(base.describe(), "prefer (verified)");
        assert_eq!(
            UpstreamSsl {
                insecure: true,
                ..base.clone()
            }
            .describe(),
            "prefer (unverified)"
        );
        assert_eq!(
            UpstreamSsl {
                mode: UpstreamSslMode::Disable,
                ..base.clone()
            }
            .describe(),
            "disable"
        );
    }
}
