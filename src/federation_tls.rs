// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Federation Mutual TLS (mTLS)
//!
//! Provides TLS configuration for relay-to-relay federation connections.
//! When configured with client certificates and a CA bundle, federation
//! connections use mutual TLS for authentication.
//!
//! # Certificate Requirements
//!
//! - Certificates must be PEM-encoded
//! - The relay_id should appear in the certificate's Common Name (CN) or
//!   Subject Alternative Name (SAN) for identity verification
//! - The CA bundle should contain certificates of all trusted federation peers

use std::io::BufReader;
use std::sync::Arc;

use tokio_rustls::rustls::{self, pki_types};
use tracing::info;

use crate::config::RelayConfig;

/// Result of loading mTLS configuration.
pub struct FederationTlsConfig {
    /// TLS client config for outbound connections (with client cert).
    pub client_config: Arc<rustls::ClientConfig>,
    /// TLS server config for inbound connections (requires client cert).
    pub server_config: Arc<rustls::ServerConfig>,
}

/// Loads PEM certificates from a file path.
fn load_certs(path: &str) -> Result<Vec<pki_types::CertificateDer<'static>>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("Failed to open cert file {}: {}", path, e))?;
    let mut reader = BufReader::new(file);

    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse certs from {}: {}", path, e))?;

    if certs.is_empty() {
        return Err(format!("No certificates found in {}", path));
    }

    Ok(certs)
}

/// Loads a PEM private key from a file path.
fn load_private_key(path: &str) -> Result<pki_types::PrivateKeyDer<'static>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("Failed to open key file {}: {}", path, e))?;
    let mut reader = BufReader::new(file);

    // Try PKCS#8 first, then RSA, then EC
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("Failed to parse private key from {}: {}", path, e))?
        .ok_or_else(|| format!("No private key found in {}", path))?;

    Ok(key)
}

/// Loads CA certificates from a PEM bundle file.
fn load_ca_certs(path: &str) -> Result<rustls::RootCertStore, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("Failed to open CA file {}: {}", path, e))?;
    let mut reader = BufReader::new(file);

    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse CA certs from {}: {}", path, e))?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| format!("Failed to add CA cert: {}", e))?;
    }

    if root_store.is_empty() {
        return Err(format!("No CA certificates found in {}", path));
    }

    Ok(root_store)
}

/// Checks if federation mTLS is configured (all three paths are set).
pub fn is_mtls_configured(config: &RelayConfig) -> bool {
    config.federation.tls_cert_path.is_some()
        && config.federation.tls_key_path.is_some()
        && config.federation.tls_ca_path.is_some()
}

/// Loads the federation mTLS configuration from file paths.
///
/// Returns `None` if mTLS is not fully configured (all three paths must be set).
/// Returns `Err` if paths are set but files can't be loaded.
pub fn load_federation_tls(config: &RelayConfig) -> Result<Option<FederationTlsConfig>, String> {
    let (cert_path, key_path, ca_path) = match (
        &config.federation.tls_cert_path,
        &config.federation.tls_key_path,
        &config.federation.tls_ca_path,
    ) {
        (Some(cert), Some(key), Some(ca)) => (cert.as_str(), key.as_str(), ca.as_str()),
        _ => return Ok(None),
    };

    info!("Loading federation mTLS certificates");

    let client_certs = load_certs(cert_path)?;
    let client_key = load_private_key(key_path)?;
    let root_store = load_ca_certs(ca_path)?;

    info!(
        "Loaded {} client cert(s), CA store with {} root(s)",
        client_certs.len(),
        root_store.len()
    );

    // Build client config (for outbound mTLS connections)
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store.clone())
        .with_client_auth_cert(client_certs.clone(), client_key.clone_key())
        .map_err(|e| format!("Failed to build client TLS config: {}", e))?;

    // Build server config (for inbound mTLS connections)
    let client_cert_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| format!("Failed to build client verifier: {}", e))?;

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(client_certs, client_key)
        .map_err(|e| format!("Failed to build server TLS config: {}", e))?;

    Ok(Some(FederationTlsConfig {
        client_config: Arc::new(client_config),
        server_config: Arc::new(server_config),
    }))
}

// INLINE_TEST_REQUIRED: Tests private helper functions (load_certs, load_private_key, load_ca_certs)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_mtls_configured_all_set() {
        let config = RelayConfig {
            federation: crate::config::FederationConfig {
                tls_cert_path: Some("/path/to/cert.pem".to_string()),
                tls_key_path: Some("/path/to/key.pem".to_string()),
                tls_ca_path: Some("/path/to/ca.pem".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(is_mtls_configured(&config));
    }

    #[test]
    fn test_is_mtls_configured_none() {
        let config = RelayConfig::default();
        assert!(!is_mtls_configured(&config));
    }

    #[test]
    fn test_is_mtls_configured_partial() {
        let config = RelayConfig {
            federation: crate::config::FederationConfig {
                tls_cert_path: Some("/path/to/cert.pem".to_string()),
                // key and ca not set
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!is_mtls_configured(&config));
    }

    #[test]
    fn test_load_federation_tls_not_configured() {
        let config = RelayConfig::default();
        let result = load_federation_tls(&config);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_load_federation_tls_missing_files() {
        let config = RelayConfig {
            federation: crate::config::FederationConfig {
                tls_cert_path: Some("/nonexistent/cert.pem".to_string()),
                tls_key_path: Some("/nonexistent/key.pem".to_string()),
                tls_ca_path: Some("/nonexistent/ca.pem".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = load_federation_tls(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certs_missing_file() {
        let result = load_certs("/nonexistent/cert.pem");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to open"));
    }

    #[test]
    fn test_load_private_key_missing_file() {
        let result = load_private_key("/nonexistent/key.pem");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to open"));
    }

    #[test]
    fn test_load_ca_certs_missing_file() {
        let result = load_ca_certs("/nonexistent/ca.pem");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to open"));
    }

    /// Generate test CA, server cert, and write them to temp files.
    /// Returns (ca_file, cert_file, key_file).
    fn generate_test_certs() -> (
        tempfile::NamedTempFile,
        tempfile::NamedTempFile,
        tempfile::NamedTempFile,
    ) {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
            PKCS_ECDSA_P256_SHA256, SanType,
        };
        use std::io::Write;

        // Generate CA
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "Test CA");
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_issuer = Issuer::new(ca_params, ca_key);

        // Generate server cert signed by CA
        let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut server_params = CertificateParams::default();
        let mut server_dn = DistinguishedName::new();
        server_dn.push(DnType::CommonName, "test-relay");
        server_params.distinguished_name = server_dn;
        server_params.is_ca = IsCa::NoCa;
        server_params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        server_params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

        // Write to temp files
        let mut ca_file = tempfile::NamedTempFile::new().unwrap();
        ca_file.write_all(ca_cert.pem().as_bytes()).unwrap();

        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(server_cert.pem().as_bytes()).unwrap();

        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file
            .write_all(server_key.serialize_pem().as_bytes())
            .unwrap();

        (ca_file, cert_file, key_file)
    }

    #[test]
    fn test_load_federation_tls_with_valid_certs() {
        let (ca_file, cert_file, key_file) = generate_test_certs();

        let config = RelayConfig {
            federation: crate::config::FederationConfig {
                tls_cert_path: Some(cert_file.path().to_str().unwrap().to_string()),
                tls_key_path: Some(key_file.path().to_str().unwrap().to_string()),
                tls_ca_path: Some(ca_file.path().to_str().unwrap().to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let tls = load_federation_tls(&config).expect("load_federation_tls failed");
        assert!(tls.is_some(), "Expected Some(FederationTlsConfig)");
    }

    /// Verify that server_config enforces mandatory client certificates (mTLS).
    ///
    /// Connects to a TLS listener backed by the federation server_config.
    /// A client without a certificate must be rejected at the TLS handshake.
    /// A client presenting a valid CA-signed certificate must succeed.
    #[tokio::test]
    async fn test_server_config_requires_client_cert() {
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let (ca_file, cert_file, key_file) = generate_test_certs();

        let config = RelayConfig {
            federation: crate::config::FederationConfig {
                tls_cert_path: Some(cert_file.path().to_str().unwrap().to_string()),
                tls_key_path: Some(key_file.path().to_str().unwrap().to_string()),
                tls_ca_path: Some(ca_file.path().to_str().unwrap().to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let tls_config = load_federation_tls(&config).unwrap().unwrap();
        let acceptor = TlsAcceptor::from(tls_config.server_config.clone());

        // Build a root store trusting our test CA (used by both client scenarios)
        let ca_pem = std::fs::read(ca_file.path()).unwrap();
        let ca_certs = rustls_pemfile::certs(&mut &ca_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert).unwrap();
        }

        let server_name = pki_types::ServerName::try_from("localhost").unwrap();

        // --- Test 1: Connection WITHOUT client cert must be rejected ---
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let acceptor1 = acceptor.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor1.accept(stream).await
        });

        let no_auth_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store.clone())
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(no_auth_config));

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _client_result = connector.connect(server_name.clone(), tcp).await;

        let server_result = server_task.await.unwrap();
        assert!(
            server_result.is_err(),
            "Server should reject connection without client certificate"
        );

        // --- Test 2: Connection WITH valid client cert must succeed ---
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();

        let acceptor2 = acceptor.clone();
        let server_task2 = tokio::spawn(async move {
            let (stream, _) = listener2.accept().await.unwrap();
            acceptor2.accept(stream).await
        });

        // Reuse the server cert+key as client cert (it has ClientAuth EKU)
        let client_cert_pem = std::fs::read(cert_file.path()).unwrap();
        let client_key_pem = std::fs::read(key_file.path()).unwrap();
        let client_certs = rustls_pemfile::certs(&mut &client_cert_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let client_key = rustls_pemfile::private_key(&mut &client_key_pem[..])
            .unwrap()
            .unwrap();

        let with_auth_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .unwrap();
        let connector2 = tokio_rustls::TlsConnector::from(Arc::new(with_auth_config));

        let tcp2 = tokio::net::TcpStream::connect(addr2).await.unwrap();
        let _client_tls = connector2.connect(server_name, tcp2).await;

        let server_result2 = server_task2.await.unwrap();
        assert!(
            server_result2.is_ok(),
            "Server should accept connection with valid client certificate, got: {:?}",
            server_result2.err()
        );
    }
}
