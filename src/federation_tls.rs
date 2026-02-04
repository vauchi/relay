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
    config.federation_tls_cert_path.is_some()
        && config.federation_tls_key_path.is_some()
        && config.federation_tls_ca_path.is_some()
}

/// Loads the federation mTLS configuration from file paths.
///
/// Returns `None` if mTLS is not fully configured (all three paths must be set).
/// Returns `Err` if paths are set but files can't be loaded.
pub fn load_federation_tls(config: &RelayConfig) -> Result<Option<FederationTlsConfig>, String> {
    let (cert_path, key_path, ca_path) = match (
        &config.federation_tls_cert_path,
        &config.federation_tls_key_path,
        &config.federation_tls_ca_path,
    ) {
        (Some(cert), Some(key), Some(ca)) => (cert.as_str(), key.as_str(), ca.as_str()),
        _ => return Ok(None),
    };

    info!("Loading federation mTLS certificates");

    // Load our client certificate and private key
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_mtls_configured_all_set() {
        let mut config = RelayConfig::default();
        config.federation_tls_cert_path = Some("/path/to/cert.pem".to_string());
        config.federation_tls_key_path = Some("/path/to/key.pem".to_string());
        config.federation_tls_ca_path = Some("/path/to/ca.pem".to_string());
        assert!(is_mtls_configured(&config));
    }

    #[test]
    fn test_is_mtls_configured_none() {
        let config = RelayConfig::default();
        assert!(!is_mtls_configured(&config));
    }

    #[test]
    fn test_is_mtls_configured_partial() {
        let mut config = RelayConfig::default();
        config.federation_tls_cert_path = Some("/path/to/cert.pem".to_string());
        // key and ca not set
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
        let mut config = RelayConfig::default();
        config.federation_tls_cert_path = Some("/nonexistent/cert.pem".to_string());
        config.federation_tls_key_path = Some("/nonexistent/key.pem".to_string());
        config.federation_tls_ca_path = Some("/nonexistent/ca.pem".to_string());
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
}
