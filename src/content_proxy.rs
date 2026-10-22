// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Serves the CDN's content files to clients over OHTTP (vauchi/private#733
//! D8, D11; ADR-037 addendum 2026-10-22): fetching one language tells its
//! server that language, and through the gateway the relay cannot tie it to
//! an IP address. The relay fetches only paths in the content tree from one
//! configured origin and caches each briefly, so the CDN sees the relay's
//! requests, not a client's. Integrity stays end to end: clients verify the
//! signed manifest and each file's checksum.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::body::{Body, Bytes};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::Instant;

/// Longest content path served; real paths are under 32 bytes.
const MAX_PATH_BYTES: usize = 64;

/// Most files cached at once; the content tree holds a few dozen.
const MAX_CACHED_FILES: usize = 128;

/// Why a content request failed. Carries no origin detail a client could
/// use to probe the relay's network (DC-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentProxyError {
    NotAContentPath,
    InvalidOrigin,
    Unavailable,
    TooLarge,
}

impl std::fmt::Display for ContentProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotAContentPath => "not a content path",
            Self::InvalidOrigin => "invalid content origin",
            Self::Unavailable => "content unavailable",
            Self::TooLarge => "content too large",
        })
    }
}

impl std::error::Error for ContentProxyError {}

/// Whether `path` names a file in the content tree: `manifest.json`,
/// `networks.json`, `themes.json`, or `locales/<name>.json` /
/// `help/<name>.json` with a name of ASCII letters, digits and `-`.
pub fn is_content_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return false;
    }
    match path.split_once('/') {
        None => matches!(path, "manifest.json" | "networks.json" | "themes.json"),
        Some((dir, file)) => {
            matches!(dir, "locales" | "help")
                && file.strip_suffix(".json").is_some_and(|name| {
                    !name.is_empty()
                        && name.len() <= 32
                        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        }
    }
}

struct Origin {
    https: bool,
    host: String,
    port: u16,
    base_path: String,
}

impl Origin {
    fn parse(origin: &str) -> Result<Self, ContentProxyError> {
        let (https, rest) = if let Some(rest) = origin.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = origin.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(ContentProxyError::InvalidOrigin);
        };
        let (authority, base_path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() || authority.contains('@') {
            return Err(ContentProxyError::InvalidOrigin);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse().map_err(|_| ContentProxyError::InvalidOrigin)?,
            ),
            None => (authority, if https { 443 } else { 80 }),
        };
        if host.is_empty() {
            return Err(ContentProxyError::InvalidOrigin);
        }
        Ok(Self {
            https,
            host: host.to_string(),
            port,
            base_path: base_path.trim_end_matches('/').to_string(),
        })
    }

    fn request_path(&self, path: &str) -> String {
        if self.base_path.is_empty() {
            format!("/{path}")
        } else {
            format!("/{}/{path}", self.base_path)
        }
    }
}

/// Fetches content files from one origin, caching each for a lifetime.
pub struct ContentProxy {
    origin: Origin,
    tls: tokio_rustls::TlsConnector,
    lifetime: Duration,
    max_bytes: usize,
    cache: Mutex<HashMap<String, CachedFile>>,
}

struct CachedFile {
    fetched: Instant,
    body: Arc<Vec<u8>>,
}

impl ContentProxy {
    /// A proxy for `origin`, such as `https://cdn.vauchi.app/v1`, keeping a
    /// fetched file for `lifetime` and refusing files over `max_bytes`.
    pub fn new(
        origin: &str,
        lifetime: Duration,
        max_bytes: usize,
    ) -> Result<Self, ContentProxyError> {
        let origin = Origin::parse(origin)?;
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            origin,
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
            lifetime,
            max_bytes,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The file at `path`, from the cache while it is fresh, else from the
    /// origin. A failed fetch is not cached.
    pub async fn fetch(&self, path: &str) -> Result<Arc<Vec<u8>>, ContentProxyError> {
        if !is_content_path(path) {
            return Err(ContentProxyError::NotAContentPath);
        }
        if let Some(body) = self.cached(path) {
            return Ok(body);
        }
        let body = Arc::new(self.fetch_from_origin(path).await?);
        if let Ok(mut cache) = self.cache.lock() {
            let now = Instant::now();
            cache.retain(|_, file| now.duration_since(file.fetched) < self.lifetime);
            if cache.len() < MAX_CACHED_FILES {
                cache.insert(
                    path.to_string(),
                    CachedFile {
                        fetched: now,
                        body: Arc::clone(&body),
                    },
                );
            }
        }
        Ok(body)
    }

    fn cached(&self, path: &str) -> Option<Arc<Vec<u8>>> {
        let cache = self.cache.lock().ok()?;
        let file = cache.get(path)?;
        (file.fetched.elapsed() < self.lifetime).then(|| Arc::clone(&file.body))
    }

    async fn fetch_from_origin(&self, path: &str) -> Result<Vec<u8>, ContentProxyError> {
        let tcp = TcpStream::connect((self.origin.host.as_str(), self.origin.port))
            .await
            .map_err(|_| ContentProxyError::Unavailable)?;
        if self.origin.https {
            let server_name = rustls::pki_types::ServerName::try_from(self.origin.host.clone())
                .map_err(|_| ContentProxyError::InvalidOrigin)?;
            let tls = self
                .tls
                .connect(server_name, tcp)
                .await
                .map_err(|_| ContentProxyError::Unavailable)?;
            self.get(TokioIo::new(tls), path).await
        } else {
            self.get(TokioIo::new(tcp), path).await
        }
    }

    async fn get<IO>(&self, io: IO, path: &str) -> Result<Vec<u8>, ContentProxyError>
    where
        IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::handshake::<_, String>(io)
            .await
            .map_err(|_| ContentProxyError::Unavailable)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = hyper::Request::get(self.origin.request_path(path))
            .header(hyper::header::HOST, self.origin.host.as_str())
            .body(String::new())
            .map_err(|_| ContentProxyError::Unavailable)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| ContentProxyError::Unavailable)?;
        if response.status() != hyper::StatusCode::OK {
            return Err(ContentProxyError::Unavailable);
        }
        read_capped(response.into_body(), self.max_bytes).await
    }
}

async fn read_capped(
    mut body: hyper::body::Incoming,
    max_bytes: usize,
) -> Result<Vec<u8>, ContentProxyError> {
    let mut data = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|_| ContentProxyError::Unavailable)?;
        if let Ok(chunk) = frame.into_data() {
            let chunk: Bytes = chunk;
            if data.len() + chunk.len() > max_bytes {
                return Err(ContentProxyError::TooLarge);
            }
            data.extend_from_slice(&chunk);
        }
    }
    Ok(data)
}

/// The OHTTP `content` action: `{"path": "<content path>"}` answers
/// `{"status": "ok", "content_b64": "..."}`, or an error naming no detail.
pub async fn content_action(
    proxy: Option<&ContentProxy>,
    payload: serde_json::Value,
) -> serde_json::Value {
    use base64::Engine as _;
    let error = |reason: &str| serde_json::json!({ "status": "error", "error": reason });
    let Some(proxy) = proxy else {
        return error("content unavailable");
    };
    let Some(path) = payload.get("path").and_then(serde_json::Value::as_str) else {
        return error("bad content payload");
    };
    match proxy.fetch(path).await {
        Ok(body) => serde_json::json!({
            "status": "ok",
            "content_b64": base64::engine::general_purpose::STANDARD.encode(body.as_slice()),
        }),
        Err(e) => error(&e.to_string()),
    }
}
