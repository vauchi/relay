// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Exchange Broker
//!
//! In-memory store for short-code mediated contact exchange. An initiator
//! creates an offer (encrypted payload) and receives a 6-digit numeric code.
//! The responder claims the offer by code, retrieves the initiator's payload,
//! and deposits their own response. The initiator then completes the exchange
//! by retrieving the responder's payload.
//!
//! All payloads are opaque base64-encoded ciphertext — the relay never sees
//! plaintext contact data.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rand::Rng;

/// Maximum retry attempts when generating a unique 6-digit code.
/// At 10k offers (max_offers default), collision probability per try is ~1%.
/// 100 retries gives P(all collide) ≈ 10^-200, effectively zero.
const MAX_CODE_RETRIES: usize = 100;

/// Total 6-digit code space: 000000–999999.
const CODE_SPACE: usize = 1_000_000;

/// S8: Maximum allowed `max_offers` — 50% of code space.
/// Beyond this, collision probability rises sharply and code generation
/// becomes unreliable even with 100 retries.
const MAX_OFFERS_CEILING: usize = CODE_SPACE / 2; // 500,000

/// S5: Minimum TTL for exchange offers (30 seconds).
/// Prevents trivially short-lived offers that waste code space.
pub const MIN_EXCHANGE_TTL_SECS: u64 = 30;

/// S5: Maximum TTL for exchange offers (1 hour).
/// Prevents long-lived offers that consume memory indefinitely.
pub const MAX_EXCHANGE_TTL_SECS: u64 = 3600;

/// S4: Maximum payload size for exchange offers/responses (64 KiB).
/// Exchange payloads are base64-encoded encrypted contact data — legitimate
/// payloads are a few hundred bytes. 64 KiB provides generous headroom.
pub const MAX_EXCHANGE_PAYLOAD_BYTES: usize = 64 * 1024;

/// In-memory broker for short-code mediated exchange offers.
pub struct ExchangeBroker {
    offers: RwLock<HashMap<String, ExchangeOffer>>,
    max_offers: usize,
    default_ttl: Duration,
}

/// A single exchange offer stored by the broker.
pub struct ExchangeOffer {
    /// Base64-encoded encrypted exchange data from the initiator.
    pub payload: String,
    /// 6-digit numeric code (000000–999999).
    pub code: String,
    /// When the offer was created.
    pub created_at: Instant,
    /// When the offer expires.
    pub expires_at: Instant,
    /// Whether the offer has been claimed by a responder.
    pub claimed: bool,
    /// The responder's encrypted payload, set on claim.
    pub response: Option<String>,
}

/// Errors returned by the exchange broker.
#[derive(Debug, PartialEq, Eq)]
pub enum ExchangeError {
    /// The code does not match any active offer.
    CodeNotFound,
    /// The offer has expired and been (or will be) cleaned up.
    CodeExpired,
    /// The offer was already claimed by another responder.
    AlreadyClaimed,
    /// The offer was already completed by the initiator.
    AlreadyCompleted,
    /// The broker has reached its maximum offer capacity.
    TooManyOffers,
    /// The initiator tried to complete before a responder claimed.
    NotYetClaimed,
    /// The payload exceeds the maximum allowed size.
    PayloadTooLarge,
    /// The requested TTL is outside the allowed range.
    InvalidTtl,
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // S1: Merge not-found and expired messages to prevent code enumeration.
            // An attacker cannot distinguish "code doesn't exist" from "code expired",
            // so they learn nothing about which codes were recently active.
            Self::CodeNotFound | Self::CodeExpired => write!(f, "invalid or expired code"),
            Self::AlreadyClaimed => write!(f, "already claimed"),
            Self::AlreadyCompleted => write!(f, "already completed"),
            Self::TooManyOffers => write!(f, "too many offers"),
            Self::NotYetClaimed => write!(f, "not yet claimed"),
            Self::PayloadTooLarge => write!(f, "payload too large"),
            Self::InvalidTtl => {
                write!(
                    f,
                    "TTL must be between {MIN_EXCHANGE_TTL_SECS} and {MAX_EXCHANGE_TTL_SECS} seconds"
                )
            }
        }
    }
}

impl ExchangeBroker {
    /// Create a new broker with the given capacity and default TTL.
    ///
    /// `default_ttl_secs` is **not** validated — operators control this value and
    /// tests use TTL=0 for immediate-expiration scenarios.  Per-offer TTL overrides
    /// are validated against [`MIN_EXCHANGE_TTL_SECS`]–[`MAX_EXCHANGE_TTL_SECS`].
    ///
    /// # Panics
    ///
    /// Panics if `max_offers` exceeds `MAX_OFFERS_CEILING` (50% of code space).
    /// This is a startup-time check to prevent misconfiguration.
    pub fn new(max_offers: usize, default_ttl_secs: u64) -> Self {
        // S8: Validate max_offers at construction time — fail fast on misconfiguration.
        assert!(
            max_offers <= MAX_OFFERS_CEILING,
            "max_offers ({max_offers}) exceeds ceiling ({MAX_OFFERS_CEILING}); \
             code generation becomes unreliable above 50% of the 6-digit code space"
        );

        Self {
            offers: RwLock::new(HashMap::new()),
            max_offers,
            default_ttl: Duration::from_secs(default_ttl_secs),
        }
    }

    /// Store an offer and return a 6-digit code.
    ///
    /// The optional `ttl_secs` overrides the broker's default TTL.
    pub fn create_offer(
        &self,
        payload: String,
        ttl_secs: Option<u64>,
    ) -> Result<String, ExchangeError> {
        // S4: Reject oversized payloads before acquiring the lock.
        if payload.len() > MAX_EXCHANGE_PAYLOAD_BYTES {
            return Err(ExchangeError::PayloadTooLarge);
        }

        // S5: Validate TTL bounds (when explicitly specified).
        if let Some(secs) = ttl_secs
            && !(MIN_EXCHANGE_TTL_SECS..=MAX_EXCHANGE_TTL_SECS).contains(&secs)
        {
            return Err(ExchangeError::InvalidTtl);
        }

        let mut offers = self.offers.write();

        if offers.len() >= self.max_offers {
            return Err(ExchangeError::TooManyOffers);
        }

        let code = Self::generate_code_inner(&offers)?;
        let ttl = ttl_secs.map_or(self.default_ttl, Duration::from_secs);
        let now = Instant::now();

        let offer = ExchangeOffer {
            payload,
            code: code.clone(),
            created_at: now,
            expires_at: now + ttl,
            claimed: false,
            response: None,
        };

        offers.insert(code.clone(), offer);
        Ok(code)
    }

    /// Claim an offer by code. Returns the initiator's payload.
    ///
    /// The responder provides their `response` payload which is stored
    /// for the initiator to retrieve via [`complete_offer`].
    pub fn claim_offer(&self, code: &str, response: String) -> Result<String, ExchangeError> {
        // S4: Reject oversized response payloads before acquiring the lock.
        if response.len() > MAX_EXCHANGE_PAYLOAD_BYTES {
            return Err(ExchangeError::PayloadTooLarge);
        }

        let mut offers = self.offers.write();
        let offer = offers.get_mut(code).ok_or(ExchangeError::CodeNotFound)?;

        if Instant::now() > offer.expires_at {
            return Err(ExchangeError::CodeExpired);
        }
        if offer.claimed {
            return Err(ExchangeError::AlreadyClaimed);
        }

        offer.claimed = true;
        offer.response = Some(response);
        Ok(offer.payload.clone())
    }

    /// Complete the exchange: initiator retrieves the responder's payload.
    ///
    /// The offer is removed after completion.
    pub fn complete_offer(&self, code: &str) -> Result<String, ExchangeError> {
        let mut offers = self.offers.write();
        let offer = offers.get(code).ok_or(ExchangeError::CodeNotFound)?;

        if Instant::now() > offer.expires_at {
            return Err(ExchangeError::CodeExpired);
        }
        if !offer.claimed {
            return Err(ExchangeError::NotYetClaimed);
        }
        let response = offer
            .response
            .as_ref()
            .ok_or(ExchangeError::NotYetClaimed)?;

        let result = response.clone();
        offers.remove(code);
        Ok(result)
    }

    /// Remove expired offers. Call periodically.
    ///
    /// Returns the number of offers removed.
    pub fn cleanup_expired(&self) -> usize {
        let mut offers = self.offers.write();
        let before = offers.len();
        let now = Instant::now();
        offers.retain(|_, offer| now < offer.expires_at);
        before - offers.len()
    }

    /// Current number of active offers.
    pub fn offer_count(&self) -> usize {
        self.offers.read().len()
    }

    /// Generate a unique 6-digit code, retrying on collision.
    fn generate_code_inner(
        offers: &HashMap<String, ExchangeOffer>,
    ) -> Result<String, ExchangeError> {
        let mut rng = rand::thread_rng();
        for _ in 0..MAX_CODE_RETRIES {
            let code = format!("{:06}", rng.gen_range(0..1_000_000u32));
            if !offers.contains_key(&code) {
                return Ok(code);
            }
        }
        // If we exhaust retries, the namespace is too crowded
        Err(ExchangeError::TooManyOffers)
    }
}

// INLINE_TEST_REQUIRED: tests access private field `default_ttl`
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ttl() {
        let broker = ExchangeBroker::new(100, 300);
        assert_eq!(broker.default_ttl, Duration::from_secs(300));
    }
}
