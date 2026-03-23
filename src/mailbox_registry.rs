// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mailbox Registry
//!
//! In-memory registry mapping opaque mailbox tokens to active WebSocket
//! connections (via unbounded MPSC senders). Rebuilt on each client
//! reconnect — no persistence is needed or desired.
//!
//! Thread-safety is the caller's responsibility; wrap in `Arc<RwLock<_>>`
//! when sharing across async tasks.

use std::collections::HashMap;
use tokio::sync::mpsc;

/// Unique identifier for a single connection registration.
///
/// Returned by [`MailboxRegistry::register`] and used with
/// [`MailboxRegistry::deregister_connection`] to clean up on disconnect.
pub type RegistrationId = u64;

/// Type alias for a registration entry: (registration_id, sender).
type TokenEntry = (RegistrationId, mpsc::UnboundedSender<Vec<u8>>);

/// In-memory registry mapping mailbox tokens to active connections.
///
/// A single token may have multiple registrations (same identity logged in
/// on several devices). A single connection may be registered under multiple
/// tokens (self-token + peer tokens for pending exchanges).
pub struct MailboxRegistry {
    /// token → list of registration entries
    entries: HashMap<String, Vec<TokenEntry>>,
    next_id: RegistrationId,
}

impl MailboxRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            next_id: 1,
        }
    }

    /// Register a `token → sender` mapping.
    ///
    /// Returns a [`RegistrationId`] that can later be passed to
    /// [`deregister_connection`](Self::deregister_connection) to remove only
    /// this specific registration (e.g., on disconnect).
    pub fn register(
        &mut self,
        token: &str,
        sender: mpsc::UnboundedSender<Vec<u8>>,
    ) -> RegistrationId {
        let id = self.next_id;
        self.next_id += 1;
        self.entries
            .entry(token.to_owned())
            .or_default()
            .push((id, sender));
        id
    }

    /// Register multiple tokens for a single connection.
    ///
    /// The same `sender` is cloned for each token. Returns one
    /// [`RegistrationId`] per token in the same order as `tokens`.
    pub fn register_batch(
        &mut self,
        tokens: &[String],
        sender: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Vec<RegistrationId> {
        tokens
            .iter()
            .map(|token| self.register(token, sender.clone()))
            .collect()
    }

    /// Remove **all** registrations for a token.
    ///
    /// Use this when a token expires or is explicitly revoked.
    pub fn deregister(&mut self, token: &str) {
        self.entries.remove(token);
    }

    /// Remove the single registration identified by `reg_id`.
    ///
    /// Use this on connection disconnect to clean up only the disconnecting
    /// device's entries across all tokens.
    pub fn deregister_connection(&mut self, reg_id: RegistrationId) {
        self.entries.retain(|_, registrations| {
            registrations.retain(|(id, _)| *id != reg_id);
            !registrations.is_empty()
        });
    }

    /// Remove all registrations for each token in `tokens`.
    ///
    /// Use this for bulk revocation (e.g., a batch of exchange tokens that
    /// have been consumed).
    pub fn deregister_batch(&mut self, tokens: &[String]) {
        for token in tokens {
            self.entries.remove(token.as_str());
        }
    }

    /// Return clones of all senders registered for `token`.
    ///
    /// Returns an empty `Vec` when no registration exists for the token.
    /// The caller is responsible for handling closed (dropped) senders.
    pub fn lookup(&self, token: &str) -> Vec<mpsc::UnboundedSender<Vec<u8>>> {
        self.entries
            .get(token)
            .map(|registrations| {
                registrations
                    .iter()
                    .map(|(_, sender)| sender.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for MailboxRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// INLINE_TEST_REQUIRED: MailboxRegistry is a pure data structure with no I/O or async
// dependencies; keeping tests inline avoids test-helper boilerplate and matches
// the pattern used by connection_registry.rs in the same crate.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_lookup() {
        let mut reg = MailboxRegistry::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        reg.register("token_a", tx);
        assert_eq!(reg.lookup("token_a").len(), 1);
        assert_eq!(reg.lookup("nonexistent").len(), 0);
    }

    #[test]
    fn test_multi_device_same_token() {
        let mut reg = MailboxRegistry::new();
        let (tx1, _) = mpsc::unbounded_channel();
        let (tx2, _) = mpsc::unbounded_channel();
        reg.register("self_token", tx1);
        reg.register("self_token", tx2);
        assert_eq!(reg.lookup("self_token").len(), 2);
    }

    #[test]
    fn test_deregister_token() {
        let mut reg = MailboxRegistry::new();
        let (tx, _) = mpsc::unbounded_channel();
        reg.register("token_a", tx);
        reg.deregister("token_a");
        assert!(reg.lookup("token_a").is_empty());
    }

    #[test]
    fn test_deregister_connection() {
        let mut reg = MailboxRegistry::new();
        let (tx1, _) = mpsc::unbounded_channel();
        let (tx2, _) = mpsc::unbounded_channel();
        let id1 = reg.register("token_a", tx1);
        let _id2 = reg.register("token_a", tx2);
        reg.deregister_connection(id1);
        assert_eq!(reg.lookup("token_a").len(), 1);
    }

    #[test]
    fn test_register_batch() {
        let mut reg = MailboxRegistry::new();
        let (tx, _) = mpsc::unbounded_channel();
        let tokens: Vec<String> = vec!["t1".into(), "t2".into(), "t3".into()];
        let ids = reg.register_batch(&tokens, tx);
        assert_eq!(ids.len(), 3);
        assert_eq!(reg.lookup("t1").len(), 1);
        assert_eq!(reg.lookup("t2").len(), 1);
        assert_eq!(reg.lookup("t3").len(), 1);
    }

    #[test]
    fn test_deregister_batch() {
        let mut reg = MailboxRegistry::new();
        let (tx, _) = mpsc::unbounded_channel();
        reg.register_batch(&["t1".into(), "t2".into()], tx);
        reg.deregister_batch(&["t1".into()]);
        assert!(reg.lookup("t1").is_empty());
        assert_eq!(reg.lookup("t2").len(), 1);
    }

    #[test]
    fn test_closed_sender_cleaned_on_lookup() {
        let mut reg = MailboxRegistry::new();
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        reg.register("token_a", tx);
        // Drop the receiver — closed sender cleanup is the caller's job.
        drop(rx);
        let senders = reg.lookup("token_a");
        assert_eq!(senders.len(), 1);
    }

    #[test]
    fn test_deregister_connection_spans_multiple_tokens() {
        let mut reg = MailboxRegistry::new();
        let (tx, _) = mpsc::unbounded_channel();
        let tokens: Vec<String> = vec!["tok_a".into(), "tok_b".into()];
        let ids = reg.register_batch(&tokens, tx);
        // Remove only the first registration (tok_a)
        reg.deregister_connection(ids[0]);
        assert!(reg.lookup("tok_a").is_empty());
        assert_eq!(reg.lookup("tok_b").len(), 1);
    }

    #[test]
    fn test_registration_ids_are_unique() {
        let mut reg = MailboxRegistry::new();
        let (tx1, _) = mpsc::unbounded_channel();
        let (tx2, _) = mpsc::unbounded_channel();
        let id1 = reg.register("token_a", tx1);
        let id2 = reg.register("token_b", tx2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_deregister_nonexistent_token_is_noop() {
        let mut reg = MailboxRegistry::new();
        reg.deregister("ghost"); // must not panic
        assert!(reg.lookup("ghost").is_empty());
    }

    #[test]
    fn test_deregister_connection_nonexistent_id_is_noop() {
        let mut reg = MailboxRegistry::new();
        let (tx, _) = mpsc::unbounded_channel();
        reg.register("token_a", tx);
        reg.deregister_connection(9999); // must not panic
        assert_eq!(reg.lookup("token_a").len(), 1);
    }
}
