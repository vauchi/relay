// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The error a storage write reports when the database refuses it.

/// A write the database did not accept (full disk, read-only file, lock).
/// Carries the backend's message for logs only; callers answer clients with
/// a generic error (DC-05).
#[derive(Debug)]
pub struct StorageWriteError(String);

impl std::fmt::Display for StorageWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage write failed: {}", self.0)
    }
}

impl std::error::Error for StorageWriteError {}

impl From<rusqlite::Error> for StorageWriteError {
    fn from(e: rusqlite::Error) -> Self {
        Self(e.to_string())
    }
}
