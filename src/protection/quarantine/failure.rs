// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Échec d'un appel Discord de la quarantaine, réduit à ce qui sert à le
//! classer.

use crate::logs::FailureCode;

/// Code JSON de Discord : rôle inconnu.
pub const UNKNOWN_ROLE: i64 = 10011;
/// Code JSON de Discord : membre inconnu.
pub const UNKNOWN_MEMBER: i64 = 10007;
/// Code JSON de Discord : salon inconnu.
pub const UNKNOWN_CHANNEL: i64 = 10003;

/// Réponse d'erreur de l'API, ou erreur locale (`status` à `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscordFailure {
    pub status: Option<u16>,
    /// Code JSON de Discord (`10011`, `50013`…), s'il est connu.
    pub code: Option<i64>,
    pub details: String,
}

impl DiscordFailure {
    pub fn new(status: Option<u16>, code: Option<i64>, details: impl Into<String>) -> Self {
        Self {
            status,
            code,
            details: details.into(),
        }
    }

    /// `404` avec le code JSON attendu.
    pub fn is_unknown(&self, code: i64) -> bool {
        self.status == Some(404) && self.code == Some(code)
    }

    /// Classement commun aux sanctions : `403` → permission, `404` →
    /// ressource disparue, `429`, `5xx` ou pas de réponse → Discord
    /// indisponible.
    pub fn failure_code(&self) -> FailureCode {
        match self.status {
            Some(403) => FailureCode::MissingPermission,
            Some(404) => FailureCode::ResourceMissing,
            Some(429 | 500..=599) | None => FailureCode::DiscordUnavailable,
            Some(_) => FailureCode::Unknown,
        }
    }
}
