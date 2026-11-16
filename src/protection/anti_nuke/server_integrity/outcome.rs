// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Résultat d'une action unitaire de l'intégrité du serveur (retour en
//! arrière des permissions, suppression d'un webhook, retrait du rôle
//! plafonné), sans effet Discord.

use crate::logs::{ActionCode, ActionStatus, FailureCode, SecurityActionOutcome};
use crate::protection::quarantine::DiscordFailure;

/// Issue d'une action tentée, ou non tentée d'après le cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityActionResult {
    Applied,
    /// Non tentée : vérification d'après le cache (permission, hiérarchie,
    /// ressource absente, auteur exempté).
    Skipped {
        failure_code: Option<FailureCode>,
        details: String,
    },
    /// Refusée ou échouée côté Discord.
    Failed {
        failure_code: FailureCode,
        details: String,
    },
}

impl IntegrityActionResult {
    pub const fn applied(&self) -> bool {
        matches!(self, Self::Applied)
    }

    /// Classe l'échec d'un appel Discord : `404` → ressource disparue (non
    /// tentée), `403` → permission, `429`/`5xx` → Discord indisponible.
    pub fn from_failure(failure: &DiscordFailure) -> Self {
        let failure_code = failure.failure_code();
        if failure_code == FailureCode::ResourceMissing {
            return Self::Skipped {
                failure_code: Some(failure_code),
                details: failure.details.clone(),
            };
        }
        Self::Failed {
            failure_code,
            details: failure.details.clone(),
        }
    }

    /// Résultat journalisé sous le code d'action donné.
    pub fn action_outcome(&self, action: ActionCode) -> SecurityActionOutcome {
        let (status, failure_code, details) = match self {
            Self::Applied => (ActionStatus::Success, None, None),
            Self::Skipped {
                failure_code,
                details,
            } => (ActionStatus::Skipped, *failure_code, Some(details.clone())),
            Self::Failed {
                failure_code,
                details,
            } => (
                ActionStatus::Failed,
                Some(*failure_code),
                Some(details.clone()),
            ),
        };
        SecurityActionOutcome {
            action,
            status,
            details,
            failure_code,
        }
    }
}
