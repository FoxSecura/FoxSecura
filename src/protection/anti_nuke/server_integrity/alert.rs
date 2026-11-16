// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Auteur d'une alerte de l'intégrité du serveur (server-edit, vanity,
//! suppression de webhook) : aucune sanction, l'incident porte l'auteur s'il
//! est connu et l'exemption s'il y en a une.

use crate::logs::{ActionCode, ActionStatus, SecurityActionOutcome, SecurityActor};
use crate::protection::shared::exempt_member_action;

/// Auteur d'une alerte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertAuthor {
    /// Auteur corrélé, absent de la liste blanche.
    Resolved(u64),
    /// Auteur corrélé, sur la liste blanche : l'alerte reste visible.
    Exempt(u64),
    /// Aucune entrée d'audit corrélée.
    Unresolved,
}

impl AlertAuthor {
    pub const fn author_id(self) -> Option<u64> {
        match self {
            Self::Resolved(id) | Self::Exempt(id) => Some(id),
            Self::Unresolved => None,
        }
    }

    pub const fn is_exempt(self) -> bool {
        matches!(self, Self::Exempt(_))
    }

    pub fn actor(self) -> Option<SecurityActor> {
        self.author_id().map(|id| SecurityActor {
            user_id: id.to_string(),
            tag: None,
            account_created_at: None,
        })
    }

    /// Résultats d'action : alerte enregistrée, et `ignore_exempt_member`
    /// pour un auteur exempté.
    pub fn alert_actions(self) -> Vec<SecurityActionOutcome> {
        let mut actions = vec![record_alert()];
        if self.is_exempt() {
            actions.push(exempt_member_action());
        }
        actions
    }
}

/// Alerte enregistrée, sans action sur Discord.
pub fn record_alert() -> SecurityActionOutcome {
    SecurityActionOutcome {
        action: ActionCode::RecordAlert,
        status: ActionStatus::Success,
        details: None,
        failure_code: None,
    }
}
