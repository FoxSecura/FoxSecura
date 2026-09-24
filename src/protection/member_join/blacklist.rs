// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Liste noire : un utilisateur listé est banni dès son arrivée.
//!
//! - Le résultat est **terminal même si le ban échoue** (V1) : la liste noire
//!   reste la référence, aucun autre module ne s'exécute pour ce membre.
//! - Appliquée seulement à l'arrivée : inscrire un membre déjà présent ne le
//!   bannit pas.
//! - Les listes blanche et noire s'excluent (base de données, migration 6).

use std::time::Duration;

use super::{MemberRef, ModuleResponse, ModuleResult, member_incident};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{LogSeverity, SecurityEvidence};
use crate::protection::shared::{SanctionKind, SanctionOutcome, audit_reason};

/// Clé du module dans les incidents.
pub const BLACKLIST_MODULE: &str = "blacklist";

/// Nom du module dans les raisons d'audit log (`FoxSecura Blacklist: …`).
pub const BLACKLIST_AUDIT_LABEL: &str = "Blacklist";

/// Ban appliqué : sans purge, le membre vient d'arriver.
pub const BLACKLIST_BAN: SanctionKind = SanctionKind::Ban {
    purge: Duration::ZERO,
};

/// Raison d'audit log du ban.
pub fn blacklist_audit_reason() -> String {
    audit_reason(BLACKLIST_AUDIT_LABEL, "user on the guild blacklist")
}

/// Résultat et incident, que le ban ait réussi ou non.
///
/// Incident `critical` dans tous les cas : un utilisateur explicitement
/// refusé a tenté de rejoindre le serveur.
pub fn blacklist_response(
    language: Language,
    member: MemberRef,
    outcome: &SanctionOutcome,
) -> ModuleResponse {
    let mut incident = member_incident(
        BLACKLIST_MODULE,
        LogSeverity::Critical,
        text(language, TextKey::BlacklistSummary),
        member,
        outcome.action_outcome(BLACKLIST_BAN),
    );
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::BlacklistEvidenceEntry).to_owned(),
        value: member.user_id.to_string(),
    });
    incident.recommendation = Some(
        text(
            language,
            if outcome.is_applied() {
                TextKey::BlacklistRecommendationBanned
            } else {
                TextKey::MemberRecommendationCheckBanHierarchy
            },
        )
        .to_owned(),
    );

    ModuleResponse {
        result: ModuleResult {
            detected: true,
            action_applied: outcome.is_applied(),
            terminal: true,
        },
        incident,
    }
}
