// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Doubles comptes : un membre qui arrive avec le même nom affiché et le
//! même avatar personnalisé qu'un membre déjà présent (V1).
//!
//! - **Identités tirées du cache des membres uniquement** : nom affiché
//!   (nom global, à défaut nom d'utilisateur) et hash d'avatar. Aucun fetch
//!   complet des membres à l'arrivée : pendant un raid, ce serait la
//!   limitation de débit garantie. Le cache est préchauffé au démarrage pour
//!   les guildes où le module est actif ([`needs_member_prewarm`]) ; un
//!   membre absent du cache n'est simplement pas comparé.
//! - **Jamais appliqué** au propriétaire, à un membre de la liste blanche ni
//!   à un bot (laissé à l'anti-bot) : aucun incident.
//! - **Action** : quarantaine **avec repli timeout** (V1,
//!   [`DOUBLE_ACCOUNT_QUARANTINE`]). Incident `warning` si le membre est
//!   contenu, `critical` sinon, avec la recommandation d'examiner le
//!   doublon. Résultat terminal si le membre est contenu.
//! - Place dans la chaîne : après les nouveaux comptes, avant l'usurpation.

use super::{MemberRef, ModuleResponse, ModuleResult, member_incident, removed_roles_evidence};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{ActionCode, ActionStatus, LogSeverity, SecurityActionOutcome, SecurityEvidence};
use crate::protection::anti_raid::anti_double_account::{
    AccountIdentity, AntiDoubleAccountDetectionResult, AntiDoubleAccountInput,
    detect_likely_double_account,
};
use crate::protection::quarantine::{QuarantineOutcome, QuarantineRequest};
use crate::protection::shared::{ProtectionModule, audit_reason};

/// Nom du module dans les raisons d'audit log
/// (`FoxSecura Anti-Double-Account: …`).
pub const ANTI_DOUBLE_ACCOUNT_AUDIT_LABEL: &str = "Anti-Double-Account";

/// Quarantaine avec repli timeout, sans retrait des rôles dangereux (V1).
pub const DOUBLE_ACCOUNT_QUARANTINE: QuarantineRequest = QuarantineRequest {
    allow_timeout_fallback: true,
    ..QuarantineRequest::ROLE_ONLY
};

/// Nom comparé : nom global, à défaut nom d'utilisateur (le pseudo de
/// serveur est propre à chaque membre et absent à l'arrivée).
pub fn identity_name<'a>(username: &'a str, global_name: Option<&'a str>) -> &'a str {
    global_name
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(username)
}

/// Faut-il demander les membres de la guilde au démarrage ?
///
/// Seulement si le module est actif et que le cache est incomplet : une
/// petite guilde arrive déjà complète avec `GUILD_CREATE`.
pub const fn needs_member_prewarm(enabled: bool, member_count: u64, cached_members: usize) -> bool {
    enabled && (cached_members as u64) < member_count
}

/// Doublon probable ; `None` pour un bot, un membre exempté (propriétaire
/// ou liste blanche) ou sans correspondance.
pub fn plan_double_account(
    candidate: AccountIdentity<'_>,
    cached: &[AccountIdentity<'_>],
    is_bot: bool,
    is_guild_owner: bool,
    whitelist_exempt: bool,
) -> Option<AntiDoubleAccountDetectionResult> {
    if is_bot || is_guild_owner || whitelist_exempt {
        return None;
    }
    let detection = detect_likely_double_account(AntiDoubleAccountInput {
        user_id: candidate.user_id,
        display_name: candidate.display_name,
        avatar_hash: candidate.avatar_hash,
        existing_identities: cached,
    });
    detection.triggered.then_some(detection)
}

/// Raison d'audit log de la quarantaine.
pub fn double_account_audit_reason() -> String {
    audit_reason(
        ANTI_DOUBLE_ACCOUNT_AUDIT_LABEL,
        "likely alternate account of a member",
    )
}

/// Incident (`warning` si contenu, `critical` sinon) et résultat.
pub fn double_account_response(
    language: Language,
    member: MemberRef,
    detection: &AntiDoubleAccountDetectionResult,
    outcome: &QuarantineOutcome,
) -> ModuleResponse {
    let contained = outcome.contained();
    let mut actions = outcome.action_outcomes();
    let first = if actions.is_empty() {
        SecurityActionOutcome {
            action: ActionCode::QuarantineMember,
            status: ActionStatus::Skipped,
            details: None,
            failure_code: None,
        }
    } else {
        actions.remove(0)
    };
    let mut incident = member_incident(
        ProtectionModule::AntiDoubleAccount.key(),
        if contained {
            LogSeverity::Warning
        } else {
            LogSeverity::Critical
        },
        text(language, TextKey::DoubleAccountSummary),
        member,
        first,
    );
    incident.actions.extend(actions);
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::DoubleAccountEvidenceMatch).to_owned(),
        value: detection
            .matched_user_id
            .map(|user_id| user_id.to_string())
            .unwrap_or_default(),
    });
    incident
        .evidence
        .extend(removed_roles_evidence(language, outcome));
    incident.recommendation = Some(
        text(
            language,
            if contained {
                TextKey::DoubleAccountRecommendationReview
            } else {
                TextKey::QuarantineRecommendationFailed
            },
        )
        .to_owned(),
    );

    ModuleResponse {
        result: ModuleResult {
            detected: true,
            action_applied: contained,
            terminal: contained,
        },
        incident,
    }
}
