// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Usurpation d'identité : un membre qui arrive avec le nom d'un membre
//! protégé est mis en quarantaine (V1).
//!
//! - **Noms protégés** : ceux du propriétaire et des membres **en cache** qui
//!   ont `ADMINISTRATOR` ou `MANAGE_GUILD` (nom d'utilisateur, nom global,
//!   pseudo). La comparaison normalise la casse, les accents et les
//!   substitutions courantes (`0` → `o`, `vv` → `w`…), voir
//!   `anti_impersonation::normalize_name`.
//! - **Jamais appliqué** au propriétaire, à un membre privilégié ni à un
//!   membre de la liste blanche : aucun incident.
//! - **Action** : quarantaine **sans retrait des rôles dangereux et sans
//!   repli timeout** (V1), incident `critical`. Le résultat est terminal si
//!   la quarantaine (ou un timeout) a été appliquée.
//! - Uniquement à l'arrivée : un changement de nom ultérieur n'est pas
//!   analysé.
//! - Les noms sont rendus dans le log par `inline_literal` : ni mention, ni
//!   formatage.

use poise::serenity_prelude::Permissions;

use super::{MemberRef, ModuleResponse, ModuleResult, member_incident, removed_roles_evidence};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{ActionCode, ActionStatus, LogSeverity, SecurityActionOutcome, SecurityEvidence};
use crate::protection::anti_raid::anti_impersonation::{
    AntiImpersonationDetectionInput, AntiImpersonationDetectionResult, detect_impersonation,
};
use crate::protection::quarantine::{QuarantineOutcome, QuarantineRequest};
use crate::protection::shared::{ProtectionModule, audit_reason};

/// Nom du module dans les raisons d'audit log
/// (`FoxSecura Anti-Impersonation: …`).
pub const ANTI_IMPERSONATION_AUDIT_LABEL: &str = "Anti-Impersonation";

/// Quarantaine seule : ni retrait des rôles dangereux, ni repli timeout
/// (V1).
pub const IMPERSONATION_QUARANTINE: QuarantineRequest = QuarantineRequest::ROLE_ONLY;

/// Membre privilégié : `ADMINISTRATOR` ou `MANAGE_GUILD`.
pub fn is_privileged(permissions: Permissions) -> bool {
    permissions.administrator() || permissions.manage_guild()
}

/// Membre connu, candidat à la protection de ses noms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownMember<'a> {
    pub user_id: u64,
    /// `ADMINISTRATOR` ou `MANAGE_GUILD` (voir [`is_privileged`]).
    pub privileged: bool,
    /// Nom d'utilisateur, nom global et pseudo (absents ignorés).
    pub names: [Option<&'a str>; 3],
}

/// Noms protégés : propriétaire et membres privilégiés, sauf le membre qui
/// arrive.
pub fn protected_names<'a>(
    owner_id: Option<u64>,
    joining_user_id: u64,
    members: impl IntoIterator<Item = KnownMember<'a>>,
) -> Vec<&'a str> {
    let mut names: Vec<&str> = members
        .into_iter()
        .filter(|member| member.user_id != joining_user_id)
        .filter(|member| owner_id == Some(member.user_id) || member.privileged)
        .flat_map(|member| member.names.into_iter().flatten())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Raison pour laquelle le membre n'est pas analysé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpersonationExemption {
    GuildOwner,
    Privileged,
    Whitelist,
}

impl ImpersonationExemption {
    /// Propriétaire → membre privilégié → liste blanche.
    pub const fn from_member(
        is_guild_owner: bool,
        is_privileged: bool,
        whitelist_exempt: bool,
    ) -> Option<Self> {
        if is_guild_owner {
            Some(Self::GuildOwner)
        } else if is_privileged {
            Some(Self::Privileged)
        } else if whitelist_exempt {
            Some(Self::Whitelist)
        } else {
            None
        }
    }
}

/// Usurpation détectée ; `None` si le membre est exempté ou si aucun de ses
/// noms ne correspond à un nom protégé.
pub fn plan_impersonation(
    candidate_names: &[&str],
    protected_names: &[&str],
    exemption: Option<ImpersonationExemption>,
) -> Option<AntiImpersonationDetectionResult> {
    if exemption.is_some() {
        return None;
    }
    let detection = detect_impersonation(AntiImpersonationDetectionInput {
        candidate_names,
        protected_names,
    });
    detection.triggered.then_some(detection)
}

/// Raison d'audit log de la quarantaine.
pub fn impersonation_audit_reason() -> String {
    audit_reason(
        ANTI_IMPERSONATION_AUDIT_LABEL,
        "name matches a protected member",
    )
}

/// Incident `critical` et résultat : terminal si le membre est contenu
/// (rôle de quarantaine ou timeout appliqué).
pub fn impersonation_response(
    language: Language,
    member: MemberRef,
    detection: &AntiImpersonationDetectionResult,
    outcome: &QuarantineOutcome,
) -> ModuleResponse {
    let contained = outcome.contained();
    let mut actions = outcome.action_outcomes();
    // Une quarantaine produit toujours au moins une action ; la première
    // sert à construire l'incident.
    let first = if actions.is_empty() {
        quarantine_not_attempted()
    } else {
        actions.remove(0)
    };
    let mut incident = member_incident(
        ProtectionModule::AntiImpersonation.key(),
        LogSeverity::Critical,
        text(language, TextKey::ImpersonationSummary),
        member,
        first,
    );
    incident.actions.extend(actions);
    // Rendus par `inline_literal` : un nom ne peut ni notifier, ni injecter
    // de formatage.
    incident.evidence.extend([
        SecurityEvidence::Text {
            label: text(language, TextKey::ImpersonationEvidenceName).to_owned(),
            value: detection.matched_candidate.clone().unwrap_or_default(),
        },
        SecurityEvidence::Text {
            label: text(language, TextKey::ImpersonationEvidenceProtected).to_owned(),
            value: detection.impersonated_name.clone().unwrap_or_default(),
        },
    ]);
    incident
        .evidence
        .extend(removed_roles_evidence(language, outcome));
    incident.recommendation = Some(
        text(
            language,
            if contained {
                TextKey::ImpersonationRecommendationQuarantined
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

fn quarantine_not_attempted() -> SecurityActionOutcome {
    SecurityActionOutcome {
        action: ActionCode::QuarantineMember,
        status: ActionStatus::Skipped,
        details: None,
        failure_code: None,
    }
}
