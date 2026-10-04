// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Réponse à une rafale de l'anti-nuke (V1), sans effet Discord.
//!
//! - **Auteur exempté** (liste blanche par identifiant ou par rôle ; le rôle
//!   de quarantaine n'exempte jamais) : incident `warning` avec
//!   `ignore_exempt_member`, **sans confinement**. L'équipe garde la
//!   visibilité ; aucun signal n'est envoyé au mode panique.
//! - Sinon : **quarantaine de l'auteur** avec retrait de ses rôles
//!   dangereux, **sans repli timeout** ([`ANTI_NUKE_QUARANTINE`]). Un auteur
//!   introuvable (parti du serveur, lecture impossible) donne une quarantaine
//!   `skipped` avec le code `executor_unavailable`. Incident `critical`, qui
//!   envoie un signal au mode panique.
//!
//! # Aucune annulation en masse
//!
//! Les bans, expulsions, exclusions et créations déjà faits ne sont **jamais
//! annulés automatiquement** (V1) : un débannissement de masse annulerait
//! aussi les bans légitimes de la fenêtre, une suppression de masse pourrait
//! effacer des salons voulus. L'incident liste la dernière cible ; l'équipe
//! revoit les actions une par une.

use std::time::UNIX_EPOCH;

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, ActionStatus, AffectedResource, AffectedResourceType, FailureCode, LogSeverity,
    LogType, SecurityActionOutcome, SecurityActor, SecurityEvidence, SecurityIncident,
    ThresholdUnit,
};
use crate::protection::quarantine::{
    DEFAULT_QUARANTINE_TIMEOUT, QuarantineOutcome, QuarantineRequest,
};
use crate::protection::shared::{
    AuthorWhitelist, audit_reason, exempt_member_action, is_author_exempt, snowflake_timestamp,
};

use super::audit::NukeAction;
use super::burst::NukeBurst;

/// Nom du module dans les raisons d'audit log
/// (`FoxSecura Anti-Nuke: burst of anti_mass_ban`).
pub const ANTI_NUKE_AUDIT_LABEL: &str = "Anti-Nuke";

/// Quarantaine de l'auteur : retrait des rôles dangereux, sans repli
/// timeout (V1).
pub const ANTI_NUKE_QUARANTINE: QuarantineRequest = QuarantineRequest {
    allow_timeout_fallback: false,
    remove_dangerous_roles: true,
    timeout: DEFAULT_QUARANTINE_TIMEOUT,
};

/// Raison d'audit log de la quarantaine.
pub fn anti_nuke_audit_reason(action: NukeAction) -> String {
    audit_reason(
        ANTI_NUKE_AUDIT_LABEL,
        &format!("burst of {}", action.module().key()),
    )
}

/// Ce que le runtime sait de l'auteur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorFacts<'a> {
    /// L'identifiant de l'auteur est sur la liste blanche.
    pub user_listed: bool,
    pub whitelist_roles: &'a [u64],
    /// Rôles posés par FoxSecura (rôle de quarantaine) : n'exemptent jamais.
    pub ignored_roles: &'a [u64],
    /// Rôles de l'auteur ; `None` s'il est introuvable.
    pub member_roles: Option<&'a [u64]>,
}

/// Réponse décidée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NukeResponsePlan {
    /// Auteur exempté : incident sans confinement.
    IgnoreExempt,
    /// Auteur introuvable : rien à confiner.
    AuthorUnavailable,
    /// Quarantaine de l'auteur.
    Quarantine,
}

/// Décide de la réponse. L'exemption par identifiant vaut même pour un
/// auteur introuvable ; celle par rôle exige ses rôles.
pub fn plan_response(author: AuthorFacts<'_>) -> NukeResponsePlan {
    let exempt = is_author_exempt(
        &AuthorWhitelist {
            user_listed: author.user_listed,
            listed_roles: author.whitelist_roles,
        },
        author.member_roles,
        author.ignored_roles,
    );
    if exempt {
        NukeResponsePlan::IgnoreExempt
    } else if author.member_roles.is_none() {
        NukeResponsePlan::AuthorUnavailable
    } else {
        NukeResponsePlan::Quarantine
    }
}

/// Confinement effectivement tenté.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Containment {
    Exempt,
    AuthorUnavailable { details: String },
    Quarantine(QuarantineOutcome),
}

impl Containment {
    /// L'auteur est contenu (rôle de quarantaine posé).
    pub fn contained(&self) -> bool {
        matches!(self, Self::Quarantine(outcome) if outcome.contained())
    }

    /// Résultats d'action de l'incident.
    pub fn action_outcomes(&self) -> Vec<SecurityActionOutcome> {
        match self {
            Self::Exempt => vec![exempt_member_action()],
            Self::AuthorUnavailable { details } => vec![SecurityActionOutcome {
                action: ActionCode::QuarantineMember,
                status: ActionStatus::Skipped,
                details: Some(details.clone()),
                failure_code: Some(FailureCode::ExecutorUnavailable),
            }],
            Self::Quarantine(outcome) => outcome.action_outcomes(),
        }
    }

    const fn severity(&self) -> LogSeverity {
        match self {
            Self::Exempt => LogSeverity::Warning,
            Self::AuthorUnavailable { .. } | Self::Quarantine(_) => LogSeverity::Critical,
        }
    }
}

/// Rafale à journaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NukeIncidentInput<'a> {
    pub guild_id: u64,
    pub author_id: u64,
    pub burst: NukeBurst,
    /// Dernière cible (entrée qui a déclenché).
    pub target_id: Option<u64>,
    /// Nom de la cible créée ; valeur non fiable, rendue par `inline_literal`.
    pub target_name: Option<&'a str>,
}

/// Type de log de chaque module.
pub const fn log_type(action: NukeAction) -> LogType {
    match action {
        NukeAction::Ban | NukeAction::Kick | NukeAction::Timeout | NukeAction::Unban => {
            LogType::Member
        }
        NukeAction::RoleCreate | NukeAction::RoleGrant => LogType::Role,
        NukeAction::ChannelCreate | NukeAction::EmojiSticker => LogType::Server,
    }
}

const fn resource_type(action: NukeAction) -> AffectedResourceType {
    match action {
        NukeAction::Ban
        | NukeAction::Kick
        | NukeAction::Timeout
        | NukeAction::Unban
        | NukeAction::RoleGrant => AffectedResourceType::Member,
        NukeAction::ChannelCreate => AffectedResourceType::Channel,
        NukeAction::RoleCreate => AffectedResourceType::Role,
        NukeAction::EmojiSticker => AffectedResourceType::Server,
    }
}

/// Incident d'une rafale : `critical` (signal au mode panique) sauf pour un
/// auteur exempté (`warning`).
///
/// Preuves : nombre observé, seuil et fenêtre ; dernière cible (rendue par
/// `inline_literal`) ; rôles dangereux retirés.
pub fn nuke_incident(
    language: Language,
    input: NukeIncidentInput<'_>,
    containment: &Containment,
) -> SecurityIncident {
    let action = input.burst.action;
    let exempt = matches!(containment, Containment::Exempt);
    let mut incident = SecurityIncident::new(
        action.module().key(),
        log_type(action),
        containment.severity(),
        text(
            language,
            if exempt {
                TextKey::AntiNukeExemptSummary
            } else {
                TextKey::AntiNukeSummary
            },
        ),
        containment.action_outcomes(),
    );
    incident.actor = Some(SecurityActor {
        user_id: input.author_id.to_string(),
        tag: None,
        account_created_at: Some(UNIX_EPOCH + snowflake_timestamp(input.author_id)),
    });
    incident.affected_resource = Some(AffectedResource {
        resource_type: resource_type(action),
        id: input
            .target_id
            .or((action == NukeAction::EmojiSticker).then_some(input.guild_id))
            .map(|id| id.to_string()),
        name: input.target_name.map(str::to_owned),
    });
    incident.evidence.push(SecurityEvidence::Threshold {
        observed: input.burst.count as u64,
        threshold: input.burst.threshold as u64,
        window_seconds: Some(input.burst.window.as_secs()),
        unit: ThresholdUnit::Actions,
    });
    if let Some(target) = target_label(input.target_id, input.target_name) {
        incident.evidence.push(SecurityEvidence::Text {
            label: text(language, TextKey::AntiNukeEvidenceTarget).to_owned(),
            value: target,
        });
    }
    if let Containment::Quarantine(outcome) = containment {
        let removed = outcome.removed_roles();
        if !removed.is_empty() {
            incident.evidence.push(SecurityEvidence::Text {
                label: text(language, TextKey::QuarantineEvidenceRemovedRoles).to_owned(),
                value: removed
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
    }
    incident.recommendation = Some(
        text(
            language,
            if exempt {
                TextKey::AntiNukeRecommendationExempt
            } else {
                TextKey::AntiNukeRecommendation
            },
        )
        .to_owned(),
    );
    incident
}

/// Cible lisible : `nom (identifiant)`, l'identifiant seul, ou rien.
fn target_label(target_id: Option<u64>, target_name: Option<&str>) -> Option<String> {
    match (target_name, target_id) {
        (Some(name), Some(id)) => Some(format!("{name} ({id})")),
        (Some(name), None) => Some(name.to_owned()),
        (None, Some(id)) => Some(id.to_string()),
        (None, None) => None,
    }
}

/// Un incident critique de l'anti-nuke envoie un signal au mode panique.
pub fn sends_panic_signal(incident: &SecurityIncident) -> bool {
    incident.severity == LogSeverity::Critical
}
