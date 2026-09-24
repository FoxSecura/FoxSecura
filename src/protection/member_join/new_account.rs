// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Nouveaux comptes : un compte plus jeune que l'âge minimal de la guilde
//! (7 jours par défaut, 1 à 365) est banni à son arrivée, avec une purge de
//! 7 jours de messages.
//!
//! - Âge = date d'arrivée − date de création déduite du snowflake, en jours
//!   entiers : un compte d'exactement 7 jours passe un minimum de 7 jours.
//! - Propriétaire ou membre de la liste blanche : incident `warning` avec
//!   `ignore_exempt_member`, aucune action.
//! - Les bots sont laissés à l'anti-bot : un bot autorisé est souvent un
//!   compte récent et ne doit pas être banni par ce module.
//! - Un faux positif bannit un nouveau membre légitime : l'incident rappelle
//!   de vérifier chaque ban.
//!
//! # Repli
//!
//! Un ban non appliqué déclenche une **quarantaine de repli avec repli
//! timeout** (V1, [`NEW_ACCOUNT_FALLBACK`]) : rôle de quarantaine et verrou
//! des salons, ou timeout de 10 minutes si le rôle ne peut pas être posé.
//! L'incident reprend l'action de ban en échec, puis les actions de la
//! quarantaine ; il reste `critical` (le ban a échoué) et devient terminal si
//! le membre est contenu.

use std::time::Duration;

use super::{MemberRef, ModuleResponse, ModuleResult, member_incident, removed_roles_evidence};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{LogSeverity, SecurityActionOutcome, SecurityEvidence};
use crate::protection::anti_raid::anti_new_account::{
    AntiNewAccountDetectionResult, AntiNewAccountInput, detect_new_account,
};
use crate::protection::quarantine::{QuarantineOutcome, QuarantineRequest};
use crate::protection::shared::{
    ProtectionModule, SanctionKind, SanctionOutcome, audit_reason, exempt_member_action,
};

/// Nom du module dans les raisons d'audit log
/// (`FoxSecura Anti-New-Account: …`).
pub const ANTI_NEW_ACCOUNT_AUDIT_LABEL: &str = "Anti-New-Account";

/// Ban d'un compte trop récent, avec purge de 7 jours (V1).
pub const NEW_ACCOUNT_BAN: SanctionKind = SanctionKind::Ban {
    purge: Duration::from_secs(7 * 24 * 60 * 60),
};

/// Quarantaine de repli d'un ban non appliqué : avec repli timeout, sans
/// retrait des rôles dangereux (V1).
pub const NEW_ACCOUNT_FALLBACK: QuarantineRequest = QuarantineRequest {
    allow_timeout_fallback: true,
    ..QuarantineRequest::ROLE_ONLY
};

/// Raison pour laquelle un compte trop récent n'est pas banni.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewAccountExemption {
    GuildOwner,
    Whitelist,
}

impl NewAccountExemption {
    /// Le propriétaire passe avant la liste blanche.
    pub const fn from_member(is_guild_owner: bool, whitelist_exempt: bool) -> Option<Self> {
        if is_guild_owner {
            Some(Self::GuildOwner)
        } else if whitelist_exempt {
            Some(Self::Whitelist)
        } else {
            None
        }
    }

    const fn details(self) -> &'static str {
        match self {
            Self::GuildOwner => "guild_owner",
            Self::Whitelist => "whitelist",
        }
    }
}

/// Suite donnée à une arrivée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewAccountPlan {
    /// Compte assez ancien, ou bot : rien à faire.
    Allowed,
    /// Compte trop récent mais exempté : incident sans action.
    Exempt(NewAccountExemption),
    /// Compte trop récent : ban.
    Ban,
}

/// Détection et suite donnée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewAccountCheck {
    pub detection: AntiNewAccountDetectionResult,
    pub plan: NewAccountPlan,
}

/// Mesure l'âge du compte et choisit la suite.
pub fn plan_new_account(
    input: AntiNewAccountInput,
    is_bot: bool,
    exemption: Option<NewAccountExemption>,
) -> NewAccountCheck {
    let detection = detect_new_account(input);
    let plan = match (detection.triggered && !is_bot, exemption) {
        (false, _) => NewAccountPlan::Allowed,
        (true, Some(exemption)) => NewAccountPlan::Exempt(exemption),
        (true, None) => NewAccountPlan::Ban,
    };
    NewAccountCheck { detection, plan }
}

/// Raison d'audit log du ban.
pub fn new_account_audit_reason() -> String {
    audit_reason(ANTI_NEW_ACCOUNT_AUDIT_LABEL, "account age below threshold")
}

/// Compte trop récent mais exempté : incident `warning`, la chaîne continue.
pub fn exempt_new_account_response(
    language: Language,
    member: MemberRef,
    detection: &AntiNewAccountDetectionResult,
    exemption: NewAccountExemption,
) -> ModuleResponse {
    let mut incident = member_incident(
        ProtectionModule::AntiNewAccount.key(),
        LogSeverity::Warning,
        text(language, TextKey::NewAccountSummary),
        member,
        SecurityActionOutcome {
            details: Some(exemption.details().to_owned()),
            ..exempt_member_action()
        },
    );
    incident.evidence.push(age_evidence(detection));
    incident.recommendation =
        Some(text(language, TextKey::NewAccountRecommendationExempt).to_owned());

    ModuleResponse {
        result: ModuleResult {
            detected: true,
            action_applied: false,
            terminal: false,
        },
        incident,
    }
}

/// Compte trop récent : résultat du ban, puis de la quarantaine de repli.
///
/// Ban appliqué : incident `warning`, résultat terminal, `fallback` ignoré.
/// Ban non appliqué : incident `critical` ; les actions de la quarantaine de
/// repli suivent celle du ban, et le résultat est terminal si le membre est
/// contenu (rôle de quarantaine ou timeout). `fallback` à `None` : repli non
/// exécuté (le runtime l'exécute toujours après un ban non appliqué).
pub fn new_account_ban_response(
    language: Language,
    member: MemberRef,
    detection: &AntiNewAccountDetectionResult,
    outcome: &SanctionOutcome,
    fallback: Option<&QuarantineOutcome>,
) -> ModuleResponse {
    let banned = outcome.is_applied();
    let mut incident = member_incident(
        ProtectionModule::AntiNewAccount.key(),
        if banned {
            LogSeverity::Warning
        } else {
            LogSeverity::Critical
        },
        text(language, TextKey::NewAccountSummary),
        member,
        outcome.action_outcome(NEW_ACCOUNT_BAN),
    );
    incident.evidence.push(age_evidence(detection));

    let fallback = fallback.filter(|_| !banned);
    let contained = fallback.is_some_and(QuarantineOutcome::contained);
    if let Some(fallback) = fallback {
        incident.actions.extend(fallback.action_outcomes());
        incident
            .evidence
            .extend(removed_roles_evidence(language, fallback));
    }
    let recommendation = if banned {
        TextKey::NewAccountRecommendationBanned
    } else if contained {
        TextKey::NewAccountRecommendationQuarantined
    } else {
        TextKey::NewAccountRecommendationBanFailed
    };
    incident.recommendation = Some(text(language, recommendation).to_owned());

    ModuleResponse {
        result: ModuleResult {
            detected: true,
            action_applied: banned || contained,
            terminal: banned || contained,
        },
        incident,
    }
}

fn age_evidence(detection: &AntiNewAccountDetectionResult) -> SecurityEvidence {
    SecurityEvidence::AccountAge {
        age_seconds: detection.account_age.as_secs(),
        minimum_age_seconds: detection.min_age_days.saturating_mul(24 * 60 * 60),
    }
}
