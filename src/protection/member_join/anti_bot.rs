// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-bot : un bot qui rejoint le serveur sans figurer sur la liste blanche
//! (par identifiant) est expulsé.
//!
//! - Bot de la liste blanche : incident `info`, aucune action.
//! - Expulsion réussie : incident `warning`, résultat terminal.
//! - Expulsion non appliquée (`KICK_MEMBERS` absent, hiérarchie, refus de
//!   Discord) : incident `critical`, le bot est peut-être encore présent avec
//!   ses permissions.

use super::{MemberRef, ModuleResponse, ModuleResult, member_incident};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{LogSeverity, SecurityEvidence};
use crate::protection::anti_raid::anti_bot::detect_bot_join;
use crate::protection::shared::{
    ProtectionModule, SanctionKind, SanctionOutcome, audit_reason, exempt_member_action,
};

/// Nom du module dans les raisons d'audit log (`FoxSecura Anti-Bot: …`).
pub const ANTI_BOT_AUDIT_LABEL: &str = "Anti-Bot";

/// Sanction d'un bot non autorisé.
pub const ANTI_BOT_SANCTION: SanctionKind = SanctionKind::Kick;

/// Suite donnée à une arrivée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiBotPlan {
    /// Compte utilisateur : l'anti-bot ne fait rien.
    NotABot,
    /// Bot dont l'identifiant est sur la liste blanche.
    Authorized,
    /// Bot non autorisé : expulsion.
    Kick,
}

/// Choisit la suite. Seule l'exemption par identifiant compte : un bot n'a
/// pas encore de rôle attribué par l'équipe à son arrivée.
pub fn plan_anti_bot(is_bot: bool, user_whitelisted: bool) -> AntiBotPlan {
    if !detect_bot_join(is_bot).triggered {
        AntiBotPlan::NotABot
    } else if user_whitelisted {
        AntiBotPlan::Authorized
    } else {
        AntiBotPlan::Kick
    }
}

/// Raison d'audit log de l'expulsion.
pub fn anti_bot_audit_reason() -> String {
    audit_reason(ANTI_BOT_AUDIT_LABEL, "unauthorized bot join")
}

/// Bot autorisé : incident `info`, la chaîne continue.
pub fn authorized_bot_response(language: Language, member: MemberRef) -> ModuleResponse {
    let mut incident = member_incident(
        ProtectionModule::AntiBot.key(),
        LogSeverity::Info,
        text(language, TextKey::AntiBotSummaryAuthorized),
        member,
        exempt_member_action(),
    );
    incident.evidence.push(bot_evidence(language));

    ModuleResponse {
        result: ModuleResult {
            detected: true,
            action_applied: false,
            terminal: false,
        },
        incident,
    }
}

/// Bot non autorisé : résultat de l'expulsion.
pub fn anti_bot_response(
    language: Language,
    member: MemberRef,
    outcome: &SanctionOutcome,
) -> ModuleResponse {
    let kicked = outcome.is_applied();
    let mut incident = member_incident(
        ProtectionModule::AntiBot.key(),
        if kicked {
            LogSeverity::Warning
        } else {
            LogSeverity::Critical
        },
        text(language, TextKey::AntiBotSummaryUnauthorized),
        member,
        outcome.action_outcome(ANTI_BOT_SANCTION),
    );
    incident.evidence.push(bot_evidence(language));
    incident.recommendation = Some(
        text(
            language,
            if kicked {
                TextKey::AntiBotRecommendationKicked
            } else {
                TextKey::AntiBotRecommendationCheckKick
            },
        )
        .to_owned(),
    );

    ModuleResponse {
        result: ModuleResult {
            detected: true,
            action_applied: kicked,
            terminal: kicked,
        },
        incident,
    }
}

fn bot_evidence(language: Language) -> SecurityEvidence {
    SecurityEvidence::Text {
        label: text(language, TextKey::AntiBotEvidenceAccount).to_owned(),
        value: "bot".to_owned(),
    }
}
