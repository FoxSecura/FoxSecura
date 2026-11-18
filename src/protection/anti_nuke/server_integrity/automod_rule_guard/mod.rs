// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Garde des règles AutoMod natives de FoxSecura (module `automod_rule_guard`,
//! désactivé par défaut), sans effet Discord.
//!
//! Sur les entrées d'audit `AutoModRuleUpdate` (141) et `AutoModRuleDelete`
//! (142) retenues par le socle — propriétaire du serveur et FoxSecura
//! lui-même ignorés, donc **aucune boucle** avec nos propres réconciliations :
//!
//! - altération = **suppression** d'une règle FoxSecura, ou **modification
//!   qui la désactive** (`enabled` passe à `false`) ; une modification qui
//!   laisse la règle active est ignorée ;
//! - nom considéré : l'**ancien** nom s'il figure dans les changements, sinon
//!   le nom actuel (relu sur Discord pour une modification). Un renommage et
//!   une désactivation dans la même édition sont donc détectés (correctif par
//!   rapport à la V1) ; une règle sans le préfixe `FoxSecura •` est ignorée ;
//! - module lié à la règle désactivé : rien à protéger, ignoré ;
//! - sinon : **seule cette règle** est réconciliée (verrou de la guilde,
//!   `create_when_disabled = false`), même si l'auteur est sur la liste
//!   blanche — c'est la restauration d'une ressource protégée, pas une
//!   sanction. **Aucune sanction** de l'auteur (parité V1).
//!
//! Incident `critical` « AutoMod Rule Guard » : auteur, nom de la règle
//! (rendu par `inline_literal`), preuve `deleted` / `disabled`, action
//! `restore_automod_rule` réussie ou échouée (`missing_permission` sans
//! `MANAGE_GUILD`).
//!
//! # Intents
//!
//! Rien de nouveau : les entrées d'audit arrivent par `GUILD_MODERATION`
//! (`GUILD_AUDIT_LOG_ENTRY_CREATE`, avec `VIEW_AUDIT_LOG`), et la règle est
//! relue et restaurée par l'HTTP. `AUTO_MODERATION_CONFIGURATION` n'est pas
//! nécessaire (ses événements ne portent pas l'auteur).

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, FailureCode, LogSeverity, LogType, SecurityActor, SecurityEvidence,
    SecurityIncident,
};
use crate::protection::anti_nuke::audit::AuditAction;
use crate::protection::automod::native_rules::{
    AUTOMOD_RULE_PREFIX, AutoModRuleKey, AutoModRuleSkipReason, ReconcileOutcome, RuleSyncStatus,
};
use crate::protection::shared::{ModuleSet, ProtectionModule};

use super::outcome::IntegrityActionResult;

/// Altération d'une règle FoxSecura.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAlteration {
    Deleted,
    Disabled,
}

impl RuleAlteration {
    /// Preuve journalisée.
    pub const fn evidence(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::Disabled => "disabled",
        }
    }
}

/// Altération portée par une entrée ; `None` si l'entrée n'en est pas une
/// (création, modification qui laisse la règle active).
pub const fn detect_alteration(
    action: AuditAction,
    enabled_after: Option<bool>,
) -> Option<RuleAlteration> {
    match (action, enabled_after) {
        (AuditAction::AutoModRuleDelete, _) => Some(RuleAlteration::Deleted),
        (AuditAction::AutoModRuleUpdate, Some(false)) => Some(RuleAlteration::Disabled),
        _ => None,
    }
}

/// Nom à considérer : l'ancien s'il est connu (règle supprimée ou renommée),
/// sinon le nom actuel.
pub fn considered_rule_name<'a>(
    previous_name: Option<&'a str>,
    current_name: Option<&'a str>,
) -> Option<&'a str> {
    previous_name.or(current_name)
}

/// Raison pour laquelle la garde ne fait rien.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardIgnore {
    /// Module de la garde désactivé.
    GuardDisabled,
    /// Création, ou modification qui laisse la règle active.
    NotAnAlteration,
    /// Nom introuvable (règle relue impossible).
    UnknownName,
    /// Règle sans le préfixe FoxSecura.
    ForeignRule,
    /// Préfixe FoxSecura mais aucune des six règles.
    UnknownFoxSecuraRule,
    /// Interrupteur lié désactivé : rien à protéger.
    LinkedSwitchDisabled,
}

/// Réponse décidée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardPlan {
    Ignore(GuardIgnore),
    /// Réconcilier cette règle seule. `author_exempt` n'est que journalisé :
    /// la restauration a lieu même pour la liste blanche, sans sanction.
    Restore {
        key: AutoModRuleKey,
        alteration: RuleAlteration,
        author_exempt: bool,
    },
}

/// Ce que le runtime sait de l'entrée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardInput<'a> {
    pub action: AuditAction,
    pub enabled_after: Option<bool>,
    /// Nom considéré ([`considered_rule_name`]).
    pub rule_name: Option<&'a str>,
    pub modules: ModuleSet,
    pub anti_spam_enabled: bool,
    pub author_exempt: bool,
}

/// Décide de la réponse de la garde.
pub fn plan_rule_guard(input: GuardInput<'_>) -> GuardPlan {
    if !input.modules.contains(ProtectionModule::AutoModRuleGuard) {
        return GuardPlan::Ignore(GuardIgnore::GuardDisabled);
    }
    let Some(alteration) = detect_alteration(input.action, input.enabled_after) else {
        return GuardPlan::Ignore(GuardIgnore::NotAnAlteration);
    };
    let Some(name) = input.rule_name else {
        return GuardPlan::Ignore(GuardIgnore::UnknownName);
    };
    if !name.starts_with(AUTOMOD_RULE_PREFIX) {
        return GuardPlan::Ignore(GuardIgnore::ForeignRule);
    }
    let Some(key) = AutoModRuleKey::from_rule_name(name) else {
        return GuardPlan::Ignore(GuardIgnore::UnknownFoxSecuraRule);
    };
    if !key.is_switched_on(input.modules, input.anti_spam_enabled) {
        return GuardPlan::Ignore(GuardIgnore::LinkedSwitchDisabled);
    }
    GuardPlan::Restore {
        key,
        alteration,
        author_exempt: input.author_exempt,
    }
}

/// Résultat non tenté faute de `MANAGE_GUILD` (d'après le cache).
pub fn missing_manage_guild() -> IntegrityActionResult {
    IntegrityActionResult::Skipped {
        failure_code: Some(FailureCode::MissingPermission),
        details: "MANAGE_GUILD".to_owned(),
    }
}

/// Résultat de la restauration d'après la réconciliation de la règle.
pub fn restore_result(outcome: &ReconcileOutcome) -> IntegrityActionResult {
    let report = match outcome {
        ReconcileOutcome::MissingPermission => return missing_manage_guild(),
        ReconcileOutcome::ReadFailed(failure) => {
            return IntegrityActionResult::from_failure(failure);
        }
        ReconcileOutcome::Synced(reports) => reports.first(),
    };
    match report.map(|report| &report.status) {
        Some(RuleSyncStatus::Created { .. } | RuleSyncStatus::Updated { .. }) => {
            IntegrityActionResult::Applied
        }
        Some(RuleSyncStatus::Failed(failure)) => IntegrityActionResult::from_failure(failure),
        Some(RuleSyncStatus::Skipped(reason)) => IntegrityActionResult::Skipped {
            failure_code: None,
            details: match reason {
                AutoModRuleSkipReason::NoKeywords => "no_keywords",
                AutoModRuleSkipReason::KeywordPresetConflict => "keyword_preset_conflict",
                AutoModRuleSkipReason::TriggerTypeConflict => "trigger_type_conflict",
            }
            .to_owned(),
        },
        Some(RuleSyncStatus::Missing) | None => IntegrityActionResult::Skipped {
            failure_code: None,
            details: "rule_not_restored".to_owned(),
        },
    }
}

/// Altération à journaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleGuardIncidentInput<'a> {
    pub author_id: u64,
    /// Nom de la règle ; valeur venue de Discord, rendue par `inline_literal`.
    pub rule_name: &'a str,
    pub alteration: RuleAlteration,
    pub author_exempt: bool,
}

/// Incident `critical` de la garde.
pub fn rule_guard_incident(
    language: Language,
    input: RuleGuardIncidentInput<'_>,
    restore: &IntegrityActionResult,
) -> SecurityIncident {
    let mut incident = SecurityIncident::new(
        ProtectionModule::AutoModRuleGuard.key(),
        LogType::Server,
        LogSeverity::Critical,
        text(
            language,
            match input.alteration {
                RuleAlteration::Deleted => TextKey::AutoModRuleGuardDeletedSummary,
                RuleAlteration::Disabled => TextKey::AutoModRuleGuardDisabledSummary,
            },
        ),
        vec![restore.action_outcome(ActionCode::RestoreAutomodRule)],
    );
    incident.actor = Some(SecurityActor {
        user_id: input.author_id.to_string(),
        tag: None,
        account_created_at: None,
    });
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::AutoModRuleGuardEvidenceRule).to_owned(),
        value: input.rule_name.to_owned(),
    });
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::AutoModRuleGuardEvidenceChange).to_owned(),
        value: input.alteration.evidence().to_owned(),
    });
    if input.author_exempt {
        incident.evidence.push(SecurityEvidence::Text {
            label: text(language, TextKey::AutoModRuleGuardEvidenceExempt).to_owned(),
            value: "true".to_owned(),
        });
    }
    incident.recommendation = Some(
        text(
            language,
            if restore.applied() {
                TextKey::AutoModRuleGuardRecommendation
            } else {
                TextKey::AutoModRuleGuardRecommendationFailed
            },
        )
        .to_owned(),
    );
    incident
}
