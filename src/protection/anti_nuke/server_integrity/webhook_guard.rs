// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Surveillance des webhooks (V1), sans effet Discord.
//!
//! Sur les entrées d'audit `WebhookCreate`, `WebhookUpdate` et
//! `WebhookDelete` retenues par le socle : un auteur non autorisé (ni le bot,
//! ni le propriétaire — gardes du socle —, ni un membre de la liste blanche)
//! qui crée ou modifie un webhook voit ce webhook **supprimé** ; la
//! suppression d'un webhook donne une alerte seule (`record_alert`).
//! Sévérité `warning`, `critical` si le webhook n'a pas pu être supprimé
//! (il reste actif). Permission requise : `MANAGE_WEBHOOKS`.
//!
//! # Différence avec la V1
//!
//! La V1 relisait le journal d'audit après un événement `WebhooksUpdate` et
//! alertait « auteur non résolu » quand la corrélation échouait. La V2
//! consomme l'entrée poussée par Discord, qui porte l'auteur : une entrée
//! sans auteur est écartée par le socle et **n'est pas traitée** (aucune
//! alerte « non résolu »).

use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, AffectedResource, AffectedResourceType, FailureCode, LogSeverity, LogType,
    SecurityActor, SecurityEvidence, SecurityIncident,
};
use crate::protection::anti_nuke::audit::AuditAction;
use crate::protection::anti_raid::webhook_watch::is_unauthorized_webhook_executor;
use crate::protection::shared::{ProtectionModule, audit_reason};

use super::alert::record_alert;
use super::outcome::IntegrityActionResult;

/// Nom du module dans les raisons d'audit log.
pub const WEBHOOK_WATCH_AUDIT_LABEL: &str = "Webhook Watch";

/// Raison d'audit log de la suppression d'un webhook non autorisé.
pub fn webhook_removal_reason() -> String {
    audit_reason(WEBHOOK_WATCH_AUDIT_LABEL, "unauthorized webhook removed")
}

/// Changement de webhook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookChange {
    Created,
    Updated,
    Deleted,
}

impl WebhookChange {
    /// Changement d'une entrée d'audit ; `None` hors webhooks.
    pub const fn from_audit(action: AuditAction) -> Option<Self> {
        match action {
            AuditAction::WebhookCreate => Some(Self::Created),
            AuditAction::WebhookUpdate => Some(Self::Updated),
            AuditAction::WebhookDelete => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// Réponse décidée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookPlan {
    /// Auteur autorisé : rien.
    Ignore,
    /// Création ou modification non autorisée : supprimer le webhook.
    Remove,
    /// Suppression non autorisée : alerte seule.
    Alert,
}

/// Décide de la réponse. `bot_id` et `owner_id` doublent les gardes du socle.
pub fn plan_webhook_response(
    change: WebhookChange,
    author_id: u64,
    bot_id: u64,
    owner_id: Option<u64>,
    whitelisted: bool,
) -> WebhookPlan {
    let owner = owner_id.unwrap_or(0);
    if owner_id == Some(author_id)
        || !is_unauthorized_webhook_executor(Some(author_id), Some(bot_id), owner, whitelisted)
    {
        return WebhookPlan::Ignore;
    }
    match change {
        WebhookChange::Created | WebhookChange::Updated => WebhookPlan::Remove,
        WebhookChange::Deleted => WebhookPlan::Alert,
    }
}

/// Résultat non tenté faute de `MANAGE_WEBHOOKS` (d'après le cache).
pub fn missing_manage_webhooks() -> IntegrityActionResult {
    IntegrityActionResult::Skipped {
        failure_code: Some(FailureCode::MissingPermission),
        details: "MANAGE_WEBHOOKS".to_owned(),
    }
}

/// Le webhook est-il encore actif après la réponse ?
fn webhook_left_active(removal: &IntegrityActionResult) -> bool {
    match removal {
        IntegrityActionResult::Applied => false,
        IntegrityActionResult::Skipped { failure_code, .. } => {
            *failure_code != Some(FailureCode::ResourceMissing)
        }
        IntegrityActionResult::Failed { .. } => true,
    }
}

/// Changement à journaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookIncidentInput<'a> {
    pub change: WebhookChange,
    pub author_id: u64,
    pub webhook_id: Option<u64>,
    /// Nom du webhook ; valeur non fiable, rendue par `inline_literal`.
    pub webhook_name: Option<&'a str>,
}

/// Incident `warning`, `critical` si un webhook non autorisé reste actif.
///
/// `removal` : résultat de la suppression ; `None` pour une alerte seule
/// (suppression de webhook).
pub fn webhook_incident(
    language: Language,
    input: WebhookIncidentInput<'_>,
    removal: Option<&IntegrityActionResult>,
) -> SecurityIncident {
    let (actions, critical) = match removal {
        Some(removal) => (
            vec![removal.action_outcome(ActionCode::RemoveWebhook)],
            webhook_left_active(removal),
        ),
        None => (vec![record_alert()], false),
    };
    let summary = match input.change {
        WebhookChange::Created => TextKey::WebhookWatchCreatedSummary,
        WebhookChange::Updated => TextKey::WebhookWatchUpdatedSummary,
        WebhookChange::Deleted => TextKey::WebhookWatchDeletedSummary,
    };
    let mut incident = SecurityIncident::new(
        ProtectionModule::WebhookWatch.key(),
        LogType::Server,
        if critical {
            LogSeverity::Critical
        } else {
            LogSeverity::Warning
        },
        text(language, summary),
        actions,
    );
    incident.actor = Some(SecurityActor {
        user_id: input.author_id.to_string(),
        tag: None,
        account_created_at: None,
    });
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Webhook,
        id: input.webhook_id.map(|id| id.to_string()),
        name: input.webhook_name.map(str::to_owned),
    });
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::WebhookWatchEvidenceWebhook).to_owned(),
        value: match (input.webhook_name, input.webhook_id) {
            (Some(name), Some(id)) => format!("{name} ({id})"),
            (Some(name), None) => name.to_owned(),
            (None, Some(id)) => id.to_string(),
            (None, None) => "?".to_owned(),
        },
    });
    incident.recommendation = Some(
        text(
            language,
            if critical {
                TextKey::WebhookWatchRecommendationFailed
            } else {
                TextKey::WebhookWatchRecommendation
            },
        )
        .to_owned(),
    );
    incident
}
