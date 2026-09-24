// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Plan d'action et incident de l'anti-spam, sans aucun effet Discord.

use super::MessageFloodDetection;
use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, ActionStatus, AffectedResource, AffectedResourceType, FailureCode, LogSeverity,
    LogType, SecurityActionOutcome, SecurityActor, SecurityEvidence, SecurityIncident,
    SecurityLocation, ThresholdUnit,
};
use crate::protection::shared::GuildMessage;

/// Nom du module inscrit dans les incidents.
pub const MESSAGE_FLOOD_MODULE: &str = "anti_spam";

/// Action à exécuter : supprimer le message qui a atteint le seuil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteMessagePlan {
    pub guild_id: u64,
    pub channel_id: u64,
    pub message_id: u64,
}

/// Retourne l'action à exécuter si la détection a déclenché la protection.
pub fn plan_response(
    message: &GuildMessage,
    detection: &MessageFloodDetection,
) -> Option<DeleteMessagePlan> {
    detection.is_triggered().then_some(DeleteMessagePlan {
        guild_id: message.guild_id,
        channel_id: message.channel_id,
        message_id: message.message_id,
    })
}

/// Résultat de la suppression du message déclencheur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteMessageOutcome {
    Deleted,
    /// Le bot n'a pas la permission `MANAGE_MESSAGES` dans le salon.
    NotDeletable,
    /// L'API Discord a refusé ou échoué pour une autre raison.
    Failed {
        failure_code: FailureCode,
        details: String,
    },
}

impl DeleteMessageOutcome {
    /// Classe un échec HTTP de suppression.
    ///
    /// `403` signifie que le bot ne peut pas supprimer le message dans ce salon.
    pub fn from_http_status(status: u16, details: impl Into<String>) -> Self {
        let failure_code = match status {
            403 => return Self::NotDeletable,
            404 => FailureCode::ResourceMissing,
            429 | 500..=599 => FailureCode::DiscordUnavailable,
            _ => FailureCode::Unknown,
        };

        Self::Failed {
            failure_code,
            details: details.into(),
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::NotDeletable => "not_deletable",
            Self::Failed { .. } => "failed",
        }
    }

    pub fn severity(&self) -> LogSeverity {
        match self {
            Self::Deleted => LogSeverity::Warning,
            Self::NotDeletable | Self::Failed { .. } => LogSeverity::Critical,
        }
    }

    pub fn action_outcome(&self) -> SecurityActionOutcome {
        let (status, failure_code, details) = match self {
            Self::Deleted => (ActionStatus::Success, None, None),
            Self::NotDeletable => (
                ActionStatus::Skipped,
                Some(FailureCode::MissingPermission),
                Some("MANAGE_MESSAGES".to_owned()),
            ),
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
            action: ActionCode::DeleteMessage,
            status,
            details,
            failure_code,
        }
    }

    fn recommendation_key(&self) -> TextKey {
        match self {
            Self::Deleted => TextKey::AntiSpamRecommendationReviewMember,
            Self::NotDeletable | Self::Failed { .. } => {
                TextKey::AntiSpamRecommendationCheckPermissions
            }
        }
    }
}

/// Construit l'incident structuré à partir de la détection et du résultat.
pub fn build_incident(
    language: Language,
    message: &GuildMessage,
    detection: &MessageFloodDetection,
    outcome: &DeleteMessageOutcome,
) -> SecurityIncident {
    let mut incident = SecurityIncident::new(
        MESSAGE_FLOOD_MODULE,
        LogType::Message,
        outcome.severity(),
        text(language, TextKey::AntiSpamIncidentSummary),
        vec![outcome.action_outcome()],
    );

    incident.actor = Some(SecurityActor {
        user_id: message.author_id.to_string(),
        tag: None,
        account_created_at: None,
    });
    incident.location = Some(SecurityLocation {
        channel_id: Some(message.channel_id.to_string()),
        message_id: Some(message.message_id.to_string()),
        jump_url: Some(format!(
            "https://discord.com/channels/{}/{}/{}",
            message.guild_id, message.channel_id, message.message_id
        )),
    });
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Message,
        id: Some(message.message_id.to_string()),
        name: None,
    });
    incident.evidence = vec![SecurityEvidence::Threshold {
        observed: u64::from(detection.observed),
        threshold: u64::from(detection.threshold),
        window_seconds: Some(u64::from(detection.window_seconds)),
        unit: ThresholdUnit::Messages,
    }];
    incident.recommendation = Some(text(language, outcome.recommendation_key()).to_owned());

    incident
}
