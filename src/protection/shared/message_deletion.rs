// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Suppression d'un message déclencheur : plan, résultat et squelette
//! d'incident, communs à l'anti-spam et aux filtres de contenu.

use super::GuildMessage;
use crate::i18n::TextKey;
use crate::logs::{
    ActionCode, ActionStatus, AffectedResource, AffectedResourceType, FailureCode, LogSeverity,
    LogType, SecurityActionOutcome, SecurityActor, SecurityIncident, SecurityLocation,
};

/// Action à exécuter : supprimer le message déclencheur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteMessagePlan {
    pub guild_id: u64,
    pub channel_id: u64,
    pub message_id: u64,
}

impl DeleteMessagePlan {
    pub const fn for_message(message: &GuildMessage) -> Self {
        Self {
            guild_id: message.guild_id,
            channel_id: message.channel_id,
            message_id: message.message_id,
        }
    }
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

    /// `Warning` si le message a disparu, `Critical` s'il est resté visible.
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

    /// Recommandation adressée aux modérateurs.
    pub const fn recommendation_key(&self) -> TextKey {
        match self {
            Self::Deleted => TextKey::AntiSpamRecommendationReviewMember,
            Self::NotDeletable | Self::Failed { .. } => {
                TextKey::AntiSpamRecommendationCheckPermissions
            }
        }
    }
}

/// Incident d'un message supprimé (ou qu'il fallait supprimer) : module,
/// sévérité, action, auteur, emplacement et ressource touchée.
///
/// Les preuves et la recommandation restent à la charge du module.
pub fn message_incident(
    module: &str,
    summary: &str,
    message: &GuildMessage,
    outcome: &DeleteMessageOutcome,
) -> SecurityIncident {
    let mut incident = SecurityIncident::new(
        module,
        LogType::Message,
        outcome.severity(),
        summary,
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

    incident
}
