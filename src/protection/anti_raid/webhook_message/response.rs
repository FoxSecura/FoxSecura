// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Messages de webhook (V1, activés par le module `webhook_watch`) : gardes et
//! incident, sans effet Discord.
//!
//! Un message posté par un webhook est supprimé s'il contient une invitation,
//! un lien malveillant, `@everyone`/`@here`, au moins 5 mentions, ou si le
//! même webhook a posté au moins 5 messages en 5 s. Jamais de sanction : un
//! webhook n'est pas un membre. L'équipe décide de supprimer le webhook.

use std::time::Duration;

use super::{WebhookMessageDetectionResult, WebhookMessageThreat};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{SecurityEvidence, SecurityIncident, ThresholdUnit};
use crate::protection::content_filter::excerpt;
use crate::protection::shared::{
    DeleteMessageOutcome, GuildMessage, ProtectionModule, message_incident,
};

/// Rafale d'un même webhook : 5 messages…
pub const WEBHOOK_SPAM_THRESHOLD: usize = 5;
/// … en 5 secondes.
pub const WEBHOOK_SPAM_WINDOW: Duration = Duration::from_secs(5);
/// Mentions (utilisateurs et rôles) à partir desquelles un message de webhook
/// est retenu.
pub const WEBHOOK_MASS_MENTION_THRESHOLD: usize = 5;

impl WebhookMessageThreat {
    /// Clé stable, citée dans l'incident.
    pub const fn key(self) -> &'static str {
        match self {
            Self::DiscordInvite => "discord_invite",
            Self::SuspiciousLink => "malicious_link",
            Self::BroadcastMention => "everyone_here",
            Self::MassMention => "mass_mention",
            Self::Spam => "webhook_spam",
        }
    }
}

/// Origine d'un message de webhook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookOrigin {
    pub bot_id: u64,
    pub author_id: u64,
    pub webhook_id: u64,
    /// Application qui a posté le message : réponses d'interaction et
    /// webhooks créés par une application.
    pub application_id: Option<u64>,
}

/// Messages de FoxSecura lui-même : son propre compte, ses réponses
/// d'interaction (dont le webhook porte l'identifiant de l'application, celui
/// du bot) et les webhooks de son application. Jamais traités.
pub const fn is_own_webhook_message(origin: WebhookOrigin) -> bool {
    let own_application = match origin.application_id {
        Some(application_id) => application_id == origin.bot_id,
        None => false,
    };
    origin.author_id == origin.bot_id || origin.webhook_id == origin.bot_id || own_application
}

/// Message de webhook retenu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookMessageIncidentInput<'a> {
    pub message: &'a GuildMessage,
    pub webhook_id: u64,
    /// Nom affiché du webhook ; valeur non fiable, rendue par
    /// `inline_literal`.
    pub webhook_name: Option<&'a str>,
    pub content: &'a str,
}

/// Incident d'un message de webhook supprimé (ou qu'il fallait supprimer) :
/// raisons, seuils atteints, webhook et extrait.
pub fn webhook_message_incident(
    language: Language,
    input: WebhookMessageIncidentInput<'_>,
    result: &WebhookMessageDetectionResult,
    deletion: &DeleteMessageOutcome,
) -> SecurityIncident {
    let mut incident = message_incident(
        ProtectionModule::WebhookWatch.key(),
        text(language, TextKey::WebhookMessageSummary),
        input.message,
        deletion,
    );
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::WebhookMessageEvidenceReasons).to_owned(),
        value: result
            .threats
            .iter()
            .map(|threat| threat.key())
            .collect::<Vec<_>>()
            .join(", "),
    });
    if result.threats.contains(&WebhookMessageThreat::MassMention) {
        incident.evidence.push(SecurityEvidence::Threshold {
            observed: result.mention_count as u64,
            threshold: result.mass_mention_threshold as u64,
            window_seconds: None,
            unit: ThresholdUnit::Mentions,
        });
    }
    if result.threats.contains(&WebhookMessageThreat::Spam) {
        incident.evidence.push(SecurityEvidence::Threshold {
            observed: result.recent_message_count as u64,
            threshold: result.spam_threshold as u64,
            window_seconds: Some(WEBHOOK_SPAM_WINDOW.as_secs()),
            unit: ThresholdUnit::Messages,
        });
    }
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::WebhookMessageEvidenceWebhook).to_owned(),
        value: match input.webhook_name {
            Some(name) => format!("{} ({name})", input.webhook_id),
            None => input.webhook_id.to_string(),
        },
    });
    if !input.content.is_empty() {
        incident.evidence.push(SecurityEvidence::Content {
            excerpt: excerpt(input.content),
        });
    }
    incident.recommendation = Some(
        text(
            language,
            if matches!(deletion, DeleteMessageOutcome::Deleted) {
                TextKey::WebhookMessageRecommendation
            } else {
                deletion.recommendation_key()
            },
        )
        .to_owned(),
    );
    incident
}
