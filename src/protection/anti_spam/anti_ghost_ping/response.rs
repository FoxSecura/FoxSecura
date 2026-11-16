// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Réponse à un ghost ping de masse : alerte, sanction de la récidive et
//! incident, sans effet Discord.
//!
//! # Attribution
//!
//! Le journal d'audit ne journalise pas la suppression d'un message par son
//! propre auteur, et regroupe celles des modérateurs : aucune suppression n'a
//! d'auteur d'action fiable. Le ghost ping est donc **attribué à l'auteur du
//! message**, ce que l'incident dit explicitement. Faux positif possible : un
//! modérateur qui supprime un message de masse produit une alerte au nom de
//! son auteur. C'est pourquoi un premier ghost ping n'est jamais sanctionné :
//! seule la récidive (2 en 10 minutes) mène à un timeout de 5 minutes, jamais
//! pour le propriétaire (garde du socle des sanctions) ni pour un auteur de la
//! liste blanche.

use std::time::Duration;

use super::GhostPingDetectionResult;
use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, ActionStatus, AffectedResource, AffectedResourceType, LogSeverity, LogType,
    SecurityActionOutcome, SecurityActor, SecurityEvidence, SecurityIncident, SecurityLocation,
    ThresholdUnit,
};
use crate::protection::shared::{
    ProtectionModule, SanctionKind, SanctionOutcome, exempt_member_action,
};

/// Un message suivi mentionne au moins 5 utilisateurs ou rôles.
pub const GHOST_PING_MENTION_THRESHOLD: usize = 5;
/// Mémoire d'un message suivi.
pub const GHOST_PING_MEMORY: Duration = Duration::from_secs(5 * 60);
/// Récidive : 2 ghost pings…
pub const GHOST_PING_REPEAT_THRESHOLD: usize = 2;
/// … en 10 minutes, par auteur.
pub const GHOST_PING_REPEAT_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Timeout d'une récidive.
pub const GHOST_PING_REPEAT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Raison d'audit log du timeout de récidive (V1).
pub const ANTI_GHOST_PING_REPEAT_REASON: &str = "FoxSecura Anti-Ghost Ping repeat offense";

/// Mentions citées au plus dans l'incident.
pub const MAX_GHOST_PING_TARGETS: usize = 10;

/// Ce qui a fait disparaître les mentions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhostPingEvent {
    Deleted,
    Edited,
}

/// Suite donnée à un ghost ping détecté.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhostPingFollowUp {
    /// Premier ghost ping : alerte seule.
    Alert,
    /// Récidive : timeout de 5 minutes.
    Sanction(SanctionKind),
    /// Récidive d'un auteur de la liste blanche : jamais sanctionné.
    ExemptMember(SanctionKind),
}

/// Décide de la suite : alerte, sauf récidive (timeout, ou rien pour un
/// auteur exempté).
pub const fn plan_ghost_ping_follow_up(
    repeat_offense: bool,
    author_exempt: bool,
) -> GhostPingFollowUp {
    let kind = SanctionKind::Timeout {
        duration: GHOST_PING_REPEAT_TIMEOUT,
    };
    match (repeat_offense, author_exempt) {
        (false, _) => GhostPingFollowUp::Alert,
        (true, false) => GhostPingFollowUp::Sanction(kind),
        (true, true) => GhostPingFollowUp::ExemptMember(kind),
    }
}

/// Résultat de la suite, pour l'incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhostPingOutcome {
    Alert,
    Sanction {
        kind: SanctionKind,
        outcome: SanctionOutcome,
    },
    ExemptMember(SanctionKind),
}

/// Message concerné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GhostPingIncidentInput<'a> {
    pub guild_id: u64,
    pub message_id: u64,
    pub event: GhostPingEvent,
    pub result: &'a GhostPingDetectionResult,
}

/// Incident `warning` (alerte), `critical` pour une récidive.
///
/// Le message a disparu (ou ses mentions) : pas de lien vers lui, pas
/// d'extrait. Preuves : mentions retirées et seuil, liste des cibles
/// (identifiants), attribution à l'auteur, nature de l'événement et, pour une
/// récidive, la règle de récidive.
pub fn ghost_ping_incident(
    language: Language,
    input: GhostPingIncidentInput<'_>,
    outcome: &GhostPingOutcome,
) -> SecurityIncident {
    let result = input.result;
    let repeat = result.repeat_offense;
    let mut actions = vec![SecurityActionOutcome {
        action: ActionCode::RecordAlert,
        status: ActionStatus::Success,
        details: None,
        failure_code: None,
    }];
    let recommendation = match outcome {
        GhostPingOutcome::Alert => TextKey::AntiGhostPingRecommendation,
        GhostPingOutcome::Sanction { kind, outcome } => {
            actions.push(outcome.action_outcome(*kind));
            if outcome.is_applied() {
                TextKey::AntiGhostPingRecommendationRepeat
            } else {
                TextKey::AntiGhostPingRecommendationSanctionFailed
            }
        }
        GhostPingOutcome::ExemptMember(_) => {
            actions.push(exempt_member_action());
            TextKey::RecommendationReviewWhitelist
        }
    };

    let mut incident = SecurityIncident::new(
        ProtectionModule::AntiGhostPing.key(),
        LogType::Message,
        if repeat {
            LogSeverity::Critical
        } else {
            LogSeverity::Warning
        },
        text(
            language,
            if repeat {
                TextKey::AntiGhostPingRepeatSummary
            } else {
                TextKey::AntiGhostPingSummary
            },
        ),
        actions,
    );
    if let Some(author_id) = result.author_id {
        incident.actor = Some(SecurityActor {
            user_id: author_id.to_string(),
            tag: None,
            account_created_at: None,
        });
    }
    incident.location = Some(SecurityLocation {
        channel_id: result.channel_id.map(|id| id.to_string()),
        message_id: Some(input.message_id.to_string()),
        jump_url: match input.event {
            // Le message existe encore : lien vers sa version modifiée.
            GhostPingEvent::Edited => result.channel_id.map(|channel_id| {
                format!(
                    "https://discord.com/channels/{}/{channel_id}/{}",
                    input.guild_id, input.message_id
                )
            }),
            GhostPingEvent::Deleted => None,
        },
    });
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Message,
        id: Some(input.message_id.to_string()),
        name: None,
    });

    incident.evidence.push(SecurityEvidence::Threshold {
        observed: result.mention_count as u64,
        threshold: result.threshold as u64,
        window_seconds: None,
        unit: ThresholdUnit::Mentions,
    });
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::AntiGhostPingEvidenceTargets).to_owned(),
        value: targets(result),
    });
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::ContentFilterEvidenceEvent).to_owned(),
        value: text(
            language,
            match input.event {
                GhostPingEvent::Deleted => TextKey::AntiGhostPingEventDeleted,
                GhostPingEvent::Edited => TextKey::ContentFilterEventEdited,
            },
        )
        .to_owned(),
    });
    incident.evidence.push(SecurityEvidence::Text {
        label: text(language, TextKey::AntiGhostPingEvidenceAttribution).to_owned(),
        value: text(language, TextKey::AntiGhostPingAttributionAuthor).to_owned(),
    });
    if repeat {
        incident.evidence.push(SecurityEvidence::Text {
            label: text(language, TextKey::AntiGhostPingEvidenceRepeat).to_owned(),
            value: format!(
                "{GHOST_PING_REPEAT_THRESHOLD} / {} s",
                GHOST_PING_REPEAT_WINDOW.as_secs()
            ),
        });
    }
    incident.recommendation = Some(text(language, recommendation).to_owned());
    incident
}

/// Cibles retirées, par identifiant (`user:…`, `role:…`, `everyone`), au plus
/// [`MAX_GHOST_PING_TARGETS`].
fn targets(result: &GhostPingDetectionResult) -> String {
    let all: Vec<String> = result
        .mention_ids
        .iter()
        .map(|id| format!("user:{id}"))
        .chain(
            result
                .role_mention_ids
                .iter()
                .map(|id| format!("role:{id}")),
        )
        .chain(result.mentions_everyone.then(|| "everyone".to_owned()))
        .collect();
    let mut shown = all
        .iter()
        .take(MAX_GHOST_PING_TARGETS)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if all.len() > MAX_GHOST_PING_TARGETS {
        shown.push_str(&format!(" (+{})", all.len() - MAX_GHOST_PING_TARGETS));
    }
    shown
}
