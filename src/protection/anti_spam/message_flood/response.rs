// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Plan d'action et incident de l'anti-spam, sans aucun effet Discord.

use super::MessageFloodDetection;
use crate::i18n::{Language, TextKey, text};
use crate::logs::{SecurityEvidence, SecurityIncident, ThresholdUnit};
use crate::protection::shared::{
    DeleteMessageOutcome, DeleteMessagePlan, GuildMessage, message_incident,
};

/// Nom du module inscrit dans les incidents.
pub const MESSAGE_FLOOD_MODULE: &str = "anti_spam";

/// Retourne l'action à exécuter si la détection a déclenché la protection :
/// supprimer le message qui a atteint le seuil.
pub fn plan_response(
    message: &GuildMessage,
    detection: &MessageFloodDetection,
) -> Option<DeleteMessagePlan> {
    detection
        .is_triggered()
        .then_some(DeleteMessagePlan::for_message(message))
}

/// Construit l'incident structuré à partir de la détection et du résultat.
pub fn build_incident(
    language: Language,
    message: &GuildMessage,
    detection: &MessageFloodDetection,
    outcome: &DeleteMessageOutcome,
) -> SecurityIncident {
    let mut incident = message_incident(
        MESSAGE_FLOOD_MODULE,
        text(language, TextKey::AntiSpamIncidentSummary),
        message,
        outcome,
    );

    incident.evidence = vec![SecurityEvidence::Threshold {
        observed: u64::from(detection.observed),
        threshold: u64::from(detection.threshold),
        window_seconds: Some(u64::from(detection.window_seconds)),
        unit: ThresholdUnit::Messages,
    }];
    incident.recommendation = Some(text(language, outcome.recommendation_key()).to_owned());

    incident
}
