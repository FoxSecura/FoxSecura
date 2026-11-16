// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Incident publié à la pose du mode lent automatique.

use super::{AUTO_SLOWMODE_LIFT_DELAY, AUTO_SLOWMODE_WINDOW};
use crate::i18n::{Language, TextKey, text};
use crate::logs::{
    ActionCode, AffectedResource, AffectedResourceType, LogSeverity, LogType, SecurityEvidence,
    SecurityIncident, SecurityLocation, ThresholdUnit,
};
use crate::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use crate::protection::shared::{ProtectionModule, audit_reason};

/// Nom du module dans la raison d'audit log.
pub const AUTO_SLOWMODE_AUDIT_LABEL: &str = "Auto Slowmode";

/// Raison d'audit log de la pose (`FoxSecura Auto Slowmode: channel burst`).
pub fn auto_slowmode_audit_reason() -> String {
    audit_reason(AUTO_SLOWMODE_AUDIT_LABEL, "channel burst")
}

/// Raison d'audit log de la levée (`FoxSecura Auto Slowmode: restore`).
pub fn auto_slowmode_restore_reason() -> String {
    audit_reason(AUTO_SLOWMODE_AUDIT_LABEL, "restore")
}

/// Pose à journaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlowmodeIncidentInput {
    pub guild_id: u64,
    pub channel_id: u64,
    /// Messages comptés dans la fenêtre au déclenchement.
    pub observed: usize,
    pub threshold: usize,
    pub previous_seconds: u16,
    pub applied_seconds: u16,
}

/// Incident `warning` : c'est un réglage du salon, pas une sanction.
pub fn slowmode_incident(
    language: Language,
    input: SlowmodeIncidentInput,
    result: &IntegrityActionResult,
) -> SecurityIncident {
    let mut incident = SecurityIncident::new(
        ProtectionModule::AutoSlowmode.key(),
        LogType::Channel,
        LogSeverity::Warning,
        text(language, TextKey::AutoSlowmodeSummary),
        vec![result.action_outcome(ActionCode::ApplySlowmode)],
    );
    incident.location = Some(SecurityLocation {
        channel_id: Some(input.channel_id.to_string()),
        message_id: None,
        jump_url: Some(format!(
            "https://discord.com/channels/{}/{}",
            input.guild_id, input.channel_id
        )),
    });
    incident.affected_resource = Some(AffectedResource {
        resource_type: AffectedResourceType::Channel,
        id: Some(input.channel_id.to_string()),
        name: None,
    });
    incident.evidence.extend([
        SecurityEvidence::Threshold {
            observed: input.observed as u64,
            threshold: input.threshold as u64,
            window_seconds: Some(AUTO_SLOWMODE_WINDOW.as_secs()),
            unit: ThresholdUnit::Messages,
        },
        SecurityEvidence::Text {
            label: text(language, TextKey::AutoSlowmodeEvidenceSlowmode).to_owned(),
            value: format!(
                "{} s -> {} s",
                input.previous_seconds, input.applied_seconds
            ),
        },
        SecurityEvidence::Text {
            label: text(language, TextKey::AutoSlowmodeEvidenceLift).to_owned(),
            value: format!("{} s", AUTO_SLOWMODE_LIFT_DELAY.as_secs()),
        },
    ]);
    incident.recommendation = Some(
        text(
            language,
            if result.applied() {
                TextKey::AutoSlowmodeRecommendation
            } else {
                TextKey::AutoSlowmodeRecommendationFailed
            },
        )
        .to_owned(),
    );
    incident
}
