// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use foxsecura::logs::{
    format_security_log, ActionCode, ActionStatus, LogSeverity, LogType, SecurityActionOutcome,
    SecurityEvidence, SecurityIncident, SecurityIncidentError, LOG_CHANNEL_DEFINITIONS,
    LOG_STRUCTURE_CATEGORY_NAME,
};

fn successful_action(action: ActionCode) -> SecurityActionOutcome {
    SecurityActionOutcome {
        action,
        status: ActionStatus::Success,
        details: None,
        failure_code: None,
    }
}

#[test]
fn exposes_the_expected_log_structure() {
    assert_eq!(LOG_STRUCTURE_CATEGORY_NAME, "🦊 FoxSecura Logs");
    assert_eq!(LOG_CHANNEL_DEFINITIONS.len(), 6);

    let channel_names = LOG_CHANNEL_DEFINITIONS
        .iter()
        .map(|definition| definition.channel_name)
        .collect::<HashSet<_>>();

    assert_eq!(channel_names.len(), LOG_CHANNEL_DEFINITIONS.len());
}

#[test]
fn creates_foxsecura_incident_ids() {
    let first = SecurityIncident::new(
        "anti_spam",
        LogType::Moderation,
        LogSeverity::Warning,
        "Spam détecté",
        vec![successful_action(ActionCode::DeleteMessage)],
    );
    let second = SecurityIncident::new(
        "anti_raid",
        LogType::Moderation,
        LogSeverity::Warning,
        "Raid détecté",
        vec![successful_action(ActionCode::ApplyLockdown)],
    );

    assert!(first.incident_id.starts_with("FS-"));
    assert!(second.incident_id.starts_with("FS-"));
    assert_ne!(first.incident_id, second.incident_id);
}

#[test]
fn critical_incident_requires_evidence() {
    let incident = SecurityIncident::new(
        "anti_nuke",
        LogType::Moderation,
        LogSeverity::Critical,
        "Action critique détectée",
        vec![successful_action(ActionCode::RecordAlert)],
    );

    assert_eq!(
        incident.validate(),
        Err(SecurityIncidentError::CriticalIncidentWithoutEvidence)
    );
}

#[test]
fn critical_incident_with_evidence_is_valid() {
    let mut incident = SecurityIncident::new(
        "anti_nuke",
        LogType::Moderation,
        LogSeverity::Critical,
        "Action critique détectée",
        vec![successful_action(ActionCode::RecordAlert)],
    );
    incident.evidence.push(SecurityEvidence::Content {
        excerpt: "contenu de test".to_owned(),
    });

    assert_eq!(incident.validate(), Ok(()));
}

#[test]
fn formats_security_incident_summary() {
    let incident = SecurityIncident::new(
        "anti_spam",
        LogType::Message,
        LogSeverity::Warning,
        "Spam détecté",
        vec![successful_action(ActionCode::DeleteMessage)],
    );

    let formatted = format_security_log(&incident);

    assert!(formatted.contains(&incident.incident_id));
    assert!(formatted.contains("Module: anti_spam"));
    assert!(formatted.contains("Type: message"));
    assert!(formatted.contains("Severity: warning"));
    assert!(formatted.contains("delete_message:success"));
}
