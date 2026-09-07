// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use foxsecura::i18n::Language;
use foxsecura::logs::{
    format_security_log, ActionCode, ActionStatus, LogSeverity, LogType, SecurityActionOutcome,
    SecurityEvidence, SecurityIncident, SecurityIncidentError, LOG_CHANNEL_DEFINITIONS,
    LOG_STRUCTURE_CATEGORY_ALIASES, LOG_STRUCTURE_CATEGORY_NAME,
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
fn obsolete_vulpesguard_log_aliases_are_not_supported() {
    assert!(
        LOG_STRUCTURE_CATEGORY_ALIASES
            .iter()
            .all(|alias| !alias.contains("VulpesGuard"))
    );
}

#[test]
fn log_channel_metadata_is_localized() {
    let message_logs = LOG_CHANNEL_DEFINITIONS
        .iter()
        .find(|definition| definition.log_type == LogType::Message)
        .expect("message log definition must exist");

    assert_eq!(message_logs.label(Language::English), "Message logs");
    assert_eq!(message_logs.label(Language::French), "Logs messages");
    assert_eq!(message_logs.label(Language::German), "Nachrichtenprotokolle");

    assert_ne!(
        message_logs.purpose(Language::English),
        message_logs.purpose(Language::German)
    );
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
fn formats_security_incident_in_all_supported_languages() {
    let incident = SecurityIncident::new(
        "anti_spam",
        LogType::Message,
        LogSeverity::Warning,
        "Spam detected",
        vec![successful_action(ActionCode::DeleteMessage)],
    );

    let english = format_security_log(Language::English, &incident);
    let french = format_security_log(Language::French, &incident);
    let german = format_security_log(Language::German, &incident);

    assert!(english.contains("FoxSecura Security Incident"));
    assert!(english.contains("Type: Messages"));
    assert!(english.contains("Severity: Warning"));
    assert!(english.contains("Delete message: Success"));

    assert!(french.contains("Incident de sécurité FoxSecura"));
    assert!(french.contains("Type: Messages"));
    assert!(french.contains("Sévérité: Avertissement"));
    assert!(french.contains("Supprimer le message: Réussie"));

    assert!(german.contains("FoxSecura-Sicherheitsvorfall"));
    assert!(german.contains("Typ: Nachrichten"));
    assert!(german.contains("Schweregrad: Warnung"));
    assert!(german.contains("Nachricht löschen: Erfolgreich"));
}
