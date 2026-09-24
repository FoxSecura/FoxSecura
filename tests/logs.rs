// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use foxsecura::i18n::Language;
use foxsecura::logs::{
    ActionCode, ActionStatus, LOG_CHANNEL_DEFINITIONS, LOG_STRUCTURE_CATEGORY_ALIASES,
    LOG_STRUCTURE_CATEGORY_NAME, LogSeverity, LogType, SecurityActionOutcome, SecurityActor,
    SecurityEvidence, SecurityIncident, SecurityIncidentError, SecurityLocation, ThresholdUnit,
    format_security_log, format_security_log_message, inline_literal,
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
    assert_eq!(
        message_logs.label(Language::German),
        "Nachrichtenprotokolle"
    );

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

#[test]
fn log_message_adds_actor_channel_evidence_and_recommendation() {
    let mut incident = SecurityIncident::new(
        "anti_spam",
        LogType::Message,
        LogSeverity::Warning,
        "Rafale de messages détectée.",
        vec![successful_action(ActionCode::DeleteMessage)],
    );
    incident.actor = Some(SecurityActor {
        user_id: "10".to_owned(),
        tag: None,
        account_created_at: None,
    });
    incident.location = Some(SecurityLocation {
        channel_id: Some("900".to_owned()),
        message_id: Some("5".to_owned()),
        jump_url: None,
    });
    incident.evidence = vec![SecurityEvidence::Threshold {
        observed: 6,
        threshold: 5,
        window_seconds: Some(5),
        unit: ThresholdUnit::Messages,
    }];
    incident.recommendation = Some("Examiner le membre suspect.".to_owned());

    let message = format_security_log_message(Language::French, &incident);

    assert!(message.starts_with(&format_security_log(Language::French, &incident)));
    assert!(message.contains("Membre: <@10>"));
    assert!(message.contains("Salon: <#900>"));
    assert!(message.contains("Preuve: 6/5 messages en 5 s"));
    assert!(message.contains("Recommandation: Examiner le membre suspect."));
}

// --- Rendu des valeurs non fiables ---

#[test]
fn inline_literal_wraps_values_in_unbreakable_inline_code() {
    assert_eq!(inline_literal("simple", 50), "`simple`");
    assert_eq!(inline_literal("", 50), "` `");
    // Un accent grave du contenu ne peut pas fermer le bloc.
    assert_eq!(inline_literal("a`b``c", 50), "`aˋbˋˋc`");
}

#[test]
fn inline_literal_neutralizes_line_breaks_and_hidden_characters() {
    assert_eq!(
        inline_literal("ligne1\nligne2\r\tfin", 50),
        "`ligne1 ligne2  fin`"
    );
    assert_eq!(
        inline_literal("a\u{200b}b\u{202e}c\u{e0041}d\u{feff}", 50),
        "`a\u{fffd}b\u{fffd}c\u{fffd}d\u{fffd}`"
    );
    // Les émojis composés restent lisibles.
    assert_eq!(inline_literal("❤️ 👍🏽 👨‍👩‍👧", 50), "`❤️ 👍🏽 👨‍👩‍👧`");
}

#[test]
fn inline_literal_collapses_zalgo_and_truncates() {
    let zalgo = format!("a{}b", "\u{0301}".repeat(30));
    assert_eq!(inline_literal(&zalgo, 50), "`a\u{0301}b`");

    assert_eq!(inline_literal("abcdef", 3), "`abc…`");
    assert_eq!(inline_literal("abc", 3), "`abc`");
}

#[test]
fn account_age_evidence_is_rendered_in_whole_days_with_the_minimum() {
    let mut incident = SecurityIncident::new(
        "anti_new_account",
        LogType::Member,
        LogSeverity::Warning,
        "Nouveau compte",
        vec![successful_action(ActionCode::BanMember)],
    );
    incident.evidence.push(SecurityEvidence::AccountAge {
        age_seconds: 2 * 24 * 60 * 60 + 3600,
        minimum_age_seconds: 7 * 24 * 60 * 60,
    });

    let message = format_security_log_message(Language::French, &incident);
    assert!(
        message.contains("Âge du compte = 2 jours (minimum 7 jours)"),
        "{message}"
    );
    let message = format_security_log_message(Language::English, &incident);
    assert!(
        message.contains("Account age = 2 days (minimum 7 days)"),
        "{message}"
    );
}
