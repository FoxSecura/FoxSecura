// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, LogSeverity, SecurityEvidence, format_security_log_message};
use foxsecura::protection::anti_nuke::response::sends_panic_signal;
use foxsecura::protection::anti_nuke::server_integrity::alert::AlertAuthor;
use foxsecura::protection::anti_nuke::server_integrity::anti_server_edit::{
    ServerField, ServerSettings, changed_fields_label, changed_server_fields, server_edit_incident,
};
use foxsecura::protection::anti_nuke::server_integrity::anti_vanity_change::{
    vanity_change_label, vanity_changed, vanity_incident,
};

const GUILD: u64 = 1;

fn settings() -> ServerSettings {
    ServerSettings {
        name: "FoxSecura".to_owned(),
        icon: Some("a1b2".to_owned()),
        verification_level: 1,
        default_notifications: 1,
        vanity_url_code: Some("fox".to_owned()),
    }
}

#[test]
fn each_watched_field_is_detected() {
    let base = settings();
    for (changed, expected) in [
        (
            ServerSettings {
                name: "Raid".to_owned(),
                ..settings()
            },
            ServerField::Name,
        ),
        (
            ServerSettings {
                icon: None,
                ..settings()
            },
            ServerField::Icon,
        ),
        (
            ServerSettings {
                verification_level: 0,
                ..settings()
            },
            ServerField::VerificationLevel,
        ),
        (
            ServerSettings {
                default_notifications: 0,
                ..settings()
            },
            ServerField::DefaultNotifications,
        ),
    ] {
        assert_eq!(changed_server_fields(&base, &changed), vec![expected]);
    }
}

#[test]
fn unwatched_changes_produce_nothing() {
    // Seule l'URL personnalisée change : pas une modification surveillée par
    // server-edit (elle relève de anti_vanity_change).
    let changed = ServerSettings {
        vanity_url_code: None,
        ..settings()
    };
    let fields = changed_server_fields(&settings(), &changed);
    assert!(fields.is_empty());
    assert!(
        server_edit_incident(Language::English, GUILD, &fields, AlertAuthor::Unresolved).is_none()
    );
}

#[test]
fn server_edit_alert_lists_the_changed_fields_without_sanction() {
    let changed = ServerSettings {
        name: "Raid".to_owned(),
        icon: None,
        ..settings()
    };
    let fields = changed_server_fields(&settings(), &changed);
    assert_eq!(changed_fields_label(&fields), "name, icon");

    let incident =
        server_edit_incident(Language::English, GUILD, &fields, AlertAuthor::Resolved(77))
            .expect("incident");
    assert!(incident.validate().is_ok());
    assert_eq!(incident.module, "anti_server_edit");
    assert_eq!(incident.severity, LogSeverity::Warning);
    // Pas un signal du mode panique.
    assert!(!sends_panic_signal(&incident));
    assert_eq!(incident.actions.len(), 1);
    assert_eq!(incident.actions[0].action, ActionCode::RecordAlert);
    let message = format_security_log_message(Language::English, &incident);
    assert!(message.contains("Changed = `name, icon`"), "{message}");
}

#[test]
fn vanity_change_is_critical_and_feeds_panic_mode() {
    assert!(vanity_changed(Some("fox"), Some("raid")));
    assert!(vanity_changed(Some("fox"), None));
    assert!(!vanity_changed(Some("fox"), Some("fox")));
    assert_eq!(
        vanity_change_label(Some("fox"), Some("raid")),
        "discord[.]gg/fox->discord[.]gg/raid"
    );
    assert_eq!(
        vanity_change_label(None, Some("raid")),
        "none->discord[.]gg/raid"
    );

    let incident = vanity_incident(
        Language::English,
        GUILD,
        Some("fox"),
        Some("raid"),
        AlertAuthor::Resolved(77),
    )
    .expect("incident");
    assert!(incident.validate().is_ok());
    assert_eq!(incident.module, "anti_vanity_change");
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert!(sends_panic_signal(&incident));
    assert_eq!(incident.actions[0].action, ActionCode::RecordAlert);
    assert!(incident.evidence.iter().any(|evidence| matches!(
        evidence,
        SecurityEvidence::Text { value, .. } if value == "discord[.]gg/fox->discord[.]gg/raid"
    )));
    // Rendu en code en ligne, sans lien cliquable.
    let message = format_security_log_message(Language::English, &incident);
    assert!(
        message.contains("`discord[.]gg/fox->discord[.]gg/raid`"),
        "{message}"
    );

    assert!(
        vanity_incident(
            Language::English,
            GUILD,
            Some("fox"),
            Some("fox"),
            AlertAuthor::Unresolved
        )
        .is_none()
    );
}

#[test]
fn vanity_change_by_a_whitelisted_author_stays_visible_but_not_critical() {
    let incident = vanity_incident(
        Language::French,
        GUILD,
        Some("fox"),
        Some("raid"),
        AlertAuthor::Exempt(77),
    )
    .expect("incident");
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert!(!sends_panic_signal(&incident));
    assert_eq!(incident.actions[1].action, ActionCode::IgnoreExemptMember);

    let unresolved = vanity_incident(
        Language::French,
        GUILD,
        Some("fox"),
        None,
        AlertAuthor::Unresolved,
    )
    .expect("incident");
    assert_eq!(unresolved.severity, LogSeverity::Critical);
    assert!(unresolved.actor.is_none());
}
