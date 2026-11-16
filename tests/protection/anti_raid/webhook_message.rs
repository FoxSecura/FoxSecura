// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    anti_raid::webhook_message::{
        WebhookMessageDetectionInput, WebhookMessageSpamDetector, WebhookMessageSpamInput,
        WebhookMessageThreat, detect_webhook_message_threat,
    },
    anti_spam::malicious_link::MaliciousLinkContext,
};

#[test]
fn reuses_existing_message_protections() {
    let result = detect_webhook_message_threat(WebhookMessageDetectionInput {
        content: "@everyone free gift https://discord.gg/test grabify.link/test",
        mentions_everyone: Some(true),
        mention_count: 6,
        mass_mention_threshold: None,
        recent_message_count: Some(5),
        spam_threshold: None,
        malicious_link_context: MaliciousLinkContext::default(),
    });

    assert!(result.triggered);
    assert!(
        result
            .threats
            .contains(&WebhookMessageThreat::DiscordInvite)
    );
    assert!(
        result
            .threats
            .contains(&WebhookMessageThreat::SuspiciousLink)
    );
    assert!(
        result
            .threats
            .contains(&WebhookMessageThreat::BroadcastMention)
    );
    assert!(result.threats.contains(&WebhookMessageThreat::MassMention));
    assert!(result.threats.contains(&WebhookMessageThreat::Spam));
}

#[test]
fn clean_webhook_message_stays_allowed() {
    let result = detect_webhook_message_threat(WebhookMessageDetectionInput {
        content: "Mise à jour du service terminée.",
        mentions_everyone: Some(false),
        mention_count: 0,
        mass_mention_threshold: None,
        recent_message_count: Some(1),
        spam_threshold: None,
        malicious_link_context: MaliciousLinkContext::default(),
    });

    assert!(!result.triggered);
    assert!(result.threats.is_empty());
}

#[test]
fn webhook_spam_uses_shared_burst_detector() {
    let mut detector = WebhookMessageSpamDetector::default();

    for second in 0..4 {
        let result = detector.detect(WebhookMessageSpamInput {
            guild_id: 1,
            webhook_id: 42,
            timestamp: Duration::from_secs(second),
            threshold: None,
            window: None,
        });
        assert!(!result.triggered);
    }

    let result = detector.detect(WebhookMessageSpamInput {
        guild_id: 1,
        webhook_id: 42,
        timestamp: Duration::from_secs(4),
        threshold: None,
        window: None,
    });
    assert!(result.triggered);
}

// --- Tranche 10 : motifs, seuils, webhook du bot et incident ---

use foxsecura::i18n::Language;
use foxsecura::logs::{LogSeverity, SecurityEvidence, ThresholdUnit};
use foxsecura::protection::anti_raid::webhook_message::{
    WEBHOOK_MASS_MENTION_THRESHOLD, WEBHOOK_SPAM_THRESHOLD, WEBHOOK_SPAM_WINDOW,
    WebhookMessageIncidentInput, WebhookOrigin, is_own_webhook_message, webhook_message_incident,
};
use foxsecura::protection::shared::{DeleteMessageOutcome, GuildMessage};

fn webhook_input(
    content: &str,
    everyone: bool,
    mentions: usize,
    recent: usize,
) -> WebhookMessageDetectionInput<'_> {
    WebhookMessageDetectionInput {
        content,
        mentions_everyone: Some(everyone),
        mention_count: mentions,
        mass_mention_threshold: Some(WEBHOOK_MASS_MENTION_THRESHOLD),
        recent_message_count: Some(recent),
        spam_threshold: Some(WEBHOOK_SPAM_THRESHOLD),
        malicious_link_context: MaliciousLinkContext::default(),
    }
}

fn threats(input: WebhookMessageDetectionInput<'_>) -> Vec<WebhookMessageThreat> {
    detect_webhook_message_threat(input).threats
}

#[test]
fn each_webhook_motive_triggers_on_its_own() {
    assert_eq!(
        threats(webhook_input("rejoins discord.gg/raid", false, 0, 1)),
        vec![WebhookMessageThreat::DiscordInvite]
    );
    assert_eq!(
        threats(webhook_input("https://grabify.link/x", false, 0, 1)),
        vec![WebhookMessageThreat::SuspiciousLink]
    );
    assert_eq!(
        threats(webhook_input("@everyone annonce", true, 0, 1)),
        vec![WebhookMessageThreat::BroadcastMention]
    );
    assert_eq!(
        threats(webhook_input("salut", false, 5, 1)),
        vec![WebhookMessageThreat::MassMention]
    );
    assert_eq!(
        threats(webhook_input("salut", false, 0, 5)),
        vec![WebhookMessageThreat::Spam]
    );
}

#[test]
fn webhook_thresholds_are_respected_at_their_bounds() {
    assert_eq!(WEBHOOK_MASS_MENTION_THRESHOLD, 5);
    assert_eq!(WEBHOOK_SPAM_THRESHOLD, 5);
    assert_eq!(WEBHOOK_SPAM_WINDOW, Duration::from_secs(5));
    assert!(threats(webhook_input("salut", false, 4, 4)).is_empty());
    // Le texte « @everyone » sans mention réelle ne notifie personne.
    assert!(threats(webhook_input("@everyone", false, 0, 1)).is_empty());
}

#[test]
fn webhook_spam_counts_five_messages_in_five_seconds_per_webhook() {
    let mut detector = WebhookMessageSpamDetector::default();
    let detect = |detector: &mut WebhookMessageSpamDetector, webhook_id, second| {
        detector.detect(WebhookMessageSpamInput {
            guild_id: 1,
            webhook_id,
            timestamp: Duration::from_secs(second),
            threshold: Some(WEBHOOK_SPAM_THRESHOLD),
            window: Some(WEBHOOK_SPAM_WINDOW),
        })
    };
    for second in 0..4 {
        assert!(!detect(&mut detector, 42, second).triggered);
    }
    // Un autre webhook est compté à part.
    assert!(!detect(&mut detector, 43, 4).triggered);
    // Cinquième message à 5 s pile du premier : dans la fenêtre.
    let fifth = detect(&mut detector, 42, 5);
    assert!(fifth.triggered);
    assert_eq!(fifth.message_count, 5);
    // Hors fenêtre : les anciens messages sont oubliés.
    let mut slow = WebhookMessageSpamDetector::default();
    for second in [0, 2, 4, 6, 8, 10, 12] {
        assert!(!detect(&mut slow, 42, second).triggered, "seconde {second}");
    }
}

#[test]
fn foxsecura_own_webhook_and_interaction_messages_are_never_processed() {
    let bot = 1_000;
    let other = |author_id, webhook_id, application_id| WebhookOrigin {
        bot_id: bot,
        author_id,
        webhook_id,
        application_id,
    };
    // Réponse d'interaction : webhook et application du bot.
    assert!(is_own_webhook_message(other(bot, bot, Some(bot))));
    // Webhook créé par l'application du bot.
    assert!(is_own_webhook_message(other(55, 55, Some(bot))));
    assert!(is_own_webhook_message(other(55, bot, None)));
    // Webhook d'un tiers, ou d'une autre application : traité.
    assert!(!is_own_webhook_message(other(55, 55, None)));
    assert!(!is_own_webhook_message(other(55, 55, Some(77))));
}

#[test]
fn webhook_incident_lists_reasons_thresholds_and_the_webhook() {
    let message = GuildMessage {
        guild_id: 1,
        channel_id: 10,
        message_id: 20,
        author_id: 55,
        timestamp: Duration::ZERO,
    };
    let result = detect_webhook_message_threat(webhook_input("discord.gg/raid", false, 6, 5));
    let incident = webhook_message_incident(
        Language::French,
        WebhookMessageIncidentInput {
            message: &message,
            webhook_id: 55,
            webhook_name: Some("Captain Hook"),
            content: "discord.gg/raid",
        },
        &result,
        &DeleteMessageOutcome::Deleted,
    );
    assert_eq!(incident.module, "webhook_watch");
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert!(incident.evidence.iter().any(|evidence| matches!(
        evidence,
        SecurityEvidence::Text { value, .. }
            if value == "discord_invite, mass_mention, webhook_spam"
    )));
    assert!(incident.evidence.contains(&SecurityEvidence::Threshold {
        observed: 6,
        threshold: 5,
        window_seconds: None,
        unit: ThresholdUnit::Mentions,
    }));
    assert!(incident.evidence.contains(&SecurityEvidence::Threshold {
        observed: 5,
        threshold: 5,
        window_seconds: Some(5),
        unit: ThresholdUnit::Messages,
    }));
    // Aucune sanction : seule la suppression est journalisée.
    assert_eq!(incident.actions.len(), 1);
    assert!(incident.validate().is_ok());

    let kept = webhook_message_incident(
        Language::French,
        WebhookMessageIncidentInput {
            message: &message,
            webhook_id: 55,
            webhook_name: None,
            content: "",
        },
        &result,
        &DeleteMessageOutcome::NotDeletable,
    );
    assert_eq!(kept.severity, LogSeverity::Critical);
}
