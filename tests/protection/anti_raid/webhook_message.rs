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
    assert!(result.threats.contains(&WebhookMessageThreat::DiscordInvite));
    assert!(result.threats.contains(&WebhookMessageThreat::SuspiciousLink));
    assert!(result.threats.contains(&WebhookMessageThreat::BroadcastMention));
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
