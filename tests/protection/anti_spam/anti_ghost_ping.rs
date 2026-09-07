// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    anti_spam::anti_ghost_ping::{AntiGhostPingDetector, GhostPingMessage},
    shared::ProtectionDecision,
};

fn message(message_id: u64, timestamp: u64) -> GhostPingMessage {
    GhostPingMessage {
        guild_id: 1,
        message_id,
        channel_id: 10,
        author_id: 20,
        mention_ids: vec![1, 2, 3, 4, 5],
        role_mention_ids: Vec::new(),
        mentions_everyone: false,
        timestamp: Duration::from_secs(timestamp),
    }
}

#[test]
fn deletion_after_mass_ping_is_blocked() {
    let mut detector = AntiGhostPingDetector::default();
    assert!(detector.record(message(1, 0)));
    let result = detector.detect_deleted(1, 1, Duration::from_secs(1));
    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(result.mention_count, 5);
}

#[test]
fn edit_removing_mentions_is_detected_once() {
    let mut detector = AntiGhostPingDetector::default();
    detector.record(message(1, 0));
    let mut edited = message(1, 1);
    edited.mention_ids.clear();
    let result = detector.detect_updated(edited);
    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(detector.detect_deleted(1, 1, Duration::from_secs(2)).decision, ProtectionDecision::Allow);
}

#[test]
fn second_incident_marks_repeat_offense() {
    let mut detector = AntiGhostPingDetector::default();
    detector.record(message(1, 0));
    assert!(!detector.detect_deleted(1, 1, Duration::from_secs(1)).repeat_offense);
    detector.record(message(2, 2));
    assert!(detector.detect_deleted(1, 2, Duration::from_secs(3)).repeat_offense);
}
