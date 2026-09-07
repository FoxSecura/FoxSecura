// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    ProtectionDecision,
    anti_raid::join_burst::{JoinBurstConfig, JoinBurstDetector, JoinEvent},
};

fn config(enabled: bool, threshold: usize) -> JoinBurstConfig {
    JoinBurstConfig::new(enabled, threshold, Duration::from_secs(20))
}

#[test]
fn disabled_protection_does_not_track_joins() {
    let mut detector = JoinBurstDetector::new();
    let result = detector.detect(config(false, 5), JoinEvent::new(1, 10, 1_000));

    assert_eq!(result.decision, ProtectionDecision::Allow);
    assert_eq!(result.join_count, 0);
    assert_eq!(detector.tracked_guild_count(), 0);
}

#[test]
fn joins_below_threshold_are_allowed() {
    let mut detector = JoinBurstDetector::new();

    for user_id in 1..5 {
        let result = detector.detect(config(true, 5), JoinEvent::new(1, user_id, user_id * 1_000));
        assert_eq!(result.decision, ProtectionDecision::Allow);
    }
}

#[test]
fn join_at_threshold_is_blocked() {
    let mut detector = JoinBurstDetector::new();
    let mut result = detector.detect(config(true, 5), JoinEvent::new(1, 1, 1_000));

    for user_id in 2..=5 {
        result = detector.detect(config(true, 5), JoinEvent::new(1, user_id, user_id * 1_000));
    }

    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(result.join_count, 5);
}

#[test]
fn expired_joins_are_removed_from_the_window() {
    let mut detector = JoinBurstDetector::new();
    let config = JoinBurstConfig::new(true, 3, Duration::from_secs(20));

    detector.detect(config, JoinEvent::new(1, 1, 0));
    detector.detect(config, JoinEvent::new(1, 2, 10_000));
    let result = detector.detect(config, JoinEvent::new(1, 3, 21_000));

    assert_eq!(result.decision, ProtectionDecision::Allow);
    assert_eq!(result.join_count, 2);
}

#[test]
fn guilds_are_tracked_independently() {
    let mut detector = JoinBurstDetector::new();

    for user_id in 1..5 {
        detector.detect(config(true, 5), JoinEvent::new(1, user_id, user_id * 1_000));
    }

    let other_guild = detector.detect(config(true, 5), JoinEvent::new(2, 99, 5_000));
    let first_guild = detector.detect(config(true, 5), JoinEvent::new(1, 5, 5_000));

    assert_eq!(other_guild.decision, ProtectionDecision::Allow);
    assert_eq!(other_guild.join_count, 1);
    assert_eq!(first_guild.decision, ProtectionDecision::Block);
    assert_eq!(first_guild.join_count, 5);
}

#[test]
fn reset_clears_tracked_guilds() {
    let mut detector = JoinBurstDetector::new();
    detector.detect(config(true, 5), JoinEvent::new(1, 1, 1_000));

    detector.reset();

    assert_eq!(detector.tracked_guild_count(), 0);
}
