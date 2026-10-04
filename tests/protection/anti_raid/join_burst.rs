// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    ProtectionDecision,
    anti_raid::join_burst::{
        JoinBurstConfig, JoinBurstDetector, JoinEvent, MAX_JOIN_THRESHOLD, MAX_TRACKED_GUILDS,
    },
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

#[test]
fn joins_at_the_threshold_trigger_and_so_do_the_next_ones() {
    let mut detector = JoinBurstDetector::new();
    let config = config(true, 5);
    let results: Vec<bool> = (1..=7)
        .map(|user_id| {
            detector
                .detect(config, JoinEvent::new(1, user_id, user_id * 100))
                .triggered()
        })
        .collect();
    assert_eq!(results, [false, false, false, false, true, true, true]);
}

#[test]
fn a_join_exactly_at_the_window_edge_still_counts() {
    let mut detector = JoinBurstDetector::new();
    let config = JoinBurstConfig::new(true, 2, Duration::from_secs(20));
    detector.detect(config, JoinEvent::new(1, 1, 0));
    assert!(
        detector
            .detect(config, JoinEvent::new(1, 2, 20_000))
            .triggered()
    );
    let mut detector = JoinBurstDetector::new();
    detector.detect(config, JoinEvent::new(1, 1, 0));
    assert!(
        !detector
            .detect(config, JoinEvent::new(1, 2, 20_001))
            .triggered()
    );
}

#[test]
fn tracked_guilds_are_bounded_and_idle_guilds_are_swept_first() {
    assert_eq!(MAX_TRACKED_GUILDS, 10_000);
    let mut detector = JoinBurstDetector::with_capacity(3);
    let config = config(true, 2);

    detector.detect(config, JoinEvent::new(1, 1, 0));
    detector.detect(config, JoinEvent::new(2, 1, 100_000));
    detector.detect(config, JoinEvent::new(3, 1, 130_000));
    assert_eq!(detector.tracked_guild_count(), 3);

    // Guilde 1 inactive depuis plus de 120 s : balayée.
    detector.detect(config, JoinEvent::new(4, 1, 130_500));
    assert_eq!(detector.tracked_guild_count(), 3);
    // La guilde 2 est toujours suivie : sa deuxième arrivée déclenche.
    assert!(
        detector
            .detect(config, JoinEvent::new(2, 2, 110_000))
            .triggered()
    );

    // Toutes actives : la plus ancienne dernière arrivée est oubliée.
    detector.detect(config, JoinEvent::new(5, 1, 131_000));
    assert_eq!(detector.tracked_guild_count(), 3);
    // Guilde 2 oubliée (dernière arrivée à 110 s) : elle repart de zéro.
    assert!(
        !detector
            .detect(config, JoinEvent::new(2, 3, 131_500))
            .triggered()
    );
}

#[test]
fn per_guild_history_is_capped() {
    let mut detector = JoinBurstDetector::new();
    let config = JoinBurstConfig::new(true, 50, Duration::from_secs(120));
    let mut last = None;
    for user_id in 0..500 {
        last = Some(detector.detect(config, JoinEvent::new(1, user_id, user_id)));
    }
    let last = last.unwrap();
    assert_eq!(last.join_count, MAX_JOIN_THRESHOLD as usize);
    assert!(last.triggered(), "le seuil maximal reste atteignable");
}
