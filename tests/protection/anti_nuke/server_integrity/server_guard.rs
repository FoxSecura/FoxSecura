// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use poise::serenity_prelude::Permissions;

use foxsecura::protection::{
    ProtectionDecision,
    anti_nuke::server_integrity::server_guard::{
        ActionBurstDetector, ActionBurstDetectorConfig, ActionBurstInput,
        detect_dangerous_permission_change,
    },
};

const WINDOW: Duration = Duration::from_secs(20);

fn event<'a>(
    guild_id: u64,
    executor_id: u64,
    action: &'a str,
    threshold: usize,
    seconds: u64,
) -> ActionBurstInput<'a> {
    ActionBurstInput::new(
        guild_id,
        executor_id,
        action,
        threshold,
        WINDOW,
        Duration::from_secs(seconds),
    )
}

#[test]
fn burst_triggers_exactly_at_threshold() {
    let mut detector = ActionBurstDetector::default();

    assert_eq!(
        detector.detect(event(1, 10, "channel_create", 3, 0)).decision,
        ProtectionDecision::Allow
    );
    assert_eq!(
        detector.detect(event(1, 10, "channel_create", 3, 1)).decision,
        ProtectionDecision::Allow
    );

    let result = detector.detect(event(1, 10, "channel_create", 3, 2));
    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(result.count, 3);
    assert_eq!(result.threshold, 3);
}

#[test]
fn dangerous_permission_additions_are_detected() {
    assert!(detect_dangerous_permission_change(
        Permissions::empty(),
        Permissions::ADMINISTRATOR,
    ));
    assert!(!detect_dangerous_permission_change(
        Permissions::ADMINISTRATOR,
        Permissions::ADMINISTRATOR,
    ));
}

#[test]
fn actions_are_isolated_per_type() {
    let mut detector = ActionBurstDetector::default();

    detector.detect(event(1, 10, "channel_create", 2, 0));
    let role_result = detector.detect(event(1, 10, "role_create", 2, 1));

    assert_eq!(role_result.decision, ProtectionDecision::Allow);
    assert_eq!(role_result.count, 1);
}

#[test]
fn actions_are_isolated_per_executor_and_guild() {
    let mut detector = ActionBurstDetector::default();

    detector.detect(event(1, 10, "channel_create", 2, 0));

    assert_eq!(
        detector.detect(event(1, 11, "channel_create", 2, 1)).count,
        1
    );
    assert_eq!(
        detector.detect(event(2, 10, "channel_create", 2, 1)).count,
        1
    );
}

#[test]
fn expired_actions_leave_the_window() {
    let mut detector = ActionBurstDetector::default();

    detector.detect(event(1, 10, "channel_create", 2, 0));
    let result = detector.detect(event(1, 10, "channel_create", 2, 21));

    assert_eq!(result.decision, ProtectionDecision::Allow);
    assert_eq!(result.count, 1);
}

#[test]
fn reset_clears_all_tracked_actions() {
    let mut detector = ActionBurstDetector::default();
    detector.detect(event(1, 10, "channel_create", 2, 0));
    detector.detect(event(2, 20, "role_create", 2, 0));

    assert_eq!(detector.tracked_key_count(), 2);
    detector.reset();
    assert_eq!(detector.tracked_key_count(), 0);
}

#[test]
fn tracked_key_limit_evicts_an_older_key() {
    let mut detector = ActionBurstDetector::new(ActionBurstDetectorConfig {
        max_tracked_keys: 2,
        sweep_interval: Duration::from_secs(30),
    });

    detector.detect(event(1, 10, "channel_create", 2, 0));
    detector.detect(event(1, 11, "channel_create", 2, 1));
    detector.detect(event(1, 12, "channel_create", 2, 2));

    assert_eq!(detector.tracked_key_count(), 2);
}
