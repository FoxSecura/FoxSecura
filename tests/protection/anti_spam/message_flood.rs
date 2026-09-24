// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::logs::{
    ActionCode, ActionStatus, FailureCode, LogSeverity, LogType, SecurityEvidence, ThresholdUnit,
};
use foxsecura::protection::anti_spam::{
    ProtectionDecision,
    message_flood::{
        DeleteMessageOutcome, DeleteMessagePlan, MAX_MESSAGE_THRESHOLD, MAX_WINDOW_SECONDS,
        MESSAGE_FLOOD_MODULE, MIN_MESSAGE_THRESHOLD, MIN_WINDOW_SECONDS, MessageFloodConfig,
        MessageFloodConfigError, MessageFloodTracker, MessageWindow, build_incident, evaluate,
        plan_response,
    },
};
use foxsecura::protection::shared::{
    ActionBurstDetectorConfig, GuildMessage, MessageSnapshot, screen_message,
};

fn config(enabled: bool) -> MessageFloodConfig {
    MessageFloodConfig::new(enabled, 5, 5)
}

fn message(guild_id: u64, author_id: u64, message_id: u64, at_millis: u64) -> GuildMessage {
    GuildMessage {
        guild_id,
        channel_id: 900,
        message_id,
        author_id,
        timestamp: Duration::from_millis(at_millis),
    }
}

/// Envoie `count` messages espacés de `step_millis` et retourne le dernier résultat.
fn send_burst(
    tracker: &mut MessageFloodTracker,
    config: &MessageFloodConfig,
    guild_id: u64,
    author_id: u64,
    count: u64,
    step_millis: u64,
) -> Option<foxsecura::protection::anti_spam::message_flood::MessageFloodDetection> {
    (0..count)
        .map(|index| {
            tracker.observe(
                config,
                &message(guild_id, author_id, index + 1, index * step_millis),
            )
        })
        .last()
        .flatten()
}

// --- Évaluation sans état : même sémantique `count >= seuil` que le runtime ---

#[test]
fn disabled_protection_allows_messages() {
    let decision = evaluate(
        config(false),
        MessageWindow::new(20, Duration::from_secs(1)),
    );

    assert_eq!(decision, ProtectionDecision::Allow);
}

#[test]
fn message_count_below_threshold_is_allowed() {
    let decision = evaluate(config(true), MessageWindow::new(4, Duration::from_secs(5)));

    assert_eq!(decision, ProtectionDecision::Allow);
}

#[test]
fn message_count_at_threshold_is_blocked() {
    let decision = evaluate(config(true), MessageWindow::new(5, Duration::from_secs(5)));

    assert_eq!(decision, ProtectionDecision::Block);
}

#[test]
fn message_count_above_threshold_is_blocked() {
    let decision = evaluate(config(true), MessageWindow::new(6, Duration::from_secs(5)));

    assert_eq!(decision, ProtectionDecision::Block);
}

#[test]
fn messages_outside_the_window_are_allowed() {
    let decision = evaluate(config(true), MessageWindow::new(20, Duration::from_secs(6)));

    assert_eq!(decision, ProtectionDecision::Allow);
}

// --- Configuration ---

#[test]
fn default_config_matches_database_defaults() {
    assert_eq!(
        MessageFloodConfig::default(),
        MessageFloodConfig::new(false, 5, 5)
    );
}

#[test]
fn config_accepts_bounds() {
    assert!(MessageFloodConfig::validated(true, MIN_MESSAGE_THRESHOLD, MIN_WINDOW_SECONDS).is_ok());
    assert!(MessageFloodConfig::validated(true, MAX_MESSAGE_THRESHOLD, MAX_WINDOW_SECONDS).is_ok());
    assert_eq!((MIN_MESSAGE_THRESHOLD, MAX_MESSAGE_THRESHOLD), (2, 50));
    assert_eq!((MIN_WINDOW_SECONDS, MAX_WINDOW_SECONDS), (1, 60));
}

#[test]
fn config_rejects_out_of_range_values() {
    assert_eq!(
        MessageFloodConfig::validated(true, 1, 5),
        Err(MessageFloodConfigError::MessageThresholdOutOfRange(1))
    );
    assert_eq!(
        MessageFloodConfig::validated(true, 51, 5),
        Err(MessageFloodConfigError::MessageThresholdOutOfRange(51))
    );
    assert_eq!(
        MessageFloodConfig::validated(true, 5, 0),
        Err(MessageFloodConfigError::WindowOutOfRange(0))
    );
    assert_eq!(
        MessageFloodConfig::validated(true, 5, 61),
        Err(MessageFloodConfigError::WindowOutOfRange(61))
    );
}

#[test]
fn invalid_limits_message_mentions_the_bounds() {
    for language in [Language::English, Language::French, Language::German] {
        let message = text(language, TextKey::ConfigAntiSpamInvalidLimits);
        for bound in [
            MIN_MESSAGE_THRESHOLD,
            MAX_MESSAGE_THRESHOLD,
            MIN_WINDOW_SECONDS,
            MAX_WINDOW_SECONDS,
        ] {
            assert!(message.contains(&bound.to_string()), "{message}");
        }
    }
}

// --- Détection avec état (runtime) ---

#[test]
fn below_threshold_is_not_triggered() {
    let mut tracker = MessageFloodTracker::default();
    let detection = send_burst(&mut tracker, &config(true), 1, 10, 4, 500).unwrap();

    assert!(!detection.is_triggered());
    assert_eq!(detection.observed, 4);
    assert_eq!(detection.threshold, 5);
}

#[test]
fn reaching_threshold_triggers() {
    let mut tracker = MessageFloodTracker::default();
    let detection = send_burst(&mut tracker, &config(true), 1, 10, 5, 500).unwrap();

    assert!(detection.is_triggered());
    assert_eq!(detection.decision, ProtectionDecision::Block);
    assert_eq!(detection.observed, 5);
    assert_eq!(detection.window_seconds, 5);
}

#[test]
fn expired_messages_leave_the_window() {
    let mut tracker = MessageFloodTracker::default();
    let config = config(true);

    for index in 0..4 {
        tracker.observe(&config, &message(1, 10, index + 1, index * 100));
    }

    // 6 s plus tard, les quatre premiers messages sont hors de la fenêtre de 5 s.
    let detection = tracker.observe(&config, &message(1, 10, 5, 6_300)).unwrap();

    assert!(!detection.is_triggered());
    assert_eq!(detection.observed, 1);
}

#[test]
fn counters_are_isolated_per_guild() {
    let mut tracker = MessageFloodTracker::default();
    let config = config(true);

    send_burst(&mut tracker, &config, 1, 10, 4, 100);
    let other_guild = tracker.observe(&config, &message(2, 10, 99, 500)).unwrap();

    assert!(!other_guild.is_triggered());
    assert_eq!(other_guild.observed, 1);
}

#[test]
fn counters_are_isolated_per_user() {
    let mut tracker = MessageFloodTracker::default();
    let config = config(true);

    send_burst(&mut tracker, &config, 1, 10, 4, 100);
    let other_user = tracker.observe(&config, &message(1, 11, 99, 500)).unwrap();

    assert!(!other_user.is_triggered());
    assert_eq!(other_user.observed, 1);
}

#[test]
fn disabled_config_neither_detects_nor_records() {
    let mut tracker = MessageFloodTracker::default();

    assert_eq!(
        send_burst(&mut tracker, &config(false), 1, 10, 20, 10),
        None
    );
    assert_eq!(tracker.tracked_key_count(), 0);

    let first_enabled = tracker
        .observe(&config(true), &message(1, 10, 100, 300))
        .unwrap();
    assert_eq!(first_enabled.observed, 1);
}

#[test]
fn threshold_and_window_come_from_the_guild_config() {
    let mut tracker = MessageFloodTracker::default();
    let strict = MessageFloodConfig::new(true, 2, 1);

    let detection = send_burst(&mut tracker, &strict, 1, 10, 2, 400).unwrap();

    assert!(detection.is_triggered());
    assert_eq!((detection.threshold, detection.window_seconds), (2, 1));
}

#[test]
fn tracked_keys_are_bounded() {
    let mut tracker = MessageFloodTracker::new(ActionBurstDetectorConfig {
        max_tracked_keys: 3,
        sweep_interval: Duration::from_secs(30),
    });
    let config = config(true);

    for user in 0..10 {
        tracker.observe(&config, &message(1, user, user, user * 10));
    }

    assert_eq!(tracker.tracked_key_count(), 3);
}

// --- Plan d'action et incident ---

#[test]
fn no_action_is_planned_below_threshold() {
    let mut tracker = MessageFloodTracker::default();
    let detection = send_burst(&mut tracker, &config(true), 1, 10, 3, 100).unwrap();

    assert_eq!(plan_response(&message(1, 10, 3, 200), &detection), None);
}

#[test]
fn triggering_message_is_planned_for_deletion() {
    let mut tracker = MessageFloodTracker::default();
    let detection = send_burst(&mut tracker, &config(true), 1, 10, 5, 100).unwrap();

    assert_eq!(
        plan_response(&message(1, 10, 5, 400), &detection),
        Some(DeleteMessagePlan {
            guild_id: 1,
            channel_id: 900,
            message_id: 5,
        })
    );
}

#[test]
fn deleted_outcome_maps_to_success_and_warning() {
    let outcome = DeleteMessageOutcome::Deleted;
    let action = outcome.action_outcome();

    assert_eq!(outcome.as_str(), "deleted");
    assert_eq!(outcome.severity(), LogSeverity::Warning);
    assert_eq!(action.action, ActionCode::DeleteMessage);
    assert_eq!(action.status, ActionStatus::Success);
    assert_eq!(action.failure_code, None);
}

#[test]
fn not_deletable_outcome_maps_to_skipped_missing_permission_and_critical() {
    let outcome = DeleteMessageOutcome::NotDeletable;
    let action = outcome.action_outcome();

    assert_eq!(outcome.as_str(), "not_deletable");
    assert_eq!(outcome.severity(), LogSeverity::Critical);
    assert_eq!(action.status, ActionStatus::Skipped);
    assert_eq!(action.failure_code, Some(FailureCode::MissingPermission));
}

#[test]
fn failed_outcome_maps_to_failed_and_critical() {
    let outcome = DeleteMessageOutcome::Failed {
        failure_code: FailureCode::DiscordUnavailable,
        details: "HTTP 503".to_owned(),
    };
    let action = outcome.action_outcome();

    assert_eq!(outcome.as_str(), "failed");
    assert_eq!(outcome.severity(), LogSeverity::Critical);
    assert_eq!(action.status, ActionStatus::Failed);
    assert_eq!(action.failure_code, Some(FailureCode::DiscordUnavailable));
    assert_eq!(action.details.as_deref(), Some("HTTP 503"));
}

#[test]
fn http_failures_are_classified() {
    assert_eq!(
        DeleteMessageOutcome::from_http_status(403, "Missing Permissions"),
        DeleteMessageOutcome::NotDeletable
    );

    for (status, code) in [
        (404, FailureCode::ResourceMissing),
        (429, FailureCode::DiscordUnavailable),
        (502, FailureCode::DiscordUnavailable),
        (400, FailureCode::Unknown),
    ] {
        match DeleteMessageOutcome::from_http_status(status, "error") {
            DeleteMessageOutcome::Failed { failure_code, .. } => assert_eq!(failure_code, code),
            other => panic!("statut {status} mal classé : {other:?}"),
        }
    }
}

#[test]
fn incident_carries_evidence_and_review_recommendation_when_deleted() {
    let trigger = message(1, 10, 5, 400);
    let mut tracker = MessageFloodTracker::default();
    let detection = send_burst(&mut tracker, &config(true), 1, 10, 5, 100).unwrap();

    let incident = build_incident(
        Language::French,
        &trigger,
        &detection,
        &DeleteMessageOutcome::Deleted,
    );

    assert!(incident.validate().is_ok());
    assert_eq!(incident.module, MESSAGE_FLOOD_MODULE);
    assert_eq!(incident.log_type, LogType::Message);
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(
        incident.evidence,
        vec![SecurityEvidence::Threshold {
            observed: 5,
            threshold: 5,
            window_seconds: Some(5),
            unit: ThresholdUnit::Messages,
        }]
    );
    assert_eq!(
        incident.recommendation.as_deref(),
        Some(text(
            Language::French,
            TextKey::AntiSpamRecommendationReviewMember
        ))
    );
    assert_eq!(incident.actor.as_ref().unwrap().user_id, "10");
    let location = incident.location.as_ref().unwrap();
    assert_eq!(location.channel_id.as_deref(), Some("900"));
    assert_eq!(location.message_id.as_deref(), Some("5"));
}

#[test]
fn incident_recommends_checking_permissions_when_not_deleted() {
    let trigger = message(1, 10, 5, 400);
    let mut tracker = MessageFloodTracker::default();
    let detection = send_burst(&mut tracker, &config(true), 1, 10, 5, 100).unwrap();

    for outcome in [
        DeleteMessageOutcome::NotDeletable,
        DeleteMessageOutcome::Failed {
            failure_code: FailureCode::Unknown,
            details: "boom".to_owned(),
        },
    ] {
        let incident = build_incident(Language::English, &trigger, &detection, &outcome);

        assert!(incident.validate().is_ok());
        assert_eq!(incident.severity, LogSeverity::Critical);
        assert_eq!(
            incident.recommendation.as_deref(),
            Some(text(
                Language::English,
                TextKey::AntiSpamRecommendationCheckPermissions
            ))
        );
    }
}

#[test]
fn pure_pipeline_ignores_bots_and_triggers_on_members() {
    let mut tracker = MessageFloodTracker::default();
    let config = config(true);
    let snapshot = |message_id: u64, author_is_bot: bool| MessageSnapshot {
        guild_id: Some(1),
        channel_id: 900,
        message_id,
        author_id: 10,
        author_is_bot,
        webhook_id: None,
        timestamp: Duration::from_millis(message_id * 100),
    };

    let mut planned = Vec::new();
    for message_id in 1..=10 {
        let author_is_bot = message_id <= 5;
        let Ok(guild_message) = screen_message(&snapshot(message_id, author_is_bot)) else {
            continue;
        };
        let detection = tracker.observe(&config, &guild_message).unwrap();
        planned.extend(plan_response(&guild_message, &detection));
    }

    // Les 5 messages de bot sont ignorés ; le 5e message du membre déclenche.
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].message_id, 10);
}
