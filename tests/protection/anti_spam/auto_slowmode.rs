// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    anti_spam::auto_slowmode::AutoSlowmodeDetector, shared::ProtectionDecision,
};

#[test]
fn channel_burst_triggers_slowmode_signal() {
    let mut detector = AutoSlowmodeDetector::new(3, Duration::from_secs(7));
    assert_eq!(
        detector.record(1, 10, Duration::from_secs(0)).decision,
        ProtectionDecision::Allow
    );
    assert_eq!(
        detector.record(1, 10, Duration::from_secs(1)).decision,
        ProtectionDecision::Allow
    );
    assert_eq!(
        detector.record(1, 10, Duration::from_secs(2)).decision,
        ProtectionDecision::Block
    );
}

#[test]
fn channels_are_isolated() {
    let mut detector = AutoSlowmodeDetector::new(2, Duration::from_secs(7));
    detector.record(1, 10, Duration::ZERO);
    assert_eq!(
        detector.record(1, 11, Duration::from_secs(1)).decision,
        ProtectionDecision::Allow
    );
}

// --- Tranche 10 : seuils, pose et levée ---

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, LogSeverity, SecurityEvidence, ThresholdUnit};
use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use foxsecura::protection::anti_spam::auto_slowmode::{
    AUTO_SLOWMODE_LIFT_DELAY, AUTO_SLOWMODE_RETRY_INTERVAL, AUTO_SLOWMODE_SECONDS,
    AUTO_SLOWMODE_THRESHOLD, AUTO_SLOWMODE_WINDOW, AutoSlowmode, SlowmodeChannel,
    SlowmodeIncidentInput, SlowmodeLift, SlowmodePlan, SlowmodeSkip, auto_slowmode_audit_reason,
    auto_slowmode_restore_reason, due_rows, lift_deadline, plan_slowmode, plan_slowmode_lift,
    slowmode_incident,
};
use foxsecura::protection::shared::is_foxsecura_audit_reason;

#[test]
fn default_burst_is_twelve_messages_in_seven_seconds_per_channel() {
    assert_eq!(AUTO_SLOWMODE_THRESHOLD, 12);
    assert_eq!(AUTO_SLOWMODE_WINDOW, Duration::from_secs(7));
    let mut detector = AutoSlowmodeDetector::default();
    for index in 0..11 {
        assert_eq!(
            detector
                .record(1, 10, Duration::from_millis(index * 600))
                .decision,
            ProtectionDecision::Allow
        );
    }
    // Douzième message à 7 s pile du premier : encore dans la fenêtre.
    let twelfth = detector.record(1, 10, Duration::from_secs(7));
    assert_eq!(twelfth.decision, ProtectionDecision::Block);
    assert_eq!(twelfth.count, 12);
    // Un autre salon, ou une autre guilde : rien.
    assert_eq!(
        detector.record(1, 11, Duration::from_secs(7)).decision,
        ProtectionDecision::Allow
    );
    assert_eq!(
        detector.record(2, 10, Duration::from_secs(7)).decision,
        ProtectionDecision::Allow
    );
}

#[test]
fn messages_spread_beyond_the_window_never_trigger() {
    let mut detector = AutoSlowmodeDetector::default();
    for index in 0..30 {
        // Un message toutes les 0,64 s : 11 messages par fenêtre de 7 s au plus.
        assert_eq!(
            detector
                .record(1, 10, Duration::from_millis(index * 640))
                .decision,
            ProtectionDecision::Allow,
            "message {index}"
        );
    }
}

#[test]
fn slowmode_is_never_reduced_nor_applied_during_a_lockdown() {
    assert_eq!(AUTO_SLOWMODE_SECONDS, 10);
    assert_eq!(
        plan_slowmode(0, false),
        SlowmodePlan::Apply {
            previous: 0,
            applied: 10
        }
    );
    assert_eq!(
        plan_slowmode(9, false),
        SlowmodePlan::Apply {
            previous: 9,
            applied: 10
        }
    );
    assert_eq!(
        plan_slowmode(10, false),
        SlowmodePlan::Skip(SlowmodeSkip::AlreadySlow { current: 10 })
    );
    assert_eq!(
        plan_slowmode(600, false),
        SlowmodePlan::Skip(SlowmodeSkip::AlreadySlow { current: 600 })
    );
    assert_eq!(
        plan_slowmode(0, true),
        SlowmodePlan::Skip(SlowmodeSkip::LockdownActive)
    );
}

fn row(previous: u16, lift_at: u64) -> AutoSlowmode {
    AutoSlowmode {
        guild_id: 1,
        channel_id: 10,
        previous_seconds: previous,
        applied_seconds: 10,
        lift_at,
    }
}

#[test]
fn lift_is_ninety_seconds_after_the_last_trigger_and_retries_every_thirty() {
    assert_eq!(AUTO_SLOWMODE_LIFT_DELAY, Duration::from_secs(90));
    assert_eq!(AUTO_SLOWMODE_RETRY_INTERVAL, Duration::from_secs(30));
    assert_eq!(lift_deadline(1_000), 1_090);

    let row = row(3, lift_deadline(1_000));
    assert_eq!(
        plan_slowmode_lift(&row, 1_089, SlowmodeChannel::Current(10), false),
        SlowmodeLift::NotDue
    );
    assert_eq!(
        plan_slowmode_lift(&row, 1_090, SlowmodeChannel::Current(10), false),
        SlowmodeLift::Restore { seconds: 3 }
    );
    // Salon illisible : nouvelle tentative 30 s plus tard.
    assert_eq!(
        plan_slowmode_lift(&row, 1_100, SlowmodeChannel::Unavailable, false),
        SlowmodeLift::Postpone { lift_at: 1_130 }
    );
}

#[test]
fn a_continuing_burst_postpones_the_lift() {
    // Chaque déclenchement repousse l'échéance (`MAX` en base) : à 1 080 s,
    // un nouveau déclenchement repousse la levée de 1 090 à 1 170.
    let first = lift_deadline(1_000);
    let later = lift_deadline(1_080).max(first);
    let row = row(0, later);
    assert_eq!(
        plan_slowmode_lift(&row, first, SlowmodeChannel::Current(10), false),
        SlowmodeLift::NotDue
    );
    assert_eq!(
        plan_slowmode_lift(&row, 1_170, SlowmodeChannel::Current(10), false),
        SlowmodeLift::Restore { seconds: 0 }
    );
}

#[test]
fn lift_restores_only_if_the_channel_still_has_the_applied_slowmode() {
    let row = row(2, 100);
    assert_eq!(
        plan_slowmode_lift(&row, 100, SlowmodeChannel::Current(30), false),
        SlowmodeLift::LeaveChanged { current: 30 }
    );
    assert_eq!(
        plan_slowmode_lift(&row, 100, SlowmodeChannel::Current(0), false),
        SlowmodeLift::LeaveChanged { current: 0 }
    );
    assert_eq!(
        plan_slowmode_lift(&row, 100, SlowmodeChannel::Missing, false),
        SlowmodeLift::ChannelMissing
    );
}

#[test]
fn lift_waits_for_an_active_lockdown() {
    let row = row(0, 100);
    assert_eq!(
        plan_slowmode_lift(&row, 120, SlowmodeChannel::Current(10), true),
        SlowmodeLift::Postpone { lift_at: 150 }
    );
}

#[test]
fn resume_after_restart_lifts_every_overdue_row_by_deadline() {
    let rows = [row(0, 500), row(0, 100), row(0, 900)];
    let due: Vec<u64> = due_rows(&rows, 600).iter().map(|row| row.lift_at).collect();
    assert_eq!(due, vec![100, 500]);
}

#[test]
fn audit_reasons_follow_the_foxsecura_convention() {
    assert_eq!(
        auto_slowmode_audit_reason(),
        "FoxSecura Auto Slowmode: channel burst"
    );
    assert!(is_foxsecura_audit_reason(&auto_slowmode_audit_reason()));
    assert!(is_foxsecura_audit_reason(&auto_slowmode_restore_reason()));
}

#[test]
fn slowmode_incident_is_a_warning_with_the_burst_and_the_change() {
    let input = SlowmodeIncidentInput {
        guild_id: 1,
        channel_id: 10,
        observed: 12,
        threshold: 12,
        previous_seconds: 0,
        applied_seconds: 10,
    };
    let applied = slowmode_incident(Language::French, input, &IntegrityActionResult::Applied);
    assert_eq!(applied.module, "auto_slowmode");
    assert_eq!(applied.severity, LogSeverity::Warning);
    assert_eq!(applied.actions[0].action, ActionCode::ApplySlowmode);
    assert_eq!(applied.actions[0].status, ActionStatus::Success);
    assert!(applied.evidence.contains(&SecurityEvidence::Threshold {
        observed: 12,
        threshold: 12,
        window_seconds: Some(7),
        unit: ThresholdUnit::Messages,
    }));
    assert!(applied.validate().is_ok());

    let failed = slowmode_incident(
        Language::French,
        input,
        &IntegrityActionResult::Failed {
            failure_code: foxsecura::logs::FailureCode::MissingPermission,
            details: "403".to_owned(),
        },
    );
    assert_eq!(failed.actions[0].status, ActionStatus::Failed);
    assert_ne!(failed.recommendation, applied.recommendation);
}
