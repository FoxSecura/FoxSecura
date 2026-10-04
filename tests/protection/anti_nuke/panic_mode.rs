// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, LogSeverity, LogType, SecurityEvidence, ThresholdUnit};
use foxsecura::protection::anti_nuke::panic_mode::{
    DEFAULT_CORRELATION_WINDOW, DEFAULT_LOCKDOWN_DURATION, DEFAULT_LOCKDOWN_SLOWMODE_SECONDS,
    PanicDecision, PanicModeConfig, PanicModeDetector, panic_incident,
};
use foxsecura::protection::lockdown::{LockdownOutcome, LockdownReason};

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

#[test]
fn panic_mode_counts_distinct_protection_types() {
    let mut detector = PanicModeDetector::default();

    assert!(
        !detector
            .record(1, "ban", Duration::from_secs(0))
            .triggered()
    );
    assert!(
        !detector
            .record(1, "ban", Duration::from_secs(1))
            .triggered()
    );
    assert!(
        !detector
            .record(1, "role_delete", Duration::from_secs(2))
            .triggered()
    );
    let result = detector.record(1, "channel_delete", Duration::from_secs(3));

    assert!(result.triggered());
    assert_eq!(result.distinct_types, 3);
}

#[test]
fn expired_signals_do_not_contribute() {
    let mut detector = PanicModeDetector::new(PanicModeConfig {
        signal_threshold: 2,
        correlation_window: Duration::from_secs(5),
    });

    detector.record(1, "ban", Duration::from_secs(0));
    let result = detector.record(1, "role_delete", Duration::from_secs(6));

    assert!(!result.triggered());
    assert_eq!(result.distinct_types, 1);
}

#[test]
fn v1_defaults() {
    assert_eq!(DEFAULT_CORRELATION_WINDOW, secs(30));
    assert_eq!(DEFAULT_LOCKDOWN_DURATION, secs(15 * 60));
    assert_eq!(DEFAULT_LOCKDOWN_SLOWMODE_SECONDS, 30);
    assert_eq!(
        DEFAULT_LOCKDOWN_DURATION,
        LockdownReason::PanicMode.duration()
    );
    assert_eq!(
        DEFAULT_LOCKDOWN_SLOWMODE_SECONDS,
        LockdownReason::PanicMode.slowmode_seconds()
    );
}

#[test]
fn one_noisy_module_never_triggers_panic() {
    let mut detector = PanicModeDetector::default();
    for second in 0..20 {
        let result = detector.record_with(1, "anti_mass_ban", secs(second), 3, false);
        assert_eq!(result.decision, PanicDecision::Below);
        assert_eq!(result.distinct_types, 1);
    }
}

#[test]
fn the_threshold_is_the_guild_setting() {
    for threshold in [2_usize, 3, 10] {
        let mut detector = PanicModeDetector::default();
        for index in 0..threshold - 1 {
            let result = detector.record_with(
                1,
                format!("module_{index}"),
                secs(index as u64),
                threshold,
                false,
            );
            assert_eq!(result.decision, PanicDecision::Below, "{threshold}");
        }
        let result = detector.record_with(1, "last", secs(threshold as u64), threshold, false);
        assert_eq!(result.decision, PanicDecision::Trigger, "{threshold}");
        assert_eq!(result.distinct_types, threshold);
        assert_eq!(result.threshold, threshold);
    }
}

#[test]
fn signals_are_correlated_over_thirty_seconds_per_guild() {
    let mut detector = PanicModeDetector::default();
    detector.record_with(1, "anti_mass_ban", secs(0), 3, false);
    detector.record_with(1, "anti_mass_role_create", secs(10), 3, false);
    // Autre guilde : jamais cumulée.
    assert_eq!(
        detector
            .record_with(2, "anti_mass_kick", secs(11), 3, false)
            .distinct_types,
        1
    );
    // 31 s après le premier signal : il est sorti de la fenêtre.
    let result = detector.record_with(1, "anti_mass_kick", secs(31), 3, false);
    assert_eq!(result.decision, PanicDecision::Below);
    assert_eq!(result.distinct_types, 2);
    // Exactement 30 s après le deuxième : encore dans la fenêtre.
    let result = detector.record_with(1, "anti_mass_unban", secs(40), 3, false);
    assert_eq!(result.decision, PanicDecision::Trigger);
    assert_eq!(
        result.kinds,
        ["anti_mass_kick", "anti_mass_role_create", "anti_mass_unban"]
    );
}

#[test]
fn a_trigger_resets_the_guild_signals() {
    let mut detector = PanicModeDetector::default();
    for (index, kind) in ["a", "b", "c"].into_iter().enumerate() {
        detector.record_with(1, kind, secs(index as u64), 3, false);
    }
    assert_eq!(detector.tracked_guilds(), 0);
    // Les signaux suivants repartent de zéro : pas de second verrouillage
    // au signal suivant.
    let result = detector.record_with(1, "a", secs(4), 3, false);
    assert_eq!(result.decision, PanicDecision::Below);
    assert_eq!(result.distinct_types, 1);
}

#[test]
fn an_active_lockdown_is_never_relaunched() {
    let mut detector = PanicModeDetector::default();
    detector.record_with(1, "a", secs(0), 3, true);
    detector.record_with(1, "b", secs(1), 3, true);
    let result = detector.record_with(1, "c", secs(2), 3, true);
    assert_eq!(result.decision, PanicDecision::LockdownActive);
    assert!(!result.triggered());
    // Les signaux sont gardés : levé entre-temps, le verrouillage est posé
    // au signal suivant de la fenêtre.
    let result = detector.record_with(1, "a", secs(3), 3, false);
    assert_eq!(result.decision, PanicDecision::Trigger);
}

#[test]
fn panic_incident_is_critical_and_explains_the_correlation() {
    let mut detector = PanicModeDetector::default();
    detector.record_with(7, "anti_mass_ban", secs(0), 2, false);
    let result = detector.record_with(7, "anti_mass_role_grant", secs(1), 2, false);
    let incident = panic_incident(
        Language::French,
        7,
        &result,
        &LockdownOutcome::already_active(4),
    );

    assert_eq!(incident.module, "panic_mode");
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert_eq!(incident.log_type, LogType::Server);
    assert_eq!(incident.actions[0].action, ActionCode::ApplyLockdown);
    assert!(incident.evidence.contains(&SecurityEvidence::Threshold {
        observed: 2,
        threshold: 2,
        window_seconds: Some(30),
        unit: ThresholdUnit::Signals,
    }));
    assert!(incident.evidence.iter().any(|evidence| matches!(
        evidence,
        SecurityEvidence::Text { value, .. } if value == "anti_mass_ban, anti_mass_role_grant"
    )));
    assert!(incident.validate().is_ok());
}
