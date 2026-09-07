// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::anti_nuke::panic_mode::{PanicModeConfig, PanicModeDetector};

#[test]
fn panic_mode_counts_distinct_protection_types() {
    let mut detector = PanicModeDetector::default();

    assert!(!detector.record(1, "ban", Duration::from_secs(0)).triggered);
    assert!(!detector.record(1, "ban", Duration::from_secs(1)).triggered);
    assert!(!detector.record(1, "role_delete", Duration::from_secs(2)).triggered);
    let result = detector.record(1, "channel_delete", Duration::from_secs(3));

    assert!(result.triggered);
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

    assert!(!result.triggered);
    assert_eq!(result.distinct_types, 1);
}
