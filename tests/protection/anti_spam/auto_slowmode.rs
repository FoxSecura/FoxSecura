// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    anti_spam::auto_slowmode::AutoSlowmodeDetector,
    shared::ProtectionDecision,
};

#[test]
fn channel_burst_triggers_slowmode_signal() {
    let mut detector = AutoSlowmodeDetector::new(3, Duration::from_secs(7));
    assert_eq!(detector.record(1, 10, Duration::from_secs(0)).decision, ProtectionDecision::Allow);
    assert_eq!(detector.record(1, 10, Duration::from_secs(1)).decision, ProtectionDecision::Allow);
    assert_eq!(detector.record(1, 10, Duration::from_secs(2)).decision, ProtectionDecision::Block);
}

#[test]
fn channels_are_isolated() {
    let mut detector = AutoSlowmodeDetector::new(2, Duration::from_secs(7));
    detector.record(1, 10, Duration::ZERO);
    assert_eq!(detector.record(1, 11, Duration::from_secs(1)).decision, ProtectionDecision::Allow);
}
