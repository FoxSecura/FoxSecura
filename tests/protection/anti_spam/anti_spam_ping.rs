// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    anti_spam::anti_spam_ping::{
        AntiSpamPingDetector, AntiSpamPingInput, MentionTarget, MentionTargetKind,
    },
    shared::ProtectionDecision,
};

fn detect(detector: &mut AntiSpamPingDetector, target: MentionTarget, timestamp: u64) -> ProtectionDecision {
    detector
        .detect(AntiSpamPingInput {
            enabled: true,
            author_is_bot: false,
            guild_id: 1,
            author_id: 2,
            targets: &[target],
            timestamp: Duration::from_secs(timestamp),
            threshold: None,
            window: None,
        })
        .decision
}

#[test]
fn repeated_same_target_blocks() {
    let mut detector = AntiSpamPingDetector::default();
    let target = MentionTarget { kind: MentionTargetKind::User, id: 9 };
    assert_eq!(detect(&mut detector, target, 0), ProtectionDecision::Allow);
    assert_eq!(detect(&mut detector, target, 1), ProtectionDecision::Allow);
    assert_eq!(detect(&mut detector, target, 2), ProtectionDecision::Block);
}

#[test]
fn different_targets_are_isolated() {
    let mut detector = AntiSpamPingDetector::default();
    let first = MentionTarget { kind: MentionTargetKind::User, id: 9 };
    let second = MentionTarget { kind: MentionTargetKind::User, id: 10 };
    assert_eq!(detect(&mut detector, first, 0), ProtectionDecision::Allow);
    assert_eq!(detect(&mut detector, first, 1), ProtectionDecision::Allow);
    assert_eq!(detect(&mut detector, second, 2), ProtectionDecision::Allow);
}
