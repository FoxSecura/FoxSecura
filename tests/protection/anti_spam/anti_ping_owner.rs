// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::{
    anti_spam::anti_ping_owner::{AntiPingOwnerDetector, AntiPingOwnerInput},
    shared::ProtectionDecision,
};

fn input(timestamp: u64) -> AntiPingOwnerInput {
    AntiPingOwnerInput {
        enabled: true,
        author_is_bot: false,
        author_is_owner: false,
        mentions_owner: true,
        guild_id: 1,
        author_id: 2,
        timestamp: Duration::from_secs(timestamp),
        threshold: None,
        window: None,
    }
}

#[test]
fn blocks_repeated_owner_pings_at_threshold() {
    let mut detector = AntiPingOwnerDetector::default();
    assert_eq!(detector.detect(input(0)).decision, ProtectionDecision::Allow);
    assert_eq!(detector.detect(input(1)).decision, ProtectionDecision::Allow);
    assert_eq!(detector.detect(input(2)).decision, ProtectionDecision::Block);
}

#[test]
fn ignores_owner_and_bot_authors() {
    let mut detector = AntiPingOwnerDetector::default();
    let mut owner = input(0);
    owner.author_is_owner = true;
    assert_eq!(detector.detect(owner).ping_count, 0);

    let mut bot = input(1);
    bot.author_is_bot = true;
    assert_eq!(detector.detect(bot).ping_count, 0);
}
