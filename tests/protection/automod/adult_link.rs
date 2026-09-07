// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::{ProtectionDecision, automod::adult_link::detect_adult_link};

#[test]
fn detects_known_adult_domain() {
    let result = detect_adult_link("https://www.pornhub.com/view_video.php?id=1");

    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(result.matched_domain.as_deref(), Some("www.pornhub.com"));
}

#[test]
fn detects_adult_top_level_domain() {
    let result = detect_adult_link("https://example.xxx/content");

    assert_eq!(result.decision, ProtectionDecision::Block);
}

#[test]
fn detects_adult_signal_in_path() {
    let result = detect_adult_link("https://example.com/onlyfans/profile");

    assert_eq!(result.decision, ProtectionDecision::Block);
}

#[test]
fn ignores_unrelated_domain() {
    let result = detect_adult_link("https://example.com/documentation");

    assert_eq!(result.decision, ProtectionDecision::Allow);
    assert!(result.matched_domain.is_none());
}

#[test]
fn avoids_not_prefixed_compound_false_positive() {
    let result = detect_adult_link("https://notpornhub.example/page");

    assert_eq!(result.decision, ProtectionDecision::Allow);
}
