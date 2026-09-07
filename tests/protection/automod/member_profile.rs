// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::automod::{
    anti_invite::INVITE_PATTERNS,
    member_profile::{PROFILE_LURE_KEYWORDS, profile_filter_keywords},
};

#[test]
fn profile_filter_reuses_invite_patterns() {
    let keywords = profile_filter_keywords();

    for pattern in INVITE_PATTERNS {
        assert!(keywords.iter().any(|keyword| keyword == pattern));
    }
}

#[test]
fn profile_filter_contains_specific_scam_lures() {
    let keywords = profile_filter_keywords();

    assert!(PROFILE_LURE_KEYWORDS.contains(&"free nitro"));
    assert!(keywords.iter().any(|keyword| keyword == "crypto giveaway"));
    assert!(keywords.iter().any(|keyword| keyword == "bit.ly/*"));
}
