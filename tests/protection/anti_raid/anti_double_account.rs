// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_raid::anti_double_account::{
    AccountIdentity, AntiDoubleAccountInput, detect_likely_double_account,
};

#[test]
fn requires_display_name_and_custom_avatar_to_match() {
    let existing = [AccountIdentity::new(10, Some("Fox"), Some("avatar-a"))];
    let result = detect_likely_double_account(AntiDoubleAccountInput {
        user_id: 20,
        display_name: Some(" fox "),
        avatar_hash: Some("avatar-a"),
        existing_identities: &existing,
    });

    assert!(result.triggered);
    assert_eq!(result.matched_user_id, Some(10));
}

#[test]
fn shared_display_name_alone_is_not_enough() {
    let existing = [AccountIdentity::new(10, Some("Fox"), Some("avatar-a"))];
    let result = detect_likely_double_account(AntiDoubleAccountInput {
        user_id: 20,
        display_name: Some("Fox"),
        avatar_hash: Some("avatar-b"),
        existing_identities: &existing,
    });

    assert!(!result.triggered);
}

#[test]
fn never_matches_the_same_user() {
    let existing = [AccountIdentity::new(10, Some("Fox"), Some("avatar-a"))];
    let result = detect_likely_double_account(AntiDoubleAccountInput {
        user_id: 10,
        display_name: Some("Fox"),
        avatar_hash: Some("avatar-a"),
        existing_identities: &existing,
    });

    assert!(!result.triggered);
}
