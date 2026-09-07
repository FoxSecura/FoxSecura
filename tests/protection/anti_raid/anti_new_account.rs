// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::anti_raid::anti_new_account::{
    AntiNewAccountInput, detect_new_account,
};

#[test]
fn detects_accounts_younger_than_minimum_age() {
    let result = detect_new_account(AntiNewAccountInput {
        account_created_at: Duration::from_secs(0),
        joined_at: Duration::from_secs(2 * 24 * 60 * 60),
        min_age_days: 7,
    });

    assert!(result.triggered);
    assert_eq!(result.account_age_days, 2);
}

#[test]
fn accepts_account_exactly_at_minimum_age() {
    let result = detect_new_account(AntiNewAccountInput {
        account_created_at: Duration::from_secs(0),
        joined_at: Duration::from_secs(7 * 24 * 60 * 60),
        min_age_days: 7,
    });

    assert!(!result.triggered);
}
