// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

const DAY_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiNewAccountInput {
    pub account_created_at: Duration,
    pub joined_at: Duration,
    pub min_age_days: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiNewAccountDetectionResult {
    pub triggered: bool,
    pub account_age_days: u64,
    pub min_age_days: u64,
}

pub fn detect_new_account(input: AntiNewAccountInput) -> AntiNewAccountDetectionResult {
    let account_age_days = input
        .joined_at
        .saturating_sub(input.account_created_at)
        .as_secs()
        / DAY_SECONDS;

    AntiNewAccountDetectionResult {
        triggered: account_age_days < input.min_age_days,
        account_age_days,
        min_age_days: input.min_age_days,
    }
}
