// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

const DAY_SECONDS: u64 = 24 * 60 * 60;

/// Âge minimal par défaut d'un compte, en jours (V1).
pub const DEFAULT_MIN_ACCOUNT_AGE_DAYS: u16 = 7;

/// Bornes de l'âge minimal réglable, en jours (V1).
pub const MIN_ACCOUNT_AGE_DAYS_RANGE: std::ops::RangeInclusive<u16> = 1..=365;

/// Indique si un âge minimal est dans les bornes de la V1.
pub fn is_valid_min_account_age_days(days: u16) -> bool {
    MIN_ACCOUNT_AGE_DAYS_RANGE.contains(&days)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiNewAccountInput {
    pub account_created_at: Duration,
    pub joined_at: Duration,
    pub min_age_days: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiNewAccountDetectionResult {
    pub triggered: bool,
    /// Âge exact à l'arrivée (0 si l'horloge est incohérente).
    pub account_age: Duration,
    /// Âge en jours entiers, arrondi à l'inférieur : un compte de 6 jours et
    /// 23 heures a 6 jours.
    pub account_age_days: u64,
    pub min_age_days: u64,
}

pub fn detect_new_account(input: AntiNewAccountInput) -> AntiNewAccountDetectionResult {
    let account_age = input.joined_at.saturating_sub(input.account_created_at);
    let account_age_days = account_age.as_secs() / DAY_SECONDS;

    AntiNewAccountDetectionResult {
        triggered: account_age_days < input.min_age_days,
        account_age,
        account_age_days,
        min_age_days: input.min_age_days,
    }
}
