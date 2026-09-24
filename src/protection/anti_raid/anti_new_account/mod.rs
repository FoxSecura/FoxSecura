// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod detector;

pub use detector::{
    AntiNewAccountDetectionResult, AntiNewAccountInput, DEFAULT_MIN_ACCOUNT_AGE_DAYS,
    MIN_ACCOUNT_AGE_DAYS_RANGE, detect_new_account, is_valid_min_account_age_days,
};
