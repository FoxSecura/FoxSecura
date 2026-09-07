// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod detector;

pub use detector::{
    AccountIdentity, AntiDoubleAccountDetectionResult, AntiDoubleAccountInput,
    detect_likely_double_account,
};
