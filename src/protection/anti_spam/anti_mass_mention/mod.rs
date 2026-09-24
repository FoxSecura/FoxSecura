// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod detector;

pub use detector::{
    AntiMassMentionDetectionResult, DEFAULT_MASS_MENTION_THRESHOLD, detect_mass_mention,
};
