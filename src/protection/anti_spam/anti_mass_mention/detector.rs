// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

pub const DEFAULT_MASS_MENTION_THRESHOLD: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiMassMentionDetectionResult {
    pub triggered: bool,
    pub mention_count: usize,
    pub threshold: usize,
}

pub fn detect_mass_mention(
    mention_count: usize,
    threshold: Option<usize>,
) -> AntiMassMentionDetectionResult {
    let threshold = threshold.unwrap_or(DEFAULT_MASS_MENTION_THRESHOLD).max(1);

    AntiMassMentionDetectionResult {
        triggered: mention_count >= threshold,
        mention_count,
        threshold,
    }
}
