// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoistingDetectionResult {
    pub triggered: bool,
    pub cleaned: String,
}

pub fn detect_hoisted_name(name: &str) -> HoistingDetectionResult {
    let trimmed = name.trim();
    let cleaned = trimmed
        .trim_start_matches(|character: char| !character.is_alphanumeric())
        .trim()
        .to_owned();

    HoistingDetectionResult {
        triggered: cleaned != trimmed,
        cleaned,
    }
}
