// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiBotDetectionResult {
    pub triggered: bool,
}

pub const fn detect_bot_join(is_bot: bool) -> AntiBotDetectionResult {
    AntiBotDetectionResult { triggered: is_bot }
}
