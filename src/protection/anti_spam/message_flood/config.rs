// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageFloodConfig {
    pub enabled: bool,
    pub message_limit: usize,
    pub window: Duration,
}

impl MessageFloodConfig {
    pub const fn new(enabled: bool, message_limit: usize, window: Duration) -> Self {
        Self {
            enabled,
            message_limit,
            window,
        }
    }
}

impl Default for MessageFloodConfig {
    fn default() -> Self {
        Self::new(false, 5, Duration::from_secs(5))
    }
}
