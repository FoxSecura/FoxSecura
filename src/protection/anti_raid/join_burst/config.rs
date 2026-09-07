// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinBurstConfig {
    pub enabled: bool,
    pub threshold: usize,
    pub window: Duration,
}

impl JoinBurstConfig {
    pub const fn new(enabled: bool, threshold: usize, window: Duration) -> Self {
        Self {
            enabled,
            threshold: if threshold == 0 { 1 } else { threshold },
            window,
        }
    }
}

impl Default for JoinBurstConfig {
    fn default() -> Self {
        Self::new(false, 5, Duration::from_secs(20))
    }
}
