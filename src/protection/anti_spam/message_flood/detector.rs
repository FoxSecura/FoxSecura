// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::MessageFloodConfig;
use crate::protection::anti_spam::shared::ProtectionDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageWindow {
    pub message_count: usize,
    pub elapsed: Duration,
}

impl MessageWindow {
    pub const fn new(message_count: usize, elapsed: Duration) -> Self {
        Self {
            message_count,
            elapsed,
        }
    }
}

pub fn evaluate(config: MessageFloodConfig, window: MessageWindow) -> ProtectionDecision {
    if !config.enabled
        || window.elapsed > config.window
        || window.message_count <= config.message_limit
    {
        return ProtectionDecision::Allow;
    }

    ProtectionDecision::Block
}
