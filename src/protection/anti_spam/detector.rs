// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::AntiSpamConfig;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiSpamDecision {
    Allow,
    Block,
}

pub fn evaluate(config: AntiSpamConfig, window: MessageWindow) -> AntiSpamDecision {
    if !config.enabled
        || window.elapsed > config.window
        || window.message_count <= config.message_limit
    {
        return AntiSpamDecision::Allow;
    }

    AntiSpamDecision::Block
}
