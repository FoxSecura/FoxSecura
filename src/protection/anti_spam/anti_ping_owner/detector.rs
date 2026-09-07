// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::protection::shared::{ActionBurstDetector, ActionBurstInput, ProtectionDecision};

const ACTION_KEY: &str = "anti_ping_owner";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiPingOwnerInput {
    pub enabled: bool,
    pub author_is_bot: bool,
    pub author_is_owner: bool,
    pub mentions_owner: bool,
    pub guild_id: u64,
    pub author_id: u64,
    pub timestamp: Duration,
    pub threshold: Option<usize>,
    pub window: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiPingOwnerResult {
    pub decision: ProtectionDecision,
    pub ping_count: usize,
    pub threshold: usize,
    pub window: Duration,
}

#[derive(Debug)]
pub struct AntiPingOwnerDetector {
    burst: ActionBurstDetector,
    threshold: usize,
    window: Duration,
}

impl Default for AntiPingOwnerDetector {
    fn default() -> Self {
        Self {
            burst: ActionBurstDetector::default(),
            threshold: 3,
            window: Duration::from_secs(30),
        }
    }
}

impl AntiPingOwnerDetector {
    pub fn detect(&mut self, input: AntiPingOwnerInput) -> AntiPingOwnerResult {
        let threshold = input.threshold.unwrap_or(self.threshold).max(1);
        let window = input.window.unwrap_or(self.window);

        if !input.enabled || input.author_is_bot || input.author_is_owner || !input.mentions_owner {
            return AntiPingOwnerResult {
                decision: ProtectionDecision::Allow,
                ping_count: 0,
                threshold,
                window,
            };
        }

        let result = self.burst.detect(ActionBurstInput::new(
            input.guild_id,
            input.author_id,
            ACTION_KEY,
            threshold,
            window,
            input.timestamp,
        ));

        AntiPingOwnerResult {
            decision: result.decision,
            ping_count: result.count,
            threshold,
            window,
        }
    }

    pub fn reset(&mut self) {
        self.burst.reset();
    }

    pub fn tracked_key_count(&self) -> usize {
        self.burst.tracked_key_count()
    }
}
