// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::plan::{AUTO_SLOWMODE_THRESHOLD, AUTO_SLOWMODE_WINDOW};
use crate::protection::shared::{ActionBurstDetector, ActionBurstInput, ProtectionDecision};

const ACTION_KEY: &str = "auto_slowmode_channel_burst";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoSlowmodeResult {
    pub decision: ProtectionDecision,
    pub count: usize,
    pub threshold: usize,
}

#[derive(Debug)]
pub struct AutoSlowmodeDetector {
    burst: ActionBurstDetector,
    threshold: usize,
    window: Duration,
}

impl Default for AutoSlowmodeDetector {
    fn default() -> Self {
        Self {
            burst: ActionBurstDetector::default(),
            threshold: AUTO_SLOWMODE_THRESHOLD,
            window: AUTO_SLOWMODE_WINDOW,
        }
    }
}

impl AutoSlowmodeDetector {
    pub fn new(threshold: usize, window: Duration) -> Self {
        Self {
            burst: ActionBurstDetector::default(),
            threshold: threshold.max(1),
            window,
        }
    }

    pub fn record(
        &mut self,
        guild_id: u64,
        channel_id: u64,
        timestamp: Duration,
    ) -> AutoSlowmodeResult {
        let result = self.burst.detect(ActionBurstInput::new(
            guild_id,
            channel_id,
            ACTION_KEY,
            self.threshold,
            self.window,
            timestamp,
        ));

        AutoSlowmodeResult {
            decision: result.decision,
            count: result.count,
            threshold: result.threshold,
        }
    }

    pub fn reset(&mut self) {
        self.burst.reset();
    }
}
