// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::protection::shared::{ActionBurstDetector, ActionBurstInput, ProtectionDecision};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MentionTargetKind {
    User,
    Role,
}

impl MentionTargetKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Role => "role",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MentionTarget {
    pub kind: MentionTargetKind,
    pub id: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct AntiSpamPingInput<'a> {
    pub enabled: bool,
    pub author_is_bot: bool,
    pub guild_id: u64,
    pub author_id: u64,
    pub targets: &'a [MentionTarget],
    pub timestamp: Duration,
    pub threshold: Option<usize>,
    pub window: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiSpamPingResult {
    pub decision: ProtectionDecision,
    pub target: Option<MentionTarget>,
    pub ping_count: usize,
    pub threshold: usize,
    pub window: Duration,
}

#[derive(Debug)]
pub struct AntiSpamPingDetector {
    burst: ActionBurstDetector,
    threshold: usize,
    window: Duration,
}

impl Default for AntiSpamPingDetector {
    fn default() -> Self {
        Self {
            burst: ActionBurstDetector::default(),
            threshold: 3,
            window: Duration::from_secs(10),
        }
    }
}

impl AntiSpamPingDetector {
    pub fn detect(&mut self, input: AntiSpamPingInput<'_>) -> AntiSpamPingResult {
        let threshold = input.threshold.unwrap_or(self.threshold).max(1);
        let window = input.window.unwrap_or(self.window);

        if !input.enabled || input.author_is_bot || input.targets.is_empty() {
            return AntiSpamPingResult {
                decision: ProtectionDecision::Allow,
                target: None,
                ping_count: 0,
                threshold,
                window,
            };
        }

        let mut latest = AntiSpamPingResult {
            decision: ProtectionDecision::Allow,
            target: None,
            ping_count: 0,
            threshold,
            window,
        };

        for target in input.targets {
            let action = format!("anti_spam_ping:{}:{}", target.kind.as_str(), target.id);
            let result = self.burst.detect(ActionBurstInput::new(
                input.guild_id,
                input.author_id,
                &action,
                threshold,
                window,
                input.timestamp,
            ));

            latest = AntiSpamPingResult {
                decision: result.decision,
                target: Some(*target),
                ping_count: result.count,
                threshold,
                window,
            };

            if result.decision == ProtectionDecision::Block {
                return latest;
            }
        }

        latest
    }

    pub fn reset(&mut self) {
        self.burst.reset();
    }

    pub fn tracked_key_count(&self) -> usize {
        self.burst.tracked_key_count()
    }
}
