// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, VecDeque};

use super::JoinBurstConfig;
use crate::protection::shared::ProtectionDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinEvent {
    pub guild_id: u64,
    pub user_id: u64,
    pub timestamp_ms: u64,
}

impl JoinEvent {
    pub const fn new(guild_id: u64, user_id: u64, timestamp_ms: u64) -> Self {
        Self {
            guild_id,
            user_id,
            timestamp_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinBurstResult {
    pub decision: ProtectionDecision,
    pub join_count: usize,
    pub threshold: usize,
}

#[derive(Debug, Default)]
pub struct JoinBurstDetector {
    joins_by_guild: HashMap<u64, VecDeque<JoinEvent>>,
}

impl JoinBurstDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(&mut self, config: JoinBurstConfig, event: JoinEvent) -> JoinBurstResult {
        if !config.enabled {
            return JoinBurstResult {
                decision: ProtectionDecision::Allow,
                join_count: 0,
                threshold: config.threshold,
            };
        }

        let window_ms = config.window.as_millis().min(u64::MAX as u128) as u64;
        let cutoff = event.timestamp_ms.saturating_sub(window_ms);
        let joins = self.joins_by_guild.entry(event.guild_id).or_default();

        while joins
            .front()
            .is_some_and(|join| join.timestamp_ms < cutoff)
        {
            joins.pop_front();
        }

        joins.push_back(event);

        let join_count = joins.len();
        let decision = if join_count >= config.threshold {
            ProtectionDecision::Block
        } else {
            ProtectionDecision::Allow
        };

        JoinBurstResult {
            decision,
            join_count,
            threshold: config.threshold,
        }
    }

    pub fn reset(&mut self) {
        self.joins_by_guild.clear();
    }

    pub fn tracked_guild_count(&self) -> usize {
        self.joins_by_guild.len()
    }
}
