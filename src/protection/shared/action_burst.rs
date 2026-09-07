// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

use super::ProtectionDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionBurstDetectorConfig {
    pub max_tracked_keys: usize,
    pub sweep_interval: Duration,
}

impl Default for ActionBurstDetectorConfig {
    fn default() -> Self {
        Self {
            max_tracked_keys: 10_000,
            sweep_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionBurstInput<'a> {
    pub guild_id: u64,
    pub executor_id: u64,
    pub action: &'a str,
    pub threshold: usize,
    pub window: Duration,
    pub timestamp: Duration,
}

impl<'a> ActionBurstInput<'a> {
    pub const fn new(
        guild_id: u64,
        executor_id: u64,
        action: &'a str,
        threshold: usize,
        window: Duration,
        timestamp: Duration,
    ) -> Self {
        Self {
            guild_id,
            executor_id,
            action,
            threshold,
            window,
            timestamp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionBurstResult {
    pub decision: ProtectionDecision,
    pub count: usize,
    pub threshold: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ActionBurstKey {
    guild_id: u64,
    executor_id: u64,
    action: String,
}

#[derive(Debug)]
struct ActionBurstState {
    timestamps: VecDeque<Duration>,
    window: Duration,
}

#[derive(Debug)]
pub struct ActionBurstDetector {
    config: ActionBurstDetectorConfig,
    events: HashMap<ActionBurstKey, ActionBurstState>,
    next_sweep_at: Option<Duration>,
}

impl Default for ActionBurstDetector {
    fn default() -> Self {
        Self::new(ActionBurstDetectorConfig::default())
    }
}

impl ActionBurstDetector {
    pub fn new(mut config: ActionBurstDetectorConfig) -> Self {
        config.max_tracked_keys = config.max_tracked_keys.max(1);
        config.sweep_interval = config.sweep_interval.max(Duration::from_millis(1));

        Self {
            config,
            events: HashMap::new(),
            next_sweep_at: None,
        }
    }

    pub fn detect(&mut self, input: ActionBurstInput<'_>) -> ActionBurstResult {
        let threshold = input.threshold.max(1);
        self.maybe_sweep(input.timestamp);

        let key = ActionBurstKey {
            guild_id: input.guild_id,
            executor_id: input.executor_id,
            action: input.action.to_owned(),
        };

        self.ensure_capacity_for(&key);

        let state = self.events.entry(key).or_insert_with(|| ActionBurstState {
            timestamps: VecDeque::new(),
            window: input.window,
        });

        state.window = input.window;
        state.timestamps.retain(|timestamp| {
            input.timestamp.saturating_sub(*timestamp) <= input.window
        });
        state.timestamps.push_back(input.timestamp);

        let count = state.timestamps.len();
        let decision = if count >= threshold {
            ProtectionDecision::Block
        } else {
            ProtectionDecision::Allow
        };

        ActionBurstResult {
            decision,
            count,
            threshold,
        }
    }

    pub fn reset(&mut self) {
        self.events.clear();
        self.next_sweep_at = None;
    }

    pub fn tracked_key_count(&self) -> usize {
        self.events.len()
    }

    fn maybe_sweep(&mut self, now: Duration) {
        if self.next_sweep_at.is_some_and(|next| now < next) {
            return;
        }

        self.next_sweep_at = Some(now.saturating_add(self.config.sweep_interval));
        self.events.retain(|_, state| {
            state
                .timestamps
                .retain(|timestamp| now.saturating_sub(*timestamp) <= state.window);
            !state.timestamps.is_empty()
        });
    }

    fn ensure_capacity_for(&mut self, key: &ActionBurstKey) {
        if self.events.contains_key(key) || self.events.len() < self.config.max_tracked_keys {
            return;
        }

        let oldest_key = self
            .events
            .iter()
            .min_by_key(|(_, state)| state.timestamps.back().copied().unwrap_or(Duration::ZERO))
            .map(|(key, _)| key.clone());

        if let Some(oldest_key) = oldest_key {
            self.events.remove(&oldest_key);
        }
    }
}
