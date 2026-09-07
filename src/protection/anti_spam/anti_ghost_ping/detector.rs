// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use crate::protection::shared::{
    ActionBurstDetector, ActionBurstDetectorConfig, ActionBurstInput, ProtectionDecision,
};

const REPEAT_ACTION_KEY: &str = "anti_ghost_ping_repeat";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostPingMessage {
    pub guild_id: u64,
    pub message_id: u64,
    pub channel_id: u64,
    pub author_id: u64,
    pub mention_ids: Vec<u64>,
    pub role_mention_ids: Vec<u64>,
    pub mentions_everyone: bool,
    pub timestamp: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiGhostPingDetectorConfig {
    pub mention_threshold: usize,
    pub message_ttl: Duration,
    pub repeat_threshold: usize,
    pub repeat_window: Duration,
    pub max_tracked_messages: usize,
    pub max_tracked_authors: usize,
}

impl Default for AntiGhostPingDetectorConfig {
    fn default() -> Self {
        Self {
            mention_threshold: 5,
            message_ttl: Duration::from_secs(5 * 60),
            repeat_threshold: 2,
            repeat_window: Duration::from_secs(10 * 60),
            max_tracked_messages: 5_000,
            max_tracked_authors: 5_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostPingDetectionResult {
    pub decision: ProtectionDecision,
    pub author_id: Option<u64>,
    pub channel_id: Option<u64>,
    pub mention_ids: Vec<u64>,
    pub role_mention_ids: Vec<u64>,
    pub mentions_everyone: bool,
    pub mention_count: usize,
    pub threshold: usize,
    pub repeat_offense: bool,
}

#[derive(Debug)]
pub struct AntiGhostPingDetector {
    config: AntiGhostPingDetectorConfig,
    messages: HashMap<(u64, u64), GhostPingMessage>,
    repeat_detector: ActionBurstDetector,
}

impl Default for AntiGhostPingDetector {
    fn default() -> Self {
        Self::new(AntiGhostPingDetectorConfig::default())
    }
}

impl AntiGhostPingDetector {
    pub fn new(mut config: AntiGhostPingDetectorConfig) -> Self {
        config.mention_threshold = config.mention_threshold.max(1);
        config.repeat_threshold = config.repeat_threshold.max(1);
        config.max_tracked_messages = config.max_tracked_messages.max(1);
        config.max_tracked_authors = config.max_tracked_authors.max(1);

        let repeat_detector = ActionBurstDetector::new(ActionBurstDetectorConfig {
            max_tracked_keys: config.max_tracked_authors,
            sweep_interval: Duration::from_secs(30),
        });

        Self {
            config,
            messages: HashMap::new(),
            repeat_detector,
        }
    }

    pub fn record(&mut self, message: GhostPingMessage) -> bool {
        self.sweep_messages(message.timestamp);

        if mention_count(&message) == 0 {
            return false;
        }

        let key = (message.guild_id, message.message_id);
        self.ensure_message_capacity(&key);
        self.messages.insert(key, message);
        true
    }

    pub fn detect_deleted(
        &mut self,
        guild_id: u64,
        message_id: u64,
        timestamp: Duration,
    ) -> GhostPingDetectionResult {
        self.sweep_messages(timestamp);
        let Some(previous) = self.messages.remove(&(guild_id, message_id)) else {
            return empty_result(self.config.mention_threshold);
        };

        self.evaluate_incident(previous, timestamp)
    }

    pub fn detect_updated(
        &mut self,
        current: GhostPingMessage,
    ) -> GhostPingDetectionResult {
        self.sweep_messages(current.timestamp);
        let key = (current.guild_id, current.message_id);
        let previous = self.messages.get(&key).cloned();

        if mention_count(&current) == 0 {
            self.messages.remove(&key);
        } else {
            self.ensure_message_capacity(&key);
            self.messages.insert(key, current.clone());
        }

        let Some(previous) = previous else {
            return empty_result(self.config.mention_threshold);
        };

        let current_users: HashSet<u64> = current.mention_ids.iter().copied().collect();
        let current_roles: HashSet<u64> = current.role_mention_ids.iter().copied().collect();
        let removed_users: Vec<u64> = previous
            .mention_ids
            .iter()
            .copied()
            .filter(|id| !current_users.contains(id))
            .collect();
        let removed_roles: Vec<u64> = previous
            .role_mention_ids
            .iter()
            .copied()
            .filter(|id| !current_roles.contains(id))
            .collect();
        let removed_everyone = previous.mentions_everyone && !current.mentions_everyone;
        let removed_count = removed_users.len() + removed_roles.len() + usize::from(removed_everyone);

        if removed_count < self.config.mention_threshold {
            return GhostPingDetectionResult {
                decision: ProtectionDecision::Allow,
                author_id: Some(previous.author_id),
                channel_id: Some(previous.channel_id),
                mention_ids: removed_users,
                role_mention_ids: removed_roles,
                mentions_everyone: removed_everyone,
                mention_count: removed_count,
                threshold: self.config.mention_threshold,
                repeat_offense: false,
            };
        }

        self.messages.remove(&key);
        self.build_triggered_result(
            previous.author_id,
            previous.channel_id,
            removed_users,
            removed_roles,
            removed_everyone,
            removed_count,
            current.timestamp,
            current.guild_id,
        )
    }

    pub fn discard(&mut self, guild_id: u64, message_id: u64) -> bool {
        self.messages.remove(&(guild_id, message_id)).is_some()
    }

    pub fn reset(&mut self) {
        self.messages.clear();
        self.repeat_detector.reset();
    }

    pub fn tracked_message_count(&self) -> usize {
        self.messages.len()
    }

    pub fn tracked_violation_author_count(&self) -> usize {
        self.repeat_detector.tracked_key_count()
    }

    fn evaluate_incident(
        &mut self,
        previous: GhostPingMessage,
        timestamp: Duration,
    ) -> GhostPingDetectionResult {
        let count = mention_count(&previous);

        if count < self.config.mention_threshold {
            return GhostPingDetectionResult {
                decision: ProtectionDecision::Allow,
                author_id: Some(previous.author_id),
                channel_id: Some(previous.channel_id),
                mention_ids: previous.mention_ids,
                role_mention_ids: previous.role_mention_ids,
                mentions_everyone: previous.mentions_everyone,
                mention_count: count,
                threshold: self.config.mention_threshold,
                repeat_offense: false,
            };
        }

        self.build_triggered_result(
            previous.author_id,
            previous.channel_id,
            previous.mention_ids,
            previous.role_mention_ids,
            previous.mentions_everyone,
            count,
            timestamp,
            previous.guild_id,
        )
    }

    fn build_triggered_result(
        &mut self,
        author_id: u64,
        channel_id: u64,
        mention_ids: Vec<u64>,
        role_mention_ids: Vec<u64>,
        mentions_everyone: bool,
        mention_count: usize,
        timestamp: Duration,
        guild_id: u64,
    ) -> GhostPingDetectionResult {
        let repeat = self.repeat_detector.detect(ActionBurstInput::new(
            guild_id,
            author_id,
            REPEAT_ACTION_KEY,
            self.config.repeat_threshold,
            self.config.repeat_window,
            timestamp,
        ));

        GhostPingDetectionResult {
            decision: ProtectionDecision::Block,
            author_id: Some(author_id),
            channel_id: Some(channel_id),
            mention_ids,
            role_mention_ids,
            mentions_everyone,
            mention_count,
            threshold: self.config.mention_threshold,
            repeat_offense: repeat.decision == ProtectionDecision::Block,
        }
    }

    fn sweep_messages(&mut self, now: Duration) {
        self.messages.retain(|_, message| {
            now.saturating_sub(message.timestamp) <= self.config.message_ttl
        });
    }

    fn ensure_message_capacity(&mut self, key: &(u64, u64)) {
        if self.messages.contains_key(key) || self.messages.len() < self.config.max_tracked_messages {
            return;
        }

        let oldest = self
            .messages
            .iter()
            .min_by_key(|(_, message)| message.timestamp)
            .map(|(key, _)| *key);

        if let Some(oldest) = oldest {
            self.messages.remove(&oldest);
        }
    }
}

fn mention_count(message: &GhostPingMessage) -> usize {
    message.mention_ids.len()
        + message.role_mention_ids.len()
        + usize::from(message.mentions_everyone)
}

fn empty_result(threshold: usize) -> GhostPingDetectionResult {
    GhostPingDetectionResult {
        decision: ProtectionDecision::Allow,
        author_id: None,
        channel_id: None,
        mention_ids: Vec::new(),
        role_mention_ids: Vec::new(),
        mentions_everyone: false,
        mention_count: 0,
        threshold,
        repeat_offense: false,
    }
}
