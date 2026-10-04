// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Fenêtre glissante des arrivées, par guilde.
//!
//! # Mémoire bornée
//!
//! - Au plus [`MAX_TRACKED_GUILDS`] guildes suivies. Quand la table est
//!   pleine, une nouvelle guilde déclenche un balayage des guildes sans
//!   arrivée depuis la fenêtre maximale (120 s) ; si la table est encore
//!   pleine, la guilde dont la dernière arrivée est la plus ancienne est
//!   oubliée.
//! - Au plus [`MAX_JOIN_THRESHOLD`] horodatages par guilde : au-delà, le
//!   seuil (50 au plus) est de toute façon atteint, le compte rapporté est
//!   plafonné.
//!
//! État en mémoire, mono-instance : perdu au redémarrage, non partagé entre
//! plusieurs processus.

use std::collections::{HashMap, VecDeque};

use super::JoinBurstConfig;
use super::config::{MAX_JOIN_THRESHOLD, MAX_JOIN_WINDOW_SECONDS};
use crate::protection::shared::ProtectionDecision;

/// Guildes suivies au plus.
pub const MAX_TRACKED_GUILDS: usize = 10_000;

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

impl JoinBurstResult {
    /// Le seuil est atteint par l'arrivée courante.
    pub fn triggered(&self) -> bool {
        self.decision == ProtectionDecision::Block
    }
}

#[derive(Debug)]
pub struct JoinBurstDetector {
    joins_by_guild: HashMap<u64, VecDeque<u64>>,
    capacity: usize,
}

impl Default for JoinBurstDetector {
    fn default() -> Self {
        Self::with_capacity(MAX_TRACKED_GUILDS)
    }
}

impl JoinBurstDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Détecteur borné à `capacity` guildes (au moins une).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            joins_by_guild: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Enregistre une arrivée et compte celles de la fenêtre.
    ///
    /// Déclenchement quand `nombre >= seuil` : c'est l'arrivée courante qui
    /// déclenche, et chaque arrivée suivante dans la fenêtre aussi.
    pub fn detect(&mut self, config: JoinBurstConfig, event: JoinEvent) -> JoinBurstResult {
        if !config.enabled {
            return JoinBurstResult {
                decision: ProtectionDecision::Allow,
                join_count: 0,
                threshold: config.threshold,
            };
        }

        if !self.joins_by_guild.contains_key(&event.guild_id)
            && self.joins_by_guild.len() >= self.capacity
        {
            self.make_room(event.timestamp_ms);
        }

        let window_ms = config.window.as_millis().min(u64::MAX as u128) as u64;
        let cutoff = event.timestamp_ms.saturating_sub(window_ms);
        let joins = self.joins_by_guild.entry(event.guild_id).or_default();

        while joins.front().is_some_and(|timestamp| *timestamp < cutoff) {
            joins.pop_front();
        }
        if joins.len() >= MAX_JOIN_THRESHOLD as usize {
            joins.pop_front();
        }
        joins.push_back(event.timestamp_ms);

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

    /// Oublie les guildes sans arrivée depuis la fenêtre maximale, puis, si
    /// la table est encore pleine, celle dont la dernière arrivée est la plus
    /// ancienne.
    fn make_room(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(u64::from(MAX_JOIN_WINDOW_SECONDS) * 1_000);
        self.joins_by_guild
            .retain(|_, joins| joins.back().is_some_and(|last| *last >= cutoff));

        if self.joins_by_guild.len() >= self.capacity
            && let Some(oldest) = self
                .joins_by_guild
                .iter()
                .min_by_key(|(_, joins)| joins.back().copied().unwrap_or(0))
                .map(|(guild_id, _)| *guild_id)
        {
            self.joins_by_guild.remove(&oldest);
        }
    }

    pub fn reset(&mut self) {
        self.joins_by_guild.clear();
    }

    pub fn tracked_guild_count(&self) -> usize {
        self.joins_by_guild.len()
    }
}
