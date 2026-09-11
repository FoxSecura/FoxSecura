// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::{collections::HashMap, time::Duration};

use crate::protection::{
    anti_nuke::panic_mode::PanicModeDetector,
    anti_raid::{join_burst::JoinBurstDetector, webhook_message::WebhookMessageSpamDetector},
    anti_spam::{
        anti_ghost_ping::AntiGhostPingDetector, anti_ping_owner::AntiPingOwnerDetector,
        anti_spam_ping::AntiSpamPingDetector, auto_slowmode::AutoSlowmodeDetector,
    },
    shared::ActionBurstDetector,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Alert,
    DeleteMessage { channel: u64, message: u64 },
    Timeout { user: u64 },
    Kick { user: u64 },
    RemoveWebhook { webhook: u64 },
    NormalizeNickname { user: u64, nickname: String },
    RemoveRole { user: u64, role: u64 },
    ContainExecutor { user: u64 },
    RollbackPermissions { role: u64, old: u64, expected: u64 },
    Slowmode { channel: u64, seconds: u16 },
    Lockdown,
    SyncAutoMod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    pub module: &'static str,
    pub action: Action,
}

impl PlannedAction {
    pub fn new(module: &'static str, action: Action) -> Self {
        Self { module, action }
    }
}

#[derive(Debug, Default)]
pub struct ProtectionEngine {
    pub(crate) burst: ActionBurstDetector,
    pub(crate) ghost: AntiGhostPingDetector,
    pub(crate) owner_ping: AntiPingOwnerDetector,
    pub(crate) spam_ping: AntiSpamPingDetector,
    pub(crate) slowmode: AutoSlowmodeDetector,
    pub(crate) joins: JoinBurstDetector,
    pub(crate) webhook_spam: WebhookMessageSpamDetector,
    pub(crate) panic: PanicModeDetector,
    seen: HashMap<(u64, u64, &'static str), Duration>,
}

impl ProtectionEngine {
    /// Déduplication bornée des événements Discord ; les éditions restent indépendantes.
    pub(crate) fn admit(&mut self, guild: u64, id: u64, kind: &'static str, now: Duration) -> bool {
        self.seen.retain(|_, at| now.saturating_sub(*at) < Duration::from_secs(600));
        let key = (guild, id, kind);
        if self.seen.contains_key(&key) {
            return false;
        }
        if self.seen.len() >= 10_000 {
            if let Some(oldest) = self.seen.iter().min_by_key(|(_, at)| *at).map(|(key, _)| *key) {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(key, now);
        true
    }

    pub fn discard_message(&mut self, guild: u64, message: u64) {
        self.ghost.discard(guild, message);
    }
}
