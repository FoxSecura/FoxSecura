// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Messages que FoxSecura supprime lui-même (filtres, anti-spam, honeypot,
//! webhooks…) : leur `MESSAGE_DELETE` ne doit jamais compter comme un ghost
//! ping.
//!
//! Protocole : le message est marqué **avant** l'appel de suppression (Discord
//! peut envoyer l'événement avant la réponse HTTP), puis la marque est
//! retirée si l'appel échoue. À la réception de `MESSAGE_DELETE`, une marque
//! présente est consommée et l'événement ignoré.
//!
//! Borné en mémoire (durée et nombre de marques) ; mono-instance.

use std::collections::HashMap;
use std::time::Duration;

/// Durée de vie d'une marque : celle du suivi des ghost pings.
pub const BOT_DELETION_MARK_TTL: Duration = Duration::from_secs(5 * 60);

/// Nombre maximal de marques conservées.
pub const MAX_BOT_DELETION_MARKS: usize = 5_000;

/// Suppressions en cours ou récentes faites par FoxSecura.
#[derive(Debug)]
pub struct BotDeletionMarks {
    marks: HashMap<(u64, u64), Duration>,
    ttl: Duration,
    capacity: usize,
}

impl Default for BotDeletionMarks {
    fn default() -> Self {
        Self::new(BOT_DELETION_MARK_TTL, MAX_BOT_DELETION_MARKS)
    }
}

impl BotDeletionMarks {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            marks: HashMap::new(),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// Marque un message avant de le supprimer.
    pub fn mark(&mut self, guild_id: u64, message_id: u64, now: Duration) {
        let key = (guild_id, message_id);
        if !self.marks.contains_key(&key) && self.marks.len() >= self.capacity {
            let ttl = self.ttl;
            self.marks
                .retain(|_, marked_at| now.saturating_sub(*marked_at) <= ttl);
            if self.marks.len() >= self.capacity
                && let Some(oldest) = self
                    .marks
                    .iter()
                    .min_by_key(|(_, marked_at)| **marked_at)
                    .map(|(key, _)| *key)
            {
                self.marks.remove(&oldest);
            }
        }
        self.marks.insert(key, now);
    }

    /// Retire la marque d'une suppression échouée : le message existe encore.
    pub fn unmark(&mut self, guild_id: u64, message_id: u64) {
        self.marks.remove(&(guild_id, message_id));
    }

    /// Consomme la marque d'un message supprimé ; `true` si FoxSecura l'a
    /// supprimé lui-même (dans la durée de vie de la marque).
    pub fn take(&mut self, guild_id: u64, message_id: u64, now: Duration) -> bool {
        self.marks
            .remove(&(guild_id, message_id))
            .is_some_and(|marked_at| now.saturating_sub(marked_at) <= self.ttl)
    }

    pub fn len(&self) -> usize {
        self.marks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }
}
