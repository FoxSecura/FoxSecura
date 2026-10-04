// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Sérialisation des opérations de verrouillage par guilde.
//!
//! Une pose, une levée à l'échéance et une levée manuelle de la même guilde
//! ne doivent jamais s'entrelacer : l'une pourrait restaurer un salon pendant
//! que l'autre l'enregistre. Même mécanique que les verrous de quarantaine
//! (`MemberLocks`), indexée par guilde seule.

use crate::protection::quarantine::{MemberLockGuard, MemberLocks};

/// Verrous par guilde, tenus à travers les appels à Discord et à SQLite.
#[derive(Debug, Default)]
pub struct GuildLocks {
    inner: MemberLocks,
}

/// Verrou tenu sur une guilde.
pub type GuildLockGuard<'a> = MemberLockGuard<'a>;

impl GuildLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attend le verrou de la guilde ; relâché quand le garde est détruit.
    pub async fn lock(&self, guild_id: u64) -> GuildLockGuard<'_> {
        // Aucun membre n'a l'identifiant 0 : la clé est propre à la guilde.
        self.inner.lock(guild_id, 0).await
    }

    /// Guildes dont le verrou est tenu ou attendu.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
