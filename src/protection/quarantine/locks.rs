// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Sérialisation des opérations de quarantaine par membre.
//!
//! Deux quarantaines ou libérations simultanées du même membre ne doivent
//! jamais s'entrelacer : l'une pourrait restaurer un salon pendant que l'autre
//! l'enregistre. Chaque opération tient le verrou du membre du début à la fin,
//! à travers les appels à Discord et à SQLite.
//!
//! Le verrou d'un membre est un `tokio::sync::Mutex`, qui peut être tenu à
//! travers un `.await`. La table des verrous est un `std::sync::Mutex`, pris
//! seulement le temps de cloner ou de retirer une entrée, jamais à travers un
//! `.await`. Une entrée est retirée quand plus personne ne tient ni n'attend
//! le verrou : la table ne grossit pas avec le nombre de membres traités.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

type Key = (u64, u64);

/// Verrous par membre `(guild_id, user_id)`.
#[derive(Debug, Default)]
pub struct MemberLocks {
    entries: Mutex<HashMap<Key, Arc<AsyncMutex<()>>>>,
}

impl MemberLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attend le verrou du membre. Il est relâché quand le garde est détruit.
    pub async fn lock(&self, guild_id: u64, user_id: u64) -> MemberLockGuard<'_> {
        let key = (guild_id, user_id);
        let mutex = Arc::clone(self.entries().entry(key).or_default());
        let guard = mutex.lock_owned().await;
        MemberLockGuard {
            locks: self,
            key,
            guard: Some(guard),
        }
    }

    /// Membres dont le verrou est tenu ou attendu.
    pub fn len(&self) -> usize {
        self.entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Un verrou empoisonné est récupéré : la table ne contient que des
    /// verrous, toujours valides.
    fn entries(&self) -> MutexGuard<'_, HashMap<Key, Arc<AsyncMutex<()>>>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Verrou tenu sur un membre.
#[derive(Debug)]
pub struct MemberLockGuard<'a> {
    locks: &'a MemberLocks,
    key: Key,
    guard: Option<OwnedMutexGuard<()>>,
}

impl Drop for MemberLockGuard<'_> {
    fn drop(&mut self) {
        // Relâche d'abord le verrou du membre, puis retire l'entrée si plus
        // personne ne la tient ni ne l'attend. Un clonage se fait sous le
        // verrou de la table : le compte ne peut pas augmenter pendant ce
        // contrôle.
        drop(self.guard.take());
        let mut entries = self.locks.entries();
        if entries
            .get(&self.key)
            .is_some_and(|mutex| Arc::strong_count(mutex) == 1)
        {
            entries.remove(&self.key);
        }
    }
}
