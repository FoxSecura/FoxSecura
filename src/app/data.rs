// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use foxsecura::database::{Database, DatabaseError};
use foxsecura::protection::anti_raid::join_burst::JoinBurstDetector;
use foxsecura::protection::anti_spam::message_flood::MessageFloodTracker;
use foxsecura::protection::automod::bad_words::BadWordsMatcherCache;
use foxsecura::protection::lockdown::{GuildLocks, LockdownTimers};
use foxsecura::protection::quarantine::MemberLocks;

use super::Error;

/// État partagé par les commandes et les événements.
pub struct AppData {
    pub database: Arc<Database>,
    pub protection: ProtectionState,
}

impl AppData {
    pub fn new(database: Arc<Database>) -> Self {
        Self {
            database,
            protection: ProtectionState::default(),
        }
    }
}

/// État en mémoire des protections.
///
/// Mono-instance : perdu au redémarrage et non partagé entre plusieurs
/// processus. Les verrous sont des `std::sync::Mutex` : ils ne doivent être
/// pris que dans du code synchrone, jamais conservés à travers un `.await`.
/// Seules exceptions, les verrous de quarantaine (par membre) et de
/// verrouillage (par guilde), asynchrones et conçus pour être tenus pendant
/// toute une opération.
#[derive(Default)]
pub struct ProtectionState {
    message_flood: Mutex<MessageFloodTracker>,
    join_bursts: Mutex<JoinBurstDetector>,
    bad_words: Mutex<BadWordsMatcherCache>,
    quarantine_locks: Arc<MemberLocks>,
    lockdown_locks: Arc<GuildLocks>,
    lockdown_timers: Arc<LockdownTimers>,
    member_prewarm: Arc<tokio::sync::Mutex<()>>,
}

impl ProtectionState {
    /// Accès exclusif au tracker anti-spam.
    ///
    /// Un verrou empoisonné (panique d'un autre thread) est récupéré : l'état
    /// ne contient que des horodatages, toujours cohérents entre deux appels.
    pub fn message_flood(&self) -> MutexGuard<'_, MessageFloodTracker> {
        self.message_flood
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Fenêtres glissantes des arrivées, par guilde (bornées).
    ///
    /// Un verrou empoisonné est récupéré : l'état ne contient que des
    /// horodatages.
    pub fn join_bursts(&self) -> MutexGuard<'_, JoinBurstDetector> {
        self.join_bursts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Matchers de mots interdits compilés, un par liste (cache borné).
    ///
    /// Un verrou empoisonné est récupéré : le cache ne contient que des
    /// matchers immuables, toujours valides.
    pub fn bad_words(&self) -> MutexGuard<'_, BadWordsMatcherCache> {
        self.bad_words
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Verrous par membre des quarantaines et libérations, partagés avec la
    /// maintenance périodique.
    pub fn quarantine_locks(&self) -> &Arc<MemberLocks> {
        &self.quarantine_locks
    }

    /// Verrous par guilde des poses et levées de verrouillage, partagés avec
    /// les minuteries.
    pub fn lockdown_locks(&self) -> &Arc<GuildLocks> {
        &self.lockdown_locks
    }

    /// Tour de rôle du préchauffage du cache des membres : une demande à la
    /// fois, toutes guildes confondues.
    pub fn member_prewarm(&self) -> &Arc<tokio::sync::Mutex<()>> {
        &self.member_prewarm
    }

    /// Minuteries de levée armées (au plus une par guilde).
    pub fn lockdown_timers(&self) -> &Arc<LockdownTimers> {
        &self.lockdown_timers
    }
}

/// Exécute une opération SQLite hors des threads asynchrones.
///
/// `rusqlite` est synchrone et la connexion est protégée par un verrou avec un
/// délai d'attente : l'appel passe donc par `spawn_blocking` pour ne jamais
/// bloquer le runtime Tokio.
pub async fn run_database<T, F>(database: &Arc<Database>, operation: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> Result<T, DatabaseError> + Send + 'static,
{
    let database = Arc::clone(database);
    let result = tokio::task::spawn_blocking(move || operation(&database)).await?;
    Ok(result?)
}
