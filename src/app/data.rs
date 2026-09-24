// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use foxsecura::database::{Database, DatabaseError};
use foxsecura::protection::anti_spam::message_flood::MessageFloodTracker;
use foxsecura::protection::automod::bad_words::BadWordsMatcherCache;

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
#[derive(Default)]
pub struct ProtectionState {
    message_flood: Mutex<MessageFloodTracker>,
    bad_words: Mutex<BadWordsMatcherCache>,
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

    /// Matchers de mots interdits compilés, un par liste (cache borné).
    ///
    /// Un verrou empoisonné est récupéré : le cache ne contient que des
    /// matchers immuables, toujours valides.
    pub fn bad_words(&self) -> MutexGuard<'_, BadWordsMatcherCache> {
        self.bad_words
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
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
