// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs;
use std::ops::Deref;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rusqlite::Connection;

use crate::protection::anti_spam::message_flood::MessageFloodConfigError;
use crate::protection::automod::bad_words::CustomWordsError;

use super::cache::{DEFAULT_GUILD_CACHE_CAPACITY, GuildCache, GuildCacheStats};
use super::migrations::run_migrations;

pub const DEFAULT_DATABASE_PATH: &str = "data/foxsecura.sqlite3";

/// Base SQLite et cache mémoire de la configuration des guildes.
///
/// Ordre des verrous : connexion, puis cache ; jamais l'inverse.
pub struct Database {
    connection: Mutex<Connection>,
    guild_cache: Mutex<GuildCache>,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }

        let mut connection = Connection::open(path)?;
        configure_connection(&connection)?;
        run_migrations(&mut connection)?;

        Ok(Self::with_connection(connection))
    }

    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let mut connection = Connection::open_in_memory()?;
        configure_connection(&connection)?;
        run_migrations(&mut connection)?;

        Ok(Self::with_connection(connection))
    }

    fn with_connection(connection: Connection) -> Self {
        Self {
            connection: Mutex::new(connection),
            guild_cache: Mutex::new(GuildCache::new(DEFAULT_GUILD_CACHE_CAPACITY)),
        }
    }

    /// Compteurs du cache de configuration (succès, chargements SQLite,
    /// invalidations, évictions).
    pub fn guild_cache_stats(&self) -> GuildCacheStats {
        self.guild_cache().stats()
    }

    /// Connexion pour une écriture qui touche la configuration d'une guilde.
    ///
    /// Le cache de la guilde est invalidé quand le garde est relâché, encore
    /// sous le verrou de la connexion, que l'écriture ait réussi ou non.
    pub(crate) fn write_connection(
        &self,
        guild_id: u64,
    ) -> Result<WriteConnection<'_>, DatabaseError> {
        Ok(WriteConnection {
            connection: self.connection()?,
            cache: &self.guild_cache,
            guild_id,
        })
    }

    /// Un verrou empoisonné est récupéré : au pire une entrée manque, et une
    /// entrée manquante est rechargée depuis SQLite.
    pub(crate) fn guild_cache(&self) -> MutexGuard<'_, GuildCache> {
        self.guild_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn connection(&self) -> Result<MutexGuard<'_, Connection>, DatabaseError> {
        self.connection
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned)
    }
}

/// Connexion verrouillée pour une écriture ; invalide le cache de la guilde
/// à sa libération.
pub(crate) struct WriteConnection<'a> {
    connection: MutexGuard<'a, Connection>,
    cache: &'a Mutex<GuildCache>,
    guild_id: u64,
}

impl Deref for WriteConnection<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.connection
    }
}

impl Drop for WriteConnection<'_> {
    // `drop` s'exécute avant la libération des champs : la connexion est
    // encore verrouillée pendant l'invalidation.
    fn drop(&mut self) {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .invalidate(self.guild_id);
    }
}

fn configure_connection(connection: &Connection) -> Result<(), DatabaseError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA foreign_keys = ON;\nPRAGMA synchronous = NORMAL;")?;

    let _: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;

    Ok(())
}

#[derive(Debug)]
pub enum DatabaseError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    LockPoisoned,
    InvalidLanguage(String),
    InvalidLogType(String),
    InvalidSnowflake(String),
    InvalidAntiSpamConfig(MessageFloodConfigError),
    /// `@everyone` ne peut pas être exempté : il exempterait tout le serveur.
    EveryoneRoleNotExemptable,
    InvalidBadWordsLanguage(String),
    InvalidCustomWords(CustomWordsError),
    /// Un utilisateur de la liste blanche ne peut pas être mis sur la liste
    /// noire : les deux listes s'excluent.
    UserWhitelisted(u64),
    /// Un utilisateur de la liste noire ne peut pas être mis sur la liste
    /// blanche : les deux listes s'excluent.
    UserBlacklisted(u64),
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "erreur SQLite : {error}"),
            Self::Io(error) => write!(formatter, "erreur d'accès au stockage : {error}"),
            Self::LockPoisoned => {
                formatter.write_str("le verrou de la base de données est empoisonné")
            }
            Self::InvalidLanguage(value) => {
                write!(formatter, "langue invalide stockée en base : {value}")
            }
            Self::InvalidLogType(value) => {
                write!(formatter, "type de log invalide stocké en base : {value}")
            }
            Self::InvalidSnowflake(value) => {
                write!(
                    formatter,
                    "identifiant Discord invalide stocké en base : {value}"
                )
            }
            Self::InvalidAntiSpamConfig(error) => error.fmt(formatter),
            Self::EveryoneRoleNotExemptable => {
                formatter.write_str("le rôle @everyone ne peut pas être exempté")
            }
            Self::InvalidBadWordsLanguage(value) => {
                write!(
                    formatter,
                    "langue de mots interdits invalide stockée en base : {value}"
                )
            }
            Self::InvalidCustomWords(error) => error.fmt(formatter),
            Self::UserWhitelisted(user_id) => write!(
                formatter,
                "l'utilisateur {user_id} est sur la liste blanche : il ne peut pas être mis sur la liste noire"
            ),
            Self::UserBlacklisted(user_id) => write!(
                formatter,
                "l'utilisateur {user_id} est sur la liste noire : il ne peut pas être mis sur la liste blanche"
            ),
        }
    }
}

impl Error for DatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::InvalidAntiSpamConfig(error) => Some(error),
            Self::InvalidCustomWords(error) => Some(error),
            Self::LockPoisoned
            | Self::InvalidLanguage(_)
            | Self::InvalidLogType(_)
            | Self::InvalidSnowflake(_)
            | Self::EveryoneRoleNotExemptable
            | Self::InvalidBadWordsLanguage(_)
            | Self::UserWhitelisted(_)
            | Self::UserBlacklisted(_) => None,
        }
    }
}

impl From<rusqlite::Error> for DatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<MessageFloodConfigError> for DatabaseError {
    fn from(error: MessageFloodConfigError) -> Self {
        Self::InvalidAntiSpamConfig(error)
    }
}

impl From<CustomWordsError> for DatabaseError {
    fn from(error: CustomWordsError) -> Self {
        Self::InvalidCustomWords(error)
    }
}

impl From<std::io::Error> for DatabaseError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
