// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::Connection;

use super::migrations::run_migrations;

pub const DEFAULT_DATABASE_PATH: &str = "data/foxsecura.sqlite3";

pub struct Database {
    connection: Mutex<Connection>,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }

        let mut connection = Connection::open(path)?;
        configure_connection(&connection)?;
        run_migrations(&mut connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let mut connection = Connection::open_in_memory()?;
        configure_connection(&connection)?;
        run_migrations(&mut connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(crate) fn connection(&self) -> Result<MutexGuard<'_, Connection>, DatabaseError> {
        self.connection
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned)
    }
}

fn configure_connection(connection: &Connection) -> Result<(), DatabaseError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;\nPRAGMA synchronous = NORMAL;",
    )?;

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
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "erreur SQLite : {error}"),
            Self::Io(error) => write!(formatter, "erreur d'accès au stockage : {error}"),
            Self::LockPoisoned => formatter.write_str("le verrou de la base de données est empoisonné"),
            Self::InvalidLanguage(value) => {
                write!(formatter, "langue invalide stockée en base : {value}")
            }
            Self::InvalidLogType(value) => {
                write!(formatter, "type de log invalide stocké en base : {value}")
            }
            Self::InvalidSnowflake(value) => {
                write!(formatter, "identifiant Discord invalide stocké en base : {value}")
            }
        }
    }
}

impl Error for DatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::LockPoisoned
            | Self::InvalidLanguage(_)
            | Self::InvalidLogType(_)
            | Self::InvalidSnowflake(_) => None,
        }
    }
}

impl From<rusqlite::Error> for DatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<std::io::Error> for DatabaseError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
