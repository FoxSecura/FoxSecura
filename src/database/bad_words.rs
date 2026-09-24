// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Mots interdits d'une guilde : langue de la liste intégrée et mots
//! personnalisés (migration 5).

use rusqlite::{Connection, params};

use crate::protection::automod::bad_words::{
    BadWordsLanguage, DEFAULT_BAD_WORDS_LANGUAGE, normalize_custom_words,
};

use super::repository::{ensure_guild_config, read_guild_config};
use super::{Database, DatabaseError};

/// Réglages des mots interdits d'une guilde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadWordsSettings {
    pub language: BadWordsLanguage,
    /// Mots personnalisés, en minuscules, triés.
    pub custom_words: Vec<String>,
}

impl Database {
    /// Choisit la liste intégrée (`french`, `english` ou `all`).
    pub fn set_bad_words_language(
        &self,
        guild_id: u64,
        language: BadWordsLanguage,
    ) -> Result<BadWordsSettings, DatabaseError> {
        self.write(guild_id, |connection| {
            connection.execute(
                r#"
INSERT INTO guild_configs (guild_id, bad_words_language)
VALUES (?1, ?2)
ON CONFLICT(guild_id) DO UPDATE SET
    bad_words_language = excluded.bad_words_language,
    updated_at = unixepoch()
"#,
                params![guild_id.to_string(), language.key()],
            )?;
            read_bad_words(connection, guild_id)
        })
    }

    /// Remplace la liste des mots personnalisés, après validation des bornes
    /// de la V1 (200 mots, 100 caractères par mot). Une liste refusée ne
    /// modifie rien.
    pub fn set_custom_bad_words<I, S>(
        &self,
        guild_id: u64,
        words: I,
    ) -> Result<BadWordsSettings, DatabaseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let words = normalize_custom_words(words)?;
        self.write(guild_id, move |connection| {
            let transaction = connection.unchecked_transaction()?;
            ensure_guild_config(&transaction, guild_id)?;
            transaction.execute(
                "DELETE FROM guild_bad_words WHERE guild_id = ?1",
                params![guild_id.to_string()],
            )?;
            {
                let mut insert = transaction.prepare_cached(
                    "INSERT INTO guild_bad_words (guild_id, word) VALUES (?1, ?2)",
                )?;
                for word in &words {
                    insert.execute(params![guild_id.to_string(), word])?;
                }
            }
            transaction.commit()?;
            read_bad_words(connection, guild_id)
        })
    }

    /// Réglages des mots interdits ; aucun écrit.
    pub fn bad_words_settings(&self, guild_id: u64) -> Result<BadWordsSettings, DatabaseError> {
        let connection = self.connection()?;
        read_bad_words(&connection, guild_id)
    }
}

/// Lit la langue (celle par défaut, `all`, si la guilde n'est pas configurée) et les mots.
pub(super) fn read_bad_words(
    connection: &Connection,
    guild_id: u64,
) -> Result<BadWordsSettings, DatabaseError> {
    let language = match read_guild_config(connection, guild_id) {
        Ok(config) => config.bad_words_language,
        Err(DatabaseError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
            DEFAULT_BAD_WORDS_LANGUAGE
        }
        Err(error) => return Err(error),
    };

    Ok(BadWordsSettings {
        language,
        custom_words: read_custom_words(connection, guild_id)?,
    })
}

pub(super) fn read_custom_words(
    connection: &Connection,
    guild_id: u64,
) -> Result<Vec<String>, DatabaseError> {
    let mut statement = connection
        .prepare_cached("SELECT word FROM guild_bad_words WHERE guild_id = ?1 ORDER BY word")?;
    let rows = statement.query_map(params![guild_id.to_string()], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}
