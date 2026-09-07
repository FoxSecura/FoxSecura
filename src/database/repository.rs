// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use rusqlite::{OptionalExtension, params};

use crate::i18n::Language;
use crate::logs::LogType;

use super::models::{parse_language, parse_log_type, parse_snowflake};
use super::{Database, DatabaseError, GuildConfig, GuildLogChannel};

impl Database {
    pub fn schema_version(&self) -> Result<i64, DatabaseError> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn guild_config(&self, guild_id: u64) -> Result<GuildConfig, DatabaseError> {
        let connection = self.connection()?;
        ensure_guild_config(&connection, guild_id)?;
        read_guild_config(&connection, guild_id)
    }

    pub fn set_guild_language(
        &self,
        guild_id: u64,
        language: Language,
    ) -> Result<GuildConfig, DatabaseError> {
        let connection = self.connection()?;
        let guild_id_text = guild_id.to_string();

        connection.execute(
            r#"
INSERT INTO guild_configs (guild_id, language)
VALUES (?1, ?2)
ON CONFLICT(guild_id) DO UPDATE SET
    language = excluded.language,
    updated_at = unixepoch()
"#,
            params![guild_id_text, language.code()],
        )?;

        read_guild_config(&connection, guild_id)
    }

    pub fn set_log_channel(
        &self,
        guild_id: u64,
        log_type: LogType,
        channel_id: u64,
    ) -> Result<GuildLogChannel, DatabaseError> {
        let connection = self.connection()?;
        ensure_guild_config(&connection, guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
VALUES (?1, ?2, ?3)
ON CONFLICT(guild_id, log_type) DO UPDATE SET
    channel_id = excluded.channel_id,
    updated_at = unixepoch()
"#,
            params![guild_id.to_string(), log_type.as_str(), channel_id.to_string()],
        )?;

        read_log_channel(&connection, guild_id, log_type)?.ok_or_else(|| {
            DatabaseError::Sqlite(rusqlite::Error::QueryReturnedNoRows)
        })
    }

    pub fn log_channel(
        &self,
        guild_id: u64,
        log_type: LogType,
    ) -> Result<Option<GuildLogChannel>, DatabaseError> {
        let connection = self.connection()?;
        read_log_channel(&connection, guild_id, log_type)
    }

    pub fn log_channels(&self, guild_id: u64) -> Result<Vec<GuildLogChannel>, DatabaseError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
SELECT guild_id, log_type, channel_id, created_at, updated_at
FROM guild_log_channels
WHERE guild_id = ?1
ORDER BY log_type
"#,
        )?;

        let rows = statement.query_map(params![guild_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;

        let mut channels = Vec::new();
        for row in rows {
            channels.push(map_log_channel(row?)?);
        }

        Ok(channels)
    }

    pub fn remove_log_channel(
        &self,
        guild_id: u64,
        log_type: LogType,
    ) -> Result<bool, DatabaseError> {
        let connection = self.connection()?;
        let affected = connection.execute(
            "DELETE FROM guild_log_channels WHERE guild_id = ?1 AND log_type = ?2",
            params![guild_id.to_string(), log_type.as_str()],
        )?;

        Ok(affected > 0)
    }
}

fn ensure_guild_config(
    connection: &rusqlite::Connection,
    guild_id: u64,
) -> Result<(), DatabaseError> {
    connection.execute(
        "INSERT INTO guild_configs (guild_id) VALUES (?1) ON CONFLICT(guild_id) DO NOTHING",
        params![guild_id.to_string()],
    )?;
    Ok(())
}

fn read_guild_config(
    connection: &rusqlite::Connection,
    guild_id: u64,
) -> Result<GuildConfig, DatabaseError> {
    let row = connection.query_row(
        r#"
SELECT guild_id, language, created_at, updated_at
FROM guild_configs
WHERE guild_id = ?1
"#,
        params![guild_id.to_string()],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;

    Ok(GuildConfig {
        guild_id: parse_snowflake(&row.0)?,
        language: parse_language(&row.1)?,
        created_at: row.2,
        updated_at: row.3,
    })
}

fn read_log_channel(
    connection: &rusqlite::Connection,
    guild_id: u64,
    log_type: LogType,
) -> Result<Option<GuildLogChannel>, DatabaseError> {
    let row = connection
        .query_row(
            r#"
SELECT guild_id, log_type, channel_id, created_at, updated_at
FROM guild_log_channels
WHERE guild_id = ?1 AND log_type = ?2
"#,
            params![guild_id.to_string(), log_type.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;

    row.map(map_log_channel).transpose()
}

fn map_log_channel(
    row: (String, String, String, i64, i64),
) -> Result<GuildLogChannel, DatabaseError> {
    Ok(GuildLogChannel {
        guild_id: parse_snowflake(&row.0)?,
        log_type: parse_log_type(&row.1)?,
        channel_id: parse_snowflake(&row.2)?,
        created_at: row.3,
        updated_at: row.4,
    })
}
