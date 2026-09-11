// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use rusqlite::params;
use super::{Database, DatabaseError};
use super::models::parse_snowflake;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporarySlowmode {
    pub guild: u64,
    pub channel: u64,
    pub previous_seconds: u16,
    pub applied_seconds: u16,
    pub restore_at: i64,
}

impl Database {
    /// Le premier état gagne : ne jamais remplacer la valeur originale par celle de FoxSecura.
    pub fn save_temporary_slowmode(&self, mode: &TemporarySlowmode) -> Result<bool, DatabaseError> {
        Ok(self.connection()?.execute(
            "INSERT OR IGNORE INTO temporary_slowmodes
             (guild_id, channel_id, previous_seconds, applied_seconds, restore_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![mode.guild.to_string(), mode.channel.to_string(), mode.previous_seconds,
                mode.applied_seconds, mode.restore_at],
        )? != 0)
    }

    pub fn temporary_slowmodes(&self) -> Result<Vec<TemporarySlowmode>, DatabaseError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT guild_id, channel_id, previous_seconds, applied_seconds, restore_at
             FROM temporary_slowmodes ORDER BY restore_at"
        )?;
        let rows = statement.query_map([], |row| Ok((
            row.get::<_, String>(0)?, row.get::<_, String>(1)?,
            row.get::<_, u16>(2)?, row.get::<_, u16>(3)?, row.get::<_, i64>(4)?,
        )))?;
        let mut modes = Vec::new();
        for row in rows {
            let (guild, channel, previous_seconds, applied_seconds, restore_at) = row?;
            modes.push(TemporarySlowmode {
                guild: parse_snowflake(&guild)?, channel: parse_snowflake(&channel)?,
                previous_seconds, applied_seconds, restore_at,
            });
        }
        Ok(modes)
    }

    pub fn remove_temporary_slowmode(&self, channel: u64) -> Result<(), DatabaseError> {
        self.connection()?.execute("DELETE FROM temporary_slowmodes WHERE channel_id = ?1",
            params![channel.to_string()])?;
        Ok(())
    }
}
