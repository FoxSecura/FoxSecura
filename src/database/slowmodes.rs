// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::models::parse_snowflake;
use super::{Database, DatabaseError};
use rusqlite::params;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporarySlowmode {
    pub guild: u64,
    pub channel: u64,
    pub previous_seconds: u16,
    pub applied_seconds: u16,
    pub pending_seconds: Option<u16>,
    pub restore_at: i64,
}

impl Database {
    /// Conserver l'état original et permettre une escalade depuis le ralentissement connu.
    pub fn save_temporary_slowmode(&self, mode: &TemporarySlowmode) -> Result<bool, DatabaseError> {
        Ok(self.connection()?.execute(
            "INSERT INTO temporary_slowmodes
             (guild_id, channel_id, previous_seconds, applied_seconds, restore_at, pending_seconds)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(channel_id) DO UPDATE SET
                pending_seconds = excluded.previous_seconds,
                applied_seconds = excluded.applied_seconds,
                restore_at = MAX(temporary_slowmodes.restore_at, excluded.restore_at)
             WHERE temporary_slowmodes.guild_id = excluded.guild_id
               AND ((temporary_slowmodes.applied_seconds = excluded.previous_seconds
                     AND temporary_slowmodes.applied_seconds < excluded.applied_seconds)
                 OR (temporary_slowmodes.pending_seconds = excluded.previous_seconds
                     AND temporary_slowmodes.applied_seconds <= excluded.applied_seconds))",
            params![
                mode.guild.to_string(),
                mode.channel.to_string(),
                mode.previous_seconds,
                mode.applied_seconds,
                mode.restore_at,
                mode.pending_seconds
            ],
        )? != 0)
    }

    pub fn temporary_slowmodes(&self) -> Result<Vec<TemporarySlowmode>, DatabaseError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT guild_id, channel_id, previous_seconds, applied_seconds, restore_at, pending_seconds
             FROM temporary_slowmodes ORDER BY restore_at"
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u16>(2)?,
                row.get::<_, u16>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<u16>>(5)?,
            ))
        })?;
        let mut modes = Vec::new();
        for row in rows {
            let (guild, channel, previous_seconds, applied_seconds, restore_at, pending_seconds) =
                row?;
            modes.push(TemporarySlowmode {
                guild: parse_snowflake(&guild)?,
                channel: parse_snowflake(&channel)?,
                previous_seconds,
                applied_seconds,
                restore_at,
                pending_seconds,
            });
        }
        Ok(modes)
    }

    pub fn remove_temporary_slowmode(&self, channel: u64) -> Result<(), DatabaseError> {
        self.connection()?.execute(
            "DELETE FROM temporary_slowmodes WHERE channel_id = ?1",
            params![channel.to_string()],
        )?;
        Ok(())
    }

    pub fn confirm_temporary_slowmode(&self, channel: u64) -> Result<(), DatabaseError> {
        self.connection()?.execute(
            "UPDATE temporary_slowmodes SET pending_seconds = NULL WHERE channel_id = ?1",
            params![channel.to_string()],
        )?;
        Ok(())
    }
}

impl Database {
    pub fn remember_managed_rule(&self, guild: u64, rule: u64, name: &str) -> Result<(), DatabaseError> {
        self.connection()?.execute(
            "INSERT OR IGNORE INTO managed_automod_rules (guild_id, rule_id, rule_name) VALUES (?1, ?2, ?3)",
            params![guild.to_string(), rule.to_string(), name],
        )?;
        Ok(())
    }

    pub fn managed_rule_names(&self, guild: u64) -> Result<std::collections::HashMap<u64, String>, DatabaseError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT rule_id, rule_name FROM managed_automod_rules WHERE guild_id = ?1")?;
        let rows = statement.query_map(params![guild.to_string()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut names = std::collections::HashMap::new();
        for row in rows {
            let (id, name) = row?;
            names.insert(parse_snowflake(&id)?, name);
        }
        Ok(names)
    }

    pub fn is_managed_rule(&self, guild: u64, rule: u64) -> Result<bool, DatabaseError> {
        Ok(self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_automod_rules WHERE guild_id = ?1 AND rule_id = ?2)",
            params![guild.to_string(), rule.to_string()], |row| row.get(0),
        )?)
    }

    pub fn has_managed_rules(&self, guild: u64) -> Result<bool, DatabaseError> {
        Ok(self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_automod_rules WHERE guild_id = ?1)",
            params![guild.to_string()],
            |row| row.get(0),
        )?)
    }
}
