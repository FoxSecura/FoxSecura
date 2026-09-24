// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Quarantaine (migration 7) : overwrites de membre enregistrés et
//! libérations en attente.
//!
//! Une ligne d'overwrite porte l'état d'origine des bits `VIEW_CHANNEL` et
//! `CONNECT` d'un membre dans un salon. Elle est écrite **avant** la
//! modification du salon et n'est supprimée qu'après sa restauration : un
//! plantage entre les deux laisse de quoi restaurer. Un enregistrement ne
//! remplace jamais une ligne existante, qui porte le vrai état d'origine.
//!
//! Ces tables ne font pas partie de l'instantané des guildes ; les écritures
//! passent tout de même par `WriteConnection`, qui crée la configuration de
//! la guilde si besoin (clé étrangère) et invalide son cache.

use rusqlite::{Connection, OptionalExtension, params};

use crate::protection::quarantine::{PermissionState, RecordedOverwrite};

use super::models::parse_snowflake;
use super::repository::ensure_guild_config;
use super::{Database, DatabaseError};

impl Database {
    /// Ligne enregistrée pour un membre dans un salon.
    pub fn quarantine_overwrite(
        &self,
        guild_id: u64,
        user_id: u64,
        channel_id: u64,
    ) -> Result<Option<RecordedOverwrite>, DatabaseError> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                r#"
SELECT previous_view, previous_connect
FROM guild_quarantine_overwrites
WHERE guild_id = ?1 AND user_id = ?2 AND channel_id = ?3
"#,
                params![
                    guild_id.to_string(),
                    user_id.to_string(),
                    channel_id.to_string()
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        row.map(|(view, connect)| parse_recorded(&view, &connect))
            .transpose()
    }

    /// Lignes d'un membre, triées par salon.
    pub fn quarantine_overwrites(
        &self,
        guild_id: u64,
        user_id: u64,
    ) -> Result<Vec<(u64, RecordedOverwrite)>, DatabaseError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare_cached(
            r#"
SELECT channel_id, previous_view, previous_connect
FROM guild_quarantine_overwrites
WHERE guild_id = ?1 AND user_id = ?2
"#,
        )?;
        let rows =
            statement.query_map(params![guild_id.to_string(), user_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;

        let mut overwrites = Vec::new();
        for row in rows {
            let (channel_id, view, connect) = row?;
            overwrites.push((
                parse_snowflake(&channel_id)?,
                parse_recorded(&view, &connect)?,
            ));
        }
        overwrites.sort_unstable_by_key(|(channel_id, _)| *channel_id);
        Ok(overwrites)
    }

    /// Enregistre l'état d'origine avant de modifier le salon.
    ///
    /// Retourne `false` si une ligne existait déjà : elle est conservée, car
    /// elle porte l'état d'avant la première quarantaine.
    pub fn record_quarantine_overwrite(
        &self,
        guild_id: u64,
        user_id: u64,
        channel_id: u64,
        state: RecordedOverwrite,
    ) -> Result<bool, DatabaseError> {
        let connection = self.write_connection(guild_id)?;
        ensure_guild_config(&connection, guild_id)?;
        let affected = connection.execute(
            r#"
INSERT INTO guild_quarantine_overwrites
    (guild_id, user_id, channel_id, previous_view, previous_connect)
VALUES (?1, ?2, ?3, ?4, ?5)
ON CONFLICT DO NOTHING
"#,
            params![
                guild_id.to_string(),
                user_id.to_string(),
                channel_id.to_string(),
                state.view.key(),
                state.connect.key()
            ],
        )?;
        Ok(affected > 0)
    }

    /// Supprime la ligne d'un salon (restauré, disparu, ou modification
    /// échouée).
    pub fn forget_quarantine_overwrite(
        &self,
        guild_id: u64,
        user_id: u64,
        channel_id: u64,
    ) -> Result<bool, DatabaseError> {
        let connection = self.write_connection(guild_id)?;
        let affected = connection.execute(
            r#"
DELETE FROM guild_quarantine_overwrites
WHERE guild_id = ?1 AND user_id = ?2 AND channel_id = ?3
"#,
            params![
                guild_id.to_string(),
                user_id.to_string(),
                channel_id.to_string()
            ],
        )?;
        Ok(affected > 0)
    }

    /// Enregistre (ou repousse en fin de file) ou efface la libération en
    /// attente d'un membre.
    pub fn set_pending_release(
        &self,
        guild_id: u64,
        user_id: u64,
        pending: bool,
    ) -> Result<(), DatabaseError> {
        let connection = self.write_connection(guild_id)?;
        if pending {
            ensure_guild_config(&connection, guild_id)?;
            connection.execute(
                r#"
INSERT INTO guild_quarantine_pending_releases (guild_id, user_id)
VALUES (?1, ?2)
ON CONFLICT(guild_id, user_id) DO UPDATE SET updated_at = unixepoch()
"#,
                params![guild_id.to_string(), user_id.to_string()],
            )?;
        } else {
            connection.execute(
                "DELETE FROM guild_quarantine_pending_releases WHERE guild_id = ?1 AND user_id = ?2",
                params![guild_id.to_string(), user_id.to_string()],
            )?;
        }
        Ok(())
    }

    pub fn is_pending_release(&self, guild_id: u64, user_id: u64) -> Result<bool, DatabaseError> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            r#"
SELECT EXISTS(
    SELECT 1 FROM guild_quarantine_pending_releases WHERE guild_id = ?1 AND user_id = ?2
)
"#,
            params![guild_id.to_string(), user_id.to_string()],
            |row| row.get(0),
        )?)
    }

    /// Libérations en attente, les plus anciennes d'abord, toutes guildes
    /// confondues : `(guild_id, user_id)`.
    pub fn pending_releases(&self, limit: usize) -> Result<Vec<(u64, u64)>, DatabaseError> {
        let connection = self.connection()?;
        pending_releases(&connection, limit)
    }
}

fn pending_releases(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<(u64, u64)>, DatabaseError> {
    let mut statement = connection.prepare_cached(
        r#"
SELECT guild_id, user_id
FROM guild_quarantine_pending_releases
ORDER BY updated_at, guild_id, user_id
LIMIT ?1
"#,
    )?;
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let rows = statement.query_map(params![limit], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    let mut pending = Vec::new();
    for row in rows {
        let (guild_id, user_id) = row?;
        pending.push((parse_snowflake(&guild_id)?, parse_snowflake(&user_id)?));
    }
    Ok(pending)
}

fn parse_recorded(view: &str, connect: &str) -> Result<RecordedOverwrite, DatabaseError> {
    let parse = |value: &str| {
        PermissionState::from_key(value)
            .ok_or_else(|| DatabaseError::InvalidOverwriteState(value.to_owned()))
    };
    Ok(RecordedOverwrite {
        view: parse(view)?,
        connect: parse(connect)?,
    })
}
