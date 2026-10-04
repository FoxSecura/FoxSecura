// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Verrouillage temporaire (migrations 8 et 9) : ligne de verrouillage par
//! guilde, avec le mode lent posé, et état d'origine de chaque salon.
//!
//! Une ligne de salon est écrite **avant** la modification du salon et n'est
//! supprimée qu'après sa restauration (ou sa disparition) : un plantage
//! entre les deux laisse de quoi restaurer. Un enregistrement ne remplace
//! jamais une ligne existante, qui porte le vrai état d'origine.
//!
//! Ces tables ne font pas partie de l'instantané des guildes ; les écritures
//! passent tout de même par `WriteConnection`, qui crée la configuration de
//! la guilde si besoin (clé étrangère) et invalide son cache.

use rusqlite::{Connection, OptionalExtension, params};

use crate::protection::lockdown::{
    LOCKDOWN_SLOWMODE_SECONDS, LockdownReason, LockdownRequest, LockdownState, LockdownStatus,
    MAX_SLOWMODE_SECONDS, RecordedChannel,
};

use super::models::parse_snowflake;
use super::repository::ensure_guild_config;
use super::{Database, DatabaseError};

impl Database {
    /// Insère la ligne de verrouillage ; `false` si la guilde en a déjà une
    /// (active, en cours de levée ou en attente), qui est conservée.
    pub fn begin_lockdown(
        &self,
        guild_id: u64,
        request: LockdownRequest,
    ) -> Result<bool, DatabaseError> {
        let connection = self.write_connection(guild_id)?;
        ensure_guild_config(&connection, guild_id)?;
        let affected = connection.execute(
            r#"
INSERT INTO guild_lockdowns (guild_id, reason, status, lift_at, slowmode_seconds)
VALUES (?1, ?2, 'active', ?3, ?4)
ON CONFLICT DO NOTHING
"#,
            params![
                guild_id.to_string(),
                request.reason.key(),
                clamp_unix(request.lift_at),
                request.slowmode_seconds.min(MAX_SLOWMODE_SECONDS)
            ],
        )?;
        Ok(affected > 0)
    }

    /// Supprime la ligne de verrouillage s'il ne reste aucun salon
    /// enregistré ; `true` si elle a été supprimée.
    pub fn end_lockdown(&self, guild_id: u64) -> Result<bool, DatabaseError> {
        let connection = self.write_connection(guild_id)?;
        let affected = connection.execute(
            r#"
DELETE FROM guild_lockdowns
WHERE guild_id = ?1
    AND NOT EXISTS (SELECT 1 FROM guild_lockdown_channels WHERE guild_id = ?1)
"#,
            params![guild_id.to_string()],
        )?;
        Ok(affected > 0)
    }

    /// Change l'état de la ligne ; `lift_at` repousse la prochaine tentative.
    /// Sans ligne, rien n'est écrit.
    pub fn set_lockdown_status(
        &self,
        guild_id: u64,
        status: LockdownStatus,
        lift_at: Option<u64>,
    ) -> Result<(), DatabaseError> {
        let connection = self.write_connection(guild_id)?;
        connection.execute(
            r#"
UPDATE guild_lockdowns
SET status = ?2, lift_at = COALESCE(?3, lift_at), updated_at = unixepoch()
WHERE guild_id = ?1
"#,
            params![guild_id.to_string(), status.key(), lift_at.map(clamp_unix)],
        )?;
        Ok(())
    }

    /// Verrouillage d'une guilde, s'il existe.
    pub fn lockdown_state(&self, guild_id: u64) -> Result<Option<LockdownState>, DatabaseError> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                r#"
SELECT guild_id, reason, status, lift_at, slowmode_seconds
FROM guild_lockdowns
WHERE guild_id = ?1
"#,
                params![guild_id.to_string()],
                read_state_row,
            )
            .optional()?;
        row.map(parse_state).transpose()
    }

    /// Tous les verrouillages persistés, par guilde (reprise au démarrage).
    pub fn lockdown_states(&self) -> Result<Vec<LockdownState>, DatabaseError> {
        let connection = self.connection()?;
        lockdown_states(&connection)
    }

    /// Enregistre l'état d'origine d'un salon avant de le modifier.
    ///
    /// Retourne `false` si une ligne existait déjà : elle est conservée.
    pub fn record_lockdown_channel(
        &self,
        guild_id: u64,
        channel_id: u64,
        state: RecordedChannel,
    ) -> Result<bool, DatabaseError> {
        let connection = self.write_connection(guild_id)?;
        ensure_guild_config(&connection, guild_id)?;
        let affected = connection.execute(
            r#"
INSERT INTO guild_lockdown_channels (guild_id, channel_id, previous_send, previous_slowmode)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT DO NOTHING
"#,
            params![
                guild_id.to_string(),
                channel_id.to_string(),
                state.send_messages.key(),
                state.slowmode
            ],
        )?;
        Ok(affected > 0)
    }

    /// Supprime la ligne d'un salon (restauré, disparu, ou modification
    /// échouée).
    pub fn forget_lockdown_channel(
        &self,
        guild_id: u64,
        channel_id: u64,
    ) -> Result<bool, DatabaseError> {
        let connection = self.write_connection(guild_id)?;
        let affected = connection.execute(
            "DELETE FROM guild_lockdown_channels WHERE guild_id = ?1 AND channel_id = ?2",
            params![guild_id.to_string(), channel_id.to_string()],
        )?;
        Ok(affected > 0)
    }

    /// Salons enregistrés d'une guilde, triés par identifiant.
    ///
    /// Un état illisible se relit en « absent » (voir
    /// [`RecordedChannel::from_stored`]).
    pub fn lockdown_channels(
        &self,
        guild_id: u64,
    ) -> Result<Vec<(u64, RecordedChannel)>, DatabaseError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare_cached(
            r#"
SELECT channel_id, previous_send, previous_slowmode
FROM guild_lockdown_channels
WHERE guild_id = ?1
"#,
        )?;
        let rows = statement.query_map(params![guild_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })?;

        let mut channels = Vec::new();
        for row in rows {
            let (channel_id, send, slowmode) = row?;
            channels.push((
                parse_snowflake(&channel_id)?,
                RecordedChannel::from_stored(&send, slowmode),
            ));
        }
        channels.sort_unstable_by_key(|(channel_id, _)| *channel_id);
        Ok(channels)
    }
}

type StateRow = (String, String, String, i64, i64);

fn read_state_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StateRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn parse_state(
    (guild_id, reason, status, lift_at, slowmode): StateRow,
) -> Result<LockdownState, DatabaseError> {
    Ok(LockdownState {
        guild_id: parse_snowflake(&guild_id)?,
        reason: LockdownReason::from_key(&reason),
        status: LockdownStatus::from_key(&status)
            .ok_or(DatabaseError::InvalidLockdownStatus(status))?,
        lift_at: u64::try_from(lift_at).unwrap_or(0),
        // Valeur illisible (base écrite hors de FoxSecura) : celle de la V1,
        // seule possible avant la migration 9.
        slowmode_seconds: u16::try_from(slowmode)
            .ok()
            .filter(|seconds| *seconds <= MAX_SLOWMODE_SECONDS)
            .unwrap_or(LOCKDOWN_SLOWMODE_SECONDS),
    })
}

fn lockdown_states(connection: &Connection) -> Result<Vec<LockdownState>, DatabaseError> {
    let mut statement = connection.prepare_cached(
        r#"
SELECT guild_id, reason, status, lift_at, slowmode_seconds
FROM guild_lockdowns
ORDER BY lift_at, guild_id
"#,
    )?;
    let rows = statement.query_map([], read_state_row)?;
    let mut states = Vec::new();
    for row in rows {
        states.push(parse_state(row?)?);
    }
    Ok(states)
}

/// SQLite stocke des entiers signés.
fn clamp_unix(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX)
}
