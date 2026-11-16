// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Mode lent automatique (migration 11) : une ligne par salon ralenti, avec
//! l'ancien mode lent, écrite **avant** la pose et supprimée seulement après
//! la levée (restauration, salon modifié par l'équipe ou disparu).
//!
//! Seule la pose crée la configuration de la guilde (clé étrangère) et passe
//! donc par `WriteConnection`, qui invalide le cache de la guilde. Les autres
//! écritures ne touchent que cette table, absente de l'instantané : elles
//! n'invalident rien (une rafale repousse la levée à chaque message).

use rusqlite::{OptionalExtension, params};

use crate::protection::anti_spam::auto_slowmode::AutoSlowmode;
use crate::protection::lockdown::MAX_SLOWMODE_SECONDS;

use super::models::parse_snowflake;
use super::repository::ensure_guild_config;
use super::{Database, DatabaseError};

impl Database {
    /// Enregistre l'ancien mode lent avant la pose ; `false` si le salon a
    /// déjà une ligne (pose concurrente), qui est conservée.
    pub fn begin_auto_slowmode(&self, slowmode: AutoSlowmode) -> Result<bool, DatabaseError> {
        let connection = self.write_connection(slowmode.guild_id)?;
        ensure_guild_config(&connection, slowmode.guild_id)?;
        let affected = connection.execute(
            r#"
INSERT INTO guild_auto_slowmodes (guild_id, channel_id, previous_seconds, applied_seconds, lift_at)
VALUES (?1, ?2, ?3, ?4, ?5)
ON CONFLICT DO NOTHING
"#,
            params![
                slowmode.guild_id.to_string(),
                slowmode.channel_id.to_string(),
                slowmode.previous_seconds.min(MAX_SLOWMODE_SECONDS),
                slowmode.applied_seconds.clamp(1, MAX_SLOWMODE_SECONDS),
                clamp_unix(slowmode.lift_at)
            ],
        )?;
        Ok(affected > 0)
    }

    /// Repousse la levée (rafale qui continue) sans jamais l'avancer ; `false`
    /// si le salon n'a pas de ligne.
    pub fn extend_auto_slowmode(
        &self,
        guild_id: u64,
        channel_id: u64,
        lift_at: u64,
    ) -> Result<bool, DatabaseError> {
        let connection = self.connection()?;
        let affected = connection.execute(
            r#"
UPDATE guild_auto_slowmodes
SET lift_at = MAX(lift_at, ?3), updated_at = unixepoch()
WHERE guild_id = ?1 AND channel_id = ?2
"#,
            params![
                guild_id.to_string(),
                channel_id.to_string(),
                clamp_unix(lift_at)
            ],
        )?;
        Ok(affected > 0)
    }

    /// Fixe la prochaine tentative de levée (échec, verrouillage actif).
    pub fn reschedule_auto_slowmode(
        &self,
        guild_id: u64,
        channel_id: u64,
        lift_at: u64,
    ) -> Result<(), DatabaseError> {
        let connection = self.connection()?;
        connection.execute(
            r#"
UPDATE guild_auto_slowmodes
SET lift_at = ?3, updated_at = unixepoch()
WHERE guild_id = ?1 AND channel_id = ?2
"#,
            params![
                guild_id.to_string(),
                channel_id.to_string(),
                clamp_unix(lift_at)
            ],
        )?;
        Ok(())
    }

    /// Supprime la ligne d'un salon (levée terminée, pose échouée) ; `true`
    /// si elle existait.
    pub fn forget_auto_slowmode(
        &self,
        guild_id: u64,
        channel_id: u64,
    ) -> Result<bool, DatabaseError> {
        let connection = self.connection()?;
        let affected = connection.execute(
            "DELETE FROM guild_auto_slowmodes WHERE guild_id = ?1 AND channel_id = ?2",
            params![guild_id.to_string(), channel_id.to_string()],
        )?;
        Ok(affected > 0)
    }

    /// Ligne d'un salon, s'il est ralenti par FoxSecura.
    pub fn auto_slowmode(
        &self,
        guild_id: u64,
        channel_id: u64,
    ) -> Result<Option<AutoSlowmode>, DatabaseError> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                r#"
SELECT guild_id, channel_id, previous_seconds, applied_seconds, lift_at
FROM guild_auto_slowmodes
WHERE guild_id = ?1 AND channel_id = ?2
"#,
                params![guild_id.to_string(), channel_id.to_string()],
                read_row,
            )
            .optional()?;
        row.map(parse_row).transpose()
    }

    /// Lignes échues à `now` (secondes Unix), par échéance : reprise au
    /// démarrage et maintenance périodique.
    pub fn due_auto_slowmodes(&self, now: u64) -> Result<Vec<AutoSlowmode>, DatabaseError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare_cached(
            r#"
SELECT guild_id, channel_id, previous_seconds, applied_seconds, lift_at
FROM guild_auto_slowmodes
WHERE lift_at <= ?1
ORDER BY lift_at, guild_id, channel_id
"#,
        )?;
        let rows = statement.query_map(params![clamp_unix(now)], read_row)?;
        let mut slowmodes = Vec::new();
        for row in rows {
            slowmodes.push(parse_row(row?)?);
        }
        Ok(slowmodes)
    }
}

type Row = (String, String, i64, i64, i64);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn parse_row(
    (guild_id, channel_id, previous, applied, lift_at): Row,
) -> Result<AutoSlowmode, DatabaseError> {
    Ok(AutoSlowmode {
        guild_id: parse_snowflake(&guild_id)?,
        channel_id: parse_snowflake(&channel_id)?,
        // Bornées par les contraintes `CHECK` ; une valeur illisible (base
        // écrite hors de FoxSecura) se relit en « aucun mode lent » d'origine
        // et en un mode lent posé jamais égal à celui du salon.
        previous_seconds: u16::try_from(previous)
            .ok()
            .filter(|seconds| *seconds <= MAX_SLOWMODE_SECONDS)
            .unwrap_or(0),
        applied_seconds: u16::try_from(applied)
            .ok()
            .filter(|seconds| *seconds <= MAX_SLOWMODE_SECONDS)
            .unwrap_or(u16::MAX),
        lift_at: u64::try_from(lift_at).unwrap_or(0),
    })
}

/// SQLite stocke des entiers signés.
fn clamp_unix(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX)
}
