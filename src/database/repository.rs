// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use rusqlite::{OptionalExtension, params};

use crate::i18n::Language;
use crate::logs::LogType;
use crate::protection::anti_nuke::settings::{
    AntiNukeSettings, AntiNukeThresholds, validate_panic_threshold,
};
use crate::protection::anti_raid::anti_new_account::is_valid_min_account_age_days;
use crate::protection::anti_raid::join_burst::JoinBurstLimits;
use crate::protection::anti_spam::message_flood::MessageFloodConfig;
use crate::protection::automod::bad_words::BadWordsLanguage;
use crate::protection::shared::is_everyone_role;

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
        let connection = self.write_connection(guild_id)?;
        ensure_guild_config(&connection, guild_id)?;
        read_guild_config(&connection, guild_id)
    }

    /// Lit la configuration d'une guilde sans créer de ligne.
    ///
    /// Destiné aux chemins chauds (un appel par message) : aucune écriture.
    pub fn find_guild_config(&self, guild_id: u64) -> Result<Option<GuildConfig>, DatabaseError> {
        let connection = self.connection()?;
        match read_guild_config(&connection, guild_id) {
            Ok(config) => Ok(Some(config)),
            Err(DatabaseError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Active ou désactive l'anti-spam d'une guilde.
    pub fn set_anti_spam_enabled(
        &self,
        guild_id: u64,
        enabled: bool,
    ) -> Result<GuildConfig, DatabaseError> {
        let connection = self.write_connection(guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_configs (guild_id, anti_spam_enabled)
VALUES (?1, ?2)
ON CONFLICT(guild_id) DO UPDATE SET
    anti_spam_enabled = excluded.anti_spam_enabled,
    updated_at = unixepoch()
"#,
            params![guild_id.to_string(), enabled],
        )?;

        read_guild_config(&connection, guild_id)
    }

    /// Enregistre le seuil et la fenêtre anti-spam après validation des bornes.
    pub fn set_anti_spam_limits(
        &self,
        guild_id: u64,
        message_threshold: u32,
        window_seconds: u32,
    ) -> Result<GuildConfig, DatabaseError> {
        MessageFloodConfig::validated(false, message_threshold, window_seconds)?;
        let connection = self.write_connection(guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_configs (guild_id, anti_spam_message_threshold, anti_spam_window_seconds)
VALUES (?1, ?2, ?3)
ON CONFLICT(guild_id) DO UPDATE SET
    anti_spam_message_threshold = excluded.anti_spam_message_threshold,
    anti_spam_window_seconds = excluded.anti_spam_window_seconds,
    updated_at = unixepoch()
"#,
            params![guild_id.to_string(), message_threshold, window_seconds],
        )?;

        read_guild_config(&connection, guild_id)
    }

    /// Enregistre l'âge minimal des comptes (1 à 365 jours). Une valeur hors
    /// bornes ne modifie rien.
    pub fn set_new_account_min_age(
        &self,
        guild_id: u64,
        days: u16,
    ) -> Result<GuildConfig, DatabaseError> {
        if !is_valid_min_account_age_days(days) {
            return Err(DatabaseError::InvalidNewAccountMinAge(days));
        }
        let connection = self.write_connection(guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_configs (guild_id, new_account_min_age_days)
VALUES (?1, ?2)
ON CONFLICT(guild_id) DO UPDATE SET
    new_account_min_age_days = excluded.new_account_min_age_days,
    updated_at = unixepoch()
"#,
            params![guild_id.to_string(), days],
        )?;

        read_guild_config(&connection, guild_id)
    }

    /// Enregistre le rôle de quarantaine ; `@everyone` est refusé.
    ///
    /// La validation d'un rôle existant (géré, non gérable, permission
    /// dangereuse) se fait d'après le cache Discord, avant l'écriture.
    pub fn set_quarantine_role(
        &self,
        guild_id: u64,
        role_id: u64,
    ) -> Result<GuildConfig, DatabaseError> {
        if is_everyone_role(guild_id, role_id) {
            return Err(DatabaseError::EveryoneRoleNotQuarantinable);
        }
        let connection = self.write_connection(guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_configs (guild_id, quarantine_role_id)
VALUES (?1, ?2)
ON CONFLICT(guild_id) DO UPDATE SET
    quarantine_role_id = excluded.quarantine_role_id,
    updated_at = unixepoch()
"#,
            params![guild_id.to_string(), role_id.to_string()],
        )?;

        read_guild_config(&connection, guild_id)
    }

    /// Enregistre le seuil et la fenêtre de l'anti-raid après validation
    /// des bornes (2 à 50 arrivées, 5 à 120 secondes). Une valeur hors bornes
    /// ne modifie rien.
    pub fn set_anti_raid_limits(
        &self,
        guild_id: u64,
        threshold: u32,
        window_seconds: u32,
    ) -> Result<GuildConfig, DatabaseError> {
        JoinBurstLimits::validated(threshold, window_seconds)?;
        let connection = self.write_connection(guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_configs (guild_id, anti_raid_join_threshold, anti_raid_window_seconds)
VALUES (?1, ?2, ?3)
ON CONFLICT(guild_id) DO UPDATE SET
    anti_raid_join_threshold = excluded.anti_raid_join_threshold,
    anti_raid_window_seconds = excluded.anti_raid_window_seconds,
    updated_at = unixepoch()
"#,
            params![guild_id.to_string(), threshold, window_seconds],
        )?;

        read_guild_config(&connection, guild_id)
    }

    /// Enregistre les seuils des rafales de l'anti-nuke (2 à 20). Une
    /// valeur hors bornes ne modifie rien.
    pub fn set_anti_nuke_thresholds(
        &self,
        guild_id: u64,
        thresholds: AntiNukeThresholds,
    ) -> Result<GuildConfig, DatabaseError> {
        let thresholds = thresholds.validated()?;
        let connection = self.write_connection(guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_configs (
    guild_id, anti_nuke_ban_threshold, anti_nuke_unban_threshold, anti_nuke_create_threshold,
    anti_nuke_emoji_sticker_threshold, anti_nuke_role_grant_threshold
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
ON CONFLICT(guild_id) DO UPDATE SET
    anti_nuke_ban_threshold = excluded.anti_nuke_ban_threshold,
    anti_nuke_unban_threshold = excluded.anti_nuke_unban_threshold,
    anti_nuke_create_threshold = excluded.anti_nuke_create_threshold,
    anti_nuke_emoji_sticker_threshold = excluded.anti_nuke_emoji_sticker_threshold,
    anti_nuke_role_grant_threshold = excluded.anti_nuke_role_grant_threshold,
    updated_at = unixepoch()
"#,
            params![
                guild_id.to_string(),
                thresholds.ban,
                thresholds.unban,
                thresholds.create,
                thresholds.emoji_sticker,
                thresholds.role_grant
            ],
        )?;

        read_guild_config(&connection, guild_id)
    }

    /// Enregistre le seuil du mode panique (2 à 10 types de modules
    /// distincts). Une valeur hors bornes ne modifie rien.
    pub fn set_panic_mode_threshold(
        &self,
        guild_id: u64,
        threshold: u8,
    ) -> Result<GuildConfig, DatabaseError> {
        let threshold = validate_panic_threshold(threshold)?;
        let connection = self.write_connection(guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_configs (guild_id, panic_mode_threshold)
VALUES (?1, ?2)
ON CONFLICT(guild_id) DO UPDATE SET
    panic_mode_threshold = excluded.panic_mode_threshold,
    updated_at = unixepoch()
"#,
            params![guild_id.to_string(), threshold],
        )?;

        read_guild_config(&connection, guild_id)
    }

    /// Enregistre (ou efface, avec `None`) le salon piège du honeypot.
    pub fn set_honeypot_channel(
        &self,
        guild_id: u64,
        channel_id: Option<u64>,
    ) -> Result<GuildConfig, DatabaseError> {
        let connection = self.write_connection(guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_configs (guild_id, honeypot_channel_id)
VALUES (?1, ?2)
ON CONFLICT(guild_id) DO UPDATE SET
    honeypot_channel_id = excluded.honeypot_channel_id,
    updated_at = unixepoch()
"#,
            params![guild_id.to_string(), channel_id.map(|id| id.to_string())],
        )?;

        read_guild_config(&connection, guild_id)
    }

    /// Rôle de quarantaine, servi par le cache de la guilde ; aucune écriture.
    pub fn quarantine_role_id(&self, guild_id: u64) -> Result<Option<u64>, DatabaseError> {
        Ok(self
            .guild_snapshot(guild_id)?
            .guild_config
            .as_ref()
            .and_then(|config| config.quarantine_role_id))
    }

    pub fn set_guild_language(
        &self,
        guild_id: u64,
        language: Language,
    ) -> Result<GuildConfig, DatabaseError> {
        let connection = self.write_connection(guild_id)?;
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
        let connection = self.write_connection(guild_id)?;
        ensure_guild_config(&connection, guild_id)?;

        connection.execute(
            r#"
INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
VALUES (?1, ?2, ?3)
ON CONFLICT(guild_id, log_type) DO UPDATE SET
    channel_id = excluded.channel_id,
    updated_at = unixepoch()
"#,
            params![
                guild_id.to_string(),
                log_type.as_str(),
                channel_id.to_string()
            ],
        )?;

        read_log_channel(&connection, guild_id, log_type)?
            .ok_or_else(|| DatabaseError::Sqlite(rusqlite::Error::QueryReturnedNoRows))
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
        let connection = self.write_connection(guild_id)?;
        let affected = connection.execute(
            "DELETE FROM guild_log_channels WHERE guild_id = ?1 AND log_type = ?2",
            params![guild_id.to_string(), log_type.as_str()],
        )?;

        Ok(affected > 0)
    }
}

pub(super) fn ensure_guild_config(
    connection: &rusqlite::Connection,
    guild_id: u64,
) -> Result<(), DatabaseError> {
    connection.execute(
        "INSERT INTO guild_configs (guild_id) VALUES (?1) ON CONFLICT(guild_id) DO NOTHING",
        params![guild_id.to_string()],
    )?;
    Ok(())
}

pub(super) fn read_guild_config(
    connection: &rusqlite::Connection,
    guild_id: u64,
) -> Result<GuildConfig, DatabaseError> {
    let row = connection.query_row(
        r#"
SELECT guild_id, language, created_at, updated_at,
    anti_spam_enabled, anti_spam_message_threshold, anti_spam_window_seconds,
    bad_words_language, new_account_min_age_days, quarantine_role_id,
    anti_raid_join_threshold, anti_raid_window_seconds, honeypot_channel_id,
    anti_nuke_ban_threshold, anti_nuke_unban_threshold, anti_nuke_create_threshold,
    anti_nuke_emoji_sticker_threshold, anti_nuke_role_grant_threshold, panic_mode_threshold
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
                row.get::<_, bool>(4)?,
                row.get::<_, u32>(5)?,
                row.get::<_, u32>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, u16>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, u32>(10)?,
                row.get::<_, u32>(11)?,
                row.get::<_, Option<String>>(12)?,
                [
                    row.get::<_, u8>(13)?,
                    row.get::<_, u8>(14)?,
                    row.get::<_, u8>(15)?,
                    row.get::<_, u8>(16)?,
                    row.get::<_, u8>(17)?,
                    row.get::<_, u8>(18)?,
                ],
            ))
        },
    )?;

    Ok(GuildConfig {
        guild_id: parse_snowflake(&row.0)?,
        language: parse_language(&row.1)?,
        anti_spam: MessageFloodConfig::validated(row.4, row.5, row.6)?,
        bad_words_language: BadWordsLanguage::from_key(&row.7)
            .ok_or_else(|| DatabaseError::InvalidBadWordsLanguage(row.7.clone()))?,
        new_account_min_age_days: Some(row.8)
            .filter(|days| is_valid_min_account_age_days(*days))
            .ok_or(DatabaseError::InvalidNewAccountMinAge(row.8))?,
        quarantine_role_id: row.9.as_deref().map(parse_snowflake).transpose()?,
        anti_raid: JoinBurstLimits::validated(row.10, row.11)?,
        honeypot_channel_id: row.12.as_deref().map(parse_snowflake).transpose()?,
        anti_nuke: AntiNukeSettings {
            thresholds: AntiNukeThresholds {
                ban: row.13[0],
                unban: row.13[1],
                create: row.13[2],
                emoji_sticker: row.13[3],
                role_grant: row.13[4],
            },
            panic_threshold: row.13[5],
        }
        .validated()?,
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
