// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::i18n::Language;
use crate::logs::LogType;

use super::DatabaseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuildConfig {
    pub guild_id: u64,
    pub language: Language,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuildLogChannel {
    pub guild_id: u64,
    pub log_type: LogType,
    pub channel_id: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

pub(crate) fn parse_language(value: &str) -> Result<Language, DatabaseError> {
    Language::from_locale(value).ok_or_else(|| DatabaseError::InvalidLanguage(value.to_owned()))
}

pub(crate) fn parse_log_type(value: &str) -> Result<LogType, DatabaseError> {
    match value {
        "message" => Ok(LogType::Message),
        "server" => Ok(LogType::Server),
        "member" => Ok(LogType::Member),
        "channel" => Ok(LogType::Channel),
        "role" => Ok(LogType::Role),
        "moderation" => Ok(LogType::Moderation),
        _ => Err(DatabaseError::InvalidLogType(value.to_owned())),
    }
}

pub(crate) fn parse_snowflake(value: &str) -> Result<u64, DatabaseError> {
    value
        .parse::<u64>()
        .map_err(|_| DatabaseError::InvalidSnowflake(value.to_owned()))
}
