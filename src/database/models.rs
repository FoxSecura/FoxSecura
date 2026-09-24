// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::i18n::Language;
use crate::logs::LogType;
use crate::protection::anti_spam::message_flood::MessageFloodConfig;
use crate::protection::automod::bad_words::BadWordsLanguage;
use crate::protection::shared::ModuleSet;

use super::DatabaseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuildConfig {
    pub guild_id: u64,
    pub language: Language,
    /// Réglages anti-spam persistés (migration 2), relus par le runtime.
    pub anti_spam: MessageFloodConfig,
    /// Liste intégrée des mots interdits (migration 5).
    pub bad_words_language: BadWordsLanguage,
    /// Âge minimal d'un compte à l'arrivée, en jours (migration 6, 1 à 365).
    pub new_account_min_age_days: u16,
    /// Rôle de quarantaine (migration 7) ; `None` : non configuré.
    pub quarantine_role_id: Option<u64>,
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

/// Liste blanche et salons ignorés d'une guilde (migration 3), triés par
/// identifiant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuildExemptions {
    pub whitelist_users: Vec<u64>,
    pub whitelist_roles: Vec<u64>,
    pub ignored_channels: Vec<u64>,
}

/// Données lues en un seul passage pour un message de guilde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageGuardContext {
    /// `None` si la guilde n'a jamais été configurée.
    pub guild_config: Option<GuildConfig>,
    pub channel_ignored: bool,
    /// L'identifiant de l'auteur est sur la liste blanche.
    pub author_listed: bool,
    /// Rôles de la liste blanche de la guilde.
    pub whitelist_roles: Vec<u64>,
    /// Modules de protection activés (migration 4). Vide si la guilde n'est
    /// pas configurée ou si le salon est ignoré : rien ne s'y applique.
    pub enabled_modules: ModuleSet,
    /// Mots interdits personnalisés (migration 5), lus seulement si le module
    /// `bad_words` est activé. La langue de la liste intégrée est dans
    /// `guild_config`.
    pub custom_bad_words: Arc<[String]>,
}

/// Données lues en un seul passage pour une arrivée ou une mise à jour de
/// membre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberGuardContext {
    /// `None` si la guilde n'a jamais été configurée : rien n'est activé.
    pub guild_config: Option<GuildConfig>,
    /// L'utilisateur est sur la liste noire (migration 6).
    pub blacklisted: bool,
    /// L'identifiant de l'utilisateur est sur la liste blanche.
    pub user_whitelisted: bool,
    /// Rôles de la liste blanche de la guilde.
    pub whitelist_roles: Vec<u64>,
    /// Modules de protection activés.
    pub enabled_modules: ModuleSet,
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
