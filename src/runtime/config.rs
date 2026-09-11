// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet};
use serde_json::Value;

pub const MODULES: &[&str] = &[
    "anti_everyone",
    "anti_ghost_ping",
    "anti_mass_mention",
    "anti_ping_owner",
    "anti_scam",
    "anti_spam_ping",
    "attachment_filter",
    "auto_slowmode",
    "invisible_char_filter",
    "malicious_link",
    "message_flood",
    "anti_bot",
    "anti_double_account",
    "anti_impersonation",
    "anti_new_account",
    "anti_nickname_hoisting",
    "honeypot",
    "join_burst",
    "webhook_message",
    "webhook_watch",
    "anti_mass_ban",
    "anti_mass_kick",
    "anti_mass_timeout",
    "anti_mass_unban",
    "anti_channel_delete",
    "anti_role_delete",
    "anti_mass_channel_create",
    "anti_mass_role_create",
    "anti_mass_role_grant",
    "anti_emoji_sticker_nuke",
    "anti_permissions",
    "anti_external_application",
    "anti_server_edit",
    "anti_vanity_change",
    "automod_rule_guard",
    "limit_role",
    "panic_mode",
    "adult_link",
    "anti_invite",
    "bad_words",
    "member_profile",
    "native_rules",
    "ai_moderation",
];

/// Configuration chargée au démarrage, isolée par serveur. Aucune activation implicite.
#[derive(Debug, Clone, Default)]
pub struct GuildProtectionConfig {
    pub enabled: HashSet<String>,
    pub enforce: bool,
    pub exempt_users: HashSet<u64>,
    pub exempt_roles: HashSet<u64>,
    pub ignored_channels: HashSet<u64>,
    pub honeypot_channel: Option<u64>,
    pub log_channel: Option<u64>,
    pub limited_roles: HashMap<u64, usize>,
    pub protected_names: Vec<String>,
    pub blocked_words: Vec<String>,
    pub minimum_account_age_days: u64,
}

impl GuildProtectionConfig {
    pub fn enabled(&self, module: &str) -> bool {
        self.enabled.contains(module)
    }

    pub fn exempt(&self, user_id: u64, roles: &[u64]) -> bool {
        self.exempt_users.contains(&user_id)
            || roles.iter().any(|role| self.exempt_roles.contains(role))
    }
}

/// Refuse les fautes de frappe et les valeurs ambiguës au lieu d'ignorer une protection.
pub fn parse_config(content: &str) -> Result<HashMap<u64, GuildProtectionConfig>, String> {
    let value: Value = serde_json::from_str(content).map_err(|_| "JSON de protection invalide")?;
    let guilds = value.as_object().ok_or("La configuration doit être un objet par serveur")?;
    let mut result = HashMap::new();
    for (guild, value) in guilds {
        let guild_id = snowflake(&Value::String(guild.clone()))?;
        let fields = value.as_object().ok_or("Configuration serveur invalide")?;
        for key in fields.keys() {
            if !["enabled", "enforce", "exempt_users", "exempt_roles", "ignored_channels",
                "honeypot_channel", "log_channel", "limited_roles", "protected_names",
                "blocked_words", "minimum_account_age_days"].contains(&key.as_str()) {
                return Err(format!("Option de protection inconnue : {key}"));
            }
        }
        let enabled: HashSet<String> = strings(value.get("enabled"))?.into_iter().collect();
        if let Some(unknown) = enabled.iter().find(|name| !MODULES.contains(&name.as_str())) {
            return Err(format!("Module de protection inconnu : {unknown}"));
        }
        let mut config = GuildProtectionConfig {
            enabled,
            enforce: match value.get("enforce") {
                None => false,
                Some(value) => value.as_bool().ok_or("enforce doit être un booléen")?,
            },
            exempt_users: ids(value.get("exempt_users"))?,
            exempt_roles: ids(value.get("exempt_roles"))?,
            ignored_channels: ids(value.get("ignored_channels"))?,
            honeypot_channel: value.get("honeypot_channel").map(snowflake).transpose()?,
            log_channel: value.get("log_channel").map(snowflake).transpose()?,
            protected_names: strings(value.get("protected_names"))?,
            blocked_words: strings(value.get("blocked_words"))?,
            minimum_account_age_days: match value.get("minimum_account_age_days") {
                None => 7,
                Some(value) => value.as_u64().filter(|days| *days <= 365)
                    .ok_or("Âge minimum invalide (0 à 365 jours)")?,
            },
            ..Default::default()
        };
        if let Some(roles) = value.get("limited_roles") {
            for (role, limit) in roles.as_object().ok_or("limited_roles doit être un objet")? {
                let role = snowflake(&Value::String(role.clone()))?;
                let limit = limit.as_u64().and_then(|n| usize::try_from(n).ok())
                    .ok_or("Limite de rôle invalide")?;
                config.limited_roles.insert(role, limit);
            }
        }
        if config.enabled("honeypot") && config.honeypot_channel.is_none() {
            return Err("honeypot exige honeypot_channel".into());
        }
        if config.enabled("limit_role") && config.limited_roles.is_empty() {
            return Err("limit_role exige limited_roles".into());
        }
        if config.exempt_roles.len() > 20 || config.ignored_channels.len() > 50 {
            return Err("Maximum : 20 rôles exemptés et 50 salons ignorés".into());
        }
        result.insert(guild_id, config);
    }
    Ok(result)
}

fn strings(value: Option<&Value>) -> Result<Vec<String>, String> {
    match value {
        None => Ok(Vec::new()),
        Some(value) => value.as_array().ok_or("Une liste est attendue")?.iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or("Une chaîne est attendue".into()))
            .collect(),
    }
}

fn ids(value: Option<&Value>) -> Result<HashSet<u64>, String> {
    match value {
        None => Ok(HashSet::new()),
        Some(value) => value.as_array().ok_or("Une liste d'identifiants est attendue")?
            .iter().map(snowflake).collect(),
    }
}

fn snowflake(value: &Value) -> Result<u64, String> {
    value.as_str().and_then(|s| s.parse().ok()).or_else(|| value.as_u64())
        .filter(|id| *id != 0).ok_or("Identifiant Discord invalide".into())
}
