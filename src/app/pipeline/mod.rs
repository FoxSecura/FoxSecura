// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Branchement des protections au runtime Discord.
//!
//! Chaque pipeline suit `snapshot → détection → décision → action → log` : la
//! logique métier reste dans `foxsecura::protection`, ce module ne fait que
//! convertir les événements et exécuter les effets Discord.

mod anti_spam;
mod content_filter;
mod delete;
mod incident_log;
pub mod member;
pub mod message;
pub mod quarantine;
mod sanction;

use std::time::Duration;

use foxsecura::database::GuildConfig;
use foxsecura::protection::quarantine::bot_assigned_roles as guild_bot_assigned_roles;
use poise::serenity_prelude as serenity;

/// Rôles que FoxSecura attribue lui-même dans la guilde et qui n'exemptent
/// jamais de la liste blanche.
///
/// Dans la V1 : rôles de vérification, de quarantaine et rôle limité. Seul le
/// rôle de quarantaine existe dans la V2.
fn bot_assigned_roles(guild_config: Option<&GuildConfig>) -> &[u64] {
    guild_bot_assigned_roles(guild_config.and_then(|config| config.quarantine_role_id.as_ref()))
}

/// Horodatage Discord en durée depuis l'époque Unix ; `None` avant 1970.
fn unix_duration(timestamp: serenity::Timestamp) -> Option<Duration> {
    u64::try_from(timestamp.unix_timestamp())
        .ok()
        .map(Duration::from_secs)
}
