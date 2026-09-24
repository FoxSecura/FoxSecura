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
mod sanction;

use std::time::Duration;

use poise::serenity_prelude as serenity;

/// Rôles que FoxSecura attribue lui-même et qui n'exemptent jamais.
///
/// Dans la V1 : rôles de vérification, de quarantaine et rôle limité. Aucun
/// n'existe encore dans la V2 : la liste est vide tant que ces modules ne sont
/// pas portés.
const BOT_ASSIGNED_ROLES: &[u64] = &[];

/// Horodatage Discord en durée depuis l'époque Unix ; `None` avant 1970.
fn unix_duration(timestamp: serenity::Timestamp) -> Option<Duration> {
    u64::try_from(timestamp.unix_timestamp())
        .ok()
        .map(Duration::from_secs)
}
