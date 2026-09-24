// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Instantané d'un message Discord et gardes communes du pipeline de messages.
//!
//! Le runtime convertit l'événement Discord en [`MessageSnapshot`] ; les
//! protections ne manipulent ensuite que cette structure, ce qui permet de les
//! tester sans Discord.

use std::time::Duration;

/// Époque des identifiants Discord (1er janvier 2015), en millisecondes Unix.
pub const DISCORD_EPOCH_MILLIS: u64 = 1_420_070_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageSnapshot {
    pub guild_id: Option<u64>,
    pub channel_id: u64,
    pub message_id: u64,
    pub author_id: u64,
    pub author_is_bot: bool,
    pub webhook_id: Option<u64>,
    /// Horodatage du message depuis l'époque Unix.
    pub timestamp: Duration,
}

/// Message de guilde retenu par les gardes, prêt pour les protections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuildMessage {
    pub guild_id: u64,
    pub channel_id: u64,
    pub message_id: u64,
    pub author_id: u64,
    pub timestamp: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageIgnoreReason {
    OutsideGuild,
    Webhook,
    BotAuthor,
}

/// Applique les gardes communes, dans l'ordre : hors guilde, webhook, bot.
pub fn screen_message(snapshot: &MessageSnapshot) -> Result<GuildMessage, MessageIgnoreReason> {
    let Some(guild_id) = snapshot.guild_id else {
        return Err(MessageIgnoreReason::OutsideGuild);
    };

    if snapshot.webhook_id.is_some() {
        return Err(MessageIgnoreReason::Webhook);
    }

    if snapshot.author_is_bot {
        return Err(MessageIgnoreReason::BotAuthor);
    }

    Ok(GuildMessage {
        guild_id,
        channel_id: snapshot.channel_id,
        message_id: snapshot.message_id,
        author_id: snapshot.author_id,
        timestamp: snapshot.timestamp,
    })
}

/// Horodatage encodé dans un identifiant Discord (précision à la milliseconde).
pub const fn snowflake_timestamp(id: u64) -> Duration {
    Duration::from_millis((id >> 22) + DISCORD_EPOCH_MILLIS)
}
