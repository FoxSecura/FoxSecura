// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::shared::{MessageSnapshot, screen_message, snowflake_timestamp};
use poise::serenity_prelude as serenity;

use super::anti_spam;
use crate::app::AppData;

/// Pipeline de protection des messages.
///
/// Gardes (hors guilde, webhook, bot) puis modules activés pour la guilde.
/// Chaque module est isolé : son erreur est journalisée sans interrompre le
/// pipeline ni le client.
pub async fn handle(ctx: &serenity::Context, data: &AppData, message: &serenity::Message) {
    let snapshot = snapshot(message);
    let Ok(guild_message) = screen_message(&snapshot) else {
        return;
    };

    if let Err(error) = anti_spam::run(ctx, data, &guild_message).await {
        eprintln!(
            "[anti_spam] échec sur la guilde {} (message {}) : {error}",
            guild_message.guild_id, guild_message.message_id
        );
    }
}

fn snapshot(message: &serenity::Message) -> MessageSnapshot {
    MessageSnapshot {
        guild_id: message.guild_id.map(serenity::GuildId::get),
        channel_id: message.channel_id.get(),
        message_id: message.id.get(),
        author_id: message.author.id.get(),
        author_is_bot: message.author.bot,
        webhook_id: message.webhook_id.map(serenity::WebhookId::get),
        timestamp: snowflake_timestamp(message.id.get()),
    }
}
