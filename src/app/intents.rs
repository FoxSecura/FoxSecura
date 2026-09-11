// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude::GatewayIntents;

pub fn default() -> GatewayIntents {
    GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MODERATION
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::GUILD_WEBHOOKS
        | GatewayIntents::AUTO_MODERATION_CONFIGURATION
        | GatewayIntents::AUTO_MODERATION_EXECUTION
}
