// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::Context;
use crate::app::Error;
use foxsecura::i18n::{Language, TextKey, text};

/// Affiche l'état actuel de FoxSecura.
#[poise::command(slash_command, guild_only)]
pub async fn status(ctx: Context<'_>) -> Result<(), Error> {
    let language = Language::resolve(ctx.locale());
    let embed = serenity::CreateEmbed::new()
        .title(text(language, TextKey::StatusTitle))
        .description(text(language, TextKey::StatusDescription))
        .field(
            text(language, TextKey::StatusApplication),
            text(language, TextKey::StatusOperational),
            true,
        )
        .field(
            text(language, TextKey::StatusGateway),
            text(language, TextKey::StatusConnected),
            true,
        )
        .field(text(language, TextKey::StatusFramework), "Poise + Serenity", true)
        .field(
            text(language, TextKey::StatusCommands),
            "`/config` `/help` `/status`",
            false,
        )
        .field(
            text(language, TextKey::StatusSecurityModules),
            text(language, TextKey::StatusSecurityModulesReady),
            false,
        )
        .field(
            text(language, TextKey::StatusVersion),
            env!("CARGO_PKG_VERSION"),
            true,
        );

    ctx.send(poise::CreateReply::default().embed(embed)).await?;

    Ok(())
}
