// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::Context;
use crate::app::Error;
use foxsecura::i18n::{Language, TextKey, text};

/// Affiche l'aide principale de FoxSecura.
#[poise::command(slash_command, guild_only, ephemeral)]
pub async fn help(ctx: Context<'_>) -> Result<(), Error> {
    let language = Language::resolve(ctx.locale());
    let embed = serenity::CreateEmbed::new()
        .title(text(language, TextKey::HelpTitle))
        .description(text(language, TextKey::HelpDescription))
        .field(
            "/config",
            text(language, TextKey::HelpConfigDescription),
            false,
        )
        .field(
            "/help",
            text(language, TextKey::HelpHelpDescription),
            false,
        )
        .field(
            "/status",
            text(language, TextKey::HelpStatusDescription),
            false,
        );

    ctx.send(
        poise::CreateReply::default()
            .embed(embed)
            .ephemeral(true),
    )
    .await?;

    Ok(())
}
