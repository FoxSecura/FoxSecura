// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::Context;
use crate::app::Error;

/// Affiche l'aide principale de FoxSecura.
#[poise::command(slash_command, guild_only, ephemeral)]
pub async fn help(ctx: Context<'_>) -> Result<(), Error> {
    let embed = serenity::CreateEmbed::new()
        .title("FoxSecura | Aide")
        .description("Commandes disponibles dans FoxSecura v2.")
        .field(
            "/config",
            "Ouvre le tableau de bord de configuration avec sélecteur de catégories.",
            false,
        )
        .field(
            "/help",
            "Affiche cette aide et les principales commandes du bot.",
            false,
        )
        .field(
            "/status",
            "Affiche l'état d'exécution et de préparation actuel de FoxSecura.",
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
