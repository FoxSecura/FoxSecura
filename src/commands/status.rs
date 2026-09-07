// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::Context;
use crate::app::Error;

/// Affiche l'état actuel de FoxSecura.
#[poise::command(slash_command, guild_only)]
pub async fn status(ctx: Context<'_>) -> Result<(), Error> {
    let embed = serenity::CreateEmbed::new()
        .title("FoxSecura | Statut")
        .description("État d'exécution et de préparation de FoxSecura v2.")
        .field("Application", "Opérationnelle", true)
        .field("Gateway Discord", "Connecté", true)
        .field("Framework", "Poise + Serenity", true)
        .field("Commandes", "`/config` `/help` `/status`", false)
        .field(
            "Modules de sécurité",
            "Architecture en cours de reconstruction.",
            false,
        )
        .field("Version", env!("CARGO_PKG_VERSION"), true);

    ctx.send(poise::CreateReply::default().embed(embed)).await?;

    Ok(())
}
