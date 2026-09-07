// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::{AppData, Error};

pub async fn handle(
    ctx: &serenity::Context,
    event: &serenity::FullEvent,
    _framework: poise::FrameworkContext<'_, AppData, Error>,
    _data: &AppData,
) -> Result<(), Error> {
    if let serenity::FullEvent::InteractionCreate { interaction } = event {
        if let serenity::Interaction::Component(component) = interaction {
            crate::commands::handle_component(ctx, component).await?;
        }
    }

    Ok(())
}
