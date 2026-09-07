// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::{AppData, Error};

pub async fn handle(
    framework: poise::FrameworkContext<'_, AppData, Error>,
    event: &serenity::FullEvent,
) -> Result<(), Error> {
    if let serenity::FullEvent::InteractionCreate { interaction } = event {
        if let serenity::Interaction::Component(component) = interaction {
            crate::commands::handle_component(framework.serenity_context, component).await?;
        }
    }

    Ok(())
}
