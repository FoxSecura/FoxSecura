// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod config;
mod help;
mod status;

use poise::serenity_prelude as serenity;

use crate::app::{AppData, Error};

pub type Context<'a> = poise::Context<'a, AppData, Error>;

pub fn all() -> Vec<poise::Command<AppData, Error>> {
    vec![config::config(), help::help(), status::status()]
}

/// Route les interactions hors slash commands (composants, modals).
pub async fn handle_interaction(
    ctx: &serenity::Context,
    data: &AppData,
    interaction: &serenity::Interaction,
) -> Result<(), Error> {
    match interaction {
        serenity::Interaction::Component(component) => {
            config::handle_component(ctx, data, component).await?;
        }
        serenity::Interaction::Modal(modal) => {
            config::handle_modal(ctx, data, modal).await?;
        }
        _ => {}
    }

    Ok(())
}
