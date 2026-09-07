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

pub async fn handle_component(
    ctx: &serenity::Context,
    component: &serenity::ComponentInteraction,
) -> Result<(), Error> {
    if config::handle_component(ctx, component).await? {
        return Ok(());
    }

    Ok(())
}
