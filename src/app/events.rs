// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::{AppData, Error};

pub async fn handle(
    _ctx: &serenity::Context,
    _event: &serenity::FullEvent,
    _framework: poise::FrameworkContext<'_, AppData, Error>,
    _data: &AppData,
) -> Result<(), Error> {
    Ok(())
}
