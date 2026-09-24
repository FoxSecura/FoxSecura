// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::database::GuildConfig;
use foxsecura::i18n::DEFAULT_LANGUAGE;
use foxsecura::protection::anti_spam::message_flood::{build_incident, plan_response};
use foxsecura::protection::shared::GuildMessage;
use poise::serenity_prelude as serenity;

use super::{delete, incident_log};
use crate::app::{AppData, Error};

/// Anti-spam : rafale de messages d'un membre → suppression du message
/// déclencheur → incident.
///
/// `guild_config` est lu par le pipeline avec le reste du contexte du message ;
/// `None` pour une guilde jamais configurée (anti-spam désactivé par défaut).
pub async fn run(
    ctx: &serenity::Context,
    data: &AppData,
    message: &GuildMessage,
    guild_config: Option<&GuildConfig>,
) -> Result<(), Error> {
    let guild_id = message.guild_id;
    let config = guild_config
        .map(|guild_config| guild_config.anti_spam)
        .unwrap_or_default();

    // Le verrou est relâché à la fin de l'instruction, avant tout `.await`.
    let detection = data.protection.message_flood().observe(&config, message);
    let Some(detection) = detection else {
        return Ok(());
    };
    let Some(plan) = plan_response(message, &detection) else {
        return Ok(());
    };

    let outcome = delete::delete_message(ctx, &plan).await;
    let language = guild_config.map_or(DEFAULT_LANGUAGE, |guild_config| guild_config.language);
    let incident = build_incident(language, message, &detection, &outcome);
    incident_log::publish(ctx, data, guild_id, language, &incident).await;

    Ok(())
}
