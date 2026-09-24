// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::database::GuildConfig;
use foxsecura::i18n::DEFAULT_LANGUAGE;
use foxsecura::protection::anti_spam::message_flood::{
    DeleteMessageOutcome, DeleteMessagePlan, build_incident, plan_response,
};
use foxsecura::protection::shared::GuildMessage;
use poise::serenity_prelude as serenity;

use super::incident_log;
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

    let outcome = delete_message(ctx, &plan).await;
    let language = guild_config.map_or(DEFAULT_LANGUAGE, |guild_config| guild_config.language);
    let incident = build_incident(language, message, &detection, &outcome);
    incident_log::publish(ctx, data, guild_id, language, &incident).await;

    Ok(())
}

async fn delete_message(ctx: &serenity::Context, plan: &DeleteMessagePlan) -> DeleteMessageOutcome {
    // Évite un appel voué au 403 : Discord limite le volume de requêtes
    // invalides et un spam dans un salon non géré en produirait en rafale.
    if can_manage_messages(ctx, plan) == Some(false) {
        return DeleteMessageOutcome::NotDeletable;
    }

    let result = serenity::ChannelId::new(plan.channel_id)
        .delete_message(&ctx.http, serenity::MessageId::new(plan.message_id))
        .await;

    match result {
        Ok(()) => DeleteMessageOutcome::Deleted,
        Err(serenity::Error::Http(error)) => match error.status_code() {
            Some(status) => {
                DeleteMessageOutcome::from_http_status(status.as_u16(), error.to_string())
            }
            None => DeleteMessageOutcome::Failed {
                failure_code: foxsecura::logs::FailureCode::DiscordUnavailable,
                details: error.to_string(),
            },
        },
        Err(error) => DeleteMessageOutcome::Failed {
            failure_code: foxsecura::logs::FailureCode::Unknown,
            details: error.to_string(),
        },
    }
}

/// `MANAGE_MESSAGES` du bot dans le salon, d'après le cache.
///
/// Retourne `None` si le cache ne permet pas de conclure : la suppression est
/// alors tentée et un éventuel 403 est classé `not_deletable`.
fn can_manage_messages(ctx: &serenity::Context, plan: &DeleteMessagePlan) -> Option<bool> {
    let bot_id = ctx.cache.current_user().id;
    let guild = ctx.cache.guild(serenity::GuildId::new(plan.guild_id))?;
    let member = guild.members.get(&bot_id)?;
    let channel_id = serenity::ChannelId::new(plan.channel_id);

    // Les fils héritent des permissions de leur salon parent.
    let channel = guild.channels.get(&channel_id).or_else(|| {
        guild
            .threads
            .iter()
            .find(|thread| thread.id == channel_id)
            .and_then(|thread| thread.parent_id)
            .and_then(|parent_id| guild.channels.get(&parent_id))
    })?;

    Some(guild.user_permissions_in(channel, member).manage_messages())
}
