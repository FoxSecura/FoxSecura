// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Suppression d'un message déclencheur, commune à tous les modules.

use foxsecura::logs::FailureCode;
use foxsecura::protection::shared::{DeleteMessageOutcome, DeleteMessagePlan};
use poise::serenity_prelude as serenity;

/// Supprime le message et classe le résultat.
pub async fn delete_message(
    ctx: &serenity::Context,
    plan: &DeleteMessagePlan,
) -> DeleteMessageOutcome {
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
                failure_code: FailureCode::DiscordUnavailable,
                details: error.to_string(),
            },
        },
        Err(error) => DeleteMessageOutcome::Failed {
            failure_code: FailureCode::Unknown,
            details: error.to_string(),
        },
    }
}

/// Code HTTP d'une erreur Discord, s'il y en a un.
pub fn http_status(error: &serenity::Error) -> Option<u16> {
    match error {
        serenity::Error::Http(error) => error.status_code().map(|status| status.as_u16()),
        _ => None,
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
