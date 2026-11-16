// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude as serenity;

use super::{AppData, Error, pipeline};

/// Répartit les événements Gateway vers les modules concernés.
///
/// Les erreurs sont journalisées ici et jamais propagées : une protection ou
/// un composant défaillant ne doit ni arrêter le client, ni empêcher le
/// traitement des événements suivants.
pub async fn handle(
    framework: poise::FrameworkContext<'_, AppData, Error>,
    event: &serenity::FullEvent,
) -> Result<(), Error> {
    let ctx = framework.serenity_context;
    let data = framework.user_data;

    match event {
        serenity::FullEvent::Message { new_message } => {
            pipeline::message::handle(ctx, data, new_message).await;
        }
        serenity::FullEvent::MessageUpdate { event, .. } => {
            pipeline::message::handle_update(ctx, data, event).await;
        }
        serenity::FullEvent::MessageDelete {
            deleted_message_id,
            guild_id,
            ..
        } => {
            pipeline::ghost_ping::handle_delete(ctx, data, *guild_id, *deleted_message_id).await;
        }
        serenity::FullEvent::MessageDeleteBulk {
            multiple_deleted_messages_ids,
            guild_id,
            ..
        } => {
            pipeline::ghost_ping::handle_delete_bulk(
                data,
                *guild_id,
                multiple_deleted_messages_ids,
            );
        }
        serenity::FullEvent::GuildMemberAddition { new_member } => {
            pipeline::member::handle_join(ctx, data, new_member).await;
        }
        serenity::FullEvent::GuildMemberUpdate {
            old_if_available,
            event,
            ..
        } => {
            pipeline::member::handle_update(ctx, data, old_if_available.as_ref(), event).await;
        }
        serenity::FullEvent::GuildCreate { guild, .. } => {
            pipeline::member::handle_guild_create(ctx, data, guild).await;
            pipeline::anti_nuke::handle_guild_create(ctx, data, guild.id.get()).await;
        }
        serenity::FullEvent::GuildUpdate {
            old_data_if_available,
            new_data,
        } => {
            pipeline::server_integrity::handle_guild_update(
                ctx,
                data,
                old_data_if_available.as_ref(),
                new_data,
            )
            .await;
        }
        serenity::FullEvent::ChannelCreate { channel } => {
            pipeline::quarantine::handle_channel_create(ctx, data, channel).await;
        }
        serenity::FullEvent::CategoryCreate { category } => {
            pipeline::quarantine::handle_channel_create(ctx, data, category).await;
        }
        serenity::FullEvent::ChannelDelete { channel, .. } => {
            pipeline::restore::handle_channel_delete(ctx, data, channel).await;
        }
        serenity::FullEvent::CategoryDelete { category } => {
            pipeline::restore::handle_channel_delete(ctx, data, category).await;
        }
        serenity::FullEvent::GuildRoleDelete {
            guild_id,
            removed_role_id,
            removed_role_data_if_available,
        } => {
            pipeline::restore::handle_role_delete(
                ctx,
                data,
                *guild_id,
                *removed_role_id,
                removed_role_data_if_available.as_ref(),
            )
            .await;
        }
        serenity::FullEvent::GuildAuditLogEntryCreate { entry, guild_id } => {
            pipeline::anti_nuke::handle_audit_entry(ctx, data, *guild_id, entry).await;
        }
        serenity::FullEvent::InteractionCreate { interaction } => {
            if let Err(error) = crate::commands::handle_interaction(ctx, data, interaction).await {
                eprintln!("[interaction] erreur lors du traitement d'un composant : {error}");
            }
        }
        _ => {}
    }

    Ok(())
}
