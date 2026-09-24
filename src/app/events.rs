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
        serenity::FullEvent::InteractionCreate { interaction } => {
            if let Err(error) = crate::commands::handle_interaction(ctx, data, interaction).await {
                eprintln!("[interaction] erreur lors du traitement d'un composant : {error}");
            }
        }
        _ => {}
    }

    Ok(())
}
