// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::i18n::Language;
use foxsecura::protection::content_filter::{
    ContentDetection, MessageContent, MessageEvent, RevisionCheck, build_incident, check_revision,
    revision_fetch_failure,
};
use foxsecura::protection::shared::{DeleteMessageOutcome, DeleteMessagePlan, GuildMessage};
use poise::serenity_prelude as serenity;

use super::{delete, incident_log, message};
use crate::app::AppData;

/// Filtres de contenu : suppression du message retenu → incident.
///
/// Après une modification, la version courante est relue avant de supprimer :
/// une version déjà corrigée par son auteur n'est jamais effacée.
pub async fn run(
    ctx: &serenity::Context,
    data: &AppData,
    message: &GuildMessage,
    detection: &ContentDetection,
    event: MessageEvent,
    content: &MessageContent,
    language: Language,
) {
    let plan = DeleteMessagePlan::for_message(message);
    let outcome = match event {
        MessageEvent::Created => delete::delete_message(ctx, &plan).await,
        MessageEvent::Edited => match current_revision(ctx, &plan, content).await {
            Ok(RevisionCheck::Current) => delete::delete_message(ctx, &plan).await,
            Ok(check) => {
                println!(
                    "[content_filter] {} : message {} non supprimé, version analysée obsolète ({check:?})",
                    detection.module, message.message_id
                );
                return;
            }
            Err(outcome) => outcome,
        },
    };

    let incident = build_incident(language, message, detection, event, content, &outcome);
    incident_log::publish(ctx, data, message.guild_id, language, &incident).await;
}

/// Relit le message par l'API (jamais par le cache, qui peut être en retard)
/// et le compare à la version analysée.
async fn current_revision(
    ctx: &serenity::Context,
    plan: &DeleteMessagePlan,
    analyzed: &MessageContent,
) -> Result<RevisionCheck, DeleteMessageOutcome> {
    let current = ctx
        .http
        .get_message(
            serenity::ChannelId::new(plan.channel_id),
            serenity::MessageId::new(plan.message_id),
        )
        .await;

    match current {
        Ok(current) => Ok(check_revision(
            analyzed,
            Some(&message::message_content(&current)),
        )),
        Err(error) => {
            match revision_fetch_failure(delete::http_status(&error), error.to_string()) {
                None => Ok(check_revision(analyzed, None)),
                Some(outcome) => Err(outcome),
            }
        }
    }
}
