// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::i18n::Language;
use foxsecura::protection::content_filter::{
    ContentDetection, FollowUp, FollowUpOutcome, MessageContent, MessageEvent, RevisionCheck,
    anti_scam_audit_reason, build_incident, check_revision, plan_follow_up, record_follow_up,
    revision_fetch_failure,
};
use foxsecura::protection::shared::{
    DeleteMessageOutcome, DeleteMessagePlan, GuildMessage, MessageScope,
};
use poise::serenity_prelude as serenity;

use super::sanction::{self, SanctionRequest};
use super::{delete, incident_log, message};
use crate::app::AppData;

/// Message retenu par un filtre de contenu.
pub struct FilteredMessage<'a> {
    pub message: &'a GuildMessage,
    pub detection: &'a ContentDetection,
    pub event: MessageEvent,
    pub content: &'a MessageContent,
    pub scope: MessageScope,
    /// Rôles joints à l'événement, pour la sanction (sinon lecture du membre).
    pub member_roles: Option<&'a [u64]>,
    pub language: Language,
}

/// Filtres de contenu : suppression du message retenu → suite graduée
/// (anti-arnaque : revue, timeout ou ban) → incident.
///
/// Après une modification, la version courante est relue avant de supprimer :
/// une version déjà corrigée par son auteur n'est jamais effacée, ni son
/// auteur sanctionné. La sanction ne dépend pas du succès de la suppression,
/// et un échec de sanction n'annule jamais la suppression.
pub async fn run(ctx: &serenity::Context, data: &AppData, filtered: FilteredMessage<'_>) {
    let FilteredMessage {
        message,
        detection,
        event,
        content,
        scope,
        member_roles,
        language,
    } = filtered;

    let plan = DeleteMessagePlan::for_message(message);
    let deletion = match event {
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

    let follow_up = match plan_follow_up(detection, scope) {
        FollowUp::None => FollowUpOutcome::None,
        FollowUp::StaffReview => FollowUpOutcome::StaffReview,
        FollowUp::ExemptMember(kind) => FollowUpOutcome::ExemptMember(kind),
        FollowUp::Sanction(kind) => {
            let reason = anti_scam_audit_reason(detection);
            let outcome = sanction::execute(
                ctx,
                &SanctionRequest {
                    guild_id: message.guild_id,
                    user_id: message.author_id,
                    member_roles,
                    kind,
                    reason: &reason,
                },
            )
            .await;
            FollowUpOutcome::Sanction { kind, outcome }
        }
    };

    let mut incident = build_incident(language, message, detection, event, content, &deletion);
    record_follow_up(&mut incident, language, &deletion, &follow_up);
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
