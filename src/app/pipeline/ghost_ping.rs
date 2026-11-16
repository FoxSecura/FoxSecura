// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-ghost-ping au runtime : suivi des messages de masse à la création,
//! comparaison à la modification, détection à la suppression.
//!
//! Les décisions sont dans `foxsecura::protection::anti_spam::anti_ghost_ping` ;
//! ce module tient les verrous (relâchés avant tout `.await`), relit le
//! contexte de la guilde, applique le timeout de récidive et publie
//! l'incident.

use foxsecura::i18n::DEFAULT_LANGUAGE;
use foxsecura::protection::anti_spam::anti_ghost_ping::{
    ANTI_GHOST_PING_REPEAT_REASON, GhostPingDetectionResult, GhostPingEvent, GhostPingFollowUp,
    GhostPingIncidentInput, GhostPingMessage, GhostPingOutcome, ghost_ping_incident,
    plan_ghost_ping_follow_up,
};
use foxsecura::protection::content_filter::MessageEvent;
use foxsecura::protection::shared::{
    AuthorWhitelist, GuildMessage, MessageScope, ProtectionDecision, ProtectionModule,
    is_author_exempt,
};
use poise::serenity_prelude as serenity;

use super::sanction::{self, SanctionRequest};
use super::{bot_assigned_roles, delete, incident_log};
use crate::app::{AppData, run_database};

/// Mentions d'un message, telles que résolues par Discord.
#[derive(Debug, Clone, Copy)]
pub struct ObservedMentions<'a> {
    pub users: &'a [u64],
    pub roles: &'a [u64],
}

/// Création ou modification d'un message d'une guilde où le module est
/// activé, hors salon ignoré.
///
/// - Création d'un auteur non exempté : le message est suivi s'il mentionne
///   au moins 5 utilisateurs ou rôles (`mentions_everyone` n'est pas compté).
/// - Modification : comparée à la version suivie ; si elle retire au moins 5
///   mentions, c'est un ghost ping. Un auteur passé sur la liste blanche
///   entre-temps n'est plus suivi. Mentions absentes de l'événement : rien.
pub async fn observe(
    ctx: &serenity::Context,
    data: &AppData,
    message: &GuildMessage,
    event: MessageEvent,
    scope: MessageScope,
    mentions: Option<ObservedMentions<'_>>,
) {
    let tracked = |mentions: ObservedMentions<'_>, timestamp| GhostPingMessage {
        guild_id: message.guild_id,
        message_id: message.message_id,
        channel_id: message.channel_id,
        author_id: message.author_id,
        mention_ids: mentions.users.to_vec(),
        role_mention_ids: mentions.roles.to_vec(),
        mentions_everyone: false,
        timestamp,
    };

    match (event, scope, mentions) {
        (MessageEvent::Created, MessageScope::Enforce, Some(mentions)) => {
            data.protection
                .ghost_pings()
                .record(tracked(mentions, message.timestamp));
        }
        (MessageEvent::Edited, MessageScope::Enforce, Some(mentions)) => {
            let result = data
                .protection
                .ghost_pings()
                .detect_updated(tracked(mentions, delete::wall_clock()));
            if result.decision == ProtectionDecision::Block {
                respond(
                    ctx,
                    data,
                    message.guild_id,
                    message.message_id,
                    GhostPingEvent::Edited,
                    &result,
                )
                .await;
            }
        }
        (MessageEvent::Edited, MessageScope::ExemptAuthor, _) => {
            data.protection
                .ghost_pings()
                .discard(message.guild_id, message.message_id);
        }
        _ => {}
    }
}

/// `MESSAGE_DELETE` : une suppression faite par FoxSecura est ignorée (et le
/// message oublié) ; sinon, un message suivi supprimé dans sa fenêtre de
/// mémoire est un ghost ping.
pub async fn handle_delete(
    ctx: &serenity::Context,
    data: &AppData,
    guild_id: Option<serenity::GuildId>,
    message_id: serenity::MessageId,
) {
    let Some(guild_id) = guild_id.map(serenity::GuildId::get) else {
        return;
    };
    let message_id = message_id.get();
    let now = delete::wall_clock();

    if data
        .protection
        .bot_deletions()
        .take(guild_id, message_id, now)
    {
        data.protection.ghost_pings().discard(guild_id, message_id);
        return;
    }
    let result = data
        .protection
        .ghost_pings()
        .detect_deleted(guild_id, message_id, now);
    if result.decision == ProtectionDecision::Block {
        respond(
            ctx,
            data,
            guild_id,
            message_id,
            GhostPingEvent::Deleted,
            &result,
        )
        .await;
    }
}

/// `MESSAGE_DELETE_BULK` (purge par un modérateur ou un bot) : les messages
/// suivis sont simplement oubliés, sans incident.
pub fn handle_delete_bulk(
    data: &AppData,
    guild_id: Option<serenity::GuildId>,
    message_ids: &[serenity::MessageId],
) {
    let Some(guild_id) = guild_id.map(serenity::GuildId::get) else {
        return;
    };
    let now = delete::wall_clock();
    let mut ghost_pings = data.protection.ghost_pings();
    let mut marks = data.protection.bot_deletions();
    for message_id in message_ids {
        ghost_pings.discard(guild_id, message_id.get());
        marks.take(guild_id, message_id.get(), now);
    }
}

/// Relit le contexte, sanctionne une récidive et publie l'incident.
///
/// Le module désactivé ou le salon devenu ignoré entre-temps : rien.
async fn respond(
    ctx: &serenity::Context,
    data: &AppData,
    guild_id: u64,
    message_id: u64,
    event: GhostPingEvent,
    result: &GhostPingDetectionResult,
) {
    let (Some(author_id), Some(channel_id)) = (result.author_id, result.channel_id) else {
        return;
    };
    let context = match run_database(&data.database, move |database| {
        database.message_guard_context(guild_id, channel_id, author_id)
    })
    .await
    {
        Ok(context) => context,
        Err(error) => {
            eprintln!(
                "[anti-ghost-ping] contexte illisible pour la guilde {guild_id} (message {message_id}) : {error}"
            );
            return;
        }
    };
    if context.channel_ignored
        || !context
            .enabled_modules
            .contains(ProtectionModule::AntiGhostPing)
    {
        return;
    }
    let language = context
        .guild_config
        .as_ref()
        .map_or(DEFAULT_LANGUAGE, |config| config.language);

    // Rôles d'après le cache seulement : sans eux, seule l'exemption par
    // identifiant s'applique (sûr par défaut).
    let cached_roles: Option<Vec<u64>> = ctx
        .cache
        .guild(serenity::GuildId::new(guild_id))
        .and_then(|guild| {
            guild
                .members
                .get(&serenity::UserId::new(author_id))
                .map(|member| member.roles.iter().map(|role| role.get()).collect())
        });
    let exempt = is_author_exempt(
        &AuthorWhitelist {
            user_listed: context.author_listed,
            listed_roles: &context.whitelist_roles,
        },
        cached_roles.as_deref(),
        bot_assigned_roles(context.guild_config.as_ref()),
    );

    let outcome = match plan_ghost_ping_follow_up(result.repeat_offense, exempt) {
        GhostPingFollowUp::Alert => GhostPingOutcome::Alert,
        GhostPingFollowUp::ExemptMember(kind) => GhostPingOutcome::ExemptMember(kind),
        GhostPingFollowUp::Sanction(kind) => {
            let outcome = sanction::execute(
                ctx,
                &SanctionRequest {
                    guild_id,
                    user_id: author_id,
                    member_roles: cached_roles.as_deref(),
                    kind,
                    reason: ANTI_GHOST_PING_REPEAT_REASON,
                },
            )
            .await;
            GhostPingOutcome::Sanction { kind, outcome }
        }
    };
    println!(
        "[anti-ghost-ping] message {message_id} de {author_id} sur la guilde {guild_id} ({event:?}) : {} mentions, récidive {}, {outcome:?}",
        result.mention_count, result.repeat_offense
    );

    let incident = ghost_ping_incident(
        language,
        GhostPingIncidentInput {
            guild_id,
            message_id,
            event,
            result,
        },
        &outcome,
    );
    incident_log::publish(ctx, data, guild_id, language, &incident).await;
}
