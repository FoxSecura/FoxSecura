// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::i18n::DEFAULT_LANGUAGE;
use foxsecura::protection::automod::bad_words::DEFAULT_BAD_WORDS_LANGUAGE;
use foxsecura::protection::content_filter::{
    AuthorContext, MessageContent, MessageEvent, MessageRoute, MessageUpdate, MissingFields,
    route_message,
};
use foxsecura::protection::shared::{
    AuthorWhitelist, MessageSnapshot, ProtectionModule, is_author_exempt, message_scope,
    screen_message, snowflake_timestamp,
};
use poise::serenity_prelude as serenity;

use super::{anti_spam, bot_assigned_roles, content_filter, unix_duration};
use crate::app::{AppData, run_database};

/// Message converti depuis un événement Discord, prêt pour le pipeline.
struct InspectedMessage {
    snapshot: MessageSnapshot,
    content: MessageContent,
    author: AuthorContext,
    /// `None` si Discord n'a pas joint le membre : aucune exemption par rôle.
    member_roles: Option<Vec<u64>>,
}

/// Création d'un message.
pub async fn handle(ctx: &serenity::Context, data: &AppData, message: &serenity::Message) {
    let member = message.member.as_deref();
    let inspected = InspectedMessage {
        snapshot: MessageSnapshot {
            guild_id: message.guild_id.map(serenity::GuildId::get),
            channel_id: message.channel_id.get(),
            message_id: message.id.get(),
            author_id: message.author.id.get(),
            author_is_bot: message.author.bot,
            webhook_id: message.webhook_id.map(serenity::WebhookId::get),
            timestamp: snowflake_timestamp(message.id.get()),
        },
        content: message_content(message),
        author: author_context(
            message.author.id,
            Some(snowflake_timestamp(message.id.get())),
            member,
        ),
        member_roles: member_roles(member),
    };

    process(ctx, data, inspected, MessageEvent::Created).await;
}

/// Modification d'un message : mêmes filtres de contenu, jamais d'anti-spam.
///
/// Seules les vraies modifications de texte sont analysées : Discord envoie
/// aussi des mises à jour sans `edited_timestamp` (résolution des aperçus de
/// liens), qui ne changent pas le contenu et produiraient un second incident
/// pour un message déjà traité.
pub async fn handle_update(
    ctx: &serenity::Context,
    data: &AppData,
    event: &serenity::MessageUpdateEvent,
) {
    let (Some(author), Some(content), Some(edited_at)) =
        (&event.author, &event.content, event.edited_timestamp)
    else {
        return;
    };

    let member = event.member.as_ref().and_then(|member| member.as_deref());
    let inspected = InspectedMessage {
        snapshot: MessageSnapshot {
            guild_id: event.guild_id.map(serenity::GuildId::get),
            channel_id: event.channel_id.get(),
            message_id: event.id.get(),
            author_id: author.id.get(),
            author_is_bot: author.bot,
            webhook_id: event.webhook_id.flatten().map(serenity::WebhookId::get),
            timestamp: snowflake_timestamp(event.id.get()),
        },
        // Discord peut omettre les mentions ou les pièces jointes : les champs
        // absents ne sont pas comparés à la version relue avant suppression.
        content: MessageContent::from_update(MessageUpdate {
            content: content.clone(),
            mentions_everyone: event.mention_everyone,
            user_mentions: event.mentions.as_ref().map(Vec::len),
            role_mentions: event.mention_roles.as_ref().map(Vec::len),
            attachments: event
                .attachments
                .as_ref()
                .map(|attachments| attachment_names(attachments)),
        }),
        author: author_context(author.id, unix_duration(edited_at), member),
        member_roles: member_roles(member),
    };

    process(ctx, data, inspected, MessageEvent::Edited).await;
}

/// Pipeline de protection des messages.
///
/// Gardes (hors guilde, webhook, bot), puis une seule lecture en base
/// (configuration, salon ignoré, liste blanche, modules activés, mots
/// interdits), puis les filtres de contenu et enfin l'anti-spam. Chaque module est isolé : son
/// erreur est journalisée sans interrompre le pipeline ni le client.
async fn process(
    ctx: &serenity::Context,
    data: &AppData,
    inspected: InspectedMessage,
    event: MessageEvent,
) {
    let Ok(guild_message) = screen_message(&inspected.snapshot) else {
        return;
    };

    let (guild_id, channel_id, author_id) = (
        guild_message.guild_id,
        guild_message.channel_id,
        guild_message.author_id,
    );
    let context = match run_database(&data.database, move |database| {
        database.message_guard_context(guild_id, channel_id, author_id)
    })
    .await
    {
        Ok(context) => context,
        Err(error) => {
            eprintln!(
                "[message] contexte illisible pour la guilde {guild_id} (message {}) : {error}",
                guild_message.message_id
            );
            return;
        }
    };

    let author_exempt = is_author_exempt(
        &AuthorWhitelist {
            user_listed: context.author_listed,
            listed_roles: &context.whitelist_roles,
        },
        inspected.member_roles.as_deref(),
        bot_assigned_roles(context.guild_config.as_ref()),
    );
    let scope = message_scope(context.channel_ignored, author_exempt);

    // Liste compilée une fois par liste (cache borné), jamais par message.
    let bad_words = context
        .enabled_modules
        .contains(ProtectionModule::BadWords)
        .then(|| {
            let language = context
                .guild_config
                .as_ref()
                .map_or(DEFAULT_BAD_WORDS_LANGUAGE, |guild_config| {
                    guild_config.bad_words_language
                });
            data.protection
                .bad_words()
                .matcher(language, &context.custom_bad_words)
        });

    match route_message(
        scope,
        event,
        context.enabled_modules,
        &inspected.content,
        inspected.author,
        bad_words.as_deref(),
    ) {
        MessageRoute::Skip => {}
        MessageRoute::Filter(detection) => {
            let language = context
                .guild_config
                .as_ref()
                .map_or(DEFAULT_LANGUAGE, |guild_config| guild_config.language);
            content_filter::run(
                ctx,
                data,
                content_filter::FilteredMessage {
                    message: &guild_message,
                    detection: &detection,
                    event,
                    content: &inspected.content,
                    scope,
                    member_roles: inspected.member_roles.as_deref(),
                    language,
                },
            )
            .await;
        }
        MessageRoute::AntiSpam => {
            if let Err(error) =
                anti_spam::run(ctx, data, &guild_message, context.guild_config.as_ref()).await
            {
                eprintln!(
                    "[anti_spam] échec sur la guilde {guild_id} (message {}) : {error}",
                    guild_message.message_id
                );
            }
        }
    }
}

/// Version analysée d'un message complet (création, ou relecture avant une
/// suppression après modification).
pub fn message_content(message: &serenity::Message) -> MessageContent {
    MessageContent {
        content: message.content.clone(),
        mentions_everyone: message.mention_everyone,
        mention_count: message.mentions.len() + message.mention_roles.len(),
        attachments: attachment_names(&message.attachments),
        missing: MissingFields::default(),
    }
}

fn attachment_names(attachments: &[serenity::Attachment]) -> Vec<String> {
    attachments
        .iter()
        .map(|attachment| attachment.filename.clone())
        .collect()
}

fn author_context(
    author_id: serenity::UserId,
    now: Option<Duration>,
    member: Option<&serenity::PartialMember>,
) -> AuthorContext {
    AuthorContext {
        now,
        account_created_at: Some(snowflake_timestamp(author_id.get())),
        member_joined_at: member
            .and_then(|member| member.joined_at)
            .and_then(unix_duration),
    }
}

/// Rôles de l'auteur, lus dans le membre partiel joint à l'événement.
///
/// `None` si Discord ne l'a pas fourni : l'auteur n'est alors pas exempté par
/// rôle (sûr par défaut).
fn member_roles(member: Option<&serenity::PartialMember>) -> Option<Vec<u64>> {
    member.map(|member| member.roles.iter().map(|role| role.get()).collect())
}
