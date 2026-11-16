// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Messages de webhook au runtime (module `webhook_watch`, comme en V1).
//!
//! Écartés par les gardes communes (`screen_message`), ils suivent ce chemin
//! à part : jamais les messages de FoxSecura lui-même, jamais dans un salon
//! ignoré, jamais de sanction. Les décisions sont dans
//! `foxsecura::protection::anti_raid::webhook_message`.

use foxsecura::i18n::DEFAULT_LANGUAGE;
use foxsecura::protection::anti_raid::webhook_message::{
    WEBHOOK_MASS_MENTION_THRESHOLD, WEBHOOK_SPAM_THRESHOLD, WEBHOOK_SPAM_WINDOW,
    WebhookMessageDetectionInput, WebhookMessageIncidentInput, WebhookMessageSpamInput,
    WebhookOrigin, detect_webhook_message_threat, is_own_webhook_message, webhook_message_incident,
};
use foxsecura::protection::anti_spam::malicious_link::MaliciousLinkContext;
use foxsecura::protection::shared::{
    DeleteMessagePlan, GuildMessage, ProtectionModule, snowflake_timestamp,
};
use poise::serenity_prelude as serenity;

use super::{delete, incident_log};
use crate::app::{AppData, run_database};

/// Création d'un message posté par un webhook.
pub async fn handle(ctx: &serenity::Context, data: &AppData, message: &serenity::Message) {
    let (Some(guild_id), Some(webhook_id)) = (message.guild_id, message.webhook_id) else {
        return;
    };
    let bot_id = ctx.cache.current_user().id.get();
    let origin = WebhookOrigin {
        bot_id,
        author_id: message.author.id.get(),
        webhook_id: webhook_id.get(),
        application_id: message.application_id.map(serenity::ApplicationId::get),
    };
    if is_own_webhook_message(origin) {
        return;
    }

    let guild_message = GuildMessage {
        guild_id: guild_id.get(),
        channel_id: message.channel_id.get(),
        message_id: message.id.get(),
        author_id: message.author.id.get(),
        timestamp: snowflake_timestamp(message.id.get()),
    };
    let (guild, channel, author) = (
        guild_message.guild_id,
        guild_message.channel_id,
        guild_message.author_id,
    );
    let context = match run_database(&data.database, move |database| {
        database.message_guard_context(guild, channel, author)
    })
    .await
    {
        Ok(context) => context,
        Err(error) => {
            eprintln!(
                "[webhook-message] contexte illisible pour la guilde {guild} (message {}) : {error}",
                guild_message.message_id
            );
            return;
        }
    };
    if context.channel_ignored
        || !context
            .enabled_modules
            .contains(ProtectionModule::WebhookWatch)
    {
        return;
    }

    // Comptée seulement quand le module s'applique ; verrou relâché à la fin
    // de l'instruction.
    let spam = data
        .protection
        .webhook_spam()
        .detect(WebhookMessageSpamInput {
            guild_id: guild,
            webhook_id: webhook_id.get(),
            timestamp: guild_message.timestamp,
            threshold: Some(WEBHOOK_SPAM_THRESHOLD),
            window: Some(WEBHOOK_SPAM_WINDOW),
        });
    let result = detect_webhook_message_threat(WebhookMessageDetectionInput {
        content: &message.content,
        mentions_everyone: Some(message.mention_everyone),
        mention_count: message.mentions.len() + message.mention_roles.len(),
        mass_mention_threshold: Some(WEBHOOK_MASS_MENTION_THRESHOLD),
        recent_message_count: Some(spam.message_count),
        spam_threshold: Some(WEBHOOK_SPAM_THRESHOLD),
        malicious_link_context: MaliciousLinkContext::default(),
    });
    if !result.triggered {
        return;
    }

    let deletion =
        delete::delete_message(ctx, data, &DeleteMessagePlan::for_message(&guild_message)).await;
    println!(
        "[webhook-message] message {} du webhook {webhook_id} sur la guilde {guild} : {:?}, {}",
        guild_message.message_id,
        result.threats,
        deletion.as_str()
    );
    let language = context
        .guild_config
        .as_ref()
        .map_or(DEFAULT_LANGUAGE, |config| config.language);
    let incident = webhook_message_incident(
        language,
        WebhookMessageIncidentInput {
            message: &guild_message,
            webhook_id: webhook_id.get(),
            webhook_name: Some(message.author.name.as_str()),
            content: &message.content,
        },
        &result,
        &deletion,
    );
    incident_log::publish(ctx, data, guild, language, &incident).await;
}
