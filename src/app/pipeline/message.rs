// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::shared::{
    AuthorWhitelist, MessageScope, MessageSnapshot, is_author_exempt, message_scope,
    screen_message, snowflake_timestamp,
};
use poise::serenity_prelude as serenity;

use super::anti_spam;
use crate::app::{AppData, run_database};

/// Rôles que FoxSecura attribue lui-même et qui n'exemptent jamais.
///
/// Dans la V1 : rôles de vérification, de quarantaine et rôle limité. Aucun
/// n'existe encore dans la V2 : la liste est vide tant que ces modules ne sont
/// pas portés.
const BOT_ASSIGNED_ROLES: &[u64] = &[];

/// Pipeline de protection des messages.
///
/// Gardes (hors guilde, webhook, bot), puis une seule lecture en base
/// (configuration, salon ignoré, liste blanche), puis les modules activés.
/// Chaque module est isolé : son erreur est journalisée sans interrompre le
/// pipeline ni le client.
pub async fn handle(ctx: &serenity::Context, data: &AppData, message: &serenity::Message) {
    let snapshot = snapshot(message);
    let Ok(guild_message) = screen_message(&snapshot) else {
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

    let member_roles = member_roles(message);
    let author_exempt = is_author_exempt(
        &AuthorWhitelist {
            user_listed: context.author_listed,
            listed_roles: &context.whitelist_roles,
        },
        member_roles.as_deref(),
        BOT_ASSIGNED_ROLES,
    );

    match message_scope(context.channel_ignored, author_exempt) {
        MessageScope::IgnoredChannel => {}
        // Point d'extension : dans la V1, un auteur exempté passe encore par
        // les corrections de contenu de confiance. Aucun module de contenu
        // n'existe en Rust : l'auteur ne subit donc aucune protection.
        MessageScope::ExemptAuthor => {}
        MessageScope::Enforce => {
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

fn snapshot(message: &serenity::Message) -> MessageSnapshot {
    MessageSnapshot {
        guild_id: message.guild_id.map(serenity::GuildId::get),
        channel_id: message.channel_id.get(),
        message_id: message.id.get(),
        author_id: message.author.id.get(),
        author_is_bot: message.author.bot,
        webhook_id: message.webhook_id.map(serenity::WebhookId::get),
        timestamp: snowflake_timestamp(message.id.get()),
    }
}

/// Rôles de l'auteur, lus dans le membre partiel joint à l'événement.
///
/// `None` si Discord ne l'a pas fourni : l'auteur n'est alors pas exempté par
/// rôle (sûr par défaut).
fn member_roles(message: &serenity::Message) -> Option<Vec<u64>> {
    message
        .member
        .as_ref()
        .map(|member| member.roles.iter().map(|role| role.get()).collect())
}
