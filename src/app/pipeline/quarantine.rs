// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Quarantaine au runtime : verrou du rôle sur les salons.
//!
//! Les décisions sont dans `foxsecura::protection::quarantine` ; ce module
//! relève l'état du cache (verrou du cache relâché avant tout `.await`) et
//! appelle l'API.
//!
//! # Coût en appels API
//!
//! Un appel par salon verrouillable (catégories, salons sans catégorie,
//! salons désynchronisés), jamais pour un salon synchronisé ni pour un salon
//! déjà verrouillé. Les appels sont faits un par un : pendant une limitation
//! de débit (`429`), serenity attend la fin de la fenêtre avant de reprendre,
//! l'opération est plus lente mais n'est pas abandonnée.

use foxsecura::protection::quarantine::{
    ChannelFacts, DiscordFailure, Overwrite, OverwriteBits, OverwriteTarget,
    QUARANTINE_AUDIT_LABEL, is_lockable, role_lock_overwrite,
};
use foxsecura::protection::shared::audit_reason;
use poise::serenity_prelude as serenity;

use crate::app::{AppData, run_database};

/// Salon ou catégorie créé : réapplique le verrou du rôle s'il est
/// verrouillable (un salon créé synchronisé hérite de sa catégorie).
pub async fn handle_channel_create(
    ctx: &serenity::Context,
    data: &AppData,
    channel: &serenity::GuildChannel,
) {
    let guild_id = channel.guild_id.get();
    let role_id = match run_database(&data.database, move |database| {
        database.quarantine_role_id(guild_id)
    })
    .await
    {
        Ok(Some(role_id)) => role_id,
        Ok(None) => return,
        Err(error) => {
            eprintln!("[quarantine] rôle de quarantaine illisible ({guild_id}) : {error}");
            return;
        }
    };

    let facts = convert_channel(channel);
    let parent = channel.parent_id.and_then(|parent_id| {
        ctx.cache
            .guild(channel.guild_id)
            .and_then(|guild| guild.channels.get(&parent_id).map(convert_channel))
    });
    if !is_lockable(&facts, parent.as_ref()) {
        return;
    }
    let Some(overwrite) = role_lock_overwrite(facts.overwrite(OverwriteTarget::Role(role_id)))
    else {
        return;
    };

    if let Err(error) = put_overwrite(
        ctx,
        facts.id,
        OverwriteTarget::Role(role_id),
        overwrite,
        &role_lock_reason(),
    )
    .await
    {
        eprintln!(
            "[quarantine] verrou du rôle {role_id} impossible sur le nouveau salon {} : {}",
            facts.id, error.details
        );
    }
}

fn role_lock_reason() -> String {
    audit_reason(QUARANTINE_AUDIT_LABEL, "quarantine role channel lock")
}

/// Écrit l'overwrite d'une cible (`PUT`), avec la raison d'audit log.
async fn put_overwrite(
    ctx: &serenity::Context,
    channel_id: u64,
    target: OverwriteTarget,
    overwrite: OverwriteBits,
    reason: &str,
) -> Result<(), DiscordFailure> {
    let (target_id, kind) = match target {
        OverwriteTarget::Role(id) => (id, 0),
        OverwriteTarget::Member(id) => (id, 1),
    };
    let body = serde_json::json!({
        "allow": overwrite.allow.bits().to_string(),
        "deny": overwrite.deny.bits().to_string(),
        "type": kind,
    });
    ctx.http
        .create_permission(
            serenity::ChannelId::new(channel_id),
            serenity::TargetId::new(target_id),
            &body,
            Some(reason),
        )
        .await
        .map_err(discord_failure)
}

/// Réduit une erreur serenity à ce qui sert à la classer.
pub(super) fn discord_failure(error: serenity::Error) -> DiscordFailure {
    match &error {
        serenity::Error::Http(serenity::HttpError::UnsuccessfulRequest(response)) => {
            DiscordFailure::new(
                Some(response.status_code.as_u16()),
                i64::try_from(response.error.code).ok(),
                error.to_string(),
            )
        }
        serenity::Error::Http(http) => DiscordFailure::new(
            http.status_code().map(|status| status.as_u16()),
            None,
            error.to_string(),
        ),
        _ => DiscordFailure::new(None, None, error.to_string()),
    }
}

fn convert_channel(channel: &serenity::GuildChannel) -> ChannelFacts {
    ChannelFacts {
        id: channel.id.get(),
        parent_id: channel.parent_id.map(serenity::ChannelId::get),
        is_category: channel.kind == serenity::ChannelType::Category,
        overwrites: channel
            .permission_overwrites
            .iter()
            .filter_map(|overwrite| {
                let target = match overwrite.kind {
                    serenity::PermissionOverwriteType::Member(user_id) => {
                        OverwriteTarget::Member(user_id.get())
                    }
                    serenity::PermissionOverwriteType::Role(role_id) => {
                        OverwriteTarget::Role(role_id.get())
                    }
                    _ => return None,
                };
                Some(Overwrite {
                    target,
                    allow: overwrite.allow,
                    deny: overwrite.deny,
                })
            })
            .collect(),
    }
}
