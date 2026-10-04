// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Honeypot au runtime : permissions de l'auteur d'après le cache,
//! suppression du message, quarantaine et incident.
//!
//! La décision est dans `foxsecura::protection::anti_raid::honeypot` ; ce
//! module relève le cache (verrou relâché avant tout `.await`) et exécute
//! les effets.

use foxsecura::i18n::Language;
use foxsecura::protection::anti_raid::honeypot::{
    HONEYPOT_QUARANTINE, HoneypotAuthor, HoneypotPlan, honeypot_audit_reason, honeypot_incident,
};
use foxsecura::protection::shared::{DeleteMessagePlan, GuildMessage};
use poise::serenity_prelude as serenity;

use super::quarantine::{self, QuarantineTarget};
use super::{delete, incident_log};
use crate::app::AppData;

/// Auteur d'un message du salon piège, d'après le cache, et ses rôles.
///
/// Rôles : ceux joints au message, sinon ceux du membre en cache.
/// Permissions : `None` si la guilde, le membre ou l'un de ses rôles manque
/// au cache. Elles ne sont alors jamais devinées.
pub fn author_facts(
    ctx: &serenity::Context,
    message: &GuildMessage,
    member_roles: Option<&[u64]>,
    whitelisted: bool,
) -> (HoneypotAuthor, Option<Vec<u64>>) {
    let mut author = HoneypotAuthor {
        is_guild_owner: false,
        whitelisted,
        permissions: None,
    };
    let Some(guild) = ctx.cache.guild(serenity::GuildId::new(message.guild_id)) else {
        return (author, member_roles.map(<[u64]>::to_vec));
    };
    author.is_guild_owner = guild.owner_id.get() == message.author_id;

    let roles = member_roles.map(<[u64]>::to_vec).or_else(|| {
        guild
            .members
            .get(&serenity::UserId::new(message.author_id))
            .map(|member| member.roles.iter().map(|role| role.get()).collect())
    });
    author.permissions = roles.as_deref().and_then(|roles| {
        // `@everyone` porte l'identifiant de la guilde.
        let everyone = guild.roles.get(&serenity::RoleId::new(message.guild_id))?;
        roles
            .iter()
            .try_fold(everyone.permissions, |permissions, role_id| {
                guild
                    .roles
                    .get(&serenity::RoleId::new(*role_id))
                    .map(|role| permissions | role.permissions)
            })
    });
    (author, roles)
}

/// Supprime le message, met l'auteur en quarantaine si le plan le demande,
/// puis publie l'incident.
pub async fn run(
    ctx: &serenity::Context,
    data: &AppData,
    message: &GuildMessage,
    content: &str,
    plan: HoneypotPlan,
    member_roles: Option<&[u64]>,
    language: Language,
) {
    let deletion = delete::delete_message(ctx, &DeleteMessagePlan::for_message(message)).await;
    let quarantine = match (plan, member_roles) {
        (HoneypotPlan::Exempt(_), _) => return,
        (HoneypotPlan::Quarantine, Some(roles)) => Some(
            quarantine::quarantine(
                ctx,
                data,
                &QuarantineTarget {
                    guild_id: message.guild_id,
                    user_id: message.author_id,
                    member_roles: roles,
                    // Exemptés par la liste blanche : écartés par le plan.
                    whitelisted: false,
                },
                HONEYPOT_QUARANTINE,
                honeypot_audit_reason(),
            )
            .await,
        ),
        // Permissions connues implique rôles connus ; par sécurité, des rôles
        // absents valent permissions inconnues.
        (HoneypotPlan::Quarantine | HoneypotPlan::DeleteOnly, _) => None,
    };

    let incident = honeypot_incident(language, message, content, &deletion, quarantine.as_ref());
    incident_log::publish(ctx, data, message.guild_id, language, &incident).await;
}
