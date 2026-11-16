// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Intégrité du serveur au runtime : réponses unitaires aux entrées du
//! journal d'audit déjà retenues par les gardes du socle
//! (`anti_nuke::handle_audit_entry`).
//!
//! - `RoleUpdate` : anti-permissions (retour en arrière du bitfield, puis
//!   quarantaine de l'auteur non exempté).
//!
//! Les décisions sont dans `foxsecura::protection::anti_nuke::server_integrity` ;
//! ce module relève l'état du cache (verrou relâché avant tout `.await`) et
//! appelle l'API. Les erreurs sont journalisées et jamais propagées.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use foxsecura::database::MemberGuardContext;
use foxsecura::protection::anti_nuke::audit::{AuditAction, AuditEntry};
use foxsecura::protection::anti_nuke::response::{
    ANTI_NUKE_AUDIT_LABEL, Containment, sends_panic_signal,
};
use foxsecura::protection::anti_nuke::server_integrity::anti_permissions::{
    ANTI_PERMISSIONS_ROLLBACK_REASON, PermissionIncidentInput, PermissionPlan, UpdatedRole,
    exempt_rollback_result, permission_incident, plan_permission_rollback,
};
use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use foxsecura::protection::shared::{ProtectionModule, audit_reason};
use poise::serenity_prelude as serenity;

use super::anti_nuke::{self, contain_author, language, read_context};
use super::incident_log;
use super::quarantine::{bot_role_standing, discord_failure};
use crate::app::AppData;

/// Traite une entrée de l'intégrité du serveur ; `false` si elle n'en
/// relève pas (elle suit alors le chemin des rafales).
pub async fn handle_audit_entry(
    ctx: &serenity::Context,
    data: &AppData,
    entry: &AuditEntry,
    author_id: u64,
) -> bool {
    match entry.action {
        AuditAction::RoleUpdate => {
            role_update(ctx, data, entry, author_id).await;
            true
        }
        _ => false,
    }
}

/// Rôle modifié : retour en arrière si une permission dangereuse est
/// ajoutée, puis quarantaine de l'auteur non exempté.
async fn role_update(ctx: &serenity::Context, data: &AppData, entry: &AuditEntry, author_id: u64) {
    let (Some((old, new)), Some(role_id)) = (entry.permissions_change, entry.target_id) else {
        return;
    };
    let guild_id = entry.guild_id;
    let Some(context) = read_context(data, guild_id, author_id).await else {
        return;
    };
    if !context
        .enabled_modules
        .contains(ProtectionModule::AntiPermissions)
    {
        return;
    }
    let (old, new) = (
        serenity::Permissions::from_bits_truncate(old),
        serenity::Permissions::from_bits_truncate(new),
    );

    let bot_id = ctx.cache.current_user().id.get();
    let (role, role_name, bot) = {
        match ctx.cache.guild(serenity::GuildId::new(guild_id)) {
            Some(guild) => {
                let role = guild.roles.get(&serenity::RoleId::new(role_id));
                (
                    role.map(|role| UpdatedRole {
                        id: role.id.get(),
                        position: role.position,
                        managed: role.managed,
                        bot_role: role.tags.bot_id.map(serenity::UserId::get) == Some(bot_id),
                    }),
                    role.map(|role| role.name.clone()),
                    bot_role_standing(&guild, bot_id),
                )
            }
            None => (None, None, None),
        }
    };

    let (added, precheck) = match plan_permission_rollback(guild_id, role_id, role, bot, old, new) {
        PermissionPlan::Ignore(reason) => {
            println!(
                "[anti-permissions] rôle {role_id} sur la guilde {guild_id} ignoré : {reason:?}"
            );
            return;
        }
        PermissionPlan::Respond { added, precheck } => (added, precheck),
    };

    let exempt = anti_nuke::is_author_exempt(ctx, &context, guild_id, author_id).await;
    let (rollback, containment) = if exempt {
        (exempt_rollback_result(), Containment::Exempt)
    } else {
        // Retour en arrière d'abord : la quarantaine peut prendre plusieurs
        // appels, les permissions dangereuses ne doivent pas rester en place
        // pendant ce temps.
        let rollback = match precheck {
            Some(skipped) => skipped,
            None => rollback_permissions(ctx, guild_id, role_id, old).await,
        };
        let containment = contain_author(
            ctx,
            data,
            &context,
            guild_id,
            author_id,
            audit_reason(
                ANTI_NUKE_AUDIT_LABEL,
                ProtectionModule::AntiPermissions.key(),
            ),
        )
        .await;
        (rollback, containment)
    };
    println!(
        "[anti-permissions] rôle {role_id} sur la guilde {guild_id} par {author_id} : {} ajoutées, retour en arrière {rollback:?}",
        added.bits()
    );

    let incident = permission_incident(
        language(&context),
        PermissionIncidentInput {
            role_id,
            role_name: role_name.as_deref(),
            author_id,
            old,
            new,
            added,
        },
        &rollback,
        &containment,
    );
    publish_critical(
        ctx,
        data,
        &context,
        guild_id,
        ProtectionModule::AntiPermissions,
        &incident,
    )
    .await;
}

/// Rétablit l'ancien bitfield du rôle.
async fn rollback_permissions(
    ctx: &serenity::Context,
    guild_id: u64,
    role_id: u64,
    old: serenity::Permissions,
) -> IntegrityActionResult {
    match ctx
        .http
        .edit_role(
            serenity::GuildId::new(guild_id),
            serenity::RoleId::new(role_id),
            &serenity::EditRole::new().permissions(old),
            Some(ANTI_PERMISSIONS_ROLLBACK_REASON),
        )
        .await
    {
        Ok(_) => IntegrityActionResult::Applied,
        Err(error) => IntegrityActionResult::from_failure(&discord_failure(error)),
    }
}

/// Publie l'incident et, s'il est critique, envoie le signal au mode panique.
pub(super) async fn publish_critical(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    guild_id: u64,
    module: ProtectionModule,
    incident: &foxsecura::logs::SecurityIncident,
) {
    incident_log::publish(ctx, data, guild_id, language(context), incident).await;
    if sends_panic_signal(incident)
        && context
            .enabled_modules
            .contains(ProtectionModule::PanicMode)
    {
        anti_nuke::panic_signal(ctx, data, context, guild_id, module, now()).await;
    }
}

fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}
