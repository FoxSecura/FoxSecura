// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Intégrité du serveur au runtime : réponses unitaires aux entrées du
//! journal d'audit déjà retenues par les gardes du socle
//! (`anti_nuke::handle_audit_entry`).
//!
//! - `RoleUpdate` : anti-permissions (retour en arrière du bitfield, puis
//!   quarantaine de l'auteur non exempté).
//! - `WebhookCreate` / `WebhookUpdate` / `WebhookDelete` : suppression d'un
//!   webhook créé ou modifié par un auteur non autorisé, alerte sur une
//!   suppression.
//! - `GuildUpdate` (événement Gateway, ancienne version du serveur d'après le
//!   cache) : alertes server-edit et vanity, sans sanction ; l'auteur vient
//!   de l'entrée d'audit `GuildUpdate` indexée par le socle.
//!
//! Les décisions sont dans `foxsecura::protection::anti_nuke::server_integrity` ;
//! ce module relève l'état du cache (verrou relâché avant tout `.await`) et
//! appelle l'API. Les erreurs sont journalisées et jamais propagées.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use foxsecura::database::MemberGuardContext;
use foxsecura::protection::anti_nuke::audit::ScreenedAuthor;
use foxsecura::protection::anti_nuke::audit::{AuditAction, AuditEntry};
use foxsecura::protection::anti_nuke::response::{
    ANTI_NUKE_AUDIT_LABEL, Containment, sends_panic_signal,
};
use foxsecura::protection::anti_nuke::server_integrity::alert::AlertAuthor;
use foxsecura::protection::anti_nuke::server_integrity::anti_permissions::{
    ANTI_PERMISSIONS_ROLLBACK_REASON, PermissionIncidentInput, PermissionPlan, UpdatedRole,
    exempt_rollback_result, permission_incident, plan_permission_rollback,
};
use foxsecura::protection::anti_nuke::server_integrity::anti_server_edit::{
    ServerSettings, changed_server_fields, server_edit_incident,
};
use foxsecura::protection::anti_nuke::server_integrity::anti_vanity_change::vanity_incident;
use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use foxsecura::protection::anti_nuke::server_integrity::webhook_guard::{
    WebhookChange, WebhookIncidentInput, WebhookPlan, missing_manage_webhooks,
    plan_webhook_response, webhook_incident, webhook_removal_reason,
};
use foxsecura::protection::shared::{ProtectionModule, audit_reason};
use poise::serenity_prelude as serenity;

use super::anti_nuke::{self, contain_author, language, read_context};
use super::incident_log;
use super::quarantine::{bot_role_standing, discord_failure};
use super::restore::resolve_author;
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
        AuditAction::WebhookCreate | AuditAction::WebhookUpdate | AuditAction::WebhookDelete => {
            webhook_change(ctx, data, entry, author_id).await;
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

/// Webhook créé, modifié ou supprimé : suppression du webhook d'un auteur
/// non autorisé, alerte seule pour une suppression.
async fn webhook_change(
    ctx: &serenity::Context,
    data: &AppData,
    entry: &AuditEntry,
    author_id: u64,
) {
    let Some(change) = WebhookChange::from_audit(entry.action) else {
        return;
    };
    let guild_id = entry.guild_id;
    let Some(context) = read_context(data, guild_id, author_id).await else {
        return;
    };
    if !context
        .enabled_modules
        .contains(ProtectionModule::WebhookWatch)
    {
        return;
    }
    let bot_id = ctx.cache.current_user().id.get();
    let (owner_id, manage_webhooks) = match ctx.cache.guild(serenity::GuildId::new(guild_id)) {
        Some(guild) => (
            Some(guild.owner_id.get()),
            guild
                .members
                .get(&serenity::UserId::new(bot_id))
                .map(|member| {
                    let permissions = guild.member_permissions(member);
                    permissions.administrator() || permissions.manage_webhooks()
                }),
        ),
        None => (None, None),
    };
    let whitelisted = anti_nuke::is_author_exempt(ctx, &context, guild_id, author_id).await;
    let plan = plan_webhook_response(change, author_id, bot_id, owner_id, whitelisted);

    let removal = match plan {
        WebhookPlan::Ignore => return,
        WebhookPlan::Alert => None,
        WebhookPlan::Remove => Some(match (manage_webhooks, entry.target_id) {
            (Some(false), _) => missing_manage_webhooks(),
            (_, None) => IntegrityActionResult::Skipped {
                failure_code: Some(foxsecura::logs::FailureCode::ResourceMissing),
                details: "webhook_id_missing".to_owned(),
            },
            (_, Some(webhook_id)) => match ctx
                .http
                .delete_webhook(
                    serenity::WebhookId::new(webhook_id),
                    Some(&webhook_removal_reason()),
                )
                .await
            {
                Ok(()) => IntegrityActionResult::Applied,
                Err(error) => IntegrityActionResult::from_failure(&discord_failure(error)),
            },
        }),
    };
    println!(
        "[webhook-watch] {change:?} par {author_id} sur la guilde {guild_id} : webhook {:?}, suppression {removal:?}",
        entry.target_id
    );

    let incident = webhook_incident(
        language(&context),
        WebhookIncidentInput {
            change,
            author_id,
            webhook_id: entry.target_id,
            webhook_name: entry.target_name.as_deref(),
        },
        removal.as_ref(),
    );
    publish_critical(
        ctx,
        data,
        &context,
        guild_id,
        ProtectionModule::WebhookWatch,
        &incident,
    )
    .await;
}

/// Serveur modifié (`GuildUpdate`) : alertes server-edit (`warning`) et
/// vanity (`critical`, signal au mode panique). Aucune sanction, aucun retour
/// en arrière. Sans ancienne version en cache, rien n'est comparable.
pub async fn handle_guild_update(
    ctx: &serenity::Context,
    data: &AppData,
    old: Option<&serenity::Guild>,
    new: &serenity::PartialGuild,
) {
    let Some(old) = old else {
        return;
    };
    let old = settings(
        &old.name,
        old.icon.as_ref(),
        old.verification_level,
        old.default_message_notifications,
        old.vanity_url_code.as_deref(),
    );
    let new_settings = settings(
        &new.name,
        new.icon.as_ref(),
        new.verification_level,
        new.default_message_notifications,
        new.vanity_url_code.as_deref(),
    );
    let fields = changed_server_fields(&old, &new_settings);
    let vanity_changed = old.vanity_url_code != new_settings.vanity_url_code;
    // Cas courant (salon système, bannière…) : aucune lecture en base.
    if fields.is_empty() && !vanity_changed {
        return;
    }

    let guild_id = new.id.get();
    let Some(context) = read_context(data, guild_id, 0).await else {
        return;
    };
    let server_edit = context
        .enabled_modules
        .contains(ProtectionModule::AntiServerEdit)
        && !fields.is_empty();
    let vanity = context
        .enabled_modules
        .contains(ProtectionModule::AntiVanityChange)
        && vanity_changed;
    if !server_edit && !vanity {
        return;
    }

    let author = match resolve_author(data, guild_id, AuditAction::GuildUpdate, None).await {
        // Propriétaire libre d'agir ; FoxSecura ne modifie pas le serveur.
        ScreenedAuthor::Owner | ScreenedAuthor::Bot => return,
        ScreenedAuthor::Unresolved => AlertAuthor::Unresolved,
        ScreenedAuthor::Counted(author_id) => {
            let Some(author_context) = read_context(data, guild_id, author_id).await else {
                return;
            };
            if anti_nuke::is_author_exempt(ctx, &author_context, guild_id, author_id).await {
                AlertAuthor::Exempt(author_id)
            } else {
                AlertAuthor::Resolved(author_id)
            }
        }
    };
    let language = language(&context);

    if server_edit && let Some(incident) = server_edit_incident(language, guild_id, &fields, author)
    {
        incident_log::publish(ctx, data, guild_id, language, &incident).await;
    }
    if vanity
        && let Some(incident) = vanity_incident(
            language,
            guild_id,
            old.vanity_url_code.as_deref(),
            new_settings.vanity_url_code.as_deref(),
            author,
        )
    {
        publish_critical(
            ctx,
            data,
            &context,
            guild_id,
            ProtectionModule::AntiVanityChange,
            &incident,
        )
        .await;
    }
}

fn settings(
    name: &str,
    icon: Option<&serenity::ImageHash>,
    verification_level: serenity::VerificationLevel,
    default_notifications: serenity::DefaultMessageNotificationLevel,
    vanity_url_code: Option<&str>,
) -> ServerSettings {
    ServerSettings {
        name: name.to_owned(),
        icon: icon.map(ToString::to_string),
        verification_level: u8::from(verification_level),
        default_notifications: u8::from(default_notifications),
        vanity_url_code: vanity_url_code.map(str::to_owned),
    }
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
