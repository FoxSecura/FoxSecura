// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Restauration des salons et des rôles supprimés au runtime.
//!
//! La source des données est l'objet supprimé fourni par l'événement Gateway
//! (`ChannelDelete`, `RoleDelete`) : aucun système de sauvegarde. L'auteur
//! vient de l'entrée d'audit correspondante indexée par le socle
//! (`anti_nuke::handle_audit_entry`), corrélée par cible et fraîcheur ;
//! l'ordre des deux événements n'étant pas garanti, l'index est consulté
//! plusieurs fois avec une courte attente ([`AUTHOR_LOOKUP_DELAY`]). Un
//! auteur toujours non résolu n'empêche jamais la restauration, mais ne
//! déclenche **aucune** sanction. Une suppression par le propriétaire ou par
//! FoxSecura lui-même n'est jamais restaurée.
//!
//! Les décisions sont dans `foxsecura::protection::anti_nuke::resource_actions::restore` ;
//! ce module convertit les événements et appelle l'API. Les erreurs sont
//! journalisées et jamais propagées.

use std::time::Duration;

use foxsecura::database::MemberGuardContext;
use foxsecura::i18n::{DEFAULT_LANGUAGE, Language};
use foxsecura::protection::anti_nuke::audit::{
    AuditAction, RESOURCE_AUTHOR_MAX_AGE, ScreenedAuthor,
};
use foxsecura::protection::anti_nuke::resource_actions::restore::{
    CHANNEL_RESTORE_REASON, ChannelRestorePlan, DeletedRole, ROLE_RESTORE_REASON,
    RestoreIncidentInput, RestoreMode, RestoreOutcome, RestoredResource, channel_restore_mode,
    classify_restore_failure, plan_role_restore, restorable_channel_kind, restore_incident,
    role_restore_mode, should_publish_restore,
};
use foxsecura::protection::anti_nuke::response::{
    ANTI_NUKE_AUDIT_LABEL, AuthorFacts, Containment, NukeResponsePlan, plan_response,
    sends_panic_signal,
};
use foxsecura::protection::quarantine::{Overwrite, OverwriteTarget};
use foxsecura::protection::shared::{ProtectionModule, audit_reason};
use poise::serenity_prelude as serenity;

use super::quarantine::{self, QuarantineTarget, discord_failure};
use super::{anti_nuke, bot_assigned_roles, incident_log};
use crate::app::{AppData, run_database};

/// Attente entre deux consultations de l'index des auteurs : l'entrée d'audit
/// arrive en général dans la seconde qui entoure l'événement Gateway.
const AUTHOR_LOOKUP_DELAY: Duration = Duration::from_millis(700);

/// Consultations de l'index avant d'abandonner la résolution de l'auteur.
const AUTHOR_LOOKUP_ATTEMPTS: u32 = 3;

/// Salon supprimé (`ChannelDelete`).
pub async fn handle_channel_delete(
    ctx: &serenity::Context,
    data: &AppData,
    channel: &serenity::GuildChannel,
) {
    let guild_id = channel.guild_id.get();
    let Some(context) = read_context(data, guild_id, 0).await else {
        return;
    };
    let Some(mode) = channel_restore_mode(context.enabled_modules) else {
        return;
    };

    let plan = restorable_channel_kind(channel.kind).map(|kind| ChannelRestorePlan {
        name: channel.name.clone(),
        kind,
        parent_id: channel.parent_id.map(serenity::ChannelId::get),
        topic: channel.topic.clone(),
        nsfw: channel.nsfw,
        overwrites: channel
            .permission_overwrites
            .iter()
            .filter_map(convert_overwrite)
            .collect(),
    });

    let author = resolve_author(data, guild_id, AuditAction::ChannelDelete, channel.id.get()).await;
    if matches!(author, ScreenedAuthor::Owner | ScreenedAuthor::Bot) {
        // Propriétaire libre d'agir ; les actions de FoxSecura (dont ses
        // propres restaurations ratées) ne sont jamais combattues.
        return;
    }

    let outcome = match plan {
        Some(plan) => restore_channel(ctx, guild_id, &plan).await,
        None => RestoreOutcome::NothingToRestore {
            details: format!("channel_kind_not_restorable:{:?}", channel.kind),
        },
    };
    respond(
        ctx,
        data,
        &context,
        mode,
        RestoredResource::Channel,
        guild_id,
        channel.id.get(),
        &channel.name,
        author,
        outcome,
    )
    .await;
}

/// Rôle supprimé (`RoleDelete`). `role` vient du cache ; sans lui, rien ne
/// peut être restauré.
pub async fn handle_role_delete(
    ctx: &serenity::Context,
    data: &AppData,
    guild_id: serenity::GuildId,
    role_id: serenity::RoleId,
    role: Option<&serenity::Role>,
) {
    let guild_id = guild_id.get();
    let Some(context) = read_context(data, guild_id, 0).await else {
        return;
    };
    let Some(mode) = role_restore_mode(context.enabled_modules) else {
        return;
    };

    let deleted = role.map(|role| DeletedRole {
        id: role.id.get(),
        name: role.name.clone(),
        colour: role.colour.0,
        hoist: role.hoist,
        mentionable: role.mentionable,
        permissions: role.permissions,
        position: role.position,
        managed: role.managed,
    });

    let author = resolve_author(data, guild_id, AuditAction::RoleDelete, role_id.get()).await;
    if matches!(author, ScreenedAuthor::Owner | ScreenedAuthor::Bot) {
        return;
    }

    let (name, outcome) = match &deleted {
        Some(deleted) => match plan_role_restore(guild_id, deleted) {
            Ok(plan) => (
                deleted.name.clone(),
                restore_role(ctx, guild_id, &plan).await,
            ),
            Err(refusal) => (
                deleted.name.clone(),
                RestoreOutcome::NothingToRestore {
                    details: format!("role_not_restorable:{refusal:?}"),
                },
            ),
        },
        None => (
            String::new(),
            RestoreOutcome::NothingToRestore {
                details: "role_data_unavailable".to_owned(),
            },
        ),
    };
    respond(
        ctx,
        data,
        &context,
        mode,
        RestoredResource::Role,
        guild_id,
        role_id.get(),
        &name,
        author,
        outcome,
    )
    .await;
}

/// Confine l'auteur (mode anti), construit l'incident, le publie selon le
/// mode et envoie le signal au mode panique s'il est critique.
#[allow(clippy::too_many_arguments)]
async fn respond(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    mode: RestoreMode,
    resource: RestoredResource,
    guild_id: u64,
    deleted_id: u64,
    name: &str,
    author: ScreenedAuthor,
    outcome: RestoreOutcome,
) {
    let module = resource.module(mode);
    let author_id = match author {
        ScreenedAuthor::Counted(author_id) => Some(author_id),
        _ => None,
    };
    println!(
        "[restore] {} sur la guilde {guild_id} : cible {deleted_id}, auteur {author_id:?}, {outcome:?}",
        module.key()
    );

    let containment = match mode {
        RestoreMode::Auto => None,
        RestoreMode::Anti => Some(contain(ctx, data, context, guild_id, author_id, module).await),
    };
    let incident = restore_incident(
        language(context),
        RestoreIncidentInput {
            guild_id,
            resource,
            mode,
            deleted_id,
            name,
            author_id,
            outcome: &outcome,
        },
        containment.as_ref(),
    );
    if should_publish_restore(mode, &outcome) {
        incident_log::publish(ctx, data, guild_id, language(context), &incident).await;
    } else {
        // Mode auto : un échec ou « rien à restaurer » reste dans les logs
        // locaux pour ne pas noyer le salon de logs pendant un ménage légitime.
        println!(
            "[restore] {} sur la guilde {guild_id} : incident {} gardé en local ({})",
            module.key(),
            incident.incident_id,
            incident.severity.as_str()
        );
    }

    if sends_panic_signal(&incident)
        && context
            .enabled_modules
            .contains(ProtectionModule::PanicMode)
    {
        anti_nuke::panic_signal(ctx, data, context, guild_id, module, now()).await;
    }
}

/// Réponse à l'auteur en mode anti : quarantaine du non-exempté (retrait des
/// rôles dangereux, sans repli timeout), `ignore_exempt_member` pour la liste
/// blanche, rien pour un auteur non résolu.
async fn contain(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    guild_id: u64,
    author_id: Option<u64>,
    module: ProtectionModule,
) -> Containment {
    let Some(author_id) = author_id else {
        return Containment::AuthorUnavailable {
            details: "author_unresolved".to_owned(),
        };
    };
    // La liste blanche par identifiant est relue pour l'auteur corrélé : le
    // contexte a été chargé avant que l'auteur soit connu.
    let user_listed = match run_database(&data.database, move |database| {
        database.is_whitelisted_user(guild_id, author_id)
    })
    .await
    {
        Ok(listed) => listed,
        Err(error) => {
            eprintln!("[restore] liste blanche illisible ({guild_id}) : {error}");
            false
        }
    };
    let roles = anti_nuke::author_roles(ctx, guild_id, author_id).await;
    let plan = plan_response(AuthorFacts {
        user_listed,
        whitelist_roles: &context.whitelist_roles,
        ignored_roles: bot_assigned_roles(context.guild_config.as_ref()),
        member_roles: roles.as_deref().ok(),
    });
    match plan {
        NukeResponsePlan::IgnoreExempt => Containment::Exempt,
        NukeResponsePlan::AuthorUnavailable => Containment::AuthorUnavailable {
            details: roles.err().unwrap_or_default(),
        },
        NukeResponsePlan::Quarantine => {
            let roles = roles.unwrap_or_default();
            let target = QuarantineTarget {
                guild_id,
                user_id: author_id,
                member_roles: &roles,
                whitelisted: false,
            };
            Containment::Quarantine(
                quarantine::quarantine(
                    ctx,
                    data,
                    &target,
                    foxsecura::protection::anti_nuke::response::ANTI_NUKE_QUARANTINE,
                    audit_reason(ANTI_NUKE_AUDIT_LABEL, module.key()),
                )
                .await,
            )
        }
    }
}

/// Recrée un salon d'après le plan ; la catégorie parente n'est reprise que
/// si elle existe encore (elle a pu être supprimée dans la même attaque).
async fn restore_channel(
    ctx: &serenity::Context,
    guild_id: u64,
    plan: &ChannelRestorePlan,
) -> RestoreOutcome {
    let guild = serenity::GuildId::new(guild_id);
    let parent_id = plan.parent_id.filter(|parent_id| {
        ctx.cache.guild(guild).is_some_and(|guild| {
            guild
                .channels
                .contains_key(&serenity::ChannelId::new(*parent_id))
        })
    });

    let mut builder = serenity::CreateChannel::new(plan.name.clone())
        .kind(plan.kind.discord_kind())
        .nsfw(plan.nsfw)
        .permissions(plan.overwrites.iter().map(serenity_overwrite))
        .audit_log_reason(CHANNEL_RESTORE_REASON);
    if let Some(parent_id) = parent_id {
        builder = builder.category(serenity::ChannelId::new(parent_id));
    }
    if let Some(topic) = &plan.topic {
        builder = builder.topic(topic.clone());
    }

    match guild.create_channel(ctx, builder).await {
        Ok(channel) => RestoreOutcome::Restored {
            new_id: channel.id.get(),
        },
        Err(error) => {
            let failure = discord_failure(error);
            RestoreOutcome::Failed {
                failure_code: classify_restore_failure(failure.status),
                details: failure.details,
            }
        }
    }
}

/// Recrée un rôle d'après le plan, puis remet sa position au mieux (échec
/// ignoré : créé en bas, le rôle reste gérable).
async fn restore_role(
    ctx: &serenity::Context,
    guild_id: u64,
    plan: &foxsecura::protection::anti_nuke::resource_actions::restore::RoleRestorePlan,
) -> RestoreOutcome {
    let guild = serenity::GuildId::new(guild_id);
    let builder = serenity::EditRole::new()
        .name(plan.name.clone())
        .permissions(plan.permissions)
        .hoist(plan.hoist)
        .mentionable(plan.mentionable)
        .colour(serenity::Colour::new(plan.colour));
    let role = match ctx
        .http
        .create_role(guild, &builder, Some(ROLE_RESTORE_REASON))
        .await
    {
        Ok(role) => role,
        Err(error) => {
            let failure = discord_failure(error);
            return RestoreOutcome::Failed {
                failure_code: classify_restore_failure(failure.status),
                details: failure.details,
            };
        }
    };

    if let Err(error) = ctx
        .http
        .edit_role_position(guild, role.id, plan.position, Some(ROLE_RESTORE_REASON))
        .await
    {
        eprintln!(
            "[restore] position du rôle restauré {} impossible ({guild_id}) : {error}",
            role.id
        );
    }
    RestoreOutcome::Restored {
        new_id: role.id.get(),
    }
}

/// Auteur de la suppression, d'après l'index des entrées récentes ; consulté
/// plusieurs fois, l'ordre des événements n'étant pas garanti.
async fn resolve_author(
    data: &AppData,
    guild_id: u64,
    action: AuditAction,
    target_id: u64,
) -> ScreenedAuthor {
    for attempt in 0..AUTHOR_LOOKUP_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(AUTHOR_LOOKUP_DELAY).await;
        }
        let resolved = data.protection.audit_authors().resolve(
            guild_id,
            action,
            Some(target_id),
            now(),
            RESOURCE_AUTHOR_MAX_AGE,
        );
        if let Some(author) = resolved {
            return author;
        }
    }
    ScreenedAuthor::Unresolved
}

fn convert_overwrite(overwrite: &serenity::PermissionOverwrite) -> Option<Overwrite> {
    let target = match overwrite.kind {
        serenity::PermissionOverwriteType::Member(user_id) => {
            OverwriteTarget::Member(user_id.get())
        }
        serenity::PermissionOverwriteType::Role(role_id) => OverwriteTarget::Role(role_id.get()),
        _ => return None,
    };
    Some(Overwrite {
        target,
        allow: overwrite.allow,
        deny: overwrite.deny,
    })
}

fn serenity_overwrite(overwrite: &Overwrite) -> serenity::PermissionOverwrite {
    serenity::PermissionOverwrite {
        allow: overwrite.allow,
        deny: overwrite.deny,
        kind: match overwrite.target {
            OverwriteTarget::Member(user_id) => {
                serenity::PermissionOverwriteType::Member(serenity::UserId::new(user_id))
            }
            OverwriteTarget::Role(role_id) => {
                serenity::PermissionOverwriteType::Role(serenity::RoleId::new(role_id))
            }
        },
    }
}

fn language(context: &MemberGuardContext) -> Language {
    context
        .guild_config
        .as_ref()
        .map_or(DEFAULT_LANGUAGE, |config| config.language)
}

/// Une seule lecture par événement, servie par le cache de la guilde.
async fn read_context(data: &AppData, guild_id: u64, user_id: u64) -> Option<MemberGuardContext> {
    match run_database(&data.database, move |database| {
        database.member_guard_context(guild_id, user_id)
    })
    .await
    {
        Ok(context) => Some(context),
        Err(error) => {
            eprintln!("[restore] contexte illisible pour la guilde {guild_id} : {error}");
            None
        }
    }
}

fn now() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}
