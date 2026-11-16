// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Rôle plafonné au runtime (`GuildMemberUpdate`).
//!
//! `ajout du rôle plafonné → comptage des porteurs (cache, hydratation au
//! besoin) → retrait au membre qui vient de le recevoir → incident`. Les
//! décisions sont dans `foxsecura::protection::anti_nuke::limit_role` ; ce
//! module relève l'état du cache (verrou relâché avant tout `.await`) et
//! appelle l'API.
//!
//! # Coût de l'hydratation
//!
//! Un cache complet (intent `GUILD_MEMBERS`, petit serveur ou préchauffage)
//! ne coûte aucun appel. Sinon, la liste des membres est lue par l'API, par
//! pages de 1000 (un appel par page, [`MAX_HYDRATION_PAGES`] au plus), et
//! seulement quand le rôle plafonné vient d'être ajouté : un évènement rare.
//! Pendant une limitation de débit, serenity attend la fin de la fenêtre.

use foxsecura::database::MemberGuardContext;
use foxsecura::protection::anti_nuke::limit_role::{
    LIMIT_ROLE_REASON, LimitRoleFacts, LimitRoleIncidentInput, LimitRolePlan, LimitRoleSettings,
    LimitRoleVerdict, MAX_HYDRATION_PAGES, RoleCount, is_member_cache_complete,
    limit_role_incident, limit_role_verdict, plan_limit_role, removal_precheck,
};
use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use foxsecura::protection::shared::ProtectionModule;
use poise::serenity_prelude as serenity;

use super::quarantine::{bot_role_standing, discord_failure, role_facts};
use super::server_integrity::publish_critical;
use crate::app::{AppData, run_database};

/// Taille d'une page de la lecture des membres (maximum de l'API).
const MEMBERS_PAGE: u64 = 1000;

/// Mise à jour d'un membre : retrait du rôle plafonné au-delà du plafond.
pub async fn handle_member_update(
    ctx: &serenity::Context,
    data: &AppData,
    old: Option<&serenity::Member>,
    event: &serenity::GuildMemberUpdateEvent,
) {
    // Ancien état inconnu : aucun ajout prouvé, rien n'est fait.
    let Some(old) = old else {
        return;
    };
    // Aucun rôle ajouté (cas courant, et toujours le cas après un retrait par
    // FoxSecura) : aucune lecture en base.
    if event.roles.iter().all(|role| old.roles.contains(role)) {
        return;
    }

    let guild_id = event.guild_id.get();
    let user_id = event.user.id.get();
    let context = match run_database(&data.database, move |database| {
        database.member_guard_context(guild_id, user_id)
    })
    .await
    {
        Ok(context) => context,
        Err(error) => {
            eprintln!("[limit-role] contexte illisible pour la guilde {guild_id} : {error}");
            return;
        }
    };
    if !context
        .enabled_modules
        .contains(ProtectionModule::LimitRole)
    {
        return;
    }
    let settings = context
        .guild_config
        .as_ref()
        .map_or_else(LimitRoleSettings::default, |config| config.limit_role);
    let Some(role_id) = settings.role_id else {
        return;
    };
    let role = serenity::RoleId::new(role_id);

    let is_guild_owner = ctx
        .cache
        .guild(event.guild_id)
        .is_some_and(|guild| guild.owner_id == event.user.id);
    let plan = plan_limit_role(LimitRoleFacts {
        settings,
        had_role_before: Some(old.roles.contains(&role)),
        has_role_now: event.roles.contains(&role),
        is_guild_owner,
    });
    match plan {
        LimitRolePlan::NotAnAddition => return,
        LimitRolePlan::GuildOwner => {
            println!(
                "[limit-role] rôle plafonné {role_id} donné au propriétaire de la guilde {guild_id} : jamais retiré"
            );
            return;
        }
        LimitRolePlan::CountNeeded => {}
    }

    let count = count_role_members(ctx, event.guild_id, role).await;
    let observed = match limit_role_verdict(count, settings.max_members) {
        LimitRoleVerdict::WithinCap { .. } => return,
        LimitRoleVerdict::CountIncomplete => {
            eprintln!(
                "[limit-role] guilde {guild_id} : comptage des porteurs du rôle {role_id} incomplet, rien n'est retiré"
            );
            return;
        }
        LimitRoleVerdict::Remove { observed } => observed,
    };

    let precheck = {
        let bot_id = ctx.cache.current_user().id.get();
        ctx.cache.guild(event.guild_id).and_then(|guild| {
            removal_precheck(
                guild.roles.get(&role).map(role_facts).as_ref(),
                bot_role_standing(&guild, bot_id),
            )
        })
    };
    let removal = match precheck {
        Some(skipped) => skipped,
        None => match ctx
            .http
            .remove_member_role(event.guild_id, event.user.id, role, Some(LIMIT_ROLE_REASON))
            .await
        {
            Ok(()) => IntegrityActionResult::Applied,
            Err(error) => IntegrityActionResult::from_failure(&discord_failure(error)),
        },
    };
    println!(
        "[limit-role] guilde {guild_id} : rôle {role_id} donné à {user_id}, {observed}/{} porteurs, retrait {removal:?}",
        settings.max_members
    );

    let incident = limit_role_incident(
        language(&context),
        LimitRoleIncidentInput {
            role_id,
            member_id: user_id,
            observed,
            max_members: settings.max_members,
        },
        &removal,
    );
    publish_critical(
        ctx,
        data,
        &context,
        guild_id,
        ProtectionModule::LimitRole,
        &incident,
    )
    .await;
}

/// Porteurs du rôle : cache s'il est complet, sinon lecture paginée par
/// l'API (au plus [`MAX_HYDRATION_PAGES`] pages).
async fn count_role_members(
    ctx: &serenity::Context,
    guild_id: serenity::GuildId,
    role: serenity::RoleId,
) -> RoleCount {
    let cached = ctx.cache.guild(guild_id).and_then(|guild| {
        is_member_cache_complete(guild.member_count, guild.members.len()).then(|| {
            guild
                .members
                .values()
                .filter(|member| member.roles.contains(&role))
                .count()
        })
    });
    if let Some(count) = cached {
        return RoleCount::Complete(count);
    }

    let mut count = 0;
    let mut after = None;
    for _ in 0..MAX_HYDRATION_PAGES {
        let page = match guild_id.members(&ctx.http, Some(MEMBERS_PAGE), after).await {
            Ok(page) => page,
            Err(error) => {
                eprintln!("[limit-role] membres de la guilde {guild_id} illisibles : {error}");
                return RoleCount::Incomplete;
            }
        };
        count += page
            .iter()
            .filter(|member| member.roles.contains(&role))
            .count();
        if (page.len() as u64) < MEMBERS_PAGE {
            return RoleCount::Complete(count);
        }
        after = page.last().map(|member| member.user.id);
    }
    RoleCount::Incomplete
}

fn language(context: &MemberGuardContext) -> foxsecura::i18n::Language {
    context
        .guild_config
        .as_ref()
        .map_or(foxsecura::i18n::DEFAULT_LANGUAGE, |config| config.language)
}
