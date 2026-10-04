// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Pipeline des membres : arrivées (`GuildMemberAdd`) et mises à jour
//! (`GuildMemberUpdate`).
//!
//! Arrivée : une seule lecture de contexte (cache de la guilde), puis la
//! chaîne de la V1 (`foxsecura::protection::member_join`) : liste noire →
//! anti-raid → anti-bot → nouveaux comptes → doubles comptes → usurpation
//! d'identité → pseudos hoistés. Un résultat terminal (membre banni, expulsé ou mis en
//! quarantaine, liste noire) arrête la chaîne. Un ban de nouveau compte non
//! appliqué déclenche la quarantaine de repli. Une rafale d'arrivées
//! verrouille le serveur et met en quarantaine le membre qui arrive.
//!
//! Mise à jour : seul l'anti-pseudo hoisté s'exécute, si le nom affiché a
//! changé et qu'il est hoisté ; le contexte n'est lu qu'à ce moment-là. Un
//! rôle de quarantaine retiré à la main déclenche la restauration des
//! overwrites du membre (`quarantine::handle_member_update`).
//!
//! Les erreurs sont journalisées et jamais propagées ; l'arrivée du bot
//! lui-même est ignorée.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use foxsecura::database::MemberGuardContext;
use foxsecura::i18n::{DEFAULT_LANGUAGE, Language};
use foxsecura::protection::anti_raid::anti_double_account::AccountIdentity;
use foxsecura::protection::anti_raid::anti_new_account::{
    AntiNewAccountInput, DEFAULT_MIN_ACCOUNT_AGE_DAYS,
};
use foxsecura::protection::anti_raid::join_burst::{JoinBurstLimits, JoinEvent};
use foxsecura::protection::lockdown::LockdownReason;
use foxsecura::protection::member_join::anti_bot::{
    ANTI_BOT_SANCTION, AntiBotPlan, anti_bot_audit_reason, anti_bot_response,
    authorized_bot_response, plan_anti_bot,
};
use foxsecura::protection::member_join::anti_raid::{
    ANTI_RAID_QUARANTINE, anti_raid_audit_reason, anti_raid_response,
};
use foxsecura::protection::member_join::blacklist::{
    BLACKLIST_BAN, blacklist_audit_reason, blacklist_response,
};
use foxsecura::protection::member_join::double_account::{
    DOUBLE_ACCOUNT_QUARANTINE, double_account_audit_reason, double_account_response, identity_name,
    needs_member_prewarm, plan_double_account,
};
use foxsecura::protection::member_join::hoisting::{
    anti_hoisting_audit_reason, hoisting_response, plan_nickname_fix,
};
use foxsecura::protection::member_join::impersonation::{
    IMPERSONATION_QUARANTINE, ImpersonationExemption, KnownMember, impersonation_audit_reason,
    impersonation_response, is_privileged, plan_impersonation, protected_names,
};
use foxsecura::protection::member_join::new_account::{
    NEW_ACCOUNT_BAN, NEW_ACCOUNT_FALLBACK, NewAccountExemption, NewAccountPlan,
    exempt_new_account_response, new_account_audit_reason, new_account_ban_response,
    plan_new_account,
};
use foxsecura::protection::member_join::{
    JoinChain, JoinStep, MemberRef, ModuleResponse, ModuleResult, display_name_changed,
};
use foxsecura::protection::shared::{
    AuthorWhitelist, ProtectionModule, SanctionKind, SanctionOutcome, is_author_exempt,
    snowflake_timestamp,
};
use poise::serenity_prelude as serenity;

use super::lockdown;
use super::quarantine::{self, QuarantineTarget};
use super::sanction::{self, NicknameRequest, SanctionRequest};
use super::{bot_assigned_roles, incident_log, unix_duration};
use crate::app::{AppData, run_database};

/// Membre analysé, converti depuis l'événement.
struct MemberFacts<'a> {
    target: MemberRef,
    is_bot: bool,
    is_guild_owner: bool,
    roles: Vec<u64>,
    display_name: &'a str,
    /// Nom d'utilisateur, nom global et pseudo (usurpation d'identité).
    names: Vec<&'a str>,
    /// Nom comparé et hash d'avatar (doubles comptes).
    identity_name: &'a str,
    avatar: Option<String>,
    joined_at: Duration,
}

/// Arrivée d'un membre.
pub async fn handle_join(ctx: &serenity::Context, data: &AppData, member: &serenity::Member) {
    if member.user.id == ctx.cache.current_user().id {
        return;
    }

    let facts = MemberFacts {
        target: MemberRef {
            guild_id: member.guild_id.get(),
            user_id: member.user.id.get(),
        },
        is_bot: member.user.bot,
        is_guild_owner: is_guild_owner(ctx, member.guild_id, member.user.id),
        roles: member.roles.iter().map(|role| role.get()).collect(),
        display_name: member.display_name(),
        names: [
            Some(member.user.name.as_str()),
            member.user.global_name.as_deref(),
            member.nick.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect(),
        identity_name: identity_name(&member.user.name, member.user.global_name.as_deref()),
        avatar: member.user.avatar.map(|hash| hash.to_string()),
        joined_at: member.joined_at.and_then(unix_duration).unwrap_or_else(now),
    };
    let Some(context) = read_context(data, facts.target).await else {
        return;
    };

    let mut chain = JoinChain::new(context.enabled_modules);
    while let Some(step) = chain.next_step() {
        let result = match step {
            JoinStep::Blacklist => blacklist(ctx, data, &context, &facts).await,
            JoinStep::AntiRaid => anti_raid(ctx, data, &context, &facts).await,
            JoinStep::AntiBot => anti_bot(ctx, data, &context, &facts).await,
            JoinStep::AntiNewAccount => new_account(ctx, data, &context, &facts).await,
            JoinStep::AntiDoubleAccount => double_account(ctx, data, &context, &facts).await,
            JoinStep::AntiImpersonation => impersonation(ctx, data, &context, &facts).await,
            JoinStep::AntiNicknameHoisting => hoisting(ctx, data, &context, &facts).await,
        };
        chain.record(step, result);
    }

    if let Some(step) = chain.stopped_by() {
        println!(
            "[member] arrivée de {} sur la guilde {} arrêtée par {step:?}",
            facts.target.user_id, facts.target.guild_id
        );
    }
}

/// Mise à jour d'un membre : anti-pseudo hoisté seulement, si le nom affiché
/// a changé.
pub async fn handle_update(
    ctx: &serenity::Context,
    data: &AppData,
    old: Option<&serenity::Member>,
    event: &serenity::GuildMemberUpdateEvent,
) {
    if event.user.id == ctx.cache.current_user().id {
        return;
    }

    // Rôle de quarantaine retiré à la main : restauration des overwrites.
    quarantine::handle_member_update(ctx, data, old, event).await;

    let current = event
        .nick
        .as_deref()
        .unwrap_or_else(|| event.user.display_name());
    if !display_name_changed(old.map(serenity::Member::display_name), current) {
        return;
    }
    // Nom propre (cas courant, et toujours le cas après un renommage par
    // FoxSecura) : aucune lecture en base.
    if plan_nickname_fix(current).is_none() {
        return;
    }

    let facts = MemberFacts {
        target: MemberRef {
            guild_id: event.guild_id.get(),
            user_id: event.user.id.get(),
        },
        is_bot: event.user.bot,
        is_guild_owner: is_guild_owner(ctx, event.guild_id, event.user.id),
        roles: event.roles.iter().map(|role| role.get()).collect(),
        display_name: current,
        // Usurpation et doubles comptes : analysés seulement à l'arrivée.
        names: Vec::new(),
        identity_name: current,
        avatar: None,
        joined_at: unix_duration(event.joined_at).unwrap_or_else(now),
    };
    let Some(context) = read_context(data, facts.target).await else {
        return;
    };
    if context
        .enabled_modules
        .contains(ProtectionModule::AntiNicknameHoisting)
    {
        hoisting(ctx, data, &context, &facts).await;
    }
}

/// Liste noire : ban, terminal même en cas d'échec.
async fn blacklist(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    facts: &MemberFacts<'_>,
) -> ModuleResult {
    if !context.blacklisted {
        return ModuleResult::NOT_DETECTED;
    }
    let outcome = sanction(ctx, facts, BLACKLIST_BAN, &blacklist_audit_reason()).await;
    publish(
        ctx,
        data,
        context,
        facts,
        blacklist_response(language(context), facts.target, &outcome),
    )
    .await
}

/// Anti-raid : une rafale d'arrivées verrouille le serveur et met en
/// quarantaine le membre qui arrive, en parallèle.
async fn anti_raid(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    facts: &MemberFacts<'_>,
) -> ModuleResult {
    let limits = context
        .guild_config
        .as_ref()
        .map_or_else(JoinBurstLimits::default, |config| config.anti_raid);
    let burst = data.protection.join_bursts().detect(
        limits.config(true),
        JoinEvent::new(
            facts.target.guild_id,
            facts.target.user_id,
            u64::try_from(facts.joined_at.as_millis()).unwrap_or(u64::MAX),
        ),
    );
    if !burst.triggered() {
        return ModuleResult::NOT_DETECTED;
    }

    let whitelist_exempt = whitelist_exempt(context, facts);
    let target = quarantine_target(facts, whitelist_exempt);
    let (lockdown, quarantine) = tokio::join!(
        lockdown::apply(ctx, data, facts.target.guild_id, LockdownReason::AntiRaid),
        quarantine::quarantine(
            ctx,
            data,
            &target,
            ANTI_RAID_QUARANTINE,
            anti_raid_audit_reason(),
        ),
    );
    publish(
        ctx,
        data,
        context,
        facts,
        anti_raid_response(
            language(context),
            facts.target,
            &burst,
            limits,
            &lockdown,
            &quarantine,
        ),
    )
    .await
}

/// Anti-bot : expulsion d'un bot absent de la liste blanche.
async fn anti_bot(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    facts: &MemberFacts<'_>,
) -> ModuleResult {
    let language = language(context);
    let response = match plan_anti_bot(facts.is_bot, context.user_whitelisted) {
        AntiBotPlan::NotABot => return ModuleResult::NOT_DETECTED,
        AntiBotPlan::Authorized => authorized_bot_response(language, facts.target),
        AntiBotPlan::Kick => {
            let outcome = sanction(ctx, facts, ANTI_BOT_SANCTION, &anti_bot_audit_reason()).await;
            anti_bot_response(language, facts.target, &outcome)
        }
    };
    publish(ctx, data, context, facts, response).await
}

/// Nouveaux comptes : ban d'un compte plus jeune que l'âge minimal.
async fn new_account(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    facts: &MemberFacts<'_>,
) -> ModuleResult {
    let whitelist_exempt = whitelist_exempt(context, facts);
    let check = plan_new_account(
        AntiNewAccountInput {
            account_created_at: snowflake_timestamp(facts.target.user_id),
            joined_at: facts.joined_at,
            min_age_days: u64::from(
                context
                    .guild_config
                    .as_ref()
                    .map_or(DEFAULT_MIN_ACCOUNT_AGE_DAYS, |config| {
                        config.new_account_min_age_days
                    }),
            ),
        },
        facts.is_bot,
        NewAccountExemption::from_member(facts.is_guild_owner, whitelist_exempt),
    );

    let language = language(context);
    let response = match check.plan {
        NewAccountPlan::Allowed => return ModuleResult::NOT_DETECTED,
        NewAccountPlan::Exempt(exemption) => {
            exempt_new_account_response(language, facts.target, &check.detection, exemption)
        }
        NewAccountPlan::Ban => {
            let outcome = sanction(ctx, facts, NEW_ACCOUNT_BAN, &new_account_audit_reason()).await;
            // Ban non appliqué : quarantaine de repli, avec repli timeout.
            let fallback = if outcome.is_applied() {
                None
            } else {
                Some(
                    quarantine::quarantine(
                        ctx,
                        data,
                        &quarantine_target(facts, whitelist_exempt),
                        NEW_ACCOUNT_FALLBACK,
                        new_account_audit_reason(),
                    )
                    .await,
                )
            };
            new_account_ban_response(
                language,
                facts.target,
                &check.detection,
                &outcome,
                fallback.as_ref(),
            )
        }
    };
    publish(ctx, data, context, facts, response).await
}

/// Doubles comptes : quarantaine d'un membre qui a le nom affiché et
/// l'avatar personnalisé d'un membre en cache.
async fn double_account(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    facts: &MemberFacts<'_>,
) -> ModuleResult {
    // Sans avatar personnalisé, aucune correspondance possible : le cache
    // n'est même pas parcouru.
    let Some(avatar) = facts.avatar.as_deref() else {
        return ModuleResult::NOT_DETECTED;
    };
    let whitelist_exempt = whitelist_exempt(context, facts);
    let cached = cached_identities(ctx, facts);
    let identities: Vec<AccountIdentity<'_>> = cached
        .iter()
        .map(|(user_id, name, avatar)| {
            AccountIdentity::new(*user_id, Some(name.as_str()), Some(avatar.as_str()))
        })
        .collect();
    let Some(detection) = plan_double_account(
        AccountIdentity::new(
            facts.target.user_id,
            Some(facts.identity_name),
            Some(avatar),
        ),
        &identities,
        facts.is_bot,
        facts.is_guild_owner,
        whitelist_exempt,
    ) else {
        return ModuleResult::NOT_DETECTED;
    };

    let outcome = quarantine::quarantine(
        ctx,
        data,
        &quarantine_target(facts, whitelist_exempt),
        DOUBLE_ACCOUNT_QUARANTINE,
        double_account_audit_reason(),
    )
    .await;
    publish(
        ctx,
        data,
        context,
        facts,
        double_account_response(language(context), facts.target, &detection, &outcome),
    )
    .await
}

/// Identités des membres **en cache** qui ont un avatar personnalisé :
/// `(identifiant, nom comparé, hash d'avatar)`. Jamais de lecture par
/// l'API : pendant un raid, un fetch complet par arrivée serait limité.
fn cached_identities(
    ctx: &serenity::Context,
    facts: &MemberFacts<'_>,
) -> Vec<(u64, String, String)> {
    let Some(guild) = ctx
        .cache
        .guild(serenity::GuildId::new(facts.target.guild_id))
    else {
        return Vec::new();
    };
    guild
        .members
        .values()
        .filter(|member| member.user.id.get() != facts.target.user_id && !member.user.bot)
        .filter_map(|member| {
            let avatar = member.user.avatar?.to_string();
            let name = identity_name(&member.user.name, member.user.global_name.as_deref());
            Some((member.user.id.get(), name.to_owned(), avatar))
        })
        .collect()
}

/// Usurpation d'identité : quarantaine d'un membre qui arrive avec le nom du
/// propriétaire ou d'un membre privilégié.
async fn impersonation(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    facts: &MemberFacts<'_>,
) -> ModuleResult {
    let (protected, privileged) = protected_names_from_cache(ctx, facts).await;
    let protected: Vec<&str> = protected.iter().map(String::as_str).collect();
    let whitelist_exempt = whitelist_exempt(context, facts);
    let exemption =
        ImpersonationExemption::from_member(facts.is_guild_owner, privileged, whitelist_exempt);
    let Some(detection) = plan_impersonation(&facts.names, &protected, exemption) else {
        return ModuleResult::NOT_DETECTED;
    };

    let outcome = quarantine::quarantine(
        ctx,
        data,
        &quarantine_target(facts, whitelist_exempt),
        IMPERSONATION_QUARANTINE,
        impersonation_audit_reason(),
    )
    .await;
    publish(
        ctx,
        data,
        context,
        facts,
        impersonation_response(language(context), facts.target, &detection, &outcome),
    )
    .await
}

/// Noms protégés (propriétaire et membres privilégiés en cache) et
/// privilège du membre qui arrive, d'après ses rôles.
///
/// Le propriétaire absent du cache est lu par l'API : un appel de plus par
/// arrivée sur un serveur où il n'est pas en cache.
async fn protected_names_from_cache(
    ctx: &serenity::Context,
    facts: &MemberFacts<'_>,
) -> (Vec<String>, bool) {
    let guild_id = serenity::GuildId::new(facts.target.guild_id);
    let (mut names, privileged, missing_owner) = {
        let Some(guild) = ctx.cache.guild(guild_id) else {
            return (Vec::new(), false);
        };
        // Rôles privilégiés, calculés une fois : chaque membre en cache est
        // ensuite testé sur ses seuls rôles.
        let everyone = serenity::RoleId::new(guild_id.get());
        let privileged_roles: Vec<serenity::RoleId> = guild
            .roles
            .values()
            .filter(|role| is_privileged(role.permissions))
            .map(|role| role.id)
            .collect();
        let everyone_privileged = privileged_roles.contains(&everyone);
        let is_member_privileged = |roles: &[serenity::RoleId]| {
            everyone_privileged || roles.iter().any(|role| privileged_roles.contains(role))
        };

        let known = guild.members.values().map(|member| KnownMember {
            user_id: member.user.id.get(),
            privileged: is_member_privileged(&member.roles),
            names: [
                Some(member.user.name.as_str()),
                member.user.global_name.as_deref(),
                member.nick.as_deref(),
            ],
        });
        let names: Vec<String> =
            protected_names(Some(guild.owner_id.get()), facts.target.user_id, known)
                .into_iter()
                .map(str::to_owned)
                .collect();
        let joining_roles: Vec<serenity::RoleId> = facts
            .roles
            .iter()
            .map(|role| serenity::RoleId::new(*role))
            .collect();
        let privileged = is_member_privileged(&joining_roles);
        let missing_owner = (!guild.members.contains_key(&guild.owner_id)
            && guild.owner_id.get() != facts.target.user_id)
            .then_some(guild.owner_id);
        (names, privileged, missing_owner)
    };

    if let Some(owner_id) = missing_owner {
        match guild_id.member(ctx, owner_id).await {
            Ok(owner) => names.extend(
                [Some(owner.user.name), owner.user.global_name, owner.nick]
                    .into_iter()
                    .flatten(),
            ),
            Err(error) => eprintln!(
                "[member] propriétaire de la guilde {} illisible : {error}",
                facts.target.guild_id
            ),
        }
    }
    (names, privileged)
}

/// Le membre est-il exempté par la liste blanche ? Le rôle de quarantaine
/// n'exempte jamais.
fn whitelist_exempt(context: &MemberGuardContext, facts: &MemberFacts<'_>) -> bool {
    is_author_exempt(
        &AuthorWhitelist {
            user_listed: context.user_whitelisted,
            listed_roles: &context.whitelist_roles,
        },
        Some(&facts.roles),
        bot_assigned_roles(context.guild_config.as_ref()),
    )
}

fn quarantine_target<'a>(facts: &'a MemberFacts<'_>, whitelisted: bool) -> QuarantineTarget<'a> {
    QuarantineTarget {
        guild_id: facts.target.guild_id,
        user_id: facts.target.user_id,
        member_roles: &facts.roles,
        whitelisted,
    }
}

/// Pseudos hoistés : renommage, y compris pour la liste blanche.
async fn hoisting(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    facts: &MemberFacts<'_>,
) -> ModuleResult {
    let Some(fix) = plan_nickname_fix(facts.display_name) else {
        return ModuleResult::NOT_DETECTED;
    };
    let outcome = sanction::execute_nickname(
        ctx,
        &NicknameRequest {
            guild_id: facts.target.guild_id,
            user_id: facts.target.user_id,
            member_roles: Some(&facts.roles),
            nickname: &fix.new,
            reason: &anti_hoisting_audit_reason(),
        },
    )
    .await;
    publish(
        ctx,
        data,
        context,
        facts,
        hoisting_response(language(context), facts.target, &fix, &outcome),
    )
    .await
}

async fn sanction(
    ctx: &serenity::Context,
    facts: &MemberFacts<'_>,
    kind: SanctionKind,
    reason: &str,
) -> SanctionOutcome {
    sanction::execute(
        ctx,
        &SanctionRequest {
            guild_id: facts.target.guild_id,
            user_id: facts.target.user_id,
            member_roles: Some(&facts.roles),
            kind,
            reason,
        },
    )
    .await
}

/// Publie l'incident et renvoie le résultat du module.
async fn publish(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    facts: &MemberFacts<'_>,
    response: ModuleResponse,
) -> ModuleResult {
    incident_log::publish(
        ctx,
        data,
        facts.target.guild_id,
        language(context),
        &response.incident,
    )
    .await;
    response.result
}

/// Écart entre deux demandes de membres : la passerelle accepte 120 commandes
/// par minute et par shard, le préchauffage n'en prend qu'une par seconde.
const PREWARM_SPACING: Duration = Duration::from_secs(1);

/// Guilde reçue (`GUILD_CREATE`, notamment au démarrage) : préchauffe le
/// cache des membres si les doubles comptes sont actifs et que le cache est
/// incomplet.
///
/// Les membres sont demandés par la passerelle (intent `GUILD_MEMBERS`),
/// jamais par l'API REST, une guilde à la fois : au mieux, sans garantie de
/// délai. Les membres reçus alimentent le cache de serenity.
pub async fn handle_guild_create(ctx: &serenity::Context, data: &AppData, guild: &serenity::Guild) {
    let guild_id = guild.id.get();
    let (member_count, cached) = (guild.member_count, guild.members.len());
    // Cache déjà complet (petite guilde) : aucune lecture en base.
    if !needs_member_prewarm(true, member_count, cached) {
        return;
    }
    let enabled = match run_database(&data.database, move |database| {
        database.enabled_modules(guild_id)
    })
    .await
    {
        Ok(modules) => modules.contains(ProtectionModule::AntiDoubleAccount),
        Err(error) => {
            eprintln!("[member] modules de la guilde {guild_id} illisibles : {error}");
            return;
        }
    };
    if needs_member_prewarm(enabled, member_count, cached) {
        prewarm_members(ctx, data.protection.member_prewarm(), guild_id);
    }
}

/// Demande les membres d'une guilde, à son tour (une demande par seconde au
/// plus, toutes guildes confondues).
pub fn prewarm_members(ctx: &serenity::Context, gate: &Arc<tokio::sync::Mutex<()>>, guild_id: u64) {
    let ctx = ctx.clone();
    let gate = Arc::clone(gate);
    tokio::spawn(async move {
        let _turn = gate.lock().await;
        ctx.shard.chunk_guild(
            serenity::GuildId::new(guild_id),
            None,
            false,
            serenity::ChunkGuildFilter::None,
            None,
        );
        println!("[member] membres de la guilde {guild_id} demandés (doubles comptes)");
        tokio::time::sleep(PREWARM_SPACING).await;
    });
}

/// Une seule lecture par événement, servie par le cache de la guilde.
async fn read_context(data: &AppData, target: MemberRef) -> Option<MemberGuardContext> {
    let MemberRef { guild_id, user_id } = target;
    match run_database(&data.database, move |database| {
        database.member_guard_context(guild_id, user_id)
    })
    .await
    {
        Ok(context) => Some(context),
        Err(error) => {
            eprintln!(
                "[member] contexte illisible pour la guilde {guild_id} (membre {user_id}) : {error}"
            );
            None
        }
    }
}

fn language(context: &MemberGuardContext) -> Language {
    context
        .guild_config
        .as_ref()
        .map_or(DEFAULT_LANGUAGE, |config| config.language)
}

/// Propriété du serveur d'après le cache ; `false` si le serveur n'y est pas
/// (le socle des sanctions refuse de toute façon de viser le propriétaire).
fn is_guild_owner(
    ctx: &serenity::Context,
    guild_id: serenity::GuildId,
    user_id: serenity::UserId,
) -> bool {
    ctx.cache
        .guild(guild_id)
        .is_some_and(|guild| guild.owner_id == user_id)
}

fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}
