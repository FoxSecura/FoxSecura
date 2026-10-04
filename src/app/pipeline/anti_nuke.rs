// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-nuke au runtime : entrées du journal d'audit poussées par Discord
//! (`GUILD_AUDIT_LOG_ENTRY_CREATE`).
//!
//! `entrée → gardes → classement → contexte (cache par guilde) → rafale par
//! auteur → confinement de l'auteur → incident → signal au mode panique`. Les actions déjà faites ne
//! sont jamais annulées en masse (voir `anti_nuke::response`). Les
//! décisions sont dans `foxsecura::protection::anti_nuke` ; ce module ne fait
//! que convertir l'événement et relever l'état du cache. Les erreurs sont
//! journalisées et jamais propagées.
//!
//! Sans `VIEW_AUDIT_LOG`, Discord n'envoie aucune entrée : l'absence de la
//! permission est signalée une fois par guilde dans les logs locaux, à la
//! réception de la guilde ([`handle_guild_create`]).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use foxsecura::database::MemberGuardContext;
use foxsecura::i18n::{DEFAULT_LANGUAGE, Language};
use foxsecura::protection::anti_nuke::audit::NukeAction;
use foxsecura::protection::anti_nuke::audit::{
    AuditAction, AuditEntry, AuditGuardContext, classify_entry, screen_entry,
    should_warn_missing_audit_permission,
};
use foxsecura::protection::anti_nuke::burst::BurstVerdict;
use foxsecura::protection::anti_nuke::is_anti_nuke_enabled;
use foxsecura::protection::anti_nuke::panic_mode::{PanicDecision, panic_incident};
use foxsecura::protection::anti_nuke::response::{
    ANTI_NUKE_QUARANTINE, AuthorFacts, Containment, NukeIncidentInput, NukeResponsePlan,
    anti_nuke_audit_reason, nuke_incident, plan_response, sends_panic_signal,
};
use foxsecura::protection::anti_nuke::settings::AntiNukeSettings;
use foxsecura::protection::lockdown::LockdownReason;
use foxsecura::protection::quarantine::UNKNOWN_MEMBER;
use foxsecura::protection::shared::ProtectionModule;
use poise::serenity_prelude::{
    self as serenity,
    audit_log::{
        Action, AuditLogEntry, Change, ChannelAction, EmojiAction, MemberAction, RoleAction,
        StickerAction,
    },
};

use super::quarantine::{self, QuarantineTarget, discord_failure};
use super::{bot_assigned_roles, incident_log, lockdown};
use crate::app::{AppData, run_database};

/// Entrée du journal d'audit poussée par Discord.
pub async fn handle_audit_entry(
    ctx: &serenity::Context,
    data: &AppData,
    guild_id: serenity::GuildId,
    entry: &AuditLogEntry,
) {
    let entry = convert_entry(guild_id.get(), entry);
    let guard = AuditGuardContext {
        now: now(),
        owner_id: ctx.cache.guild(guild_id).map(|guild| guild.owner_id.get()),
        bot_id: ctx.cache.current_user().id.get(),
    };
    let screened = screen_entry(&entry, guard, &mut data.protection.audit_dedup());
    let Ok(author_id) = screened else {
        return;
    };
    let Some(action) = classify_entry(&entry) else {
        return;
    };

    let guild = guild_id.get();
    let Some(context) = read_context(data, guild, author_id).await else {
        return;
    };
    if !context.enabled_modules.contains(action.module()) {
        return;
    }
    let thresholds = context
        .guild_config
        .as_ref()
        .map_or_else(AntiNukeSettings::default, |config| config.anti_nuke)
        .thresholds;
    let verdict = data.protection.nuke_bursts().record(
        guild,
        author_id,
        action,
        usize::from(thresholds.for_action(action)),
        guard.now,
    );
    let BurstVerdict::Triggered(burst) = verdict else {
        return;
    };
    println!(
        "[anti-nuke] rafale {} de {author_id} sur la guilde {guild} : {}/{} en {} s",
        action.module(),
        burst.count,
        burst.threshold,
        burst.window.as_secs()
    );

    let containment = contain_author(ctx, data, &context, guild, author_id, action).await;
    let incident = nuke_incident(
        language(&context),
        NukeIncidentInput {
            guild_id: guild,
            author_id,
            burst,
            target_id: entry.target_id,
            target_name: entry.target_name.as_deref(),
        },
        &containment,
    );
    incident_log::publish(ctx, data, guild, language(&context), &incident).await;

    if sends_panic_signal(&incident)
        && context
            .enabled_modules
            .contains(ProtectionModule::PanicMode)
    {
        panic_signal(ctx, data, &context, guild, action, guard.now).await;
    }
}

/// Signal d'un incident critique au mode panique ; verrouille le serveur 15
/// minutes (mode lent de 30 s) si assez de modules distincts ont réagi en
/// 30 s et qu'aucun verrouillage n'est déjà actif.
async fn panic_signal(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    guild_id: u64,
    action: NukeAction,
    now: Duration,
) {
    let lockdown_active = match run_database(&data.database, move |database| {
        database.lockdown_state(guild_id)
    })
    .await
    {
        Ok(state) => state.is_some(),
        Err(error) => {
            // La pose refuse de toute façon un second verrouillage (insertion
            // atomique de la ligne) : on continue.
            eprintln!("[anti-nuke] verrouillage de la guilde {guild_id} illisible : {error}");
            false
        }
    };
    let threshold = context
        .guild_config
        .as_ref()
        .map_or_else(AntiNukeSettings::default, |config| config.anti_nuke)
        .panic_threshold;
    let result = data.protection.panic_mode().record_with(
        guild_id,
        action.module().key(),
        now,
        usize::from(threshold),
        lockdown_active,
    );
    match result.decision {
        PanicDecision::Below => return,
        PanicDecision::LockdownActive => {
            println!(
                "[anti-nuke] mode panique sur la guilde {guild_id} : {} modules distincts, verrouillage déjà actif",
                result.distinct_types
            );
            return;
        }
        PanicDecision::Trigger => {}
    }

    let outcome = lockdown::apply(ctx, data, guild_id, LockdownReason::PanicMode).await;
    println!(
        "[anti-nuke] mode panique sur la guilde {guild_id} : {} ({:?})",
        result.kinds.join(", "),
        outcome.start
    );
    let incident = panic_incident(language(context), guild_id, &result, &outcome);
    incident_log::publish(ctx, data, guild_id, language(context), &incident).await;
}

/// Confine l'auteur d'une rafale : rien s'il est exempté, quarantaine avec
/// retrait des rôles dangereux sinon (jamais de repli timeout).
async fn contain_author(
    ctx: &serenity::Context,
    data: &AppData,
    context: &MemberGuardContext,
    guild_id: u64,
    author_id: u64,
    action: NukeAction,
) -> Containment {
    let author = author_roles(ctx, guild_id, author_id).await;
    let plan = plan_response(AuthorFacts {
        user_listed: context.user_whitelisted,
        whitelist_roles: &context.whitelist_roles,
        ignored_roles: bot_assigned_roles(context.guild_config.as_ref()),
        member_roles: author.as_deref().ok(),
    });
    match plan {
        NukeResponsePlan::IgnoreExempt => Containment::Exempt,
        NukeResponsePlan::AuthorUnavailable => Containment::AuthorUnavailable {
            details: author.err().unwrap_or_default(),
        },
        NukeResponsePlan::Quarantine => {
            let roles = author.unwrap_or_default();
            let target = QuarantineTarget {
                guild_id,
                user_id: author_id,
                member_roles: &roles,
                // Exemption déjà décidée : un auteur exempté n'arrive pas ici.
                whitelisted: false,
            };
            Containment::Quarantine(
                quarantine::quarantine(
                    ctx,
                    data,
                    &target,
                    ANTI_NUKE_QUARANTINE,
                    anti_nuke_audit_reason(action),
                )
                .await,
            )
        }
    }
}

/// Rôles de l'auteur : cache de la guilde, sinon lecture par l'API (un
/// appel). `Err` avec le détail si l'auteur est introuvable.
async fn author_roles(
    ctx: &serenity::Context,
    guild_id: u64,
    author_id: u64,
) -> Result<Vec<u64>, String> {
    let guild = serenity::GuildId::new(guild_id);
    let user = serenity::UserId::new(author_id);
    let cached = ctx.cache.guild(guild).and_then(|guild| {
        guild
            .members
            .get(&user)
            .map(|member| member.roles.iter().map(|role| role.get()).collect())
    });
    if let Some(roles) = cached {
        return Ok(roles);
    }
    match guild.member(ctx, user).await {
        Ok(member) => Ok(member.roles.iter().map(|role| role.get()).collect()),
        Err(error) => {
            let failure = discord_failure(error);
            Err(if failure.is_unknown(UNKNOWN_MEMBER) {
                "member_missing".to_owned()
            } else {
                failure.details
            })
        }
    }
}

fn language(context: &MemberGuardContext) -> Language {
    context
        .guild_config
        .as_ref()
        .map_or(DEFAULT_LANGUAGE, |config| config.language)
}

/// Une seule lecture par entrée, servie par le cache de la guilde.
async fn read_context(data: &AppData, guild_id: u64, author_id: u64) -> Option<MemberGuardContext> {
    match run_database(&data.database, move |database| {
        database.member_guard_context(guild_id, author_id)
    })
    .await
    {
        Ok(context) => Some(context),
        Err(error) => {
            eprintln!(
                "[anti-nuke] contexte illisible pour la guilde {guild_id} (auteur {author_id}) : {error}"
            );
            None
        }
    }
}

/// Convertit l'entrée serenity : seuls les changements utiles sont relevés.
fn convert_entry(guild_id: u64, entry: &AuditLogEntry) -> AuditEntry {
    let action = match entry.action {
        Action::Member(MemberAction::BanAdd) => AuditAction::MemberBanAdd,
        Action::Member(MemberAction::BanRemove) => AuditAction::MemberBanRemove,
        Action::Member(MemberAction::Kick) => AuditAction::MemberKick,
        Action::Member(MemberAction::Update) => AuditAction::MemberUpdate,
        Action::Member(MemberAction::RoleUpdate) => AuditAction::MemberRoleUpdate,
        Action::Channel(ChannelAction::Create) => AuditAction::ChannelCreate,
        Action::Role(RoleAction::Create) => AuditAction::RoleCreate,
        Action::Emoji(EmojiAction::Create) => AuditAction::EmojiCreate,
        Action::Emoji(EmojiAction::Delete) => AuditAction::EmojiDelete,
        Action::Sticker(StickerAction::Create) => AuditAction::StickerCreate,
        Action::Sticker(StickerAction::Delete) => AuditAction::StickerDelete,
        _ => AuditAction::Other,
    };
    // Un identifiant nul n'est pas un auteur (snowflakes toujours positifs).
    let author_id = Some(entry.user_id.get()).filter(|id| *id != 0);
    let mut converted = AuditEntry::new(entry.id.get(), guild_id, author_id, action);
    converted.target_id = entry.target_id.map(|target| target.get());
    converted.reason = entry.reason.clone();

    for change in entry.changes.iter().flatten() {
        match change {
            Change::CommunicationDisabledUntil { new, .. } => {
                converted.timeout_until = Some(new.and_then(|timestamp| {
                    u64::try_from(timestamp.unix_timestamp())
                        .ok()
                        .map(Duration::from_secs)
                }));
            }
            Change::RolesAdded { new, .. } => {
                converted.roles_added += new.as_ref().map_or(0, Vec::len);
            }
            Change::Name {
                new: Some(name), ..
            } => {
                converted.target_name = Some(name.clone());
            }
            _ => {}
        }
    }
    converted
}

/// Guilde reçue : signale une fois l'absence de `VIEW_AUDIT_LOG` si un module
/// de l'anti-nuke est actif. Aucune lecture en base si la permission est là.
pub async fn handle_guild_create(ctx: &serenity::Context, data: &AppData, guild_id: u64) {
    let view_audit_log = {
        let bot_id = ctx.cache.current_user().id;
        ctx.cache
            .guild(serenity::GuildId::new(guild_id))
            .and_then(|guild| {
                guild.members.get(&bot_id).map(|member| {
                    let permissions = guild.member_permissions(member);
                    permissions.administrator() || permissions.view_audit_log()
                })
            })
    };
    if view_audit_log != Some(false) {
        return;
    }
    let enabled = match run_database(&data.database, move |database| {
        database.enabled_modules(guild_id)
    })
    .await
    {
        Ok(modules) => is_anti_nuke_enabled(modules),
        Err(error) => {
            eprintln!("[anti-nuke] modules de la guilde {guild_id} illisibles : {error}");
            return;
        }
    };
    let warn = {
        let mut warned = data.protection.audit_permission_warnings();
        let warn = should_warn_missing_audit_permission(
            view_audit_log,
            enabled,
            warned.contains(&guild_id),
        );
        if warn {
            warned.insert(guild_id);
        }
        warn
    };
    if warn {
        eprintln!(
            "[anti-nuke] guilde {guild_id} : FoxSecura n'a pas la permission VIEW_AUDIT_LOG \
             (Voir les logs du serveur). Discord n'envoie alors aucune entrée du journal \
             d'audit : l'anti-nuke ne peut rien détecter."
        );
    }
}

fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: serde_json::Value) -> AuditLogEntry {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn converts_a_role_grant_and_ignores_removals() {
        let entry = parse(serde_json::json!({
            "id": "1300000000000000000",
            "user_id": "42",
            "target_id": "43",
            "action_type": 25,
            "reason": "FoxSecura Anti-Nuke: test",
            "changes": [
                { "key": "$add", "new_value": [{ "id": "7", "name": "Admin" }] },
                { "key": "$remove", "new_value": [{ "id": "8", "name": "Membre" }] }
            ]
        }));
        let converted = convert_entry(1, &entry);
        assert_eq!(converted.action, AuditAction::MemberRoleUpdate);
        assert_eq!(converted.author_id, Some(42));
        assert_eq!(converted.target_id, Some(43));
        assert_eq!(converted.roles_added, 1);
        assert_eq!(
            converted.reason.as_deref(),
            Some("FoxSecura Anti-Nuke: test")
        );

        let removal = parse(serde_json::json!({
            "id": "1300000000000000001",
            "user_id": "42",
            "action_type": 25,
            "changes": [{ "key": "$remove", "new_value": [{ "id": "8", "name": "Membre" }] }]
        }));
        assert_eq!(convert_entry(1, &removal).roles_added, 0);
    }

    #[test]
    fn converts_timeout_changes() {
        let applied = parse(serde_json::json!({
            "id": "1300000000000000002",
            "user_id": "42",
            "action_type": 24,
            "changes": [{
                "key": "communication_disabled_until",
                "new_value": "2030-01-01T00:00:00+00:00"
            }]
        }));
        assert_eq!(
            convert_entry(1, &applied).timeout_until,
            Some(Some(Duration::from_secs(1_893_456_000)))
        );

        let lifted = parse(serde_json::json!({
            "id": "1300000000000000003",
            "user_id": "42",
            "action_type": 24,
            "changes": [{
                "key": "communication_disabled_until",
                "old_value": "2030-01-01T00:00:00+00:00"
            }]
        }));
        assert_eq!(convert_entry(1, &lifted).timeout_until, Some(None));
    }

    #[test]
    fn converts_created_resources_and_unknown_actions() {
        let channel = parse(serde_json::json!({
            "id": "1300000000000000004",
            "user_id": "42",
            "target_id": "99",
            "action_type": 10,
            "changes": [{ "key": "name", "new_value": "raid-@everyone" }]
        }));
        let converted = convert_entry(1, &channel);
        assert_eq!(converted.action, AuditAction::ChannelCreate);
        assert_eq!(converted.target_name.as_deref(), Some("raid-@everyone"));

        for (action_type, expected) in [
            (20, AuditAction::MemberKick),
            (22, AuditAction::MemberBanAdd),
            (23, AuditAction::MemberBanRemove),
            (30, AuditAction::RoleCreate),
            (60, AuditAction::EmojiCreate),
            (62, AuditAction::EmojiDelete),
            (90, AuditAction::StickerCreate),
            (92, AuditAction::StickerDelete),
            (12, AuditAction::Other),
        ] {
            let entry = parse(serde_json::json!({
                "id": "1300000000000000005",
                "user_id": "42",
                "action_type": action_type
            }));
            assert_eq!(convert_entry(1, &entry).action, expected, "{action_type}");
        }
    }
}
