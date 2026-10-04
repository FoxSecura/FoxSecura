// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-nuke au runtime : entrées du journal d'audit poussées par Discord
//! (`GUILD_AUDIT_LOG_ENTRY_CREATE`).
//!
//! `entrée → gardes → classement → contexte (cache par guilde)`. Les
//! décisions sont dans `foxsecura::protection::anti_nuke` ; ce module ne fait
//! que convertir l'événement et relever l'état du cache. Les erreurs sont
//! journalisées et jamais propagées.
//!
//! Sans `VIEW_AUDIT_LOG`, Discord n'envoie aucune entrée : l'absence de la
//! permission est signalée une fois par guilde dans les logs locaux, à la
//! réception de la guilde ([`handle_guild_create`]).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use foxsecura::protection::anti_nuke::audit::{
    AuditAction, AuditEntry, AuditGuardContext, classify_entry, screen_entry,
    should_warn_missing_audit_permission,
};
use foxsecura::protection::anti_nuke::is_anti_nuke_enabled;
use poise::serenity_prelude::{
    self as serenity,
    audit_log::{
        Action, AuditLogEntry, Change, ChannelAction, EmojiAction, MemberAction, RoleAction,
        StickerAction,
    },
};

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
    let Ok(_author_id) = screened else {
        return;
    };
    let Some(_action) = classify_entry(&entry) else {
        return;
    };
    // Le comptage par auteur arrive avec les rafales de l'anti-nuke.
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
