// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::protection::anti_nuke::audit::{
    AuditAction, AuditEntry, AuditEntryDedup, AuditGuardContext, AuditIgnoreReason,
    MAX_AUDIT_ENTRY_AGE, NukeAction, classify_entry, screen_entry,
    should_warn_missing_audit_permission,
};
use foxsecura::protection::anti_nuke::{NUKE_MODULES, is_anti_nuke_enabled};
use foxsecura::protection::shared::{
    DISCORD_EPOCH_MILLIS, ModuleSet, ProtectionModule, audit_reason,
};

const GUILD: u64 = 1;
const OWNER: u64 = 2;
const BOT: u64 = 3;
const AUTHOR: u64 = 4;
/// 2026-01-01, en secondes Unix.
const NOW_SECS: u64 = 1_767_225_600;

/// Snowflake créé à `secs` (secondes Unix), avec un compteur pour le rendre
/// unique.
fn snowflake_at(secs: u64, counter: u64) -> u64 {
    ((secs * 1_000 - DISCORD_EPOCH_MILLIS) << 22) | counter
}

fn entry(counter: u64, author: Option<u64>, action: AuditAction) -> AuditEntry {
    AuditEntry::new(snowflake_at(NOW_SECS, counter), GUILD, author, action)
}

fn context() -> AuditGuardContext {
    AuditGuardContext {
        now: Duration::from_secs(NOW_SECS),
        owner_id: Some(OWNER),
        bot_id: BOT,
    }
}

fn screen(entry: &AuditEntry) -> Result<u64, AuditIgnoreReason> {
    screen_entry(entry, context(), &mut AuditEntryDedup::default())
}

#[test]
fn entry_date_comes_from_its_snowflake() {
    let entry = entry(7, Some(AUTHOR), AuditAction::MemberKick);
    assert_eq!(entry.created_at(), Duration::from_secs(NOW_SECS));
}

#[test]
fn a_recent_entry_by_a_member_is_kept() {
    assert_eq!(
        screen(&entry(1, Some(AUTHOR), AuditAction::MemberBanAdd)),
        Ok(AUTHOR)
    );
}

#[test]
fn entries_older_than_five_minutes_are_ignored() {
    let limit = MAX_AUDIT_ENTRY_AGE.as_secs();
    let at = |secs| {
        AuditEntry::new(
            snowflake_at(secs, 0),
            GUILD,
            Some(AUTHOR),
            AuditAction::MemberKick,
        )
    };

    assert_eq!(screen(&at(NOW_SECS - limit)), Ok(AUTHOR));
    assert_eq!(
        screen(&at(NOW_SECS - limit - 1)),
        Err(AuditIgnoreReason::TooOld)
    );
    // Horloge locale en retard sur Discord : jamais « trop ancienne ».
    assert_eq!(screen(&at(NOW_SECS + 30)), Ok(AUTHOR));
}

#[test]
fn a_replayed_entry_is_counted_once() {
    let mut dedup = AuditEntryDedup::default();
    let entry = entry(1, Some(AUTHOR), AuditAction::MemberBanAdd);

    assert_eq!(screen_entry(&entry, context(), &mut dedup), Ok(AUTHOR));
    assert_eq!(
        screen_entry(&entry, context(), &mut dedup),
        Err(AuditIgnoreReason::Duplicate)
    );
}

#[test]
fn too_old_entries_are_not_remembered() {
    let mut dedup = AuditEntryDedup::default();
    let old = AuditEntry::new(
        snowflake_at(NOW_SECS - 3_600, 0),
        GUILD,
        Some(AUTHOR),
        AuditAction::MemberKick,
    );
    assert_eq!(
        screen_entry(&old, context(), &mut dedup),
        Err(AuditIgnoreReason::TooOld)
    );
    assert!(dedup.is_empty());
}

#[test]
fn deduplication_is_bounded_in_memory() {
    let mut dedup = AuditEntryDedup::new(3);
    for id in 1..=5 {
        assert!(dedup.first_seen(id));
    }
    assert_eq!(dedup.len(), 3);
    // Les plus anciens sont oubliés, les plus récents restent connus.
    assert!(dedup.first_seen(1));
    assert!(!dedup.first_seen(5));
}

#[test]
fn entries_without_author_are_ignored() {
    assert_eq!(
        screen(&entry(1, None, AuditAction::MemberBanAdd)),
        Err(AuditIgnoreReason::NoAuthor)
    );
}

#[test]
fn the_guild_owner_is_never_counted() {
    assert_eq!(
        screen(&entry(1, Some(OWNER), AuditAction::MemberBanAdd)),
        Err(AuditIgnoreReason::GuildOwner)
    );
    // Serveur absent du cache : le propriétaire n'est pas connu.
    let unknown_owner = AuditGuardContext {
        owner_id: None,
        ..context()
    };
    assert_eq!(
        screen_entry(
            &entry(2, Some(OWNER), AuditAction::MemberBanAdd),
            unknown_owner,
            &mut AuditEntryDedup::default()
        ),
        Ok(OWNER)
    );
}

#[test]
fn the_bot_itself_is_never_counted() {
    assert_eq!(
        screen(&entry(1, Some(BOT), AuditAction::MemberBanAdd)),
        Err(AuditIgnoreReason::BotItself)
    );
}

#[test]
fn bot_entries_with_a_foxsecura_reason_are_never_counted() {
    let mut own_sanction = entry(1, Some(BOT), AuditAction::MemberRoleUpdate);
    own_sanction.reason = Some(audit_reason("Anti-Nuke", "burst of mass_ban"));
    own_sanction.roles_added = 1;
    assert_eq!(
        screen(&own_sanction),
        Err(AuditIgnoreReason::FoxSecuraAction)
    );

    // La même raison écrite par un modérateur ne protège rien : seul
    // l'auteur compte.
    let mut forged = entry(2, Some(AUTHOR), AuditAction::MemberBanAdd);
    forged.reason = Some(audit_reason("Anti-Nuke", "burst of mass_ban"));
    assert_eq!(screen(&forged), Ok(AUTHOR));
}

#[test]
fn guards_follow_the_documented_order() {
    // Trop ancienne passe avant l'absence d'auteur, le doublon avant le bot.
    let old = AuditEntry::new(
        snowflake_at(NOW_SECS - 3_600, 0),
        GUILD,
        None,
        AuditAction::MemberKick,
    );
    assert_eq!(screen(&old), Err(AuditIgnoreReason::TooOld));

    let mut dedup = AuditEntryDedup::default();
    let bot = entry(1, Some(BOT), AuditAction::MemberKick);
    let _ = screen_entry(&bot, context(), &mut dedup);
    assert_eq!(
        screen_entry(&bot, context(), &mut dedup),
        Err(AuditIgnoreReason::Duplicate)
    );
}

#[test]
fn each_entry_type_maps_to_its_action() {
    let cases = [
        (AuditAction::MemberBanAdd, Some(NukeAction::Ban)),
        (AuditAction::MemberKick, Some(NukeAction::Kick)),
        (AuditAction::MemberBanRemove, Some(NukeAction::Unban)),
        (AuditAction::ChannelCreate, Some(NukeAction::ChannelCreate)),
        (AuditAction::RoleCreate, Some(NukeAction::RoleCreate)),
        (AuditAction::EmojiCreate, Some(NukeAction::EmojiSticker)),
        (AuditAction::EmojiDelete, Some(NukeAction::EmojiSticker)),
        (AuditAction::StickerCreate, Some(NukeAction::EmojiSticker)),
        (AuditAction::StickerDelete, Some(NukeAction::EmojiSticker)),
        (AuditAction::Other, None),
        // Sans changement utile : ni timeout, ni rôle ajouté.
        (AuditAction::MemberUpdate, None),
        (AuditAction::MemberRoleUpdate, None),
    ];
    for (action, expected) in cases {
        assert_eq!(
            classify_entry(&entry(1, Some(AUTHOR), action)),
            expected,
            "{action:?}"
        );
    }
}

#[test]
fn only_a_timeout_until_a_future_date_counts() {
    let with_timeout = |until: Option<Option<Duration>>| {
        let mut entry = entry(1, Some(AUTHOR), AuditAction::MemberUpdate);
        entry.timeout_until = until;
        classify_entry(&entry)
    };

    assert_eq!(
        with_timeout(Some(Some(Duration::from_secs(NOW_SECS + 600)))),
        Some(NukeAction::Timeout)
    );
    // Levée du timeout : la nouvelle valeur est absente.
    assert_eq!(with_timeout(Some(None)), None);
    // Date déjà passée : un timeout levé en la ramenant dans le passé.
    assert_eq!(
        with_timeout(Some(Some(Duration::from_secs(NOW_SECS)))),
        None
    );
    assert_eq!(
        with_timeout(Some(Some(Duration::from_secs(NOW_SECS - 60)))),
        None
    );
    // Autre changement de membre (pseudo) : rien.
    assert_eq!(with_timeout(None), None);
}

#[test]
fn only_added_roles_count_as_a_role_grant() {
    let mut added = entry(1, Some(AUTHOR), AuditAction::MemberRoleUpdate);
    added.roles_added = 2;
    assert_eq!(classify_entry(&added), Some(NukeAction::RoleGrant));

    // `$remove` seul : `roles_added` reste à zéro.
    let removed = entry(2, Some(AUTHOR), AuditAction::MemberRoleUpdate);
    assert_eq!(classify_entry(&removed), None);
}

#[test]
fn every_action_has_its_own_module() {
    let modules: Vec<ProtectionModule> = NukeAction::ALL.iter().map(|a| a.module()).collect();
    assert_eq!(modules, NUKE_MODULES.to_vec());
    assert_eq!(
        ProtectionModule::from_key("anti_emoji_sticker_nuke"),
        Ok(ProtectionModule::AntiEmojiStickerNuke)
    );
    assert_eq!(
        ProtectionModule::from_key("panic_mode"),
        Ok(ProtectionModule::PanicMode)
    );
}

#[test]
fn anti_nuke_is_enabled_by_any_burst_module_but_not_by_panic_mode_alone() {
    assert!(!is_anti_nuke_enabled(ModuleSet::empty()));
    assert!(!is_anti_nuke_enabled(
        [ProtectionModule::PanicMode].into_iter().collect()
    ));
    assert!(is_anti_nuke_enabled(
        [ProtectionModule::AntiMassKick].into_iter().collect()
    ));
}

#[test]
fn missing_audit_permission_is_reported_once_and_only_when_proven() {
    assert!(should_warn_missing_audit_permission(
        Some(false),
        true,
        false
    ));
    assert!(!should_warn_missing_audit_permission(
        Some(false),
        true,
        true
    ));
    assert!(!should_warn_missing_audit_permission(
        Some(true),
        true,
        false
    ));
    // Cache incomplet : aucune preuve, aucun signalement.
    assert!(!should_warn_missing_audit_permission(None, true, false));
    // Anti-nuke désactivé : la permission n'est pas nécessaire.
    assert!(!should_warn_missing_audit_permission(
        Some(false),
        false,
        false
    ));
}
