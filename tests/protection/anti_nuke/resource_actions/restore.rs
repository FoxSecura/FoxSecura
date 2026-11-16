// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use poise::serenity_prelude::{ChannelType, Permissions};

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, FailureCode, LogSeverity, LogType};
use foxsecura::protection::anti_nuke::audit::{
    AuditAction, AuditIgnoreReason, RESOURCE_AUTHOR_MAX_AGE, RecentAuditAuthors,
    RecordedAuditAuthor, ScreenedAuthor, screened_author,
};
use foxsecura::protection::anti_nuke::resource_actions::restore::{
    CHANNEL_RESTORE_REASON, DeletedRole, ROLE_RESTORE_REASON, RestoreIncidentInput, RestoreMode,
    RestoreOutcome, RestoredResource, RoleRestoreRefusal, channel_restore_mode, plan_role_restore,
    restorable_channel_kind, restore_incident, role_restore_mode, should_publish_restore,
};
use foxsecura::protection::anti_nuke::response::{Containment, sends_panic_signal};
use foxsecura::protection::quarantine::{Overwrite, OverwriteTarget};
use foxsecura::protection::shared::{ModuleSet, ProtectionModule, is_foxsecura_audit_reason};

const GUILD: u64 = 10;

fn modules(enabled: &[ProtectionModule]) -> ModuleSet {
    enabled.iter().copied().collect()
}

#[test]
fn anti_mode_wins_over_auto_mode_per_resource() {
    assert_eq!(channel_restore_mode(ModuleSet::empty()), None);
    assert_eq!(
        channel_restore_mode(modules(&[ProtectionModule::AutoChannelRestore])),
        Some(RestoreMode::Auto)
    );
    assert_eq!(
        channel_restore_mode(modules(&[
            ProtectionModule::AntiChannelDelete,
            ProtectionModule::AutoChannelRestore
        ])),
        Some(RestoreMode::Anti)
    );
    // Les interrupteurs des salons et des rôles sont indépendants.
    assert_eq!(
        role_restore_mode(modules(&[ProtectionModule::AntiChannelDelete])),
        None
    );
    assert_eq!(
        role_restore_mode(modules(&[ProtectionModule::AntiRoleDelete])),
        Some(RestoreMode::Anti)
    );
}

#[test]
fn only_v1_channel_kinds_are_restored() {
    for kind in [
        ChannelType::Category,
        ChannelType::Text,
        ChannelType::News,
        ChannelType::Voice,
        ChannelType::Stage,
    ] {
        let restorable = restorable_channel_kind(kind).expect("restorable");
        assert_eq!(restorable.discord_kind(), kind);
    }
    for kind in [
        ChannelType::PublicThread,
        ChannelType::PrivateThread,
        ChannelType::NewsThread,
        ChannelType::Forum,
        ChannelType::Directory,
    ] {
        assert_eq!(restorable_channel_kind(kind), None, "{kind:?}");
    }
}

fn deleted_role() -> DeletedRole {
    DeletedRole {
        id: 42,
        name: "Modérateur".to_owned(),
        colour: 0x00ff_8800,
        hoist: true,
        mentionable: false,
        permissions: Permissions::KICK_MEMBERS,
        position: 7,
        managed: false,
    }
}

#[test]
fn role_plan_clones_the_deleted_role_but_never_everyone_nor_managed() {
    let plan = plan_role_restore(GUILD, &deleted_role()).expect("restorable");
    assert_eq!(plan.name, "Modérateur");
    assert_eq!(plan.colour, 0x00ff_8800);
    assert!(plan.hoist);
    assert!(!plan.mentionable);
    assert_eq!(plan.permissions, Permissions::KICK_MEMBERS);
    assert_eq!(plan.position, 7);

    let everyone = DeletedRole {
        id: GUILD,
        ..deleted_role()
    };
    assert_eq!(
        plan_role_restore(GUILD, &everyone),
        Err(RoleRestoreRefusal::Everyone)
    );
    let managed = DeletedRole {
        managed: true,
        ..deleted_role()
    };
    assert_eq!(
        plan_role_restore(GUILD, &managed),
        Err(RoleRestoreRefusal::Managed)
    );
}

#[test]
fn auto_mode_stays_silent_unless_the_restore_succeeded() {
    let restored = RestoreOutcome::Restored { new_id: 99 };
    let failed = RestoreOutcome::Failed {
        failure_code: FailureCode::MissingPermission,
        details: "403".to_owned(),
    };
    let nothing = RestoreOutcome::NothingToRestore {
        details: "role_data_unavailable".to_owned(),
    };

    assert!(should_publish_restore(RestoreMode::Auto, &restored));
    assert!(!should_publish_restore(RestoreMode::Auto, &failed));
    assert!(!should_publish_restore(RestoreMode::Auto, &nothing));
    // Mode anti : toujours publié.
    assert!(should_publish_restore(RestoreMode::Anti, &restored));
    assert!(should_publish_restore(RestoreMode::Anti, &failed));
    assert!(should_publish_restore(RestoreMode::Anti, &nothing));
}

fn incident_input<'a>(
    mode: RestoreMode,
    outcome: &'a RestoreOutcome,
    author_id: Option<u64>,
) -> RestoreIncidentInput<'a> {
    RestoreIncidentInput {
        guild_id: GUILD,
        resource: RestoredResource::Channel,
        mode,
        deleted_id: 500,
        name: "général",
        author_id,
        outcome,
    }
}

#[test]
fn anti_incident_points_to_the_new_channel_id_and_quarantines() {
    let outcome = RestoreOutcome::Restored { new_id: 900 };
    let containment = Containment::AuthorUnavailable {
        details: "member_missing".to_owned(),
    };
    let incident = restore_incident(
        Language::French,
        incident_input(RestoreMode::Anti, &outcome, Some(77)),
        Some(&containment),
    );

    assert!(incident.validate().is_ok());
    assert_eq!(incident.module, "anti_channel_delete");
    assert_eq!(incident.log_type, LogType::Channel);
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert!(!sends_panic_signal(&incident));
    // Le nouvel identifiant, pas l'ancien.
    let resource = incident.affected_resource.as_ref().expect("resource");
    assert_eq!(resource.id.as_deref(), Some("900"));
    assert_eq!(incident.actions[0].action, ActionCode::RestoreChannel);
    assert_eq!(incident.actions[0].status, ActionStatus::Success);
    assert_eq!(incident.actions[1].action, ActionCode::QuarantineMember);
    assert_eq!(incident.actions[1].status, ActionStatus::Skipped);
    assert_eq!(
        incident.actor.as_ref().map(|actor| actor.user_id.as_str()),
        Some("77")
    );
}

#[test]
fn failed_anti_restore_is_critical_and_keeps_the_deleted_id() {
    let outcome = RestoreOutcome::Failed {
        failure_code: FailureCode::MissingPermission,
        details: "403".to_owned(),
    };
    let containment = Containment::AuthorUnavailable {
        details: "author_unresolved".to_owned(),
    };
    let incident = restore_incident(
        Language::French,
        incident_input(RestoreMode::Anti, &outcome, None),
        Some(&containment),
    );

    assert!(incident.validate().is_ok());
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert!(sends_panic_signal(&incident));
    assert_eq!(
        incident
            .affected_resource
            .as_ref()
            .and_then(|resource| resource.id.as_deref()),
        Some("500")
    );
    assert_eq!(incident.actions[0].status, ActionStatus::Failed);
    assert_eq!(
        incident.actions[0].failure_code,
        Some(FailureCode::MissingPermission)
    );
    // Auteur non résolu : aucune sanction, aucune mention d'acteur.
    assert!(incident.actor.is_none());
}

#[test]
fn exempt_author_is_restored_without_containment() {
    let outcome = RestoreOutcome::Restored { new_id: 901 };
    let incident = restore_incident(
        Language::French,
        incident_input(RestoreMode::Anti, &outcome, Some(77)),
        Some(&Containment::Exempt),
    );
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(incident.actions[0].action, ActionCode::RestoreChannel);
    assert_eq!(incident.actions[1].action, ActionCode::IgnoreExemptMember);
    assert!(
        incident.summary.contains("liste blanche"),
        "{}",
        incident.summary
    );
}

#[test]
fn auto_incident_is_informational_without_sanction() {
    let outcome = RestoreOutcome::Restored { new_id: 902 };
    let incident = restore_incident(
        Language::French,
        incident_input(RestoreMode::Auto, &outcome, None),
        None,
    );
    assert_eq!(incident.module, "auto_channel_restore");
    assert_eq!(incident.severity, LogSeverity::Info);
    assert_eq!(incident.actions.len(), 1);
    assert!(!sends_panic_signal(&incident));
}

#[test]
fn restore_reasons_follow_the_foxsecura_convention() {
    assert!(is_foxsecura_audit_reason(CHANNEL_RESTORE_REASON));
    assert!(is_foxsecura_audit_reason(ROLE_RESTORE_REASON));
}

#[test]
fn author_index_resolves_by_target_and_freshness() {
    let mut index = RecentAuditAuthors::new(4);
    index.record(RecordedAuditAuthor {
        guild_id: GUILD,
        action: AuditAction::ChannelDelete,
        target_id: Some(500),
        author: ScreenedAuthor::Counted(77),
        created_at: Duration::from_secs(1_000),
    });

    let now = Duration::from_secs(1_002);
    assert_eq!(
        index.resolve(
            GUILD,
            AuditAction::ChannelDelete,
            Some(500),
            now,
            RESOURCE_AUTHOR_MAX_AGE
        ),
        Some(ScreenedAuthor::Counted(77))
    );
    // Autre cible, autre action, autre guilde : rien.
    assert_eq!(
        index.resolve(
            GUILD,
            AuditAction::ChannelDelete,
            Some(501),
            now,
            RESOURCE_AUTHOR_MAX_AGE
        ),
        None
    );
    assert_eq!(
        index.resolve(
            GUILD,
            AuditAction::RoleDelete,
            Some(500),
            now,
            RESOURCE_AUTHOR_MAX_AGE
        ),
        None
    );
    assert_eq!(
        index.resolve(
            GUILD + 1,
            AuditAction::ChannelDelete,
            Some(500),
            now,
            RESOURCE_AUTHOR_MAX_AGE
        ),
        None
    );
    // Trop vieux.
    assert_eq!(
        index.resolve(
            GUILD,
            AuditAction::ChannelDelete,
            Some(500),
            now + RESOURCE_AUTHOR_MAX_AGE + Duration::from_secs(1),
            RESOURCE_AUTHOR_MAX_AGE
        ),
        None
    );
}

#[test]
fn author_index_is_bounded_and_keeps_the_most_recent_match() {
    let mut index = RecentAuditAuthors::new(2);
    for (id, author) in [(1, 10), (2, 20), (3, 30)] {
        index.record(RecordedAuditAuthor {
            guild_id: GUILD,
            action: AuditAction::RoleDelete,
            target_id: Some(id),
            author: ScreenedAuthor::Counted(author),
            created_at: Duration::from_secs(1_000),
        });
    }
    assert_eq!(index.len(), 2);
    let now = Duration::from_secs(1_001);
    // La plus ancienne est oubliée.
    assert_eq!(
        index.resolve(
            GUILD,
            AuditAction::RoleDelete,
            Some(1),
            now,
            RESOURCE_AUTHOR_MAX_AGE
        ),
        None
    );
    assert_eq!(
        index.resolve(
            GUILD,
            AuditAction::RoleDelete,
            Some(3),
            now,
            RESOURCE_AUTHOR_MAX_AGE
        ),
        Some(ScreenedAuthor::Counted(30))
    );

    // Deux entrées pour la même cible : la plus récente gagne.
    index.record(RecordedAuditAuthor {
        guild_id: GUILD,
        action: AuditAction::RoleDelete,
        target_id: Some(3),
        author: ScreenedAuthor::Owner,
        created_at: Duration::from_secs(1_001),
    });
    assert_eq!(
        index.resolve(
            GUILD,
            AuditAction::RoleDelete,
            Some(3),
            now,
            RESOURCE_AUTHOR_MAX_AGE
        ),
        Some(ScreenedAuthor::Owner)
    );
}

#[test]
fn screened_results_map_to_recordable_authors() {
    assert_eq!(screened_author(&Ok(77)), Some(ScreenedAuthor::Counted(77)));
    assert_eq!(
        screened_author(&Err(AuditIgnoreReason::GuildOwner)),
        Some(ScreenedAuthor::Owner)
    );
    assert_eq!(
        screened_author(&Err(AuditIgnoreReason::BotItself)),
        Some(ScreenedAuthor::Bot)
    );
    assert_eq!(
        screened_author(&Err(AuditIgnoreReason::FoxSecuraAction)),
        Some(ScreenedAuthor::Bot)
    );
    assert_eq!(
        screened_author(&Err(AuditIgnoreReason::NoAuthor)),
        Some(ScreenedAuthor::Unresolved)
    );
    assert_eq!(screened_author(&Err(AuditIgnoreReason::TooOld)), None);
    assert_eq!(screened_author(&Err(AuditIgnoreReason::Duplicate)), None);
}

#[test]
fn deletions_are_never_counted_as_bursts() {
    use foxsecura::protection::anti_nuke::audit::{AuditEntry, classify_entry};

    for action in [AuditAction::ChannelDelete, AuditAction::RoleDelete] {
        let entry = AuditEntry::new(1 << 22, GUILD, Some(77), action);
        assert_eq!(classify_entry(&entry), None, "{action:?}");
    }
}

#[test]
fn overwrites_are_cloned_into_the_plan() {
    use foxsecura::protection::anti_nuke::resource_actions::restore::{
        ChannelRestorePlan, RestorableChannelKind,
    };

    let plan = ChannelRestorePlan {
        name: "général".to_owned(),
        kind: RestorableChannelKind::Text,
        parent_id: Some(400),
        topic: Some("Bienvenue".to_owned()),
        nsfw: false,
        overwrites: vec![Overwrite {
            target: OverwriteTarget::Role(GUILD),
            allow: Permissions::empty(),
            deny: Permissions::SEND_MESSAGES,
        }],
    };
    assert_eq!(plan.kind.discord_kind(), ChannelType::Text);
    assert_eq!(plan.overwrites.len(), 1);
    assert_eq!(plan.overwrites[0].deny, Permissions::SEND_MESSAGES);
}
