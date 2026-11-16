// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use poise::serenity_prelude::Permissions;

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, FailureCode, LogSeverity, SecurityEvidence};
use foxsecura::protection::anti_nuke::audit::{
    AuditAction, AuditEntry, AuditEntryDedup, AuditGuardContext, AuditIgnoreReason, classify_entry,
    screen_entry,
};
use foxsecura::protection::anti_nuke::response::{Containment, sends_panic_signal};
use foxsecura::protection::anti_nuke::server_integrity::anti_permissions::{
    ANTI_PERMISSIONS_ROLLBACK_REASON, PermissionIgnore, PermissionIncidentInput, PermissionPlan,
    UpdatedRole, added_dangerous_permissions, exempt_rollback_result, permission_incident,
    plan_permission_rollback,
};
use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use foxsecura::protection::quarantine::BotRoleStanding;
use foxsecura::protection::shared::{DISCORD_EPOCH_MILLIS, is_foxsecura_audit_reason};

const GUILD: u64 = 1;
const ROLE: u64 = 50;
const BOT: u64 = 3;
const OWNER: u64 = 2;
const NOW_SECS: u64 = 1_767_225_600;

fn role(position: u16) -> UpdatedRole {
    UpdatedRole {
        id: ROLE,
        position,
        managed: false,
        bot_role: false,
    }
}

const BOT_STANDING: BotRoleStanding = BotRoleStanding {
    top_role_position: 10,
    manage_roles: true,
};

fn plan(role_facts: Option<UpdatedRole>, old: Permissions, new: Permissions) -> PermissionPlan {
    plan_permission_rollback(GUILD, ROLE, role_facts, Some(BOT_STANDING), old, new)
}

#[test]
fn added_is_new_and_not_old_restricted_to_dangerous_permissions() {
    assert_eq!(
        added_dangerous_permissions(
            Permissions::SEND_MESSAGES,
            Permissions::SEND_MESSAGES | Permissions::ADMINISTRATOR
        ),
        Permissions::ADMINISTRATOR
    );
    // Retrait d'une permission : rien.
    assert!(added_dangerous_permissions(Permissions::BAN_MEMBERS, Permissions::empty()).is_empty());
    // Ré-ajout d'une permission déjà présente : rien.
    assert!(
        added_dangerous_permissions(
            Permissions::BAN_MEMBERS,
            Permissions::BAN_MEMBERS | Permissions::SEND_MESSAGES
        )
        .is_empty()
    );
    // Permission non dangereuse ajoutée : rien.
    assert!(
        added_dangerous_permissions(Permissions::empty(), Permissions::ATTACH_FILES).is_empty()
    );
    for permission in [
        Permissions::ADMINISTRATOR,
        Permissions::MANAGE_GUILD,
        Permissions::MANAGE_ROLES,
        Permissions::MANAGE_CHANNELS,
        Permissions::MANAGE_WEBHOOKS,
        Permissions::BAN_MEMBERS,
        Permissions::KICK_MEMBERS,
        Permissions::MODERATE_MEMBERS,
        Permissions::MENTION_EVERYONE,
    ] {
        assert_eq!(
            added_dangerous_permissions(Permissions::empty(), permission),
            permission
        );
    }
}

#[test]
fn rollback_is_planned_for_a_dangerous_addition() {
    assert_eq!(
        plan(
            Some(role(5)),
            Permissions::empty(),
            Permissions::ADMINISTRATOR | Permissions::SEND_MESSAGES
        ),
        PermissionPlan::Respond {
            added: Permissions::ADMINISTRATOR,
            precheck: None,
        }
    );
    assert_eq!(
        plan(
            Some(role(5)),
            Permissions::BAN_MEMBERS,
            Permissions::empty()
        ),
        PermissionPlan::Ignore(PermissionIgnore::NoDangerousAddition)
    );
}

#[test]
fn everyone_managed_bot_and_unknown_roles_are_never_touched() {
    let dangerous = Permissions::ADMINISTRATOR;
    assert_eq!(
        plan_permission_rollback(
            GUILD,
            GUILD,
            Some(UpdatedRole {
                id: GUILD,
                ..role(0)
            }),
            Some(BOT_STANDING),
            Permissions::empty(),
            dangerous
        ),
        PermissionPlan::Ignore(PermissionIgnore::Everyone)
    );
    assert_eq!(
        plan(
            Some(UpdatedRole {
                managed: true,
                ..role(5)
            }),
            Permissions::empty(),
            dangerous
        ),
        PermissionPlan::Ignore(PermissionIgnore::Managed)
    );
    // Rôle géré du bot : ses scopes changent à la réinstallation.
    assert_eq!(
        plan(
            Some(UpdatedRole {
                managed: true,
                bot_role: true,
                ..role(5)
            }),
            Permissions::empty(),
            dangerous
        ),
        PermissionPlan::Ignore(PermissionIgnore::BotRole)
    );
    assert_eq!(
        plan(None, Permissions::empty(), dangerous),
        PermissionPlan::Ignore(PermissionIgnore::RoleUnknown)
    );
}

#[test]
fn prechecks_classify_missing_permission_and_hierarchy() {
    let without_manage_roles = plan_permission_rollback(
        GUILD,
        ROLE,
        Some(role(5)),
        Some(BotRoleStanding {
            top_role_position: 10,
            manage_roles: false,
        }),
        Permissions::empty(),
        Permissions::ADMINISTRATOR,
    );
    let PermissionPlan::Respond {
        precheck: Some(IntegrityActionResult::Skipped { failure_code, .. }),
        ..
    } = without_manage_roles
    else {
        panic!("{without_manage_roles:?}");
    };
    assert_eq!(failure_code, Some(FailureCode::MissingPermission));

    for position in [10, 11] {
        let above = plan(
            Some(role(position)),
            Permissions::empty(),
            Permissions::ADMINISTRATOR,
        );
        let PermissionPlan::Respond {
            precheck: Some(IntegrityActionResult::Skipped { failure_code, .. }),
            ..
        } = above
        else {
            panic!("{above:?}");
        };
        assert_eq!(failure_code, Some(FailureCode::RoleHierarchy));
    }

    // Bot absent du cache : tenté, l'échec sera classé d'après la réponse.
    assert_eq!(
        plan_permission_rollback(
            GUILD,
            ROLE,
            Some(role(5)),
            None,
            Permissions::empty(),
            Permissions::ADMINISTRATOR
        ),
        PermissionPlan::Respond {
            added: Permissions::ADMINISTRATOR,
            precheck: None,
        }
    );
}

fn input() -> PermissionIncidentInput<'static> {
    PermissionIncidentInput {
        role_id: ROLE,
        role_name: Some("Membres"),
        author_id: 77,
        old: Permissions::SEND_MESSAGES,
        new: Permissions::SEND_MESSAGES | Permissions::ADMINISTRATOR,
        added: Permissions::ADMINISTRATOR,
    }
}

#[test]
fn incident_is_critical_with_both_bitfields_and_separate_results() {
    let containment = Containment::AuthorUnavailable {
        details: "member_missing".to_owned(),
    };
    let incident = permission_incident(
        Language::French,
        input(),
        &IntegrityActionResult::Applied,
        &containment,
    );
    assert!(incident.validate().is_ok());
    assert_eq!(incident.module, "anti_permissions");
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert!(sends_panic_signal(&incident));
    assert_eq!(incident.actions[0].action, ActionCode::RollbackPermissions);
    assert_eq!(incident.actions[0].status, ActionStatus::Success);
    assert_eq!(incident.actions[1].action, ActionCode::QuarantineMember);

    let expected = format!(
        "{}->{}",
        Permissions::SEND_MESSAGES.bits(),
        (Permissions::SEND_MESSAGES | Permissions::ADMINISTRATOR).bits()
    );
    assert!(incident.evidence.iter().any(|evidence| matches!(
        evidence,
        SecurityEvidence::Text { value, .. } if *value == expected
    )));
}

#[test]
fn failed_rollback_is_reported_as_leaving_permissions_in_place() {
    let failed = IntegrityActionResult::Failed {
        failure_code: FailureCode::MissingPermission,
        details: "403".to_owned(),
    };
    let incident = permission_incident(
        Language::French,
        input(),
        &failed,
        &Containment::AuthorUnavailable {
            details: "x".to_owned(),
        },
    );
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert_eq!(incident.actions[0].status, ActionStatus::Failed);
    assert!(
        incident
            .recommendation
            .as_deref()
            .is_some_and(|text| text.contains("PAS")),
        "{:?}",
        incident.recommendation
    );
}

#[test]
fn exempt_author_is_neither_rolled_back_nor_contained() {
    let incident = permission_incident(
        Language::French,
        input(),
        &exempt_rollback_result(),
        &Containment::Exempt,
    );
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert!(!sends_panic_signal(&incident));
    assert_eq!(incident.actions[0].status, ActionStatus::Skipped);
    assert_eq!(incident.actions[1].action, ActionCode::IgnoreExemptMember);
}

#[test]
fn the_rollback_itself_never_retriggers() {
    // Le retour en arrière est un `RoleUpdate` du bot, avec la raison
    // FoxSecura : le socle l'écarte avant tout traitement.
    assert!(is_foxsecura_audit_reason(ANTI_PERMISSIONS_ROLLBACK_REASON));
    let entry_id = ((NOW_SECS * 1_000 - DISCORD_EPOCH_MILLIS) << 22) | 1;
    let mut entry = AuditEntry::new(entry_id, GUILD, Some(BOT), AuditAction::RoleUpdate);
    entry.target_id = Some(ROLE);
    entry.reason = Some(ANTI_PERMISSIONS_ROLLBACK_REASON.to_owned());
    entry.permissions_change = Some((
        (Permissions::SEND_MESSAGES | Permissions::ADMINISTRATOR).bits(),
        Permissions::SEND_MESSAGES.bits(),
    ));
    let context = AuditGuardContext {
        now: Duration::from_secs(NOW_SECS),
        owner_id: Some(OWNER),
        bot_id: BOT,
    };
    assert_eq!(
        screen_entry(&entry, context, &mut AuditEntryDedup::default()),
        Err(AuditIgnoreReason::FoxSecuraAction)
    );
    // Et une modification de rôle n'est jamais comptée en rafale.
    assert_eq!(classify_entry(&entry), None);
    // Le retour en arrière retire, il n'ajoute rien : même hors garde, rien.
    let (old, new) = entry.permissions_change.unwrap();
    assert!(
        added_dangerous_permissions(
            Permissions::from_bits_truncate(old),
            Permissions::from_bits_truncate(new)
        )
        .is_empty()
    );
}
