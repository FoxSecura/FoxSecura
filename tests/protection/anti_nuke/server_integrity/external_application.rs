// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_nuke::server_integrity::anti_external_application::{
    ExternalApplicationInput, detect_external_application_permission_added,
};

const FLAG: u64 = 1 << 50;

#[test]
fn external_application_permission_needs_a_resolved_unauthorized_executor() {
    let base = ExternalApplicationInput {
        enabled: true,
        old_permissions: 0,
        new_permissions: FLAG,
        permission_flag: Some(FLAG),
        role_is_in_flight: false,
        role_is_everyone: false,
        role_is_managed: false,
        executor_id: Some(42),
        executor_is_owner: false,
        executor_is_whitelisted: false,
    };

    assert!(detect_external_application_permission_added(base).triggered);

    let unresolved = detect_external_application_permission_added(ExternalApplicationInput {
        executor_id: None,
        ..base
    });
    assert!(!unresolved.triggered);
    assert!(unresolved.warning);

    assert!(
        !detect_external_application_permission_added(ExternalApplicationInput {
            executor_is_owner: true,
            ..base
        })
        .triggered
    );
}

// --- Tranche 10 : retrait du seul bit, combinaison et anti-boucle ---

use std::time::Duration;

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, LogSeverity};
use foxsecura::protection::anti_nuke::audit::{
    AuditAction, AuditEntry, AuditEntryDedup, AuditGuardContext, AuditIgnoreReason, screen_entry,
};
use foxsecura::protection::anti_nuke::response::{Containment, sends_panic_signal};
use foxsecura::protection::anti_nuke::server_integrity::anti_external_application::{
    ANTI_EXTERNAL_APPLICATION_REVERT_REASON, EXTERNAL_APPS_PERMISSION,
    ExternalApplicationIncidentInput, RoleUpdateModules, RoleUpdateResponse,
    external_application_incident, external_apps_added, plan_role_update,
};
use foxsecura::protection::anti_nuke::server_integrity::anti_permissions::{
    PermissionIgnore, UpdatedRole,
};
use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use foxsecura::protection::quarantine::BotRoleStanding;
use foxsecura::protection::shared::{
    DISCORD_EPOCH_MILLIS, ProtectionModule, is_foxsecura_audit_reason,
};
use poise::serenity_prelude::Permissions;

const GUILD: u64 = 1;
const ROLE: u64 = 50;
const BOT: u64 = 3;
const OWNER: u64 = 2;
const NOW_SECS: u64 = 1_767_225_600;
const BOT_STANDING: BotRoleStanding = BotRoleStanding {
    top_role_position: 10,
    manage_roles: true,
};
const BOTH: RoleUpdateModules = RoleUpdateModules {
    anti_permissions: true,
    external_application: true,
};
const EXTERNAL_ONLY: RoleUpdateModules = RoleUpdateModules {
    anti_permissions: false,
    external_application: true,
};

fn role(position: u16) -> UpdatedRole {
    UpdatedRole {
        id: ROLE,
        position,
        managed: false,
        bot_role: false,
    }
}

fn plan(
    role: Option<UpdatedRole>,
    old: Permissions,
    new: Permissions,
    modules: RoleUpdateModules,
) -> RoleUpdateResponse {
    plan_role_update(GUILD, ROLE, role, Some(BOT_STANDING), (old, new), modules)
}

#[test]
fn the_flag_is_the_discord_use_external_apps_bit() {
    assert_eq!(EXTERNAL_APPS_PERMISSION.bits(), FLAG);
    assert!(external_apps_added(
        Permissions::empty(),
        EXTERNAL_APPS_PERMISSION
    ));
    assert!(!external_apps_added(
        EXTERNAL_APPS_PERMISSION,
        EXTERNAL_APPS_PERMISSION
    ));
    assert!(!external_apps_added(
        EXTERNAL_APPS_PERMISSION,
        Permissions::empty()
    ));
}

#[test]
fn only_the_external_apps_bit_is_removed() {
    let old = Permissions::SEND_MESSAGES;
    // L'auteur ajoute aussi une permission non dangereuse : elle reste.
    let new = old | Permissions::ATTACH_FILES | EXTERNAL_APPS_PERMISSION;
    assert_eq!(
        plan(Some(role(2)), old, new, BOTH),
        RoleUpdateResponse::RevertExternal {
            target: Permissions::SEND_MESSAGES | Permissions::ATTACH_FILES,
            precheck: None,
        }
    );
    // Bit déjà présent : rien n'a été ajouté.
    assert_eq!(
        plan(
            Some(role(2)),
            EXTERNAL_APPS_PERMISSION,
            EXTERNAL_APPS_PERMISSION | Permissions::ATTACH_FILES,
            BOTH
        ),
        RoleUpdateResponse::Ignore(PermissionIgnore::NoDangerousAddition)
    );
}

#[test]
fn everyone_managed_bot_and_unknown_roles_are_never_touched() {
    let (old, new) = (Permissions::empty(), EXTERNAL_APPS_PERMISSION);
    assert_eq!(
        plan_role_update(
            GUILD,
            GUILD,
            Some(role(2)),
            Some(BOT_STANDING),
            (old, new),
            BOTH
        ),
        RoleUpdateResponse::Ignore(PermissionIgnore::Everyone)
    );
    assert_eq!(
        plan(
            Some(UpdatedRole {
                managed: true,
                ..role(2)
            }),
            old,
            new,
            BOTH
        ),
        RoleUpdateResponse::Ignore(PermissionIgnore::Managed)
    );
    assert_eq!(
        plan(
            Some(UpdatedRole {
                managed: true,
                bot_role: true,
                ..role(2)
            }),
            old,
            new,
            BOTH
        ),
        RoleUpdateResponse::Ignore(PermissionIgnore::BotRole)
    );
    assert_eq!(
        plan(None, old, new, BOTH),
        RoleUpdateResponse::Ignore(PermissionIgnore::RoleUnknown)
    );
}

#[test]
fn same_prechecks_as_anti_permissions() {
    let (old, new) = (Permissions::empty(), EXTERNAL_APPS_PERMISSION);
    let RoleUpdateResponse::RevertExternal { precheck, .. } = plan_role_update(
        GUILD,
        ROLE,
        Some(role(2)),
        Some(BotRoleStanding {
            top_role_position: 10,
            manage_roles: false,
        }),
        (old, new),
        BOTH,
    ) else {
        panic!("retrait attendu");
    };
    assert!(
        matches!(precheck, Some(IntegrityActionResult::Skipped { details, .. }) if details == "MANAGE_ROLES")
    );

    let RoleUpdateResponse::RevertExternal { precheck, .. } = plan(Some(role(10)), old, new, BOTH)
    else {
        panic!("retrait attendu");
    };
    assert!(matches!(
        precheck,
        Some(IntegrityActionResult::Skipped { .. })
    ));
}

#[test]
fn combined_with_anti_permissions_a_single_rollback_and_incident() {
    let old = Permissions::SEND_MESSAGES;
    let new = old | Permissions::ADMINISTRATOR | EXTERNAL_APPS_PERMISSION;
    let response = plan(Some(role(2)), old, new, BOTH);
    assert_eq!(
        response,
        RoleUpdateResponse::Rollback {
            target: old,
            added: Permissions::ADMINISTRATOR | EXTERNAL_APPS_PERMISSION,
            external: true,
            precheck: None,
        }
    );
    // L'ancien bitfield retire aussi le bit : un seul appel suffit, et
    // l'incident est celui de l'anti-permissions.
    assert_eq!(response.module(), Some(ProtectionModule::AntiPermissions));

    // Anti-permissions désactivé : seul le bit est retiré.
    assert_eq!(
        plan(Some(role(2)), old, new, EXTERNAL_ONLY),
        RoleUpdateResponse::RevertExternal {
            target: old | Permissions::ADMINISTRATOR,
            precheck: None,
        }
    );
    // Applications externes désactivées : anti-permissions seul.
    assert_eq!(
        plan(
            Some(role(2)),
            old,
            new,
            RoleUpdateModules {
                anti_permissions: true,
                external_application: false,
            }
        ),
        RoleUpdateResponse::Rollback {
            target: old,
            added: Permissions::ADMINISTRATOR,
            external: false,
            precheck: None,
        }
    );
    // Les deux désactivés : rien.
    assert_eq!(
        plan(
            Some(role(2)),
            old,
            new,
            RoleUpdateModules {
                anti_permissions: false,
                external_application: false,
            }
        ),
        RoleUpdateResponse::Ignore(PermissionIgnore::NoDangerousAddition)
    );
}

#[test]
fn the_revert_itself_never_retriggers() {
    assert!(is_foxsecura_audit_reason(
        ANTI_EXTERNAL_APPLICATION_REVERT_REASON
    ));
    let entry_id = ((NOW_SECS * 1_000 - DISCORD_EPOCH_MILLIS) << 22) | 7;
    let mut entry = AuditEntry::new(entry_id, GUILD, Some(BOT), AuditAction::RoleUpdate);
    entry.target_id = Some(ROLE);
    entry.reason = Some(ANTI_EXTERNAL_APPLICATION_REVERT_REASON.to_owned());
    entry.permissions_change = Some((
        (Permissions::SEND_MESSAGES | EXTERNAL_APPS_PERMISSION).bits(),
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
    // Même hors garde, le retrait n'ajoute rien : aucune réponse.
    let (old, new) = entry.permissions_change.unwrap();
    assert_eq!(
        plan(
            Some(role(2)),
            Permissions::from_bits_truncate(old),
            Permissions::from_bits_truncate(new),
            BOTH
        ),
        RoleUpdateResponse::Ignore(PermissionIgnore::NoDangerousAddition)
    );
}

#[test]
fn the_owner_is_screened_out_by_the_audit_guards() {
    let entry_id = ((NOW_SECS * 1_000 - DISCORD_EPOCH_MILLIS) << 22) | 8;
    let mut entry = AuditEntry::new(entry_id, GUILD, Some(OWNER), AuditAction::RoleUpdate);
    entry.target_id = Some(ROLE);
    entry.permissions_change = Some((0, FLAG));
    let context = AuditGuardContext {
        now: Duration::from_secs(NOW_SECS),
        owner_id: Some(OWNER),
        bot_id: BOT,
    };
    assert_eq!(
        screen_entry(&entry, context, &mut AuditEntryDedup::default()),
        Err(AuditIgnoreReason::GuildOwner)
    );
}

#[test]
fn external_application_incident_is_critical_and_signals_panic_mode() {
    let incident = external_application_incident(
        Language::French,
        ExternalApplicationIncidentInput {
            role_id: ROLE,
            role_name: Some("Modos"),
            author_id: 42,
            old: Permissions::empty(),
            new: EXTERNAL_APPS_PERMISSION,
        },
        &IntegrityActionResult::Applied,
        &Containment::AuthorUnavailable {
            details: "member_missing".to_owned(),
        },
    );
    assert_eq!(incident.module, "anti_external_application");
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert!(sends_panic_signal(&incident));
    assert_eq!(incident.actions[0].action, ActionCode::RollbackPermissions);
    assert_eq!(incident.actions[0].status, ActionStatus::Success);
    assert!(incident.validate().is_ok());
}
