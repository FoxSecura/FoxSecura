// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::anti_raid::honeypot::{HoneypotDetectionInput, detect_honeypot_message};

fn input() -> HoneypotDetectionInput {
    HoneypotDetectionInput {
        channel_id: 100,
        honeypot_channel_id: Some(100),
        is_owner: false,
        is_administrator: false,
        can_manage_guild: false,
        whitelisted: false,
    }
}

#[test]
fn triggers_for_non_exempt_member_in_honeypot() {
    assert!(detect_honeypot_message(input()).triggered);
}

#[test]
fn ignores_messages_outside_honeypot() {
    let mut value = input();
    value.channel_id = 200;
    assert!(!detect_honeypot_message(value).triggered);
}

#[test]
fn exempts_staff_and_whitelisted_members() {
    let mut staff = input();
    staff.can_manage_guild = true;
    assert!(!detect_honeypot_message(staff).triggered);

    let mut whitelisted = input();
    whitelisted.whitelisted = true;
    assert!(!detect_honeypot_message(whitelisted).triggered);
}

// --- Décision, routage et incident (V1) ---

use foxsecura::i18n::Language;
use foxsecura::logs::{
    ActionCode, ActionStatus, AffectedResourceType, LogSeverity, LogType, SecurityEvidence,
    format_security_log_message,
};
use foxsecura::protection::anti_raid::honeypot::{
    HONEYPOT_QUARANTINE, HoneypotAuthor, HoneypotExemption, HoneypotPlan, HoneypotRoute,
    honeypot_audit_reason, honeypot_incident, plan_honeypot, route_honeypot,
};
use foxsecura::protection::quarantine::{
    ChannelLockSummary, DangerousRoleRemoval, QuarantineOutcome, QuarantineRequest, RoleStatus,
};
use foxsecura::protection::shared::{
    DeleteMessageOutcome, GuildMessage, MessageScope, ModuleSet, ProtectionModule,
    is_foxsecura_audit_reason, message_scope,
};
use poise::serenity_prelude::Permissions;

const TRAP: u64 = 100;

fn member(permissions: Option<Permissions>) -> HoneypotAuthor {
    HoneypotAuthor {
        is_guild_owner: false,
        whitelisted: false,
        permissions,
    }
}

fn route(scope: MessageScope) -> HoneypotRoute {
    HoneypotRoute {
        created: true,
        scope,
        enabled_modules: [ProtectionModule::Honeypot].into_iter().collect(),
        channel_id: TRAP,
        honeypot_channel_id: Some(TRAP),
    }
}

#[test]
fn an_ordinary_member_is_quarantined() {
    assert_eq!(
        plan_honeypot(TRAP, Some(TRAP), member(Some(Permissions::SEND_MESSAGES))),
        Some(HoneypotPlan::Quarantine)
    );
    // Gérer les messages ou bannir ne suffit pas à être exempté (V1).
    assert_eq!(
        plan_honeypot(
            TRAP,
            Some(TRAP),
            member(Some(
                Permissions::MANAGE_MESSAGES | Permissions::BAN_MEMBERS
            ))
        ),
        Some(HoneypotPlan::Quarantine)
    );
}

#[test]
fn owner_staff_and_whitelist_are_exempt() {
    let owner = HoneypotAuthor {
        is_guild_owner: true,
        ..member(None)
    };
    assert_eq!(
        plan_honeypot(TRAP, Some(TRAP), owner),
        Some(HoneypotPlan::Exempt(HoneypotExemption::GuildOwner))
    );
    for permissions in [Permissions::ADMINISTRATOR, Permissions::MANAGE_GUILD] {
        assert_eq!(
            plan_honeypot(TRAP, Some(TRAP), member(Some(permissions))),
            Some(HoneypotPlan::Exempt(HoneypotExemption::Staff))
        );
    }
    // La liste blanche exempte même quand les permissions sont inconnues.
    let whitelisted = HoneypotAuthor {
        whitelisted: true,
        ..member(None)
    };
    assert_eq!(
        plan_honeypot(TRAP, Some(TRAP), whitelisted),
        Some(HoneypotPlan::Exempt(HoneypotExemption::Whitelist))
    );
}

#[test]
fn unknown_permissions_delete_without_quarantine() {
    assert_eq!(
        plan_honeypot(TRAP, Some(TRAP), member(None)),
        Some(HoneypotPlan::DeleteOnly)
    );
}

#[test]
fn only_the_configured_trap_channel_is_watched() {
    assert_eq!(plan_honeypot(TRAP, None, member(None)), None);
    assert_eq!(plan_honeypot(200, Some(TRAP), member(None)), None);
}

#[test]
fn an_ignored_trap_channel_is_never_watched() {
    let author = member(Some(Permissions::SEND_MESSAGES));
    assert_eq!(
        route_honeypot(route(message_scope(true, false)), author),
        None
    );
    // L'exemption de liste blanche se traduit aussi en portée.
    assert_eq!(
        route_honeypot(route(MessageScope::Enforce), author),
        Some(HoneypotPlan::Quarantine)
    );
}

#[test]
fn a_trapped_message_stops_the_pipeline_only_when_acted_upon() {
    let author = member(Some(Permissions::SEND_MESSAGES));
    // `Some` : le pipeline s'arrête, aucun filtre de contenu ne suit.
    assert!(route_honeypot(route(MessageScope::Enforce), author).is_some());
    assert_eq!(
        route_honeypot(route(MessageScope::Enforce), member(None)),
        Some(HoneypotPlan::DeleteOnly)
    );
    // Exempté, module désactivé ou modification : le pipeline continue.
    assert_eq!(
        route_honeypot(
            route(MessageScope::Enforce),
            member(Some(Permissions::ADMINISTRATOR))
        ),
        None
    );
    let disabled = HoneypotRoute {
        enabled_modules: ModuleSet::empty(),
        ..route(MessageScope::Enforce)
    };
    assert_eq!(route_honeypot(disabled, author), None);
    let edited = HoneypotRoute {
        created: false,
        ..route(MessageScope::Enforce)
    };
    assert_eq!(route_honeypot(edited, author), None);
}

#[test]
fn quarantine_removes_dangerous_roles_without_timeout_fallback() {
    assert_eq!(
        HONEYPOT_QUARANTINE,
        QuarantineRequest {
            remove_dangerous_roles: true,
            allow_timeout_fallback: false,
            ..QuarantineRequest::ROLE_ONLY
        }
    );
    let reason = honeypot_audit_reason();
    assert_eq!(
        reason,
        "FoxSecura Honeypot: message in the honeypot channel"
    );
    assert!(is_foxsecura_audit_reason(&reason));
}

fn message() -> GuildMessage {
    GuildMessage {
        guild_id: 1,
        channel_id: TRAP,
        message_id: 555,
        author_id: 42,
        timestamp: std::time::Duration::ZERO,
    }
}

#[test]
fn incident_is_critical_member_type_with_a_neutralized_excerpt() {
    let quarantined = QuarantineOutcome {
        dangerous_roles: Some(DangerousRoleRemoval {
            removed: vec![7],
            ..DangerousRoleRemoval::default()
        }),
        role: Some(RoleStatus::Applied),
        channel_lock: Some(ChannelLockSummary {
            locked: 2,
            ..ChannelLockSummary::default()
        }),
        ..QuarantineOutcome::default()
    };
    let content = "@everyone free nitro `x` https://evil.example";
    let incident = honeypot_incident(
        Language::French,
        &message(),
        content,
        &DeleteMessageOutcome::Deleted,
        Some(&quarantined),
    );

    assert_eq!(incident.module, "honeypot");
    assert_eq!(incident.log_type, LogType::Member);
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert_eq!(incident.validate(), Ok(()));
    assert_eq!(
        incident.affected_resource.as_ref().unwrap().resource_type,
        AffectedResourceType::Member
    );
    let actions: Vec<_> = incident
        .actions
        .iter()
        .map(|action| action.action)
        .collect();
    assert_eq!(
        actions,
        [
            ActionCode::DeleteMessage,
            ActionCode::RemoveDangerousRoles,
            ActionCode::QuarantineMember,
            ActionCode::LockMemberChannels,
        ]
    );
    assert!(incident.evidence.contains(&SecurityEvidence::Content {
        excerpt: content.to_owned()
    }));

    // Rendu du log : extrait en code en ligne, aucune mention active.
    let rendered = format_security_log_message(Language::French, &incident);
    assert!(
        rendered.contains("`@everyone free nitro ˋxˋ https://evil.example`"),
        "{rendered}"
    );
    assert!(
        incident
            .recommendation
            .as_deref()
            .unwrap()
            .contains("non rendus")
    );
}

#[test]
fn unknown_permissions_incident_records_a_skipped_quarantine() {
    let incident = honeypot_incident(
        Language::English,
        &message(),
        "hello",
        &DeleteMessageOutcome::NotDeletable,
        None,
    );
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert_eq!(incident.validate(), Ok(()));
    let quarantine = &incident.actions[1];
    assert_eq!(quarantine.action, ActionCode::QuarantineMember);
    assert_eq!(quarantine.status, ActionStatus::Skipped);
    assert_eq!(quarantine.details.as_deref(), Some("permissions_unknown"));
    assert!(
        incident
            .recommendation
            .as_deref()
            .unwrap()
            .contains("false positive")
    );
}
