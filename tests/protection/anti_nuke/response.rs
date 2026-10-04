// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use foxsecura::i18n::Language;
use foxsecura::logs::{
    ActionCode, ActionStatus, AffectedResourceType, FailureCode, LogSeverity, LogType,
    SecurityEvidence, ThresholdUnit, format_security_log_message,
};
use foxsecura::protection::anti_nuke::audit::NukeAction;
use foxsecura::protection::anti_nuke::burst::NukeBurst;
use foxsecura::protection::anti_nuke::response::{
    ANTI_NUKE_QUARANTINE, AuthorFacts, Containment, NukeIncidentInput, NukeResponsePlan,
    anti_nuke_audit_reason, log_type, nuke_incident, plan_response, sends_panic_signal,
};
use foxsecura::protection::quarantine::{DangerousRoleRemoval, QuarantineOutcome, RoleStatus};
use foxsecura::protection::shared::is_foxsecura_audit_reason;

const GUILD: u64 = 1;
const AUTHOR: u64 = 10;
const LISTED_ROLE: u64 = 20;
const QUARANTINE_ROLE: u64 = 30;

fn author(user_listed: bool, roles: Option<&[u64]>) -> AuthorFacts<'_> {
    AuthorFacts {
        user_listed,
        whitelist_roles: &[LISTED_ROLE, QUARANTINE_ROLE],
        ignored_roles: &[QUARANTINE_ROLE],
        member_roles: roles,
    }
}

fn burst(action: NukeAction) -> NukeBurst {
    NukeBurst {
        action,
        count: 3,
        threshold: 3,
        window: Duration::from_secs(20),
    }
}

fn input(action: NukeAction) -> NukeIncidentInput<'static> {
    NukeIncidentInput {
        guild_id: GUILD,
        author_id: AUTHOR,
        burst: burst(action),
        target_id: Some(99),
        target_name: None,
    }
}

fn quarantined() -> QuarantineOutcome {
    QuarantineOutcome {
        dangerous_roles: Some(DangerousRoleRemoval {
            removed: vec![77],
            ..DangerousRoleRemoval::default()
        }),
        role: Some(RoleStatus::Applied),
        ..QuarantineOutcome::default()
    }
}

#[test]
fn whitelisted_authors_are_never_contained() {
    // Par identifiant, même introuvable ; par rôle listé.
    assert_eq!(
        plan_response(author(true, None)),
        NukeResponsePlan::IgnoreExempt
    );
    assert_eq!(
        plan_response(author(true, Some(&[5]))),
        NukeResponsePlan::IgnoreExempt
    );
    assert_eq!(
        plan_response(author(false, Some(&[5, LISTED_ROLE]))),
        NukeResponsePlan::IgnoreExempt
    );
}

#[test]
fn the_quarantine_role_never_exempts_an_author() {
    assert_eq!(
        plan_response(author(false, Some(&[QUARANTINE_ROLE]))),
        NukeResponsePlan::Quarantine
    );
}

#[test]
fn other_authors_are_quarantined_and_missing_ones_are_unavailable() {
    assert_eq!(
        plan_response(author(false, Some(&[]))),
        NukeResponsePlan::Quarantine
    );
    assert_eq!(
        plan_response(author(false, None)),
        NukeResponsePlan::AuthorUnavailable
    );
}

#[test]
fn quarantine_removes_dangerous_roles_without_timeout_fallback() {
    const { assert!(ANTI_NUKE_QUARANTINE.remove_dangerous_roles) };
    const { assert!(!ANTI_NUKE_QUARANTINE.allow_timeout_fallback) };
    let reason = anti_nuke_audit_reason(NukeAction::Ban);
    assert_eq!(reason, "FoxSecura Anti-Nuke: burst of anti_mass_ban");
    // Le socle reconnaît ses propres sanctions.
    assert!(is_foxsecura_audit_reason(&reason));
}

#[test]
fn an_exempt_author_gets_visibility_without_containment() {
    let incident = nuke_incident(
        Language::French,
        input(NukeAction::Ban),
        &Containment::Exempt,
    );

    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(incident.actions.len(), 1);
    assert_eq!(incident.actions[0].action, ActionCode::IgnoreExemptMember);
    assert_eq!(incident.actions[0].status, ActionStatus::Skipped);
    assert!(!Containment::Exempt.contained());
    assert!(!sends_panic_signal(&incident));
    assert!(incident.validate().is_ok());
}

#[test]
fn a_missing_author_is_reported_as_executor_unavailable() {
    let containment = Containment::AuthorUnavailable {
        details: "member_missing".to_owned(),
    };
    let incident = nuke_incident(Language::English, input(NukeAction::Kick), &containment);

    assert_eq!(incident.severity, LogSeverity::Critical);
    let action = &incident.actions[0];
    assert_eq!(action.action, ActionCode::QuarantineMember);
    assert_eq!(action.status, ActionStatus::Skipped);
    assert_eq!(action.failure_code, Some(FailureCode::ExecutorUnavailable));
    assert_eq!(action.details.as_deref(), Some("member_missing"));
    assert!(!containment.contained());
    // L'attaque reste en cours : le mode panique est prévenu.
    assert!(sends_panic_signal(&incident));
}

#[test]
fn a_contained_burst_is_a_critical_incident_with_its_evidence() {
    let containment = Containment::Quarantine(quarantined());
    let incident = nuke_incident(Language::French, input(NukeAction::Ban), &containment);

    assert!(containment.contained());
    assert_eq!(incident.module, "anti_mass_ban");
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert_eq!(incident.log_type, LogType::Member);
    assert_eq!(incident.actor.as_ref().unwrap().user_id, AUTHOR.to_string());
    assert!(incident.evidence.contains(&SecurityEvidence::Threshold {
        observed: 3,
        threshold: 3,
        window_seconds: Some(20),
        unit: ThresholdUnit::Actions,
    }));
    assert!(incident.evidence.iter().any(|evidence| matches!(
        evidence,
        SecurityEvidence::Text { value, .. } if value == "77"
    )));
    let actions: Vec<_> = incident
        .actions
        .iter()
        .map(|action| action.action)
        .collect();
    assert_eq!(
        actions,
        [
            ActionCode::RemoveDangerousRoles,
            ActionCode::QuarantineMember
        ]
    );
    assert!(
        incident
            .recommendation
            .as_deref()
            .unwrap()
            .contains("permissions")
    );
    assert!(sends_panic_signal(&incident));
    assert!(incident.validate().is_ok());
}

#[test]
fn a_quarantine_that_could_not_apply_the_role_is_not_containment() {
    let outcome = QuarantineOutcome {
        role: Some(RoleStatus::NotConfigured),
        ..QuarantineOutcome::default()
    };
    // Sans repli timeout : aucun timeout n'est tenté.
    assert!(outcome.timeout.is_none());
    let containment = Containment::Quarantine(outcome);
    assert!(!containment.contained());
    let incident = nuke_incident(Language::French, input(NukeAction::Ban), &containment);
    assert_eq!(incident.severity, LogSeverity::Critical);
}

#[test]
fn each_module_logs_to_its_type() {
    let expected = [
        (NukeAction::Ban, LogType::Member),
        (NukeAction::Kick, LogType::Member),
        (NukeAction::Timeout, LogType::Member),
        (NukeAction::Unban, LogType::Member),
        (NukeAction::ChannelCreate, LogType::Server),
        (NukeAction::RoleCreate, LogType::Role),
        (NukeAction::EmojiSticker, LogType::Server),
        (NukeAction::RoleGrant, LogType::Role),
    ];
    for (action, log) in expected {
        assert_eq!(log_type(action), log, "{action:?}");
        let incident = nuke_incident(
            Language::German,
            input(action),
            &Containment::Quarantine(quarantined()),
        );
        assert_eq!(incident.log_type, log);
        assert_eq!(incident.module, action.module().key());
    }
    let incident = nuke_incident(
        Language::French,
        input(NukeAction::ChannelCreate),
        &Containment::Exempt,
    );
    assert_eq!(
        incident.affected_resource.unwrap().resource_type,
        AffectedResourceType::Channel
    );
}

#[test]
fn the_target_name_is_rendered_as_an_inert_literal() {
    let mut input = input(NukeAction::ChannelCreate);
    input.target_name = Some("raid `@everyone` <@&1> [x](https://evil.example)\nfaux");
    let incident = nuke_incident(
        Language::French,
        input,
        &Containment::Quarantine(quarantined()),
    );
    let message = format_security_log_message(Language::French, &incident);
    let line = message
        .lines()
        .find(|line| line.contains("Dernière cible"))
        .unwrap();

    // Une seule ligne, dans un code en ligne que la valeur ne peut pas fermer.
    assert!(line.ends_with("(99)`"), "{line}");
    assert_eq!(line.matches('`').count(), 2, "{line}");
    assert!(!message.contains("\nfaux"));
}
