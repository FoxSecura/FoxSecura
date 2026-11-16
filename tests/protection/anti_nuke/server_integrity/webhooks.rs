// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::i18n::Language;
use foxsecura::logs::{ActionCode, ActionStatus, FailureCode, LogSeverity};
use foxsecura::protection::anti_nuke::audit::AuditAction;
use foxsecura::protection::anti_nuke::server_integrity::outcome::IntegrityActionResult;
use foxsecura::protection::anti_nuke::server_integrity::webhook_guard::{
    WebhookChange, WebhookIncidentInput, WebhookPlan, missing_manage_webhooks,
    plan_webhook_response, webhook_incident, webhook_removal_reason,
};
use foxsecura::protection::quarantine::DiscordFailure;
use foxsecura::protection::shared::is_foxsecura_audit_reason;

const BOT: u64 = 3;
const OWNER: u64 = 2;
const AUTHOR: u64 = 77;

#[test]
fn audit_actions_map_to_webhook_changes() {
    assert_eq!(
        WebhookChange::from_audit(AuditAction::WebhookCreate),
        Some(WebhookChange::Created)
    );
    assert_eq!(
        WebhookChange::from_audit(AuditAction::WebhookUpdate),
        Some(WebhookChange::Updated)
    );
    assert_eq!(
        WebhookChange::from_audit(AuditAction::WebhookDelete),
        Some(WebhookChange::Deleted)
    );
    assert_eq!(WebhookChange::from_audit(AuditAction::RoleUpdate), None);
}

#[test]
fn unauthorized_creation_or_update_removes_the_webhook() {
    for change in [WebhookChange::Created, WebhookChange::Updated] {
        assert_eq!(
            plan_webhook_response(change, AUTHOR, BOT, Some(OWNER), false),
            WebhookPlan::Remove
        );
    }
    assert_eq!(
        plan_webhook_response(WebhookChange::Deleted, AUTHOR, BOT, Some(OWNER), false),
        WebhookPlan::Alert
    );
}

#[test]
fn bot_owner_and_whitelist_are_left_alone() {
    for change in [
        WebhookChange::Created,
        WebhookChange::Updated,
        WebhookChange::Deleted,
    ] {
        assert_eq!(
            plan_webhook_response(change, BOT, BOT, Some(OWNER), false),
            WebhookPlan::Ignore
        );
        assert_eq!(
            plan_webhook_response(change, OWNER, BOT, Some(OWNER), false),
            WebhookPlan::Ignore
        );
        assert_eq!(
            plan_webhook_response(change, AUTHOR, BOT, Some(OWNER), true),
            WebhookPlan::Ignore
        );
    }
}

fn input(change: WebhookChange) -> WebhookIncidentInput<'static> {
    WebhookIncidentInput {
        change,
        author_id: AUTHOR,
        webhook_id: Some(900),
        webhook_name: Some("Spidey Bot"),
    }
}

#[test]
fn removed_webhook_is_a_warning() {
    let incident = webhook_incident(
        Language::French,
        input(WebhookChange::Created),
        Some(&IntegrityActionResult::Applied),
    );
    assert!(incident.validate().is_ok());
    assert_eq!(incident.module, "webhook_watch");
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(incident.actions[0].action, ActionCode::RemoveWebhook);
    assert_eq!(incident.actions[0].status, ActionStatus::Success);
}

#[test]
fn failed_removal_is_critical_but_a_vanished_webhook_is_not() {
    let forbidden = IntegrityActionResult::from_failure(&DiscordFailure::new(
        Some(403),
        Some(50013),
        "Missing Permissions",
    ));
    let incident = webhook_incident(
        Language::French,
        input(WebhookChange::Updated),
        Some(&forbidden),
    );
    assert_eq!(incident.severity, LogSeverity::Critical);
    assert_eq!(incident.actions[0].status, ActionStatus::Failed);
    assert_eq!(
        incident.actions[0].failure_code,
        Some(FailureCode::MissingPermission)
    );

    let missing_permission = webhook_incident(
        Language::French,
        input(WebhookChange::Created),
        Some(&missing_manage_webhooks()),
    );
    assert_eq!(missing_permission.severity, LogSeverity::Critical);

    // Introuvable : déjà supprimé, rien ne reste actif.
    let vanished = IntegrityActionResult::from_failure(&DiscordFailure::new(
        Some(404),
        Some(10015),
        "Unknown Webhook",
    ));
    let incident = webhook_incident(
        Language::French,
        input(WebhookChange::Created),
        Some(&vanished),
    );
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(incident.actions[0].status, ActionStatus::Skipped);
    assert_eq!(
        incident.actions[0].failure_code,
        Some(FailureCode::ResourceMissing)
    );
}

#[test]
fn deletion_is_an_alert_only() {
    let incident = webhook_incident(Language::French, input(WebhookChange::Deleted), None);
    assert_eq!(incident.severity, LogSeverity::Warning);
    assert_eq!(incident.actions.len(), 1);
    assert_eq!(incident.actions[0].action, ActionCode::RecordAlert);
}

#[test]
fn removal_reason_follows_the_foxsecura_convention() {
    // La suppression du bot est elle-même une entrée `WebhookDelete` écartée
    // par le socle (bot, raison FoxSecura).
    assert!(is_foxsecura_audit_reason(&webhook_removal_reason()));
}
