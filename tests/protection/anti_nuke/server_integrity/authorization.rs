// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude::Permissions;

use foxsecura::protection::anti_nuke::{
    ExecutorDecision,
    server_integrity::{
        anti_permissions::detect_permission_escalation,
        anti_server_edit::{ServerField, detect_server_edit},
        anti_vanity_change::detect_vanity_change,
        automod_rule_guard::{AutoModRuleChange, detect_managed_rule_change},
    },
};

#[test]
fn dangerous_permission_addition_requires_enforcement() {
    assert_eq!(
        detect_permission_escalation(
            true,
            Permissions::empty(),
            Permissions::ADMINISTRATOR,
            false,
            false,
            true,
            false,
        ),
        ExecutorDecision::Enforce
    );

    assert_eq!(
        detect_permission_escalation(
            true,
            Permissions::ADMINISTRATOR,
            Permissions::ADMINISTRATOR,
            false,
            false,
            true,
            false,
        ),
        ExecutorDecision::Ignore
    );
}

#[test]
fn server_vanity_and_automod_changes_follow_executor_policy() {
    assert_eq!(
        detect_server_edit(true, &[ServerField::Name], false, false).decision,
        ExecutorDecision::Alert
    );
    assert_eq!(
        detect_vanity_change(true, Some("old"), Some("new"), true, false),
        ExecutorDecision::Enforce
    );
    assert_eq!(
        detect_managed_rule_change(
            true,
            true,
            AutoModRuleChange::Delete,
            true,
            false,
        ),
        ExecutorDecision::Enforce
    );
    assert_eq!(
        detect_managed_rule_change(
            true,
            false,
            AutoModRuleChange::Delete,
            true,
            false,
        ),
        ExecutorDecision::Ignore
    );
}
