// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use poise::serenity_prelude::Permissions;

use crate::protection::anti_nuke::{ExecutorDecision, evaluate_executor_action};

use super::server_guard::detect_dangerous_permission_change;

pub fn detect_permission_escalation(
    enabled: bool,
    old_permissions: Permissions,
    new_permissions: Permissions,
    role_is_everyone: bool,
    role_is_managed: bool,
    executor_resolved: bool,
    executor_exempt: bool,
) -> ExecutorDecision {
    if role_is_everyone
        || role_is_managed
        || !detect_dangerous_permission_change(old_permissions, new_permissions)
    {
        return ExecutorDecision::Ignore;
    }

    evaluate_executor_action(enabled, executor_resolved, executor_exempt)
}
