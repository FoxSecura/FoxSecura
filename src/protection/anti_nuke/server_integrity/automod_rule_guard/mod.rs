// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protection::anti_nuke::{ExecutorDecision, evaluate_executor_action};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoModRuleChange {
    Create,
    Update,
    Delete,
}

pub fn detect_managed_rule_change(
    enabled: bool,
    rule_is_managed_by_foxsecura: bool,
    _change: AutoModRuleChange,
    executor_resolved: bool,
    executor_exempt: bool,
) -> ExecutorDecision {
    if !rule_is_managed_by_foxsecura {
        return ExecutorDecision::Ignore;
    }

    evaluate_executor_action(enabled, executor_resolved, executor_exempt)
}
