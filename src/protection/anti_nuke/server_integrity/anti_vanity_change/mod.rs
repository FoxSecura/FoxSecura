// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protection::anti_nuke::{ExecutorDecision, evaluate_executor_action};

pub fn detect_vanity_change(
    enabled: bool,
    old_code: Option<&str>,
    new_code: Option<&str>,
    executor_resolved: bool,
    executor_exempt: bool,
) -> ExecutorDecision {
    if old_code == new_code {
        return ExecutorDecision::Ignore;
    }

    evaluate_executor_action(enabled, executor_resolved, executor_exempt)
}
