// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protection::anti_nuke::{ExecutorDecision, evaluate_executor_action};

pub const fn detect_channel_delete(
    enabled: bool,
    executor_resolved: bool,
    executor_exempt: bool,
) -> ExecutorDecision {
    evaluate_executor_action(enabled, executor_resolved, executor_exempt)
}
