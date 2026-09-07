// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protection::anti_nuke::{ExecutorDecision, evaluate_executor_action};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerField {
    Name,
    Icon,
    Banner,
    Description,
    VerificationLevel,
    DefaultNotifications,
    ExplicitContentFilter,
    AfkChannel,
    SystemChannel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerEditResult {
    pub decision: ExecutorDecision,
    pub changed_fields: usize,
}

pub fn detect_server_edit(
    enabled: bool,
    changed_fields: &[ServerField],
    executor_resolved: bool,
    executor_exempt: bool,
) -> ServerEditResult {
    if changed_fields.is_empty() {
        return ServerEditResult {
            decision: ExecutorDecision::Ignore,
            changed_fields: 0,
        };
    }

    ServerEditResult {
        decision: evaluate_executor_action(enabled, executor_resolved, executor_exempt),
        changed_fields: changed_fields.len(),
    }
}
