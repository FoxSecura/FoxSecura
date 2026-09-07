// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::{AiModerationCategory, AiSeverity, rules::{AiDecision, AiModerationAction}};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiActionPlan {
    pub log: bool,
    pub delete_message: bool,
    pub alert_moderators: bool,
    pub categories: Vec<AiModerationCategory>,
    pub severity: AiSeverity,
}

pub fn plan_action(decision: &AiDecision) -> AiActionPlan {
    AiActionPlan {
        log: decision.action != AiModerationAction::None,
        delete_message: matches!(
            decision.action,
            AiModerationAction::Delete | AiModerationAction::DeleteFlag
        ),
        alert_moderators: decision.alert_moderators,
        categories: decision.categories.clone(),
        severity: decision.severity,
    }
}
