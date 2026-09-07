// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protection::ai_moderation::{AiClassification, AiModerationCategory, AiSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiModerationAction {
    None,
    Log,
    Flag,
    Delete,
    DeleteFlag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiRuleSettings {
    pub minimum_severity: AiSeverity,
    pub delete_severity: AiSeverity,
    pub alert_severity: AiSeverity,
    pub enabled_categories: Vec<AiModerationCategory>,
}

impl AiRuleSettings {
    pub fn new(enabled_categories: Vec<AiModerationCategory>) -> Self {
        Self {
            minimum_severity: AiSeverity::Medium,
            delete_severity: AiSeverity::High,
            alert_severity: AiSeverity::High,
            enabled_categories,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiDecision {
    pub action: AiModerationAction,
    pub severity: AiSeverity,
    pub categories: Vec<AiModerationCategory>,
    pub alert_moderators: bool,
}

pub const fn is_at_least_severity(severity: AiSeverity, floor: AiSeverity) -> bool {
    severity as u8 >= floor as u8
}

pub fn decide_ai_moderation_action(
    classification: &AiClassification,
    settings: &AiRuleSettings,
) -> AiDecision {
    let no_action = || AiDecision {
        action: AiModerationAction::None,
        severity: classification.severity,
        categories: Vec::new(),
        alert_moderators: false,
    };

    if !classification.violation {
        return no_action();
    }

    let mut applicable = Vec::new();
    for category in &classification.categories {
        if settings.enabled_categories.contains(category) && !applicable.contains(category) {
            applicable.push(*category);
        }
    }

    if applicable.is_empty() {
        return no_action();
    }

    if !is_at_least_severity(classification.severity, settings.minimum_severity) {
        return AiDecision {
            action: AiModerationAction::Log,
            severity: classification.severity,
            categories: applicable,
            alert_moderators: false,
        };
    }

    let should_delete = is_at_least_severity(classification.severity, settings.delete_severity);
    let should_alert = is_at_least_severity(classification.severity, settings.alert_severity);

    let action = match (should_delete, should_alert) {
        (true, true) => AiModerationAction::DeleteFlag,
        (true, false) => AiModerationAction::Delete,
        (false, true) => AiModerationAction::Flag,
        (false, false) => AiModerationAction::Log,
    };

    AiDecision {
        action,
        severity: classification.severity,
        categories: applicable,
        alert_moderators: should_alert,
    }
}
