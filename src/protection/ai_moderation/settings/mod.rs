// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::{AiModerationCategory, AiSeverity, rules::AiRuleSettings};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiModerationSettings {
    pub enabled: bool,
    pub enabled_categories: Vec<AiModerationCategory>,
    pub minimum_severity: AiSeverity,
    pub delete_severity: AiSeverity,
    pub alert_severity: AiSeverity,
    pub ignored_channels: Vec<String>,
    pub ignored_roles: Vec<String>,
    pub timeout_ms: u64,
}

impl Default for AiModerationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            enabled_categories: AiModerationCategory::ALL.to_vec(),
            minimum_severity: AiSeverity::Medium,
            delete_severity: AiSeverity::High,
            alert_severity: AiSeverity::High,
            ignored_channels: Vec::new(),
            ignored_roles: Vec::new(),
            timeout_ms: 5_000,
        }
    }
}

impl AiModerationSettings {
    pub fn rule_settings(&self) -> AiRuleSettings {
        AiRuleSettings {
            minimum_severity: self.minimum_severity,
            delete_severity: self.delete_severity,
            alert_severity: self.alert_severity,
            enabled_categories: self.enabled_categories.clone(),
        }
    }
}
