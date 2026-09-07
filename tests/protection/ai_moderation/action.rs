// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiModerationCategory, AiSeverity,
    action::plan_action,
    rules::{AiDecision, AiModerationAction},
};

#[test]
fn delete_flag_becomes_delete_and_alert_plan() {
    let plan = plan_action(&AiDecision {
        action: AiModerationAction::DeleteFlag,
        severity: AiSeverity::High,
        categories: vec![AiModerationCategory::Threats],
        alert_moderators: true,
    });
    assert!(plan.log);
    assert!(plan.delete_message);
    assert!(plan.alert_moderators);
}
