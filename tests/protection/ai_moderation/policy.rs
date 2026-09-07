// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiModerationCategory, AiSeverity,
    policy::{baseline_severity, build_policy_prompt, undefined_policy_categories},
};

#[test]
fn every_category_has_policy_definition() {
    assert!(undefined_policy_categories().is_empty());
}

#[test]
fn dangerous_behavior_has_critical_baseline() {
    assert_eq!(baseline_severity(AiModerationCategory::DangerousBehavior), AiSeverity::Critical);
}

#[test]
fn prompt_contains_only_enabled_categories() {
    let prompt = build_policy_prompt(&[AiModerationCategory::Threats]);
    assert!(prompt.contains("THREATS"));
    assert!(!prompt.contains("SEXUAL_EXPLICIT"));
}
