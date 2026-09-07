// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiClassification, AiModerationCategory, AiSeverity,
    rules::{AiModerationAction, AiRuleSettings, decide_ai_moderation_action},
};

fn classification(
    violation: bool,
    category: AiModerationCategory,
    severity: AiSeverity,
) -> AiClassification {
    AiClassification {
        violation,
        categories: vec![category],
        severity,
        recommended_action: None,
        reason: None,
    }
}

#[test]
fn clean_classification_never_acts() {
    let settings = AiRuleSettings::new(vec![AiModerationCategory::Threats]);
    let result = decide_ai_moderation_action(
        &classification(false, AiModerationCategory::Threats, AiSeverity::Critical),
        &settings,
    );

    assert_eq!(result.action, AiModerationAction::None);
}

#[test]
fn disabled_category_never_acts() {
    let settings = AiRuleSettings::new(vec![AiModerationCategory::Threats]);
    let result = decide_ai_moderation_action(
        &classification(true, AiModerationCategory::Insults, AiSeverity::Critical),
        &settings,
    );

    assert_eq!(result.action, AiModerationAction::None);
}

#[test]
fn below_minimum_severity_is_only_logged() {
    let settings = AiRuleSettings::new(vec![AiModerationCategory::Insults]);
    let result = decide_ai_moderation_action(
        &classification(true, AiModerationCategory::Insults, AiSeverity::Low),
        &settings,
    );

    assert_eq!(result.action, AiModerationAction::Log);
    assert!(!result.alert_moderators);
}

#[test]
fn high_severity_is_deleted_and_flagged_by_default() {
    let settings = AiRuleSettings::new(vec![AiModerationCategory::Threats]);
    let result = decide_ai_moderation_action(
        &classification(true, AiModerationCategory::Threats, AiSeverity::High),
        &settings,
    );

    assert_eq!(result.action, AiModerationAction::DeleteFlag);
    assert!(result.alert_moderators);
}

#[test]
fn alert_can_happen_before_deletion() {
    let mut settings = AiRuleSettings::new(vec![AiModerationCategory::Intimidation]);
    settings.alert_severity = AiSeverity::Medium;
    settings.delete_severity = AiSeverity::Critical;

    let result = decide_ai_moderation_action(
        &classification(
            true,
            AiModerationCategory::Intimidation,
            AiSeverity::Medium,
        ),
        &settings,
    );

    assert_eq!(result.action, AiModerationAction::Flag);
    assert!(result.alert_moderators);
}
