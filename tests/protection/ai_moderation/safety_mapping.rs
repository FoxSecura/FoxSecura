// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiModerationCategory, AiSafetyTaxonomy, AiSafetyVerdict, AiSeverity,
    safety_mapping::map_safety_verdict,
};

fn verdict(labels: &[&str]) -> AiSafetyVerdict {
    AiSafetyVerdict {
        taxonomy: AiSafetyTaxonomy::OpenAiModeration,
        unsafe_content: true,
        labels: labels.iter().map(|label| (*label).to_owned()).collect(),
    }
}

#[test]
fn maps_openai_threatening_harassment() {
    let mapped = map_safety_verdict(&verdict(&["harassment/threatening"]));
    assert_eq!(mapped.classification.categories, vec![AiModerationCategory::Threats]);
    assert_eq!(mapped.classification.severity, AiSeverity::High);
}

#[test]
fn self_harm_intent_is_kept_below_delete_threshold() {
    let mapped = map_safety_verdict(&verdict(&["self-harm/intent"]));
    assert_eq!(mapped.classification.categories, vec![AiModerationCategory::DangerousBehavior]);
    assert_eq!(mapped.classification.severity, AiSeverity::Medium);
}

#[test]
fn self_harm_instructions_are_critical() {
    let mapped = map_safety_verdict(&verdict(&["self-harm/instructions"]));
    assert_eq!(mapped.classification.severity, AiSeverity::Critical);
}

#[test]
fn sexual_content_involving_minors_is_critical() {
    let mapped = map_safety_verdict(&verdict(&["sexual/minors"]));
    assert_eq!(mapped.classification.categories, vec![AiModerationCategory::SexualContent]);
    assert_eq!(mapped.classification.severity, AiSeverity::Critical);
}

#[test]
fn unknown_labels_never_create_a_violation() {
    let mapped = map_safety_verdict(&verdict(&["future-category"]));
    assert!(!mapped.classification.violation);
    assert_eq!(mapped.unmapped_labels, vec!["future-category"]);
}
