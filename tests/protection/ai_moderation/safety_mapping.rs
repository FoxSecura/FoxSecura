// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiModerationCategory, AiSafetyTaxonomy, AiSafetyVerdict, AiSeverity,
    safety_mapping::map_safety_verdict,
};

fn verdict(labels: &[&str]) -> AiSafetyVerdict {
    AiSafetyVerdict {
        taxonomy: AiSafetyTaxonomy::NemotronContentSafety,
        unsafe_content: true,
        labels: labels.iter().map(|label| (*label).to_owned()).collect(),
    }
}

#[test]
fn maps_observed_threat_label() {
    let mapped = map_safety_verdict(&verdict(&["Threat"]));
    assert_eq!(mapped.classification.categories, vec![AiModerationCategory::Threats]);
    assert_eq!(mapped.classification.severity, AiSeverity::High);
}

#[test]
fn privacy_label_is_capped_below_delete_threshold() {
    let mapped = map_safety_verdict(&verdict(&["PII/Privacy"]));
    assert_eq!(mapped.classification.categories, vec![AiModerationCategory::Doxxing]);
    assert_eq!(mapped.classification.severity, AiSeverity::Medium);
}

#[test]
fn self_harm_label_is_capped_at_high() {
    let mapped = map_safety_verdict(&verdict(&["Suicide and Self Harm"]));
    assert_eq!(mapped.classification.severity, AiSeverity::High);
}

#[test]
fn unknown_labels_never_create_a_violation() {
    let mapped = map_safety_verdict(&verdict(&["Unknown Label"]));
    assert!(!mapped.classification.violation);
    assert_eq!(mapped.unmapped_labels, vec!["Unknown Label"]);
}
