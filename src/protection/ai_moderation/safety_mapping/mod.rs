// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    AiClassification, AiModerationCategory, AiSafetyTaxonomy, AiSafetyVerdict, AiSeverity,
    policy::baseline_severity,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedSafetyVerdict {
    pub classification: AiClassification,
    pub unmapped_labels: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct LabelMapping {
    category: AiModerationCategory,
    max_severity: Option<AiSeverity>,
    inferred: bool,
}

pub fn map_safety_verdict(verdict: &AiSafetyVerdict) -> MappedSafetyVerdict {
    if !verdict.unsafe_content {
        return MappedSafetyVerdict {
            classification: AiClassification::clean(None),
            unmapped_labels: Vec::new(),
        };
    }

    let mut categories = Vec::new();
    let mut severity = AiSeverity::Low;
    let mut unmapped_labels = Vec::new();

    for label in &verdict.labels {
        let Some(mapping) = mapping_for(verdict.taxonomy, label) else {
            unmapped_labels.push(label.clone());
            continue;
        };
        if !categories.contains(&mapping.category) {
            categories.push(mapping.category);
        }
        severity = severity.max(resolve_severity(mapping));
    }

    let classification = if categories.is_empty() {
        AiClassification::clean(None)
    } else {
        AiClassification {
            violation: true,
            categories,
            severity,
            recommended_action: None,
            reason: None,
        }
    };

    MappedSafetyVerdict {
        classification,
        unmapped_labels,
    }
}

fn mapping_for(taxonomy: AiSafetyTaxonomy, label: &str) -> Option<LabelMapping> {
    if !matches!(taxonomy, AiSafetyTaxonomy::NemotronContentSafety) {
        return None;
    }

    let normalized = normalize_label(label);
    match normalized.as_str() {
        "threat" => Some(LabelMapping { category: AiModerationCategory::Threats, max_severity: None, inferred: false }),
        "harassment" => Some(LabelMapping { category: AiModerationCategory::Toxicity, max_severity: None, inferred: false }),
        "pii privacy" => Some(LabelMapping { category: AiModerationCategory::Doxxing, max_severity: Some(AiSeverity::Medium), inferred: false }),
        "hate identity hate" => Some(LabelMapping { category: AiModerationCategory::HateSpeech, max_severity: None, inferred: true }),
        "sexual" | "sexual minor" => Some(LabelMapping { category: AiModerationCategory::SexualContent, max_severity: None, inferred: true }),
        "suicide and self harm" => Some(LabelMapping { category: AiModerationCategory::DangerousBehavior, max_severity: Some(AiSeverity::High), inferred: true }),
        _ => None,
    }
}

fn normalize_label(label: &str) -> String {
    let mut normalized = String::new();
    let mut pending_space = false;
    for character in label.to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            if pending_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push(character);
            pending_space = false;
        } else {
            pending_space = true;
        }
    }
    normalized.trim().to_owned()
}

fn resolve_severity(mapping: LabelMapping) -> AiSeverity {
    let mut severity = baseline_severity(mapping.category);
    if mapping.inferred {
        severity = severity.min(AiSeverity::High);
    }
    if let Some(maximum) = mapping.max_severity {
        severity = severity.min(maximum);
    }
    severity
}
