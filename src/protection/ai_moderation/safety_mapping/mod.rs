// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    AiClassification, AiModerationCategory, AiSafetyTaxonomy, AiSafetyVerdict, AiSeverity,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedSafetyVerdict {
    pub classification: AiClassification,
    pub unmapped_labels: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct LabelMapping {
    category: AiModerationCategory,
    severity: AiSeverity,
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
        severity = severity.max(mapping.severity);
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
    if !matches!(taxonomy, AiSafetyTaxonomy::OpenAiModeration) {
        return None;
    }

    match label.to_ascii_lowercase().as_str() {
        "harassment" => Some(LabelMapping {
            category: AiModerationCategory::Toxicity,
            severity: AiSeverity::Medium,
        }),
        "harassment/threatening" => Some(LabelMapping {
            category: AiModerationCategory::Threats,
            severity: AiSeverity::High,
        }),
        "hate" | "hate/threatening" => Some(LabelMapping {
            category: AiModerationCategory::HateSpeech,
            severity: AiSeverity::High,
        }),
        "illicit" => Some(LabelMapping {
            category: AiModerationCategory::OtherHarmful,
            severity: AiSeverity::Medium,
        }),
        "illicit/violent" => Some(LabelMapping {
            category: AiModerationCategory::OtherHarmful,
            severity: AiSeverity::High,
        }),
        "self-harm" | "self-harm/intent" => Some(LabelMapping {
            category: AiModerationCategory::DangerousBehavior,
            severity: AiSeverity::Medium,
        }),
        "self-harm/instructions" => Some(LabelMapping {
            category: AiModerationCategory::DangerousBehavior,
            severity: AiSeverity::Critical,
        }),
        "sexual" => Some(LabelMapping {
            category: AiModerationCategory::SexualContent,
            severity: AiSeverity::Medium,
        }),
        "sexual/minors" => Some(LabelMapping {
            category: AiModerationCategory::SexualContent,
            severity: AiSeverity::Critical,
        }),
        "violence" => Some(LabelMapping {
            category: AiModerationCategory::OtherHarmful,
            severity: AiSeverity::Medium,
        }),
        "violence/graphic" => Some(LabelMapping {
            category: AiModerationCategory::OtherHarmful,
            severity: AiSeverity::High,
        }),
        _ => None,
    }
}
