// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protection::ai_moderation::{
    AiFailureReason, AiSafetyTaxonomy, AiSafetyVerdict,
};

pub fn parse_nemotron_safety_verdict(raw: &str) -> Result<AiSafetyVerdict, AiFailureReason> {
    let lines = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Err(AiFailureReason::EmptyResponse);
    }

    let mut safety: Option<String> = None;
    let mut labels = Vec::<String>::new();

    for line in lines {
        let Some((label, value)) = line.split_once(':') else {
            return Err(AiFailureReason::SchemaViolation);
        };
        match label.trim().to_ascii_lowercase().as_str() {
            "user safety" => {
                if safety.is_some() {
                    return Err(AiFailureReason::SchemaViolation);
                }
                safety = Some(value.trim().to_ascii_lowercase());
            }
            "safety categories" => {
                for value in value.split(',').map(str::trim).filter(|value| !value.is_empty()) {
                    if !labels.iter().any(|existing| existing == value) {
                        labels.push(value.to_owned());
                    }
                }
            }
            _ => return Err(AiFailureReason::SchemaViolation),
        }
    }

    let unsafe_content = match safety.as_deref() {
        Some("safe") => false,
        Some("unsafe") => true,
        _ => return Err(AiFailureReason::SchemaViolation),
    };

    Ok(AiSafetyVerdict {
        taxonomy: AiSafetyTaxonomy::NemotronContentSafety,
        unsafe_content,
        labels: if unsafe_content { labels } else { Vec::new() },
    })
}
