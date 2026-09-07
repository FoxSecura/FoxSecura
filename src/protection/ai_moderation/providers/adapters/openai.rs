// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::Value;

use crate::protection::ai_moderation::{
    AiFailureReason, AiSafetyTaxonomy, AiSafetyVerdict,
};

const OPENAI_CATEGORIES: [&str; 13] = [
    "sexual",
    "sexual/minors",
    "harassment",
    "harassment/threatening",
    "hate",
    "hate/threatening",
    "illicit",
    "illicit/violent",
    "self-harm",
    "self-harm/intent",
    "self-harm/instructions",
    "violence",
    "violence/graphic",
];

pub fn parse_openai_moderation_response(raw: &str) -> Result<AiSafetyVerdict, AiFailureReason> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AiFailureReason::EmptyResponse);
    }

    let value: Value = serde_json::from_str(trimmed).map_err(|_| AiFailureReason::InvalidJson)?;
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or(AiFailureReason::SchemaViolation)?;
    if results.len() != 1 {
        return Err(AiFailureReason::SchemaViolation);
    }

    let result = results[0]
        .as_object()
        .ok_or(AiFailureReason::SchemaViolation)?;
    let flagged = result
        .get("flagged")
        .and_then(Value::as_bool)
        .ok_or(AiFailureReason::SchemaViolation)?;
    let categories = result
        .get("categories")
        .and_then(Value::as_object)
        .ok_or(AiFailureReason::SchemaViolation)?;

    let mut labels = Vec::new();
    for category in OPENAI_CATEGORIES {
        let is_flagged = categories
            .get(category)
            .and_then(Value::as_bool)
            .ok_or(AiFailureReason::SchemaViolation)?;
        if is_flagged {
            labels.push(category.to_owned());
        }
    }

    for (category, value) in categories {
        if OPENAI_CATEGORIES.contains(&category.as_str()) {
            continue;
        }
        let is_flagged = value.as_bool().ok_or(AiFailureReason::SchemaViolation)?;
        if is_flagged {
            labels.push(category.clone());
        }
    }

    if flagged != !labels.is_empty() {
        return Err(AiFailureReason::SchemaViolation);
    }

    Ok(AiSafetyVerdict {
        taxonomy: AiSafetyTaxonomy::OpenAiModeration,
        unsafe_content: flagged,
        labels,
    })
}
