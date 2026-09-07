// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::Value;

use super::{
    AiClassification, AiFailureReason, AiModerationCategory, AiRecommendedAction, AiSeverity,
};

pub fn parse_classification(raw: &str) -> Result<AiClassification, AiFailureReason> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AiFailureReason::EmptyResponse);
    }

    let Some(start) = trimmed.find('{') else {
        return Err(AiFailureReason::InvalidJson);
    };
    let Some(end) = trimmed.rfind('}') else {
        return Err(AiFailureReason::InvalidJson);
    };
    if end <= start {
        return Err(AiFailureReason::InvalidJson);
    }

    let value: Value = serde_json::from_str(&trimmed[start..=end])
        .map_err(|_| AiFailureReason::InvalidJson)?;
    let object = value.as_object().ok_or(AiFailureReason::SchemaViolation)?;

    const EXPECTED_KEYS: [&str; 5] = [
        "violation",
        "categories",
        "severity",
        "recommendedAction",
        "reason",
    ];
    if object.len() != EXPECTED_KEYS.len()
        || object.keys().any(|key| !EXPECTED_KEYS.contains(&key.as_str()))
    {
        return Err(AiFailureReason::SchemaViolation);
    }

    let violation = object
        .get("violation")
        .and_then(Value::as_bool)
        .ok_or(AiFailureReason::SchemaViolation)?;

    let category_values = object
        .get("categories")
        .and_then(Value::as_array)
        .ok_or(AiFailureReason::SchemaViolation)?;
    if category_values.len() > AiModerationCategory::ALL.len() {
        return Err(AiFailureReason::SchemaViolation);
    }

    let mut categories = Vec::new();
    for value in category_values {
        let raw_category = value.as_str().ok_or(AiFailureReason::SchemaViolation)?;
        let category = AiModerationCategory::parse(raw_category)
            .ok_or(AiFailureReason::SchemaViolation)?;
        if !categories.contains(&category) {
            categories.push(category);
        }
    }

    let severity = object
        .get("severity")
        .and_then(Value::as_str)
        .and_then(AiSeverity::parse)
        .ok_or(AiFailureReason::SchemaViolation)?;
    let recommended_action = object
        .get("recommendedAction")
        .and_then(Value::as_str)
        .and_then(AiRecommendedAction::parse)
        .ok_or(AiFailureReason::SchemaViolation)?;
    let reason = object
        .get("reason")
        .and_then(Value::as_str)
        .filter(|reason| !reason.trim().is_empty() && reason.chars().count() <= 500)
        .ok_or(AiFailureReason::SchemaViolation)?
        .to_owned();

    if !violation || categories.is_empty() {
        return Ok(AiClassification::clean(Some(reason)));
    }

    Ok(AiClassification {
        violation: true,
        categories,
        severity,
        recommended_action: Some(recommended_action),
        reason: Some(reason),
    })
}
