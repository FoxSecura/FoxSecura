// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiFailureReason, AiModerationCategory, AiSeverity, schema::parse_classification,
};

#[test]
fn parses_valid_policy_json() {
    let parsed = parse_classification(r#"{"violation":true,"categories":["THREATS"],"severity":"HIGH","recommendedAction":"DELETE","reason":"Threat detected"}"#).unwrap();
    assert!(parsed.violation);
    assert_eq!(parsed.categories, vec![AiModerationCategory::Threats]);
    assert_eq!(parsed.severity, AiSeverity::High);
}

#[test]
fn accepts_json_wrapped_in_markdown() {
    let parsed = parse_classification("```json\n{\"violation\":false,\"categories\":[],\"severity\":\"LOW\",\"recommendedAction\":\"NONE\",\"reason\":\"Clean\"}\n```").unwrap();
    assert!(!parsed.violation);
}

#[test]
fn rejects_unknown_category() {
    let error = parse_classification(r#"{"violation":true,"categories":["UNKNOWN"],"severity":"HIGH","recommendedAction":"DELETE","reason":"Bad"}"#).unwrap_err();
    assert_eq!(error, AiFailureReason::SchemaViolation);
}

#[test]
fn resolves_contradiction_towards_clean() {
    let parsed = parse_classification(r#"{"violation":false,"categories":["THREATS"],"severity":"CRITICAL","recommendedAction":"DELETE","reason":"Contradictory"}"#).unwrap();
    assert!(!parsed.violation);
    assert!(parsed.categories.is_empty());
    assert_eq!(parsed.severity, AiSeverity::Low);
}

#[test]
fn deduplicates_categories() {
    let parsed = parse_classification(r#"{"violation":true,"categories":["THREATS","THREATS"],"severity":"HIGH","recommendedAction":"DELETE","reason":"Threat"}"#).unwrap();
    assert_eq!(parsed.categories.len(), 1);
}
