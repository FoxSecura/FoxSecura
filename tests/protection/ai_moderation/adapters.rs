// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiFailureReason, AiProviderVerdict,
    providers::adapters::{interpret_model_response, parse_nemotron_safety_verdict},
};

#[test]
fn parses_nemotron_unsafe_protocol() {
    let verdict = parse_nemotron_safety_verdict(
        "User Safety: unsafe\nSafety Categories: Threat, PII/Privacy, Harassment",
    ).unwrap();
    assert!(verdict.unsafe_content);
    assert_eq!(verdict.labels.len(), 3);
}

#[test]
fn safe_nemotron_reply_discards_categories() {
    let verdict = parse_nemotron_safety_verdict(
        "User Safety: safe\nSafety Categories: Threat",
    ).unwrap();
    assert!(!verdict.unsafe_content);
    assert!(verdict.labels.is_empty());
}

#[test]
fn rejects_unrecognized_nemotron_prose() {
    let error = parse_nemotron_safety_verdict("This content looks unsafe").unwrap_err();
    assert_eq!(error, AiFailureReason::SchemaViolation);
}

#[test]
fn selects_native_protocol_from_model_name() {
    let verdict = interpret_model_response(
        "nvidia/nemotron-3.5-content-safety:free",
        "User Safety: safe",
    ).unwrap();
    assert!(matches!(verdict, AiProviderVerdict::SafetyVerdict(_)));
}
