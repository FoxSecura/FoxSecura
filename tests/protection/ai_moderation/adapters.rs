// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiFailureReason, AiProviderVerdict,
    providers::{
        adapters::{interpret_model_response, parse_openai_moderation_response},
        openai::OPENAI_MODERATION_MODEL,
    },
};
use serde_json::{Value, json};

fn response(flagged: bool, flagged_categories: &[&str]) -> String {
    let mut categories = json!({
        "sexual": false,
        "sexual/minors": false,
        "harassment": false,
        "harassment/threatening": false,
        "hate": false,
        "hate/threatening": false,
        "illicit": false,
        "illicit/violent": false,
        "self-harm": false,
        "self-harm/intent": false,
        "self-harm/instructions": false,
        "violence": false,
        "violence/graphic": false
    });

    let object = categories.as_object_mut().unwrap();
    for category in flagged_categories {
        object.insert((*category).to_owned(), Value::Bool(true));
    }

    json!({
        "model": OPENAI_MODERATION_MODEL,
        "results": [{
            "flagged": flagged,
            "categories": categories
        }]
    })
    .to_string()
}

#[test]
fn parses_openai_flagged_categories() {
    let raw = response(true, &["harassment/threatening", "hate"]);
    let verdict = parse_openai_moderation_response(&raw).unwrap();
    assert!(verdict.unsafe_content);
    assert!(verdict.labels.contains(&"harassment/threatening".to_owned()));
    assert!(verdict.labels.contains(&"hate".to_owned()));
}

#[test]
fn clean_openai_reply_has_no_labels() {
    let raw = response(false, &[]);
    let verdict = parse_openai_moderation_response(&raw).unwrap();
    assert!(!verdict.unsafe_content);
    assert!(verdict.labels.is_empty());
}

#[test]
fn rejects_contradictory_openai_reply() {
    let raw = response(false, &["violence"]);
    let error = parse_openai_moderation_response(&raw).unwrap_err();
    assert_eq!(error, AiFailureReason::SchemaViolation);
}

#[test]
fn interpreter_accepts_only_selected_openai_model() {
    let raw = response(false, &[]);
    let verdict = interpret_model_response(OPENAI_MODERATION_MODEL, &raw).unwrap();
    assert!(matches!(verdict, AiProviderVerdict::SafetyVerdict(_)));

    let error = interpret_model_response("other-model", &raw).unwrap_err();
    assert_eq!(error, AiFailureReason::SchemaViolation);
}
