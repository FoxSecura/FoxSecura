// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiAnalysisRequest, AiMessageSnapshot, AiModerationCategory,
    model_input::build_ai_model_input,
    providers::openai::OPENAI_MODERATION_MODEL,
};

fn request() -> AiAnalysisRequest {
    AiAnalysisRequest {
        guild_id: "g".into(),
        channel_id: "c".into(),
        revision_id: None,
        message: AiMessageSnapshot {
            message_id: "m".into(),
            author_id: "u".into(),
            author_label: "name".into(),
            content: "message only".into(),
            created_at_ms: 1,
        },
        recent_messages: vec![AiMessageSnapshot {
            message_id: "old".into(),
            author_id: "other".into(),
            author_label: "other".into(),
            content: "context that must not be sent".into(),
            created_at_ms: 0,
        }],
        target_user_id: Some("other".into()),
        enabled_categories: vec![AiModerationCategory::Threats],
    }
}

#[test]
fn openai_moderation_receives_only_current_message() {
    let input = build_ai_model_input(OPENAI_MODERATION_MODEL, &request());
    assert_eq!(input.input, "message only");
    assert!(!input.input.contains("context that must not be sent"));
}
