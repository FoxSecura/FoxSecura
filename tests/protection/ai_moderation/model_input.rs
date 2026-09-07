// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    AiAnalysisRequest, AiMessageSnapshot, AiModerationCategory,
    model_input::build_ai_model_input,
};

fn request() -> AiAnalysisRequest {
    AiAnalysisRequest {
        guild_id: "g".into(),
        channel_id: "c".into(),
        revision_id: None,
        message: AiMessageSnapshot { message_id: "m".into(), author_id: "u".into(), author_label: "name".into(), content: "message only".into(), created_at_ms: 1 },
        recent_messages: Vec::new(),
        target_user_id: None,
        enabled_categories: vec![AiModerationCategory::Threats],
    }
}

#[test]
fn native_safety_model_receives_only_current_message() {
    let input = build_ai_model_input("nvidia/nemotron-3.5-content-safety:free", &request());
    assert!(input.system_prompt.is_empty());
    assert_eq!(input.user_prompt, "message only");
}

#[test]
fn policy_model_receives_policy_and_wrapper() {
    let input = build_ai_model_input("policy-model", &request());
    assert!(input.system_prompt.contains("THREATS"));
    assert!(input.user_prompt.contains("CURRENT MESSAGE"));
}
