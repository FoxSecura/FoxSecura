// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::{AiAnalysisRequest, context::render_analysis_prompt, policy::build_policy_prompt};
use super::providers::adapters::{ResponseProtocol, response_protocol_for_model};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiModelInput {
    pub system_prompt: String,
    pub user_prompt: String,
}

pub fn build_ai_model_input(model: &str, request: &AiAnalysisRequest) -> AiModelInput {
    match response_protocol_for_model(model) {
        ResponseProtocol::NativeSafety => AiModelInput {
            system_prompt: String::new(),
            user_prompt: request.message.content.clone(),
        },
        ResponseProtocol::PolicyJson => AiModelInput {
            system_prompt: build_policy_prompt(&request.enabled_categories),
            user_prompt: render_analysis_prompt(
                &request.message,
                &request.recent_messages,
                request.target_user_id.as_deref(),
            ),
        },
    }
}
