// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::AiAnalysisRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiModelInput {
    pub input: String,
}

pub fn build_ai_model_input(_model: &str, request: &AiAnalysisRequest) -> AiModelInput {
    AiModelInput {
        input: request.message.content.clone(),
    }
}
