// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod openai;

use super::super::{AiFailureReason, AiProviderVerdict};
use super::openai::OPENAI_MODERATION_MODEL;

pub use openai::parse_openai_moderation_response;

pub fn interpret_model_response(
    model: &str,
    raw: &str,
) -> Result<AiProviderVerdict, AiFailureReason> {
    if model != OPENAI_MODERATION_MODEL {
        return Err(AiFailureReason::SchemaViolation);
    }

    parse_openai_moderation_response(raw).map(AiProviderVerdict::SafetyVerdict)
}
