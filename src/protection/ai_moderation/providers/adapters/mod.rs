// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod nemotron;

use super::super::{AiFailureReason, AiProviderVerdict};
use crate::protection::ai_moderation::schema::parse_classification;

pub use nemotron::parse_nemotron_safety_verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseProtocol {
    PolicyJson,
    NativeSafety,
}

pub fn response_protocol_for_model(model: &str) -> ResponseProtocol {
    let model = model.to_ascii_lowercase();
    if model.contains("nemotron") && model.contains("content-safety") {
        ResponseProtocol::NativeSafety
    } else {
        ResponseProtocol::PolicyJson
    }
}

pub fn interpret_model_response(
    model: &str,
    raw: &str,
) -> Result<AiProviderVerdict, AiFailureReason> {
    match response_protocol_for_model(model) {
        ResponseProtocol::PolicyJson => {
            parse_classification(raw).map(AiProviderVerdict::PolicyClassification)
        }
        ResponseProtocol::NativeSafety => {
            parse_nemotron_safety_verdict(raw).map(AiProviderVerdict::SafetyVerdict)
        }
    }
}
