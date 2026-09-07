// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    AiAnalysisOutcome, AiAnalysisRequest, AiFailureReason, AiProviderVerdict, AiSkipReason,
    model_input::{AiModelInput, build_ai_model_input},
    providers::{AiCompletionResult, AiProviderDescriptor},
    providers::adapters::interpret_model_response,
    runtime::{AiModerationRuntime, AnalysisKey, RuntimeAdmission, build_analysis_key},
    safety_mapping::map_safety_verdict,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisPreparation {
    Ready {
        key: AnalysisKey,
        input: AiModelInput,
    },
    Cached(AiAnalysisOutcome),
    JoinInFlight {
        key: AnalysisKey,
    },
    Skipped(AiSkipReason),
}

pub fn prepare_analysis(
    request: &AiAnalysisRequest,
    provider: &AiProviderDescriptor,
    runtime: &mut AiModerationRuntime,
    now_ms: u64,
) -> AnalysisPreparation {
    if request.enabled_categories.is_empty() {
        return AnalysisPreparation::Skipped(AiSkipReason::NoCategoriesEnabled);
    }
    if !provider.configured {
        return AnalysisPreparation::Skipped(AiSkipReason::NotConfigured);
    }

    let key = build_analysis_key(request);
    if let Some(classification) = runtime.read_cached(key, now_ms) {
        return AnalysisPreparation::Cached(AiAnalysisOutcome::Classified {
            classification,
            model: provider.model.clone(),
            latency_ms: 0,
        });
    }

    match runtime.admit(key, now_ms) {
        RuntimeAdmission::Granted => AnalysisPreparation::Ready {
            key,
            input: build_ai_model_input(&provider.model, request),
        },
        RuntimeAdmission::AlreadyInFlight => AnalysisPreparation::JoinInFlight { key },
        RuntimeAdmission::QueueFull => AnalysisPreparation::Skipped(AiSkipReason::QueueFull),
        RuntimeAdmission::CircuitOpen => AnalysisPreparation::Skipped(AiSkipReason::CircuitOpen),
    }
}

pub fn complete_analysis(
    key: AnalysisKey,
    completion: AiCompletionResult,
    runtime: &mut AiModerationRuntime,
    now_ms: u64,
) -> AiAnalysisOutcome {
    runtime.finish(key);

    match completion {
        AiCompletionResult::Error {
            reason,
            model,
            status_code,
            ..
        } => {
            runtime.record_failure(reason, status_code, now_ms);
            AiAnalysisOutcome::Failed { reason, model }
        }
        AiCompletionResult::Ok {
            content,
            model,
            latency_ms,
        } => match interpret_model_response(&model, &content) {
            Err(reason) => {
                runtime.record_failure(reason, None, now_ms);
                AiAnalysisOutcome::Failed { reason, model }
            }
            Ok(verdict) => {
                let classification = classification_from_verdict(verdict);
                runtime.record_success();
                runtime.write_cached(key, classification.clone(), now_ms);
                AiAnalysisOutcome::Classified {
                    classification,
                    model,
                    latency_ms,
                }
            }
        },
    }
}

fn classification_from_verdict(verdict: AiProviderVerdict) -> super::AiClassification {
    match verdict {
        AiProviderVerdict::PolicyClassification(classification) => classification,
        AiProviderVerdict::SafetyVerdict(verdict) => map_safety_verdict(&verdict).classification,
    }
}

pub fn failure_is_provider_outage(reason: AiFailureReason) -> bool {
    matches!(
        reason,
        AiFailureReason::Timeout
            | AiFailureReason::TransportError
            | AiFailureReason::ProviderError
            | AiFailureReason::EmptyResponse
    )
}
