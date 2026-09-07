// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fmt,
    time::{Duration, Instant},
};

use reqwest::StatusCode;
use serde_json::json;

use super::{AiCompletionRequest, AiCompletionResult, AiModerationProvider, AiProviderDescriptor};
use crate::protection::ai_moderation::AiFailureReason;

pub const OPENAI_API_KEY_ENV: &str = "OPENAI_API_KEY";
pub const OPENAI_MODERATION_ENDPOINT: &str = "https://api.openai.com/v1/moderations";
pub const OPENAI_MODERATION_MODEL: &str = "omni-moderation-latest";

#[derive(Clone)]
pub struct OpenAiModerationProvider {
    client: reqwest::Client,
    api_key: String,
}

impl fmt::Debug for OpenAiModerationProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiModerationProvider")
            .field("model", &OPENAI_MODERATION_MODEL)
            .field("configured", &self.is_configured())
            .finish()
    }
}

impl OpenAiModerationProvider {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key: api_key.into(),
        }
    }

    pub fn from_env() -> Option<Self> {
        let api_key = std::env::var(OPENAI_API_KEY_ENV).ok()?;
        if api_key.trim().is_empty() {
            return None;
        }
        Some(Self::new(api_key))
    }

    pub fn descriptor_from_env() -> AiProviderDescriptor {
        AiProviderDescriptor::openai(
            std::env::var(OPENAI_API_KEY_ENV)
                .is_ok_and(|value| !value.trim().is_empty()),
        )
    }
}

impl AiModerationProvider for OpenAiModerationProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn model(&self) -> &str {
        OPENAI_MODERATION_MODEL
    }

    fn is_configured(&self) -> bool {
        !self.api_key.trim().is_empty()
    }

    fn complete<'a>(
        &'a self,
        request: AiCompletionRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AiCompletionResult> + Send + 'a>> {
        Box::pin(async move {
            let started = Instant::now();
            let model = OPENAI_MODERATION_MODEL.to_owned();

            if !self.is_configured() {
                return AiCompletionResult::Error {
                    reason: AiFailureReason::ProviderError,
                    model,
                    status_code: None,
                    latency_ms: elapsed_ms(started),
                };
            }

            let response = self
                .client
                .post(OPENAI_MODERATION_ENDPOINT)
                .bearer_auth(&self.api_key)
                .timeout(Duration::from_millis(request.timeout_ms))
                .json(&json!({
                    "model": OPENAI_MODERATION_MODEL,
                    "input": request.input,
                }))
                .send()
                .await;

            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    return AiCompletionResult::Error {
                        reason: if error.is_timeout() {
                            AiFailureReason::Timeout
                        } else {
                            AiFailureReason::TransportError
                        },
                        model,
                        status_code: None,
                        latency_ms: elapsed_ms(started),
                    };
                }
            };

            let status = response.status();
            let status_code = Some(status.as_u16());
            let body = match response.text().await {
                Ok(body) => body,
                Err(_) => {
                    return AiCompletionResult::Error {
                        reason: AiFailureReason::TransportError,
                        model,
                        status_code,
                        latency_ms: elapsed_ms(started),
                    };
                }
            };

            if !status.is_success() {
                return AiCompletionResult::Error {
                    reason: failure_reason_for_status(status),
                    model,
                    status_code,
                    latency_ms: elapsed_ms(started),
                };
            }

            if body.trim().is_empty() {
                return AiCompletionResult::Error {
                    reason: AiFailureReason::EmptyResponse,
                    model,
                    status_code,
                    latency_ms: elapsed_ms(started),
                };
            }

            AiCompletionResult::Ok {
                content: body,
                model,
                latency_ms: elapsed_ms(started),
            }
        })
    }
}

pub fn failure_reason_for_status(status: StatusCode) -> AiFailureReason {
    if status.as_u16() == 429 {
        AiFailureReason::RateLimited
    } else {
        AiFailureReason::ProviderError
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}
