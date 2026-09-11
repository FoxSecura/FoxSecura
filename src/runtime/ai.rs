// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::{sync::Mutex, time::{Duration, Instant}};

use crate::protection::ai_moderation::{
    AiAnalysisOutcome, AiAnalysisRequest, AiFailureReason, AiMessageSnapshot,
    action::{AiActionPlan, plan_action},
    analysis::{AnalysisPreparation, complete_analysis, prepare_analysis},
    prefilter::{PrefilterVerdict, prefilter_message},
    providers::{AiCompletionRequest, AiCompletionResult, AiModerationProvider, AiProviderDescriptor},
    rules::decide_ai_moderation_action,
    runtime::AiModerationRuntime,
    settings::AiModerationSettings,
};
use super::{GuildProtectionConfig, MessageInput};

pub struct AiService {
    state: Mutex<AiModerationRuntime>,
    started: Instant,
}

impl Default for AiService {
    fn default() -> Self {
        Self { state: Mutex::new(AiModerationRuntime::default()), started: Instant::now() }
    }
}

impl AiService {
    pub async fn analyze(
        &self, config: &GuildProtectionConfig, message: &MessageInput,
        provider: Option<&dyn AiModerationProvider>, timeout_ms: u64,
    ) -> Option<AiActionPlan> {
        if !config.enabled("ai_moderation") || message.exempt || message.bot
            || message.webhook.is_some() || config.ignored_channels.contains(&message.channel)
            || prefilter_message(&message.content) == PrefilterVerdict::Skip
        { return None; }
        let provider = provider.filter(|provider| provider.is_configured())?;
        let settings = AiModerationSettings { enabled: true, timeout_ms, ..Default::default() };
        let request = AiAnalysisRequest {
            guild_id: message.guild.to_string(), channel_id: message.channel.to_string(),
            revision_id: None,
            message: AiMessageSnapshot {
                message_id: message.id.to_string(), author_id: message.author.to_string(),
                author_label: "AUTHOR".into(), content: message.content.clone(), created_at_ms: 0,
            },
            recent_messages: Vec::new(), target_user_id: None,
            enabled_categories: settings.enabled_categories.clone(),
        };
        let descriptor = AiProviderDescriptor::openai(provider.is_configured());
        let prepared = {
            let mut state = self.state.lock().ok()?;
            prepare_analysis(&request, &descriptor, &mut state, self.now())
        };
        let outcome = match prepared {
            AnalysisPreparation::Cached(outcome) => outcome,
            AnalysisPreparation::Ready { key, input } => {
                let completion = tokio::time::timeout(Duration::from_millis(timeout_ms.max(1)),
                    provider.complete(AiCompletionRequest { input: input.input, timeout_ms })).await;
                let completion = completion.unwrap_or_else(|_| AiCompletionResult::Error {
                    reason: AiFailureReason::Timeout, model: provider.model().into(),
                    status_code: None, latency_ms: timeout_ms,
                });
                let mut state = self.state.lock().ok()?;
                complete_analysis(key, completion, &mut state, self.now())
            }
            AnalysisPreparation::JoinInFlight { .. } | AnalysisPreparation::Skipped(_) => return None,
        };
        match outcome {
            AiAnalysisOutcome::Classified { classification, .. } => {
                Some(plan_action(&decide_ai_moderation_action(&classification, &settings.rule_settings())))
            }
            AiAnalysisOutcome::Failed { reason, .. } => {
                eprintln!("FoxSecura : analyse IA indisponible ({reason:?})");
                None
            }
            AiAnalysisOutcome::Skipped { .. } => None,
        }
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}
