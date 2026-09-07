// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Contrat des fournisseurs IA. Les providers ne voient aucun objet Discord et
//! ne renvoient jamais directement une décision de modération.

use std::{future::Future, pin::Pin};

use super::AiFailureReason;

pub mod adapters;
pub mod openai;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiCompletionRequest {
    pub input: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiCompletionResult {
    Ok {
        content: String,
        model: String,
        latency_ms: u64,
    },
    Error {
        reason: AiFailureReason,
        model: String,
        status_code: Option<u16>,
        latency_ms: u64,
    },
}

pub trait AiModerationProvider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    fn is_configured(&self) -> bool;

    fn complete<'a>(
        &'a self,
        request: AiCompletionRequest,
    ) -> Pin<Box<dyn Future<Output = AiCompletionResult> + Send + 'a>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiProviderKind {
    OpenAiModeration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiProviderDescriptor {
    pub kind: AiProviderKind,
    pub model: String,
    pub configured: bool,
}

impl AiProviderDescriptor {
    pub fn new(kind: AiProviderKind, model: impl Into<String>, configured: bool) -> Self {
        Self {
            kind,
            model: model.into(),
            configured,
        }
    }

    pub fn openai(configured: bool) -> Self {
        Self::new(
            AiProviderKind::OpenAiModeration,
            openai::OPENAI_MODERATION_MODEL,
            configured,
        )
    }
}
