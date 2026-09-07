// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    availability::{AiAvailability, assess_availability},
    policy::{AI_POLICY_VERSION, undefined_policy_categories},
    providers::AiProviderDescriptor,
    settings::AiModerationSettings,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiDiagnosticReport {
    pub availability: AiAvailability,
    pub model: String,
    pub provider_configured: bool,
    pub policy_version: &'static str,
    pub policy_complete: bool,
}

pub fn build_diagnostic_report(
    settings: &AiModerationSettings,
    provider: &AiProviderDescriptor,
) -> AiDiagnosticReport {
    AiDiagnosticReport {
        availability: assess_availability(settings, provider),
        model: provider.model.clone(),
        provider_configured: provider.configured,
        policy_version: AI_POLICY_VERSION,
        policy_complete: undefined_policy_categories().is_empty(),
    }
}
