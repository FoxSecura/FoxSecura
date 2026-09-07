// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    availability::{AiAvailability, assess_availability},
    providers::{AiProviderDescriptor, AiProviderKind},
    settings::AiModerationSettings,
};

#[test]
fn disabled_feature_is_not_reported_as_provider_failure() {
    let settings = AiModerationSettings::default();
    let provider = AiProviderDescriptor::new(AiProviderKind::OpenRouter, "model", false);
    assert_eq!(assess_availability(&settings, &provider), AiAvailability::Disabled);
}

#[test]
fn enabled_feature_requires_configured_provider() {
    let mut settings = AiModerationSettings::default();
    settings.enabled = true;
    let provider = AiProviderDescriptor::new(AiProviderKind::OpenRouter, "model", false);
    assert_eq!(assess_availability(&settings, &provider), AiAvailability::ProviderNotConfigured);
}
