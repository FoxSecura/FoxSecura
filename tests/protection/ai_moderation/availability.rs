// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::{
    availability::{AiAvailability, assess_availability},
    providers::AiProviderDescriptor,
    settings::AiModerationSettings,
};

#[test]
fn disabled_feature_is_not_reported_as_provider_failure() {
    let settings = AiModerationSettings::default();
    let provider = AiProviderDescriptor::openai(false);
    assert_eq!(assess_availability(&settings, &provider), AiAvailability::Disabled);
}

#[test]
fn enabled_feature_requires_openai_api_key() {
    let mut settings = AiModerationSettings::default();
    settings.enabled = true;
    let provider = AiProviderDescriptor::openai(false);
    assert_eq!(
        assess_availability(&settings, &provider),
        AiAvailability::ProviderNotConfigured
    );
}
