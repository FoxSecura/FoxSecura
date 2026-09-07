// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::ai_moderation::providers::{
    AiModerationProvider, AiProviderDescriptor,
    openai::{OPENAI_MODERATION_MODEL, OpenAiModerationProvider},
};

#[test]
fn openai_provider_is_fixed_to_selected_model() {
    let provider = OpenAiModerationProvider::new("test-key-do-not-use");
    assert_eq!(provider.name(), "openai");
    assert_eq!(provider.model(), OPENAI_MODERATION_MODEL);
    assert!(provider.is_configured());

    let descriptor = AiProviderDescriptor::openai(true);
    assert_eq!(descriptor.model, OPENAI_MODERATION_MODEL);
    assert!(descriptor.configured);
}

#[test]
fn empty_openai_key_is_not_configured() {
    let provider = OpenAiModerationProvider::new("   ");
    assert!(!provider.is_configured());
}

#[test]
fn debug_output_never_exposes_openai_key() {
    let provider = OpenAiModerationProvider::new("super-secret-test-key");
    let debug = format!("{provider:?}");
    assert!(!debug.contains("super-secret-test-key"));
}
