// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use super::{providers::AiProviderDescriptor, settings::AiModerationSettings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiAvailability {
    Available,
    Disabled,
    NoCategoriesEnabled,
    ProviderNotConfigured,
}

pub fn assess_availability(
    settings: &AiModerationSettings,
    provider: &AiProviderDescriptor,
) -> AiAvailability {
    if !settings.enabled {
        return AiAvailability::Disabled;
    }
    if settings.enabled_categories.is_empty() {
        return AiAvailability::NoCategoriesEnabled;
    }
    if !provider.configured {
        return AiAvailability::ProviderNotConfigured;
    }
    AiAvailability::Available
}
