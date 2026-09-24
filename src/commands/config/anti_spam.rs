// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Réglages Anti-Spam du tableau de bord : interrupteur, seuil et fenêtre.

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::anti_spam::message_flood::{
    MAX_MESSAGE_THRESHOLD, MAX_WINDOW_SECONDS, MessageFloodConfig,
};
use poise::serenity_prelude as serenity;

pub const CATEGORY_ID: &str = "anti_spam";
pub const ENABLE_ID: &str = "foxsecura:config:anti_spam:enable";
pub const DISABLE_ID: &str = "foxsecura:config:anti_spam:disable";
pub const LIMITS_ID: &str = "foxsecura:config:anti_spam:limits";
pub const LIMITS_MODAL_ID: &str = "foxsecura:config:anti_spam:limits_modal";
const THRESHOLD_INPUT_ID: &str = "threshold";
const WINDOW_INPUT_ID: &str = "window";

/// Champs d'état affichés : uniquement les valeurs persistées lues par le moteur.
pub fn state_fields(
    language: Language,
    config: &MessageFloodConfig,
) -> Vec<(&'static str, String, bool)> {
    let state = if config.enabled {
        TextKey::ConfigAntiSpamEnabled
    } else {
        TextKey::ConfigAntiSpamDisabled
    };

    vec![
        (
            text(language, TextKey::ConfigFieldState),
            text(language, state).to_owned(),
            false,
        ),
        (
            text(language, TextKey::ConfigAntiSpamThreshold),
            config.message_threshold.to_string(),
            true,
        ),
        (
            text(language, TextKey::ConfigAntiSpamWindow),
            config.window_seconds.to_string(),
            true,
        ),
    ]
}

pub fn buttons(language: Language, config: &MessageFloodConfig) -> serenity::CreateActionRow {
    let toggle = if config.enabled {
        serenity::CreateButton::new(DISABLE_ID)
            .label(text(language, TextKey::ConfigAntiSpamDisableButton))
            .style(serenity::ButtonStyle::Danger)
    } else {
        serenity::CreateButton::new(ENABLE_ID)
            .label(text(language, TextKey::ConfigAntiSpamEnableButton))
            .style(serenity::ButtonStyle::Success)
    };

    let limits = serenity::CreateButton::new(LIMITS_ID)
        .label(text(language, TextKey::ConfigAntiSpamEditLimitsButton))
        .style(serenity::ButtonStyle::Secondary);

    serenity::CreateActionRow::Buttons(vec![toggle, limits])
}

pub fn limits_modal(language: Language, config: &MessageFloodConfig) -> serenity::CreateModal {
    let threshold = serenity::CreateInputText::new(
        serenity::InputTextStyle::Short,
        text(language, TextKey::ConfigAntiSpamThresholdInput),
        THRESHOLD_INPUT_ID,
    )
    .value(config.message_threshold.to_string())
    .min_length(1)
    .max_length(digits(MAX_MESSAGE_THRESHOLD))
    .required(true);

    let window = serenity::CreateInputText::new(
        serenity::InputTextStyle::Short,
        text(language, TextKey::ConfigAntiSpamWindowInput),
        WINDOW_INPUT_ID,
    )
    .value(config.window_seconds.to_string())
    .min_length(1)
    .max_length(digits(MAX_WINDOW_SECONDS))
    .required(true);

    serenity::CreateModal::new(
        LIMITS_MODAL_ID,
        text(language, TextKey::ConfigAntiSpamLimitsModalTitle),
    )
    .components(vec![
        serenity::CreateActionRow::InputText(threshold),
        serenity::CreateActionRow::InputText(window),
    ])
}

/// Extrait `(seuil, fenêtre)` d'une soumission de modal.
pub fn submitted_limits(rows: &[serenity::ActionRow]) -> Option<(u32, u32)> {
    let mut threshold = None;
    let mut window = None;

    for component in rows.iter().flat_map(|row| &row.components) {
        if let serenity::ActionRowComponent::InputText(input) = component {
            match input.custom_id.as_str() {
                THRESHOLD_INPUT_ID => threshold = input.value.as_deref(),
                WINDOW_INPUT_ID => window = input.value.as_deref(),
                _ => {}
            }
        }
    }

    parse_limits(threshold?, window?)
}

/// Analyse et valide les bornes saisies ; `None` si une valeur est invalide.
pub fn parse_limits(threshold: &str, window: &str) -> Option<(u32, u32)> {
    let threshold = threshold.trim().parse::<u32>().ok()?;
    let window = window.trim().parse::<u32>().ok()?;
    MessageFloodConfig::validated(false, threshold, window).ok()?;
    Some((threshold, window))
}

fn digits(value: u32) -> u16 {
    value.to_string().len() as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_limits_within_bounds() {
        assert_eq!(parse_limits("2", "1"), Some((2, 1)));
        assert_eq!(parse_limits(" 50 ", "60"), Some((50, 60)));
    }

    #[test]
    fn rejects_limits_out_of_bounds_or_not_numeric() {
        assert_eq!(parse_limits("1", "5"), None);
        assert_eq!(parse_limits("51", "5"), None);
        assert_eq!(parse_limits("5", "0"), None);
        assert_eq!(parse_limits("5", "61"), None);
        assert_eq!(parse_limits("-3", "5"), None);
        assert_eq!(parse_limits("cinq", "5"), None);
        assert_eq!(parse_limits("", "5"), None);
    }

    #[test]
    fn state_reflects_persisted_values() {
        let fields = state_fields(Language::French, &MessageFloodConfig::new(true, 7, 12));
        assert_eq!(
            fields[0].1,
            text(Language::French, TextKey::ConfigAntiSpamEnabled)
        );
        assert_eq!(fields[1].1, "7");
        assert_eq!(fields[2].1, "12");

        let fields = state_fields(Language::French, &MessageFloodConfig::default());
        assert_eq!(
            fields[0].1,
            text(Language::French, TextKey::ConfigAntiSpamDisabled)
        );
    }
}
