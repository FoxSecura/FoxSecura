// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Réglages Anti-Raid du tableau de bord : interrupteurs des modules
//! d'arrivée (anti-bot, nouveaux comptes, pseudos hoistés) et âge minimal des
//! comptes.
//!
//! L'état affiché est celui relu en base ; chaque écriture invalide le cache
//! de configuration de la guilde, le moteur l'applique dès l'arrivée
//! suivante.

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::anti_raid::anti_new_account::{
    MIN_ACCOUNT_AGE_DAYS_RANGE, is_valid_min_account_age_days,
};
use foxsecura::protection::shared::ModuleSet;
use poise::serenity_prelude as serenity;

use super::content_filters::{self, ANTI_RAID_MODULES};

pub use content_filters::ANTI_RAID_CATEGORY_ID as CATEGORY_ID;
pub const MIN_AGE_ID: &str = "foxsecura:config:anti_raid:min_age";
pub const MIN_AGE_MODAL_ID: &str = "foxsecura:config:anti_raid:min_age_modal";
const MIN_AGE_INPUT_ID: &str = "days";

/// Champs d'état : modules, âge minimal et portée.
pub fn state_fields(
    language: Language,
    modules: ModuleSet,
    min_age_days: u16,
) -> Vec<(&'static str, String, bool)> {
    vec![
        (
            text(language, TextKey::ConfigMemberProtection),
            format!(
                "{}\n\n{}",
                content_filters::module_states(language, ANTI_RAID_MODULES, modules),
                text(language, TextKey::ConfigMemberProtectionNotice)
            ),
            false,
        ),
        (
            text(language, TextKey::ConfigNewAccountMinAge),
            min_age_days.to_string(),
            true,
        ),
    ]
}

/// Interrupteurs des modules, puis réglage de l'âge minimal.
pub fn buttons(language: Language, modules: ModuleSet) -> Vec<serenity::CreateActionRow> {
    let mut rows = content_filters::buttons(language, ANTI_RAID_MODULES, modules);
    rows.push(serenity::CreateActionRow::Buttons(vec![
        serenity::CreateButton::new(MIN_AGE_ID)
            .label(text(language, TextKey::ConfigNewAccountMinAgeButton))
            .style(serenity::ButtonStyle::Secondary),
    ]));
    rows
}

/// Modal de l'âge minimal, prérempli avec la valeur actuelle.
pub fn min_age_modal(language: Language, min_age_days: u16) -> serenity::CreateModal {
    let input = serenity::CreateInputText::new(
        serenity::InputTextStyle::Short,
        text(language, TextKey::ConfigNewAccountMinAgeInput),
        MIN_AGE_INPUT_ID,
    )
    .value(min_age_days.to_string())
    .min_length(1)
    .max_length(MIN_ACCOUNT_AGE_DAYS_RANGE.end().to_string().len() as u16)
    .required(true);

    serenity::CreateModal::new(
        MIN_AGE_MODAL_ID,
        text(language, TextKey::ConfigNewAccountMinAgeModalTitle),
    )
    .components(vec![serenity::CreateActionRow::InputText(input)])
}

/// Âge saisi dans le modal ; `None` s'il est absent ou invalide.
pub fn submitted_min_age(rows: &[serenity::ActionRow]) -> Option<u16> {
    rows.iter()
        .flat_map(|row| &row.components)
        .find_map(|component| match component {
            serenity::ActionRowComponent::InputText(input)
                if input.custom_id == MIN_AGE_INPUT_ID =>
            {
                input.value.as_deref()
            }
            _ => None,
        })
        .and_then(parse_min_age)
}

/// Analyse un âge minimal (1 à 365 jours).
pub fn parse_min_age(value: &str) -> Option<u16> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|days| is_valid_min_account_age_days(*days))
}

#[cfg(test)]
mod tests {
    use foxsecura::protection::shared::ProtectionModule;

    use super::*;

    #[test]
    fn min_age_accepts_only_the_v1_bounds() {
        assert_eq!(parse_min_age("1"), Some(1));
        assert_eq!(parse_min_age(" 7 "), Some(7));
        assert_eq!(parse_min_age("365"), Some(365));
        for invalid in ["0", "366", "-1", "sept", "", "7.5", "99999999"] {
            assert_eq!(parse_min_age(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn state_shows_the_persisted_modules_and_minimum_age() {
        let modules: ModuleSet = [ProtectionModule::AntiBot].into_iter().collect();
        let fields = state_fields(Language::French, modules, 14);

        assert!(fields[0].1.contains("Anti-bot : actif"), "{}", fields[0].1);
        assert!(
            fields[0].1.contains("Nouveaux comptes : désactivé"),
            "{}",
            fields[0].1
        );
        assert!(fields[0].1.contains("Pseudos hoistés : désactivé"));
        assert_eq!(fields[1].1, "14");
    }

    #[test]
    fn every_field_fits_in_a_discord_embed_field() {
        let all: ModuleSet = ProtectionModule::ALL.into_iter().collect();
        for language in [Language::English, Language::French, Language::German] {
            for (name, value, _) in state_fields(language, all, 365) {
                assert!(value.chars().count() <= 1024, "{name} : {}", value.len());
            }
        }
    }

    #[test]
    fn buttons_stay_within_discord_limits() {
        // Menu, interrupteurs, âge minimal : trois rangées sur cinq.
        assert_eq!(buttons(Language::French, ModuleSet::empty()).len(), 2);
    }
}
