// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Catégorie « Protection serveur » du tableau de bord : interrupteurs des
//! huit modules de l'anti-nuke et du mode panique, seuils des rafales et
//! seuil du mode panique, état du verrouillage.
//!
//! Droit `Right::Config` (accès normal à `/config`), revérifié à chaque
//! composant et à chaque modal. Chaque écriture invalide le cache de
//! configuration de la guilde : le moteur l'applique dès l'entrée du journal
//! d'audit suivante. La levée manuelle du verrouillage reste dans la
//! catégorie Anti-Raid (propriétaire ou `ADMINISTRATOR`).

use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::anti_nuke::settings::{
    AntiNukeSettings, AntiNukeThresholds, FIXED_MEMBER_ACTION_THRESHOLD, NUKE_THRESHOLD_RANGE,
    PANIC_THRESHOLD_RANGE, validate_panic_threshold,
};
use foxsecura::protection::lockdown::LockdownState;
use foxsecura::protection::shared::ModuleSet;
use poise::serenity_prelude as serenity;

use super::anti_raid;
use super::content_filters::{self, ANTI_NUKE_MODULES};

pub use content_filters::ANTI_NUKE_CATEGORY_ID as CATEGORY_ID;
pub const THRESHOLDS_ID: &str = "foxsecura:config:server_protection:thresholds";
pub const THRESHOLDS_MODAL_ID: &str = "foxsecura:config:server_protection:thresholds_modal";
pub const PANIC_ID: &str = "foxsecura:config:server_protection:panic";
pub const PANIC_MODAL_ID: &str = "foxsecura:config:server_protection:panic_modal";
const BAN_INPUT_ID: &str = "ban";
const UNBAN_INPUT_ID: &str = "unban";
const CREATE_INPUT_ID: &str = "create";
const EMOJI_STICKER_INPUT_ID: &str = "emoji_sticker";
const ROLE_GRANT_INPUT_ID: &str = "role_grant";
const PANIC_INPUT_ID: &str = "panic";

/// État affiché de la catégorie, relu en base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiNukeState {
    pub modules: ModuleSet,
    pub settings: AntiNukeSettings,
    pub lockdown: Option<LockdownState>,
}

/// Champs d'état : modules, seuils, mode panique, verrouillage, puis
/// l'avertissement (permissions, faux positifs, aucune annulation).
pub fn state_fields(
    language: Language,
    state: &AntiNukeState,
) -> Vec<(&'static str, String, bool)> {
    let thresholds = state.settings.thresholds;
    vec![
        (
            text(language, TextKey::ConfigAntiNuke),
            content_filters::module_states(language, ANTI_NUKE_MODULES, state.modules),
            false,
        ),
        (
            text(language, TextKey::ConfigAntiNukeThresholds),
            text(language, TextKey::ConfigAntiNukeThresholdsValue)
                .replace("{ban}", &thresholds.ban.to_string())
                .replace("{unban}", &thresholds.unban.to_string())
                .replace("{create}", &thresholds.create.to_string())
                .replace("{emoji}", &thresholds.emoji_sticker.to_string())
                .replace("{grant}", &thresholds.role_grant.to_string())
                .replace("{fixed}", &FIXED_MEMBER_ACTION_THRESHOLD.to_string()),
            false,
        ),
        (
            text(language, TextKey::ModulePanicMode),
            text(language, TextKey::ConfigPanicThresholdValue)
                .replace("{threshold}", &state.settings.panic_threshold.to_string()),
            true,
        ),
        (
            text(language, TextKey::ConfigLockdown),
            anti_raid::lockdown_state(language, state.lockdown.as_ref()),
            true,
        ),
        (
            text(language, TextKey::ConfigAntiNukeNoticeTitle),
            text(language, TextKey::ConfigAntiNukeNotice).to_owned(),
            false,
        ),
    ]
}

/// Interrupteurs (deux rangées), puis les deux boutons de réglage.
pub fn components(language: Language, modules: ModuleSet) -> Vec<serenity::CreateActionRow> {
    let mut rows = content_filters::buttons(language, ANTI_NUKE_MODULES, modules);
    rows.push(serenity::CreateActionRow::Buttons(vec![
        serenity::CreateButton::new(THRESHOLDS_ID)
            .label(text(language, TextKey::ConfigAntiNukeThresholdsButton))
            .style(serenity::ButtonStyle::Secondary),
        serenity::CreateButton::new(PANIC_ID)
            .label(text(language, TextKey::ConfigPanicThresholdButton))
            .style(serenity::ButtonStyle::Secondary),
    ]));
    rows
}

fn threshold_input(
    language: Language,
    label: TextKey,
    custom_id: &str,
    value: u8,
    max: u8,
) -> serenity::CreateActionRow {
    serenity::CreateActionRow::InputText(
        serenity::CreateInputText::new(
            serenity::InputTextStyle::Short,
            text(language, label),
            custom_id,
        )
        .value(value.to_string())
        .min_length(1)
        .max_length(max.to_string().len() as u16)
        .required(true),
    )
}

/// Modal des seuils des rafales (cinq champs, limite Discord), prérempli.
pub fn thresholds_modal(
    language: Language,
    thresholds: AntiNukeThresholds,
) -> serenity::CreateModal {
    let max = *NUKE_THRESHOLD_RANGE.end();
    serenity::CreateModal::new(
        THRESHOLDS_MODAL_ID,
        text(language, TextKey::ConfigAntiNukeThresholdsModalTitle),
    )
    .components(vec![
        threshold_input(
            language,
            TextKey::ConfigAntiNukeBanInput,
            BAN_INPUT_ID,
            thresholds.ban,
            max,
        ),
        threshold_input(
            language,
            TextKey::ConfigAntiNukeUnbanInput,
            UNBAN_INPUT_ID,
            thresholds.unban,
            max,
        ),
        threshold_input(
            language,
            TextKey::ConfigAntiNukeCreateInput,
            CREATE_INPUT_ID,
            thresholds.create,
            max,
        ),
        threshold_input(
            language,
            TextKey::ConfigAntiNukeEmojiStickerInput,
            EMOJI_STICKER_INPUT_ID,
            thresholds.emoji_sticker,
            max,
        ),
        threshold_input(
            language,
            TextKey::ConfigAntiNukeRoleGrantInput,
            ROLE_GRANT_INPUT_ID,
            thresholds.role_grant,
            max,
        ),
    ])
}

/// Modal du seuil du mode panique, prérempli.
pub fn panic_modal(language: Language, threshold: u8) -> serenity::CreateModal {
    serenity::CreateModal::new(
        PANIC_MODAL_ID,
        text(language, TextKey::ConfigPanicThresholdButton),
    )
    .components(vec![threshold_input(
        language,
        TextKey::ConfigPanicThresholdInput,
        PANIC_INPUT_ID,
        threshold,
        *PANIC_THRESHOLD_RANGE.end(),
    )])
}

fn submitted_values(rows: &[serenity::ActionRow]) -> Vec<(&str, &str)> {
    rows.iter()
        .flat_map(|row| &row.components)
        .filter_map(|component| match component {
            serenity::ActionRowComponent::InputText(input) => {
                Some((input.custom_id.as_str(), input.value.as_deref()?))
            }
            _ => None,
        })
        .collect()
}

fn parse_value(values: &[(&str, &str)], custom_id: &str) -> Option<u8> {
    values
        .iter()
        .find(|(id, _)| *id == custom_id)
        .and_then(|(_, value)| value.trim().parse().ok())
}

/// Seuils saisis ; `None` si une valeur est absente, illisible ou hors
/// bornes (2 à 20).
pub fn submitted_thresholds(rows: &[serenity::ActionRow]) -> Option<AntiNukeThresholds> {
    let values = submitted_values(rows);
    AntiNukeThresholds {
        ban: parse_value(&values, BAN_INPUT_ID)?,
        unban: parse_value(&values, UNBAN_INPUT_ID)?,
        create: parse_value(&values, CREATE_INPUT_ID)?,
        emoji_sticker: parse_value(&values, EMOJI_STICKER_INPUT_ID)?,
        role_grant: parse_value(&values, ROLE_GRANT_INPUT_ID)?,
    }
    .validated()
    .ok()
}

/// Seuil du mode panique saisi ; `None` s'il est absent, illisible ou hors
/// bornes (2 à 10).
pub fn submitted_panic_threshold(rows: &[serenity::ActionRow]) -> Option<u8> {
    let values = submitted_values(rows);
    validate_panic_threshold(parse_value(&values, PANIC_INPUT_ID)?).ok()
}

#[cfg(test)]
mod tests {
    use foxsecura::protection::shared::ProtectionModule;

    use super::*;

    fn input_row(custom_id: &str, value: &str) -> serenity::ActionRow {
        serde_json::from_value(serde_json::json!({
            "type": 1,
            "components": [{
                "type": 4,
                "custom_id": custom_id,
                "style": 1,
                "label": "x",
                "value": value
            }]
        }))
        .unwrap()
    }

    fn thresholds_rows(values: [&str; 5]) -> Vec<serenity::ActionRow> {
        [
            BAN_INPUT_ID,
            UNBAN_INPUT_ID,
            CREATE_INPUT_ID,
            EMOJI_STICKER_INPUT_ID,
            ROLE_GRANT_INPUT_ID,
        ]
        .into_iter()
        .zip(values)
        .map(|(id, value)| input_row(id, value))
        .collect()
    }

    #[test]
    fn thresholds_are_parsed_and_bounded() {
        assert_eq!(
            submitted_thresholds(&thresholds_rows(["2", " 20 ", "7", "5", "3"])),
            Some(AntiNukeThresholds {
                ban: 2,
                unban: 20,
                create: 7,
                emoji_sticker: 5,
                role_grant: 3,
            })
        );
        for refused in ["1", "21", "-3", "abc", "", "300"] {
            assert_eq!(
                submitted_thresholds(&thresholds_rows(["3", "5", "5", "5", refused])),
                None,
                "{refused}"
            );
        }
        // Un champ manquant (modal forgé) : rien n'est écrit.
        assert_eq!(
            submitted_thresholds(&thresholds_rows(["3", "5", "5", "5", "5"])[..4]),
            None
        );
    }

    #[test]
    fn panic_threshold_is_parsed_and_bounded() {
        assert_eq!(
            submitted_panic_threshold(&[input_row(PANIC_INPUT_ID, "2")]),
            Some(2)
        );
        assert_eq!(
            submitted_panic_threshold(&[input_row(PANIC_INPUT_ID, "10")]),
            Some(10)
        );
        for refused in ["1", "11", "x"] {
            assert_eq!(
                submitted_panic_threshold(&[input_row(PANIC_INPUT_ID, refused)]),
                None
            );
        }
        assert_eq!(submitted_panic_threshold(&[]), None);
    }

    #[test]
    fn state_fits_in_an_embed_in_every_language() {
        let state = AntiNukeState {
            modules: [ProtectionModule::AntiMassBan, ProtectionModule::PanicMode]
                .into_iter()
                .collect(),
            settings: AntiNukeSettings::default(),
            lockdown: None,
        };
        let fields = state_fields(Language::French, &state);
        assert!(
            fields[0].1.contains("Bannissements de masse : actif"),
            "{}",
            fields[0].1
        );
        assert!(fields[0].1.contains("Mode panique : actif"));
        assert!(fields[0].1.contains("Expulsions de masse : désactivé"));
        assert!(fields[1].1.contains("3"), "{}", fields[1].1);
        assert!(!fields[1].1.contains('{'), "{}", fields[1].1);
        assert!(!fields[2].1.contains('{'), "{}", fields[2].1);

        for language in [Language::English, Language::French, Language::German] {
            let fields = state_fields(language, &state);
            for (name, value, _) in &fields {
                assert!(name.chars().count() <= 256, "{name}");
                assert!(value.chars().count() <= 1024, "{name} : {}", value.len());
            }
            for key in [
                TextKey::ConfigAntiNukeBanInput,
                TextKey::ConfigAntiNukeUnbanInput,
                TextKey::ConfigAntiNukeCreateInput,
                TextKey::ConfigAntiNukeEmojiStickerInput,
                TextKey::ConfigAntiNukeRoleGrantInput,
                TextKey::ConfigPanicThresholdInput,
            ] {
                // Libellé d'un champ de modal : 45 caractères au plus.
                assert!(text(language, key).chars().count() <= 45, "{key:?}");
            }
            for key in [
                TextKey::ConfigAntiNukeThresholdsModalTitle,
                TextKey::ConfigPanicThresholdButton,
                TextKey::ConfigAntiNukeThresholdsButton,
            ] {
                assert!(text(language, key).chars().count() <= 45, "{key:?}");
            }
        }
    }

    #[test]
    fn components_fit_in_discord_rows() {
        // Menu, deux rangées d'interrupteurs et les réglages : quatre sur
        // cinq.
        assert_eq!(components(Language::French, ModuleSet::empty()).len(), 3);
        for id in [THRESHOLDS_ID, THRESHOLDS_MODAL_ID, PANIC_ID, PANIC_MODAL_ID] {
            assert!(id.len() <= 100);
        }
    }
}
