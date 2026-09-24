// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Réglages des mots interdits (catégorie AutoMod) : liste intégrée et mots
//! personnalisés.
//!
//! L'état affiché est celui relu en base ; toute écriture invalide le cache
//! de configuration de la guilde, le moteur l'applique dès le message
//! suivant.

use foxsecura::database::BadWordsSettings;
use foxsecura::i18n::{Language, TextKey, text};
use foxsecura::protection::automod::bad_words::{BadWordsLanguage, MAX_CUSTOM_WORDS_INPUT_CHARS};
use poise::serenity_prelude as serenity;

const LANGUAGE_PREFIX: &str = "foxsecura:config:bad_words:language:";
pub const EDIT_ID: &str = "foxsecura:config:bad_words:edit";
pub const MODAL_ID: &str = "foxsecura:config:bad_words:modal";
const WORDS_INPUT_ID: &str = "words";

/// Composant des mots interdits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadWordsAction {
    SetLanguage(BadWordsLanguage),
    Edit,
}

/// Analyse l'identifiant d'un composant.
///
/// `None` : le composant n'appartient pas aux mots interdits. `Some(None)` :
/// identifiant forgé ou d'une autre version, rien n'est écrit.
pub fn parse_action(custom_id: &str) -> Option<Option<BadWordsAction>> {
    if custom_id == EDIT_ID {
        return Some(Some(BadWordsAction::Edit));
    }
    let key = custom_id.strip_prefix(LANGUAGE_PREFIX)?;
    Some(BadWordsLanguage::from_key(key).map(BadWordsAction::SetLanguage))
}

fn language_id(language: BadWordsLanguage) -> String {
    format!("{LANGUAGE_PREFIX}{}", language.key())
}

/// Champ d'état : liste intégrée et nombre de mots personnalisés.
pub fn state_fields(
    language: Language,
    settings: &BadWordsSettings,
) -> Vec<(&'static str, String, bool)> {
    vec![(
        text(language, TextKey::ConfigBadWords),
        format!(
            "{} : {}\n{} : {}\n\n{}",
            text(language, TextKey::ConfigBadWordsLanguage),
            text(language, language_label(settings.language)),
            text(language, TextKey::ConfigBadWordsCustomCount),
            settings.custom_words.len(),
            text(language, TextKey::ConfigBadWordsNotice),
        ),
        false,
    )]
}

/// Une rangée : les trois listes intégrées (l'active en vert) et l'édition
/// des mots personnalisés.
pub fn buttons(language: Language, settings: &BadWordsSettings) -> serenity::CreateActionRow {
    let mut buttons = BadWordsLanguage::ALL
        .into_iter()
        .map(|candidate| {
            let active = candidate == settings.language;
            serenity::CreateButton::new(language_id(candidate))
                .label(text(language, language_label(candidate)))
                .style(if active {
                    serenity::ButtonStyle::Success
                } else {
                    serenity::ButtonStyle::Secondary
                })
                .disabled(active)
        })
        .collect::<Vec<_>>();
    buttons.push(
        serenity::CreateButton::new(EDIT_ID)
            .label(text(language, TextKey::ConfigBadWordsEditButton))
            .style(serenity::ButtonStyle::Primary),
    );

    serenity::CreateActionRow::Buttons(buttons)
}

/// Modal d'édition, prérempli avec la liste actuelle (un mot par ligne).
pub fn words_modal(language: Language, settings: &BadWordsSettings) -> serenity::CreateModal {
    let mut input = serenity::CreateInputText::new(
        serenity::InputTextStyle::Paragraph,
        text(language, TextKey::ConfigBadWordsInput),
        WORDS_INPUT_ID,
    )
    .max_length(MAX_CUSTOM_WORDS_INPUT_CHARS as u16)
    .required(false);
    if let Some(value) = prefill(&settings.custom_words) {
        input = input.value(value);
    }

    serenity::CreateModal::new(MODAL_ID, text(language, TextKey::ConfigBadWordsModalTitle))
        .components(vec![serenity::CreateActionRow::InputText(input)])
}

/// Liste actuelle, un mot par ligne ; `None` si elle est vide ou dépasse la
/// longueur du champ (Discord refuserait le modal).
fn prefill(words: &[String]) -> Option<String> {
    let value = words.join("\n");
    (!value.is_empty() && value.chars().count() <= MAX_CUSTOM_WORDS_INPUT_CHARS).then_some(value)
}

/// Texte saisi dans le modal (vide si le champ a été vidé).
pub fn submitted_words(rows: &[serenity::ActionRow]) -> String {
    rows.iter()
        .flat_map(|row| &row.components)
        .find_map(|component| match component {
            serenity::ActionRowComponent::InputText(input) if input.custom_id == WORDS_INPUT_ID => {
                Some(input.value.clone().unwrap_or_default())
            }
            _ => None,
        })
        .unwrap_or_default()
}

const fn language_label(language: BadWordsLanguage) -> TextKey {
    match language {
        BadWordsLanguage::French => TextKey::ConfigBadWordsFrench,
        BadWordsLanguage::English => TextKey::ConfigBadWordsEnglish,
        BadWordsLanguage::All => TextKey::ConfigBadWordsAll,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_ids_round_trip() {
        for candidate in BadWordsLanguage::ALL {
            let custom_id = language_id(candidate);
            assert!(custom_id.len() <= 100);
            assert_eq!(
                parse_action(&custom_id),
                Some(Some(BadWordsAction::SetLanguage(candidate)))
            );
        }
        assert_eq!(parse_action(EDIT_ID), Some(Some(BadWordsAction::Edit)));
    }

    #[test]
    fn forged_or_foreign_ids_are_refused() {
        assert_eq!(
            parse_action("foxsecura:config:bad_words:language:klingon"),
            Some(None)
        );
        assert_eq!(
            parse_action("foxsecura:config:bad_words:language:French"),
            Some(None)
        );
        assert_eq!(parse_action("foxsecura:config:anti_spam:enable"), None);
        assert_eq!(parse_action(MODAL_ID), None);
    }

    #[test]
    fn prefill_is_bounded_by_the_input_length() {
        assert_eq!(prefill(&[]), None);
        assert_eq!(
            prefill(&["a".to_owned(), "gros mot".to_owned()]).as_deref(),
            Some("a\ngros mot")
        );
        let too_long = vec!["x".repeat(100); 21];
        assert_eq!(prefill(&too_long), None);
    }

    #[test]
    fn state_shows_the_persisted_settings() {
        let fields = state_fields(
            Language::French,
            &BadWordsSettings {
                language: BadWordsLanguage::English,
                custom_words: vec!["a".to_owned(), "b".to_owned()],
            },
        );
        assert!(fields[0].1.contains("Anglais"), "{}", fields[0].1);
        assert!(fields[0].1.contains(": 2"), "{}", fields[0].1);
    }
}
