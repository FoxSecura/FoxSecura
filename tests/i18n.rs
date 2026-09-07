// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::i18n::{
    DEFAULT_LANGUAGE, Language, SUPPORTED_LANGUAGES, TextKey, text,
};

#[test]
fn supports_exactly_the_three_expected_languages() {
    assert_eq!(
        SUPPORTED_LANGUAGES,
        &[Language::English, Language::French, Language::German]
    );
}

#[test]
fn resolves_discord_locale_variants() {
    assert_eq!(Language::from_locale("en-US"), Some(Language::English));
    assert_eq!(Language::from_locale("en_GB"), Some(Language::English));
    assert_eq!(Language::from_locale("fr"), Some(Language::French));
    assert_eq!(Language::from_locale("fr-FR"), Some(Language::French));
    assert_eq!(Language::from_locale("de"), Some(Language::German));
    assert_eq!(Language::from_locale("de-DE"), Some(Language::German));
}

#[test]
fn unsupported_locales_fall_back_to_french() {
    assert_eq!(DEFAULT_LANGUAGE, Language::French);
    assert_eq!(Language::resolve(Some("es-ES")), Language::French);
    assert_eq!(Language::resolve(None), Language::French);
}

#[test]
fn every_key_has_a_non_empty_translation_in_every_language() {
    for &key in TextKey::ALL {
        for &language in SUPPORTED_LANGUAGES {
            assert!(
                !text(language, key).trim().is_empty(),
                "missing translation for {key:?} in {}",
                language.code()
            );
        }
    }
}

#[test]
fn representative_translations_are_distinct_and_readable() {
    assert_eq!(text(Language::English, TextKey::HelpTitle), "FoxSecura | Help");
    assert_eq!(text(Language::French, TextKey::HelpTitle), "FoxSecura | Aide");
    assert_eq!(text(Language::German, TextKey::HelpTitle), "FoxSecura | Hilfe");
}
