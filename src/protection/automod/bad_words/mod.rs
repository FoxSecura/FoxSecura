// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Filtre lexical configurable pour les mots et expressions interdits.
//!
//! Cette responsabilité est distincte de `anti_spam::anti_scam`, qui combine
//! plusieurs signaux de fraude au lieu d'appliquer une liste de mots bloqués.

mod cache;
mod custom_words;
mod lists;
mod matcher;

pub use cache::{BadWordsMatcherCache, DEFAULT_MATCHER_CACHE_CAPACITY};
pub use custom_words::{
    CustomWordsError, MAX_CUSTOM_WORD_CHARS, MAX_CUSTOM_WORDS, MAX_CUSTOM_WORDS_INPUT_CHARS,
    normalize_custom_words, parse_custom_words,
};
pub use lists::{
    BadWordsLanguage, DEFAULT_BAD_WORDS_LANGUAGE, built_in_bad_words, resolve_bad_words_language,
    resolve_blocked_words,
};
pub use matcher::{BadWordsDetectionResult, BadWordsMatcher, detect_bad_words};
