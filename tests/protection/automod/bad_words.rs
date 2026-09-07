// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use foxsecura::protection::{
    ProtectionDecision,
    automod::bad_words::{
        BadWordsLanguage, BadWordsMatcher, resolve_bad_words_language, resolve_blocked_words,
    },
};

#[test]
fn matcher_is_case_insensitive_and_uses_word_boundaries() {
    let matcher = BadWordsMatcher::new(["blocked"]);

    assert_eq!(matcher.detect("BLOCKED!").decision, ProtectionDecision::Block);
    assert_eq!(
        matcher.detect("unblockedvalue").decision,
        ProtectionDecision::Allow
    );
}

#[test]
fn matcher_supports_phrases() {
    let matcher = BadWordsMatcher::new(["free gift"]);
    let result = matcher.detect("This is a FREE GIFT for you");

    assert_eq!(result.decision, ProtectionDecision::Block);
    assert_eq!(result.matched_word.as_deref(), Some("free gift"));
}

#[test]
fn matcher_ignores_empty_and_duplicate_entries() {
    let matcher = BadWordsMatcher::new(["word", " WORD ", "", "   "]);

    assert_eq!(matcher.len(), 1);
}

#[test]
fn language_resolution_defaults_to_all() {
    assert_eq!(resolve_bad_words_language(Some("french")), BadWordsLanguage::French);
    assert_eq!(resolve_bad_words_language(Some("ENGLISH")), BadWordsLanguage::English);
    assert_eq!(resolve_bad_words_language(Some("unknown")), BadWordsLanguage::All);
    assert_eq!(resolve_bad_words_language(None), BadWordsLanguage::All);
}

#[test]
fn resolved_words_merge_built_in_and_custom_without_duplicates() {
    let words = resolve_blocked_words(BadWordsLanguage::French, ["merde", "custom-word"]);

    assert_eq!(words.iter().filter(|word| word.as_str() == "merde").count(), 1);
    assert!(words.iter().any(|word| word == "custom-word"));
}
