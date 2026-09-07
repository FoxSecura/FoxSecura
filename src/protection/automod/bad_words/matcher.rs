// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use crate::protection::shared::ProtectionDecision;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadWordsDetectionResult {
    pub decision: ProtectionDecision,
    pub matched_word: Option<String>,
}

#[derive(Debug, Clone)]
struct CompiledBlockedWord {
    original: String,
    normalized: String,
}

#[derive(Debug, Clone, Default)]
pub struct BadWordsMatcher {
    words: Vec<CompiledBlockedWord>,
}

impl BadWordsMatcher {
    pub fn new<I, S>(blocked_words: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = HashSet::new();
        let mut words = Vec::new();

        for word in blocked_words {
            let original = word.as_ref().trim();
            if original.is_empty() {
                continue;
            }

            let normalized = original.to_lowercase();
            if seen.insert(normalized.clone()) {
                words.push(CompiledBlockedWord {
                    original: original.to_owned(),
                    normalized,
                });
            }
        }

        Self { words }
    }

    pub fn detect(&self, content: &str) -> BadWordsDetectionResult {
        let normalized_content = content.to_lowercase();
        let matched_word = self
            .words
            .iter()
            .find(|word| contains_with_word_boundaries(&normalized_content, &word.normalized))
            .map(|word| word.original.clone());

        BadWordsDetectionResult {
            decision: if matched_word.is_some() {
                ProtectionDecision::Block
            } else {
                ProtectionDecision::Allow
            },
            matched_word,
        }
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }
}

pub fn detect_bad_words<I, S>(content: &str, blocked_words: I) -> BadWordsDetectionResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    BadWordsMatcher::new(blocked_words).detect(content)
}

fn contains_with_word_boundaries(content: &str, blocked_word: &str) -> bool {
    content.match_indices(blocked_word).any(|(start, _)| {
        let end = start + blocked_word.len();
        let before = content[..start].chars().next_back();
        let after = content[end..].chars().next();

        !before.is_some_and(is_word_character) && !after.is_some_and(is_word_character)
    })
}

fn is_word_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}
