// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Mots interdits personnalisés d'une guilde : saisie et bornes de la V1.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

/// Nombre maximal de mots personnalisés par guilde.
pub const MAX_CUSTOM_WORDS: usize = 200;
/// Longueur maximale d'un mot ou d'une expression, en caractères.
pub const MAX_CUSTOM_WORD_CHARS: usize = 100;
/// Longueur maximale de la saisie complète, en caractères.
pub const MAX_CUSTOM_WORDS_INPUT_CHARS: usize = 2000;

/// Saisie refusée : rien n'est enregistré.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomWordsError {
    InputTooLong,
    TooManyWords,
    WordTooLong,
    /// Caractère de contrôle dans un mot.
    InvalidCharacter,
}

impl fmt::Display for CustomWordsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong => write!(
                formatter,
                "saisie trop longue (plus de {MAX_CUSTOM_WORDS_INPUT_CHARS} caractères)"
            ),
            Self::TooManyWords => {
                write!(formatter, "plus de {MAX_CUSTOM_WORDS} mots personnalisés")
            }
            Self::WordTooLong => write!(
                formatter,
                "mot de plus de {MAX_CUSTOM_WORD_CHARS} caractères"
            ),
            Self::InvalidCharacter => formatter.write_str("caractère de contrôle dans un mot"),
        }
    }
}

impl Error for CustomWordsError {}

/// Analyse la saisie du modal : un mot ou une expression par ligne (la virgule
/// sépare aussi).
///
/// Les mots sont nettoyés, mis en minuscules (la correspondance ignore la
/// casse) et dédoublonnés dans l'ordre de saisie. Une saisie vide vide la
/// liste.
pub fn parse_custom_words(input: &str) -> Result<Vec<String>, CustomWordsError> {
    if input.chars().count() > MAX_CUSTOM_WORDS_INPUT_CHARS {
        return Err(CustomWordsError::InputTooLong);
    }

    let words = input
        .split(['\n', ','])
        .map(|word| word.trim().to_lowercase())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    normalize_custom_words(words)
}

/// Valide et dédoublonne une liste déjà découpée (écriture en base).
pub fn normalize_custom_words<I, S>(words: I) -> Result<Vec<String>, CustomWordsError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for word in words {
        let word = word.as_ref().trim().to_lowercase();
        if word.is_empty() {
            continue;
        }
        if word.chars().any(char::is_control) {
            return Err(CustomWordsError::InvalidCharacter);
        }
        if word.chars().count() > MAX_CUSTOM_WORD_CHARS {
            return Err(CustomWordsError::WordTooLong);
        }
        if seen.insert(word.clone()) {
            normalized.push(word);
        }
    }

    if normalized.len() > MAX_CUSTOM_WORDS {
        return Err(CustomWordsError::TooManyWords);
    }

    Ok(normalized)
}
