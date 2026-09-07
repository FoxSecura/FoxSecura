// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

const MIN_COMPARABLE_LENGTH: usize = 3;

#[derive(Debug, Clone, Copy)]
pub struct AntiImpersonationDetectionInput<'a> {
    pub candidate_names: &'a [&'a str],
    pub protected_names: &'a [&'a str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiImpersonationDetectionResult {
    pub triggered: bool,
    pub impersonated_name: Option<String>,
    pub matched_candidate: Option<String>,
}

pub fn detect_impersonation(
    input: AntiImpersonationDetectionInput<'_>,
) -> AntiImpersonationDetectionResult {
    let mut protected_by_normalized = HashMap::new();

    for name in input.protected_names {
        let normalized = normalize_name(name);
        if normalized.len() >= MIN_COMPARABLE_LENGTH {
            protected_by_normalized.entry(normalized).or_insert(*name);
        }
    }

    for candidate in input.candidate_names {
        let normalized = normalize_name(candidate);
        if normalized.len() < MIN_COMPARABLE_LENGTH {
            continue;
        }

        if let Some(impersonated) = protected_by_normalized.get(&normalized) {
            return AntiImpersonationDetectionResult {
                triggered: true,
                impersonated_name: Some((*impersonated).to_owned()),
                matched_candidate: Some((*candidate).to_owned()),
            };
        }
    }

    AntiImpersonationDetectionResult {
        triggered: false,
        impersonated_name: None,
        matched_candidate: None,
    }
}

pub fn normalize_name(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());

    for character in value.trim().to_lowercase().chars() {
        match fold_character(character) {
            Some(folded) => normalized.push(folded),
            None if character.is_ascii_alphanumeric() => normalized.push(character),
            None => {}
        }
    }

    while normalized.contains("vv") {
        normalized = normalized.replace("vv", "w");
    }

    normalized
}

fn fold_character(character: char) -> Option<char> {
    match character {
        '0' => Some('o'),
        '1' | '!' | '|' => Some('i'),
        '3' => Some('e'),
        '4' | '@' => Some('a'),
        '5' | '$' => Some('s'),
        '7' => Some('t'),
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => Some('a'),
        'ç' => Some('c'),
        'è' | 'é' | 'ê' | 'ë' => Some('e'),
        'ì' | 'í' | 'î' | 'ï' => Some('i'),
        'ñ' => Some('n'),
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' => Some('o'),
        'ù' | 'ú' | 'û' | 'ü' => Some('u'),
        'ý' | 'ÿ' => Some('y'),
        _ => None,
    }
}
