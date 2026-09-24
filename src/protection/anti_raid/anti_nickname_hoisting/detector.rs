// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::LazyLock;

use regex::Regex;

/// Préfixe de hoisting de la V1 : un ou plusieurs caractères qui ne sont ni
/// une lettre (`\p{L}`), ni un chiffre (`\p{N}`) Unicode.
///
/// `char::is_alphanumeric` ne suffit pas : il accepte des symboles
/// alphabétiques (`Ⓐ`, catégorie `So`) que la V1 considère comme hoistés.
static HOISTING_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^\p{L}\p{N}]+").expect("motif de hoisting constant et valide"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoistingDetectionResult {
    pub triggered: bool,
    /// Nom sans le préfixe hoisté ni les espaces aux extrémités ; vide si le
    /// nom ne contient ni lettre ni chiffre.
    pub cleaned: String,
}

/// Détecte un nom hoisté (règle V1, après suppression des espaces aux
/// extrémités) et le nettoie.
pub fn detect_hoisted_name(name: &str) -> HoistingDetectionResult {
    let trimmed = name.trim();
    let cleaned = HOISTING_PREFIX.replace(trimmed, "").trim().to_owned();

    HoistingDetectionResult {
        triggered: cleaned != trimmed,
        cleaned,
    }
}
